use crate::core::memory::read_process_memory;
use crate::core::debugger::Debugger;
use anyhow::Result;
use capstone::prelude::*;
use log::debug;
use nix::sys::ptrace::getregs;

pub trait Disassembler {
    fn disassemble(&self) -> Result<String>;
}

impl Disassembler for Debugger {
    fn disassemble(&self) -> Result<String> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("Failed to create Capstone object");

        let regs = getregs(self.process.pid).unwrap();
        let rip = regs.rip;
        let num_bytes = 64;
        let mut code = vec![0u8; num_bytes];
        read_process_memory(self.process.pid, rip as usize, &mut code)?;
        debug!("{:?}", code);

        let insns = cs.disasm_all(&code, rip)?;
        let mut result = String::new();

        for i in insns.iter() {
            use std::fmt::Write;
            let _ = write!(
                &mut result,
                "0x{:x}: {}\t{}\n",
                i.address(),
                i.mnemonic().unwrap_or(""),
                i.op_str().unwrap_or("")
            );
            if let Some((file, line)) = self.dwarf.get_line_and_file(i.address() - self.process.base_addr) {
                let _ = write!(&mut result, "    at {}:{}\n", file.display(), line);
            }
        }
        Ok(result)
    }
}
