const CFA_REG_RBP: u16 = 6;
const CFA_REG_RSP: u16 = 7;
const CFA_REG_RIP: u16 = 16;
const MAX_FRAMES: usize = 64;

use crate::core::debugger::Debugger;
use crate::core::symbols::get_unwind_info;
use anyhow::{Result, anyhow};
use log::debug;
use nix::sys::ptrace;
use nix::sys::ptrace::*;
  
pub trait Backtrace {
    fn backtrace(&self) -> Result<Vec<String>>;
}

impl Backtrace for Debugger {
    fn backtrace(&self) -> Result<Vec<String>> {
        let regs = getregs(self.process.pid)?;
        let mut rip = regs.rip;
        let mut rsp = regs.rsp;
        let mut rbp = regs.rbp;
        let mut frames = Vec::new();

        for _frame_idx in 0..MAX_FRAMES {
            let func_offset = rip
                .checked_sub(self.process.base_addr)
                .ok_or_else(|| anyhow!("rip below base_addr"))?;
            let info = match get_unwind_info(&self.exe_path, func_offset) {
                Ok(info) => info,
                Err(_) => break, // no unwind info, end backtrace
            };

            let cfa_base = match info.cfa_register {
                CFA_REG_RBP => rbp,
                CFA_REG_RSP => rsp,
                CFA_REG_RIP => rip,
                other => return Err(anyhow!("unsupported CFA register {}", other)),
            };

            let cfa = (cfa_base as i64)
                .checked_add(info.cfa_offset)
                .ok_or_else(|| anyhow!("CFA offset overflow"))? as u64;

            let ret_addr_addr = (cfa as i64)
                .checked_add(info.ra_offset)
                .ok_or_else(|| anyhow!("RA offset overflow"))? as u64;

            let ret_addr = ptrace::read(self.process.pid, ret_addr_addr as ptrace::AddressType)? as u64;

            let func_offset = ret_addr.checked_sub(self.process.base_addr).unwrap_or(0);

            let func_name = self
                .get_function_name(func_offset)
                .unwrap_or_else(|| "_start".to_string());

            frames.push(func_name);

            if ret_addr == 0 || rip == ret_addr {
                break; // end backtrace if invalid or non-progressing pointer
            }

            rip = ret_addr;
            rsp = cfa;

            if info.cfa_register == CFA_REG_RBP {
                let saved_rbp_addr = (cfa as i64)
                    .checked_sub(16)
                    .ok_or_else(|| anyhow!("saved rbp offset overflow"))? as u64;
                rbp = ptrace::read(self.process.pid, saved_rbp_addr as ptrace::AddressType)? as u64;
            }
        }

        Ok(frames)
    }
}
