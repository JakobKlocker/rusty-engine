use crate::core::breakpoint::*;
use crate::core::process::*;
use crate::core::symbols::*;
use anyhow::Result;
use log::{debug, info};
use nix::sys::ptrace::getregs;
use std::path::Path;
use std::process::Command;
use std::fs;
use anyhow::Context;

#[derive(Debug, Clone)]
pub enum DebuggerState {
    Interactive,
    AwaitingTrap,
    Exit,
}

#[derive(Debug)]
pub struct Debugger {
    pub process: Process,
    pub breakpoint: BreakpointManager,
    pub state: DebuggerState,
    pub functions: Vec<FunctionInfo>,
    pub dwarf: DwarfContext,
    pub exe_path: String,
}

impl Debugger {
    /// Attaches debugger to an existing process.
    pub fn attach_to(pid: i32) -> Result<Self> {
        let proc = Process::attach(pid)?;
        let bp_manager = BreakpointManager::new(Box::new(RealPtrace));
        let path = get_exe_path_from_pid(pid)?;
        Ok(Debugger {
            process: proc,
            breakpoint: bp_manager,
            state: DebuggerState::Interactive,
            functions: FunctionInfo::new(&path),
            dwarf: DwarfContext::new(&path).unwrap(),
            exe_path: path
        })
    }

    /// Launches a new process to debug.
    pub fn launch(exe_path: &String, args: &[&str]) -> Result<Self> {
        let proc = Process::run(exe_path, args)?;
        let bp_manager = BreakpointManager::new(Box::new(RealPtrace));
        Ok(Debugger {
            process: proc,
            breakpoint: bp_manager,
            state: DebuggerState::Interactive,
            functions: FunctionInfo::new(&exe_path),
            dwarf: DwarfContext::new(&exe_path).unwrap(),
            exe_path: exe_path.to_string()
        })
    }

    pub fn parse_address(&self, input: &str) -> Result<u64> {
        let trimmed = input.trim();

        if let Some(stripped) = trimmed.strip_prefix("0x") {
            u64::from_str_radix(stripped, 16)
                .map_err(|e| anyhow::anyhow!("invalid hex address: {}", e))
        } else {
            u64::from_str_radix(trimmed, 10)
                .map_err(|e| anyhow::anyhow!("invalid dec address: {}", e))
        }
    }
    
        pub fn get_function_name(&self, target_addr: u64) -> Option<String> {
        self.functions
            .iter()
            .find(|f| f.offset <= target_addr && f.offset + f.size > target_addr)
            .map(|f| f.name.clone())
    }

}

fn get_pid_from_input(input: String) -> i32 {
    if Path::new(&format!("/proc/{}", input)).is_dir() {
        info!("{} is a pid", input);
        input.parse().expect("Failed to parse PID")
    } else if Path::new(&input).is_file() {
        info!("{} is a file", input);
        info!("Executing {}", input);
        let child = Command::new(input).spawn().unwrap();
        child.id() as i32
    } else {
        panic!("provided pid|path not valid");
    }
}

fn get_exe_path_from_pid(pid: i32) -> Result<String> {
    let exe_link = format!("/proc/{}/exe", pid);
    let path = fs::read_link(&exe_link)
        .with_context(|| format!("Failed to read exe link path for pid {}", pid))?;
    Ok(path.to_string_lossy().to_string())
}

