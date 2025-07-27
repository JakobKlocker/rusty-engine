use crate::core::breakpoint::*;
use crate::core::process::*;
use anyhow::Result;
use log::{debug, info};
use nix::sys::ptrace::getregs;
use std::path::Path;
use std::process::Command;

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
    //pub dwarf: DwarfContext,
    //pub path: String,
}

impl Debugger {
    pub fn new(debugee_pid_path: String, debuger_name: String) -> Self {
        let real_ptrace = Box::new(RealPtrace);

        Debugger {
            process: Process::attach(0).expect("asd"),
            breakpoint: BreakpointManager::new(real_ptrace),
            //functions: FunctionInfo::new(&debugee_pid_path, debuger_name),
            state: DebuggerState::Interactive,
            //dwarf: DwarfContext::new(&debugee_pid_path).unwrap(),
            //path: debugee_pid_path,
        }
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
