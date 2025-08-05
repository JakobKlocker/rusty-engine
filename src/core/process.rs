use crate::core::map::Map;
use anyhow::{Result, bail};
use log::{debug, info, warn};
use nix::sys::ptrace;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, execv, fork};
use std::ffi::CString;
use std::fs;
use std::io::{BufRead, BufReader};

#[derive(Debug)]
pub struct Process {
    pub pid: Pid,
    pub maps: Vec<Map>,
    pub base_addr: u64,
}

impl Process {
    pub fn run(exe_path: &str, args: &[&str]) -> Result<Self> {
        let exe_cstr = CString::new(exe_path)?;
        let args_cstr: Vec<CString> = std::iter::once(exe_path)
            .chain(args.iter().cloned())
            .map(|s| CString::new(s).unwrap())
            .collect();

        match unsafe { fork()? } {
            ForkResult::Child => {
                ptrace::traceme()?;
                nix::sys::signal::kill(nix::unistd::getpid(), nix::sys::signal::SIGSTOP)?;
                execv(&exe_cstr, &args_cstr)?;
                panic!("Failed to execv the process");
            }
            ForkResult::Parent { child } => {
                match waitpid(child, None)? {
                    WaitStatus::Stopped(_, nix::sys::signal::SIGSTOP) => {
                        info!("Child stopped before execv, continuing execution");

                        ptrace::cont(child, None)?;

                        // Wait for child to stop again after exec (some debug event or signal)
                        match waitpid(child, None)? {
                            WaitStatus::Stopped(_, _) => {

                                let maps = Map::from_pid(child)?;
                                let base =
                                    Process::get_base_addr_from_map(&maps, child).unwrap_or(0);

                                Ok(Process {
                                    pid: child,
                                    maps,
                                    base_addr: base,
                                })
                            }
                            other => {
                                bail!("Expected child to stop again after execv, got {:?}", other)
                            }
                        }
                    }
                    other => bail!("Expected child to stop due to SIGSTOP, got {:?}", other),
                }
            }
        }
    }

    pub fn attach(pid: i32) -> Result<Self> {
        let pid = Pid::from_raw(pid);
        ptrace::attach(pid)?;
        info!("Successfully attached to PID: {}", pid);

        let maps = Map::from_pid(pid)?;
        Ok(Process {
            pid,
            maps,
            base_addr: 0,
        })
    }

    pub fn detach(&self) -> Result<()> {
        ptrace::detach(self.pid, None)?;
        info!("Detached from PID: {}", self.pid);
        Ok(())
    }

    pub fn print_map_infos(&self) {
        for map in &self.maps {
            println!("{}", map);
        }
    }

    pub fn get_random_rw_memory(&self) -> Result<u64> {
        for map in &self.maps {
            if map.read && map.write {
                return Ok(map.addr_start);
            }
        }
        bail!("No readable/writable memory region found")
    }

    pub fn get_program_name(&self) -> Result<String> {
        let file_path = format!("/proc/{}/comm", self.pid);
        let file = fs::File::open(file_path)?;
        let mut reader = BufReader::new(file);
        let mut process_name = String::new();
        reader.read_line(&mut process_name)?;
        Ok(process_name.trim_end().to_string())
    }

    pub fn get_program_name_from_pid(pid: Pid) -> Result<String> {
        let file_path = format!("/proc/{}/comm", pid);
        let file = fs::File::open(file_path)?;
        let mut buff_reader = BufReader::new(file);

        let mut process_name = String::new();
        buff_reader.read_line(&mut process_name)?;

        Ok(process_name.trim_end().to_string())
    }

    pub fn get_base_addr_from_map(maps: &[Map], pid: Pid) -> Option<u64> {
        match Process::get_program_name_from_pid(pid) {
            Ok(programm_name) => maps
                .iter()
                .find(|map| map.file_path.contains(&programm_name))
                .map(|map| {
                    println!("Base is probably: {:x}", map.addr_start);
                    map.addr_start
                }),
            Err(e) => {
                eprintln!("Failed to get program name: {}", e);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_get_program_name() -> Result<()> {
        let pid = nix::unistd::getpid();
        let proc = Process {
            pid,
            maps: Vec::new(),
            base_addr: 0,
        };

        let name = proc.get_program_name()?;
        assert!(!name.is_empty(), "Process name should not be empty");
        Ok(())
    }

    #[test]
    fn test_get_random_rw_memory() -> Result<()> {
        let pid = nix::unistd::getpid();
        let maps = Map::from_pid(pid)?;
        let proc = Process {
            pid,
            maps,
            base_addr: 0,
        };

        match proc.get_random_rw_memory() {
            Ok(addr) => println!("Found read/write memory at: 0x{:x}", addr),
            Err(e) => println!("No read/write memory found: {}", e),
        }

        Ok(())
    }

    #[test]
    fn test_attach_and_detach() -> anyhow::Result<()> {
        use std::process::Command;
        use std::thread::sleep;
        use std::time::Duration;

        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("Failed to spawn child process");

        let pid = nix::unistd::Pid::from_raw(child.id() as i32);

        sleep(Duration::from_millis(100));
        let proc = Process::attach(pid.as_raw())?;

        proc.detach()?;

        let _ = child.kill();

        Ok(())
    }

    #[test]
    fn test_run_and_detach() -> Result<()> {
        let proc = Process::run("/bin/sleep", &["1"])?; // Sleeps 1 sec, not optiaml for testing
        proc.print_map_infos();
        proc.detach()?;
        let res = waitpid(proc.pid, None).unwrap();
        println!("waitpid result: {:?}", res);
        Ok(())
    }
}
