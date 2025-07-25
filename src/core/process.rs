use crate::core::map::Map;
use anyhow::{Result, bail};
use log::{debug, info, warn};
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::fs;
use std::io::{BufRead, BufReader};

#[derive(Debug)]
pub struct Process {
    pub pid: Pid,
    pub maps: Vec<Map>,
    pub base_addr: u64,
}

impl Process {
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

    pub fn update_base_addr(&mut self) -> Option<u64> {
        let program_name = match self.get_program_name() {
            Ok(name) => name,
            Err(e) => {
                warn!("Failed to get program name: {}", e);
                return None;
            }
        };

        let maybe_base = self.maps.iter().find(|map| {
            map.read
                && map.execute
                && (map.file_path.ends_with(&program_name) || map.file_path == program_name)
        });

        if let Some(map) = maybe_base {
            debug!("Base address identified: 0x{:x}", map.addr_start);
            self.base_addr = map.addr_start;
            Some(map.addr_start)
        } else {
            warn!("Failed to identify executable segment for base address.");
            None
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
    fn test_update_base_addr() -> Result<()> {
        let pid = nix::unistd::getpid();
        let mut proc = Process {
            pid,
            maps: Map::from_pid(pid)?,
            base_addr: 0,
        };

        let base = proc.update_base_addr();
        if let Some(addr) = base {
            assert_eq!(proc.base_addr, addr);
            println!("Base address: 0x{:x}", addr);
        } else {
            println!("Base address not identified");
        }
        Ok(())
    }
}
