use anyhow::{Result, bail};
use log::debug;
use nix::libc;
use nix::unistd::Pid;
use std::collections::HashMap;

pub trait PtraceOps {
    fn read(&self, pid: Pid, addr: *mut libc::c_void) -> Result<i64>;
    fn write(&self, pid: Pid, addr: *mut libc::c_void, data: i64) -> Result<()>;
}

#[derive(Debug)]
pub struct RealPtrace;

impl PtraceOps for RealPtrace {
    fn read(&self, pid: Pid, addr: *mut libc::c_void) -> Result<i64> {
        Ok(nix::sys::ptrace::read(pid, addr)?)
    }

    fn write(&self, pid: Pid, addr: *mut libc::c_void, data: i64) -> Result<()> {
        nix::sys::ptrace::write(pid, addr, data)?;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Breakpoint {
    pub(crate) enabled: bool,
    pub(crate) addr: u64,
    pub(crate) original_byte: u8,
    pub(crate) temporary: bool,
    pub(crate) hit_count: u64,
}

pub struct BreakpointManager {
    breakpoints: HashMap<u64, Breakpoint>,
    ptrace: Box<dyn PtraceOps>,
}

impl std::fmt::Debug for BreakpointManager {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("BreakpointManager")
            .field("breakpoints", &self.breakpoints)
            .field("ptrace", &"<PtraceOps>")
            .finish()
    }
}
impl BreakpointManager {
    pub fn new(ptrace: Box<dyn PtraceOps>) -> Self {
        Self {
            breakpoints: HashMap::new(),
            ptrace,
        }
    }

    pub(crate) fn set_breakpoint(&mut self, addr: u64, pid: Pid) -> Result<()> {
        if self.breakpoints.contains_key(&addr) {
            bail!("breakpoint exists already");
        }

        let aligned_addr = addr & !0x7;
        let byte_offset = (addr % 8) as u32;
        let original_word = self.ptrace.read(pid, aligned_addr as *mut libc::c_void)? as u64;
        let original_byte = ((original_word >> (byte_offset * 8)) & 0xFF) as u8;

        let patched_word =
            (original_word & !(0xFF << (byte_offset * 8))) | ((0xCCu64) << (byte_offset * 8));

        debug!("[SET BP] Patched word: {:#018x}", patched_word);

        self.ptrace
            .write(pid, aligned_addr as *mut libc::c_void, patched_word as i64)?;

        let bp = Breakpoint {
            enabled: true,
            addr,
            original_byte,
            temporary: false,
            hit_count: 0,
        };

        self.breakpoints.insert(addr, bp);
        debug!("[SET BP] Breakpoint set at {:#x}.", addr);

        Ok(())
    }

    pub fn remove_breakpoint(&mut self, addr: u64, pid: Pid) -> Result<()> {
        if let Some(bp) = self.breakpoints.remove(&addr) {
            let aligned_addr = addr & !0x7;
            let byte_offset = (addr % 8) as u32;

            let current_word = self.ptrace.read(pid, aligned_addr as *mut libc::c_void)? as u64;

            let restored_word = (current_word & !(0xFF << (byte_offset * 8)))
                | ((bp.original_byte as u64) << (byte_offset * 8));

            self.ptrace
                .write(pid, aligned_addr as *mut libc::c_void, restored_word as i64)?;

            debug!(
                "[REMOVE BP] Breakpoint at {:#x} removed and restored.",
                addr
            );

            Ok(())
        } else {
            bail!("breakpoint not found");
        }
    }

    pub fn get_breakpoints(&self) -> Vec<&Breakpoint> {
        self.breakpoints.values().collect()
    }

    pub fn has_breakpoint(&self, addr: u64) -> bool {
        self.breakpoints.contains_key(&addr)
    }

    pub fn breakpoint_addresses(&self) -> Vec<u64> {
        self.breakpoints.keys().cloned().collect()
    }

    pub fn clear_all_breakpoints(&mut self, pid: Pid) -> Result<()> {
        for addr in self.breakpoints.keys().cloned().collect::<Vec<_>>() {
            self.remove_breakpoint(addr, pid)?;
        }
        Ok(())
    }

    pub fn enable_breakpoint(&mut self, _addr: u64, _pid: Pid) -> Result<()> {
        //might be added later, check if necessary
        Ok(())
    }

    pub fn disable_breakpoint(&mut self, _addr: u64, _pid: Pid) -> Result<()> {
        //might be added later, check if necessary
        Ok(())
    }

    pub fn hit_breakpoint(&mut self, addr: u64) -> Result<()> {
        if let Some(bp) = self.breakpoints.get_mut(&addr) {
            bp.hit_count += 1;
            Ok(())
        } else {
            bail!("breakpoint not found");
        }
    }

    pub fn get_hit_count(&self, addr: u64) -> Option<u64> {
        self.breakpoints.get(&addr).map(|bp| bp.hit_count)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::{mock, predicate::*};
    use nix::unistd::Pid;

    mock! {
        pub Ptrace {}

        impl PtraceOps for Ptrace {
            fn read(&self, pid: Pid, addr: *mut libc::c_void) -> Result<i64>;
            fn write(&self, pid: Pid, addr: *mut libc::c_void, data: i64) -> Result<()>;
        }
    }

    #[test]
    fn test_set_and_remove_breakpoint() {
        let mut mock_ptrace = MockPtrace::new();
        let pid = Pid::from_raw(1234);
        let test_addr: u64 = 0x1003;
        let aligned_addr = test_addr & !0x7;
        let byte_offset = (test_addr % 8) as u32;

        let original_word: u64 = 0x1122334455667788;

        mock_ptrace
            .expect_read()
            .withf(move |p, addr| *p == pid && *addr == (aligned_addr as *mut libc::c_void))
            .times(1)
            .returning(move |_, _| Ok(original_word as i64));

        let expected_patched_word =
            (original_word & !(0xFF << (byte_offset * 8))) | (0xCCu64 << (byte_offset * 8));
        mock_ptrace
            .expect_write()
            .withf(move |_, addr, data| {
                *addr == (aligned_addr as *mut libc::c_void)
                    && (*data as u64) == expected_patched_word
            })
            .times(1)
            .returning(|_, _, _| Ok(()));

        mock_ptrace
            .expect_read()
            .withf(move |p, addr| *p == pid && *addr == (aligned_addr as *mut libc::c_void))
            .times(1)
            .returning(move |_, _| Ok(expected_patched_word as i64));

        mock_ptrace
            .expect_write()
            .withf(move |_, addr, data| {
                *addr == (aligned_addr as *mut libc::c_void) && (*data as u64) == original_word
            })
            .times(1)
            .returning(|_, _, _| Ok(()));

        let mut manager = BreakpointManager::new(Box::new(mock_ptrace));

        manager.set_breakpoint(test_addr, pid).unwrap();
        assert!(manager.has_breakpoint(test_addr));

        manager.remove_breakpoint(test_addr, pid).unwrap();
        assert!(!manager.has_breakpoint(test_addr));
    }

    #[test]
    fn test_set_breakpoint_duplicate() {
        let mut mock_ptrace = MockPtrace::new();
        let pid = Pid::from_raw(1234);
        let test_addr: u64 = 0x2000;

        mock_ptrace.expect_read().returning(|_, _| Ok(0u64 as i64));
        mock_ptrace.expect_write().returning(|_, _, _| Ok(()));

        let mut manager = BreakpointManager::new(Box::new(mock_ptrace));

        manager.set_breakpoint(test_addr, pid).unwrap();

        let res = manager.set_breakpoint(test_addr, pid);
        assert!(res.is_err());
    }
}
