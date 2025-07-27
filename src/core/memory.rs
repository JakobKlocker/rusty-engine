use crate::core::debugger;
use crate::core::debugger::Debugger;
use anyhow::{Result, anyhow};
use libc::{iovec, pid_t, process_vm_readv};
use nix::sys::ptrace;
use nix::unistd::Pid;
use std::convert::TryInto;
use std::io::Error;
use std::mem::size_of;

pub trait Memory {
    fn patch(&self, addr_str: &str, value_str: &str) -> Result<()>;
    fn get_address_value(&self, addr_str: &str) -> Result<i64>;

    fn read_addr_value<T>(&self, addr_str: &str) -> Result<T>
    where
        T: Copy + FromBytes;
}

impl Memory for Debugger {
    fn patch(&self, addr_str: &str, value_str: &str) -> Result<()> {
        let addr = self.parse_address(addr_str)?;
        let value = self.parse_address(value_str)?;
        ptrace::write(self.process.pid, addr as ptrace::AddressType, value as i64)?;
        Ok(())
    }

    fn get_address_value(&self, addr_str: &str) -> Result<i64> {
        self.read_addr_value::<i64>(addr_str)
    }

    fn read_addr_value<T>(&self, addr_str: &str) -> Result<T>
    where
        T: Copy + FromBytes,
    {
        let addr = self.parse_address(addr_str)?;
        let size = size_of::<T>();
        let mut buf = vec![0u8; size];
        read_process_memory(self.process.pid, addr as usize, &mut buf)?;
        let fixed: &[u8] = buf.as_slice();
        let arr = fixed
            .try_into()
            .map_err(|_| anyhow!("slice with incorrect length for type"))?;
        Ok(T::from_ne_bytes(arr))
    }
}

/// Reads memory from another process using process_vm_readv syscall
pub fn read_process_memory(pid: Pid, addr: usize, buf: &mut [u8]) -> Result<usize> {
    let local = iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: buf.len(),
    };

    let remote = iovec {
        iov_base: addr as *mut _,
        iov_len: buf.len(),
    };

    let result = unsafe { process_vm_readv(pid.as_raw() as pid_t, &local, 1, &remote, 1, 0) };

    if result == -1 {
        Err(Error::last_os_error().into())
    } else {
        Ok(result as usize)
    }
}

pub trait FromBytes: Sized {
    /// Convert native-endian bytes to Self
    fn from_ne_bytes(bytes: &[u8]) -> Self;
}

impl FromBytes for u8 {
    fn from_ne_bytes(bytes: &[u8]) -> Self {
        bytes[0]
    }
}

impl FromBytes for i8 {
    fn from_ne_bytes(bytes: &[u8]) -> Self {
        bytes[0] as i8
    }
}

impl FromBytes for u16 {
    fn from_ne_bytes(bytes: &[u8]) -> Self {
        let arr: [u8; 2] = bytes.try_into().expect("slice with incorrect length [u16]");
        u16::from_ne_bytes(arr)
    }
}

impl FromBytes for i16 {
    fn from_ne_bytes(bytes: &[u8]) -> Self {
        let arr: [u8; 2] = bytes.try_into().expect("slice with incorrect length [i16]");
        i16::from_ne_bytes(arr)
    }
}

impl FromBytes for u32 {
    fn from_ne_bytes(bytes: &[u8]) -> Self {
        let arr: [u8; 4] = bytes.try_into().expect("slice with incorrect length [u32]");
        u32::from_ne_bytes(arr)
    }
}

impl FromBytes for i32 {
    fn from_ne_bytes(bytes: &[u8]) -> Self {
        let arr: [u8; 4] = bytes.try_into().expect("slice with incorrect length [i32]");
        i32::from_ne_bytes(arr)
    }
}

impl FromBytes for u64 {
    fn from_ne_bytes(bytes: &[u8]) -> Self {
        let arr: [u8; 8] = bytes.try_into().expect("slice with incorrect length [u64]");
        u64::from_ne_bytes(arr)
    }
}

impl FromBytes for i64 {
    fn from_ne_bytes(bytes: &[u8]) -> Self {
        let arr: [u8; 8] = bytes.try_into().expect("slice with incorrect length [i64]");
        i64::from_ne_bytes(arr)
    }
}

#[cfg(test)]
mod from_bytes_tests {
    use super::FromBytes;

    #[test]
    fn test_u8_from_bytes() {
        let bytes = [0xAB];
        let val = u8::from_ne_bytes(bytes);
        assert_eq!(val, 0xAB);
    }

    #[test]
    fn test_i8_from_bytes() {
        let bytes = [0xFF]; // -1 in i8
        let val = i8::from_ne_bytes(bytes);
        assert_eq!(val, -1);
    }

    #[test]
    fn test_u16_from_bytes() {
        let bytes = [0x34, 0x12]; // 0x1234 little endian
        let val = u16::from_ne_bytes(bytes);
        assert_eq!(val, 0x1234);
    }

    #[test]
    fn test_i16_from_bytes() {
        let bytes = [0xFE, 0xFF]; // -2 in i16 (0xFFFE)
        let val = i16::from_ne_bytes(bytes);
        assert_eq!(val, -2);
    }

    #[test]
    fn test_u32_from_bytes() {
        let bytes = [0x78, 0x56, 0x34, 0x12]; // 0x12345678 little endian
        let val = u32::from_ne_bytes(bytes);
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_i32_from_bytes() {
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF]; // -1 in i32
        let val = i32::from_ne_bytes(bytes);
        assert_eq!(val, -1);
    }

    #[test]
    fn test_u64_from_bytes() {
        let bytes = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01]; // 0x0123456789ABCDEF little endian
        let val = u64::from_ne_bytes(bytes);
        assert_eq!(val, 0x0123456789ABCDEF);
    }

    #[test]
    fn test_i64_from_bytes() {
        let bytes = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]; // most negative i64 (-2^63)
        let val = i64::from_ne_bytes(bytes);
        assert_eq!(val, i64::MIN);
    }

    #[test]
    #[should_panic(expected = "slice with incorrect length")]
    fn test_panic_on_invalid_slice_length_u16() {
        let bytes = [0x01]; 

        let _arr: [u8; 2] = bytes[..].try_into().expect("slice with incorrect length");
    }
}
