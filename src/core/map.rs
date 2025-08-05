use log::debug;
use nix::unistd::Pid;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader};
use anyhow::{Result, bail};

/// Represents a single memory mapping of a process (a line from `/proc/[pid]/maps`).
#[derive(Debug)]
pub(crate) struct Map {
    pub addr_start: u64,
    pub addr_end: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub shared: bool,
    pub private: bool,
    pub file_path: String,
}

impl Map {
    /// Reads all memory mappings of a process identified by `pid`.
    ///
    /// Returns a vector of `Map` objects or an error if parsing fails.
    pub fn from_pid(pid: Pid) -> Result<Vec<Self>> {
        let maps_info = Self::get_maps_info(pid)?;
        let mut map_objects = Vec::with_capacity(maps_info.len());

        for line in maps_info {
            let map_object = Self::parse_maps_info(line)?;
            map_objects.push(map_object);
        }
        Ok(map_objects)
    }

    /// Parses a single line from `/proc/[pid]/maps` to a `Map` struct.
    ///
    /// Example line:
    /// `622b53609000-622b5360d000 r--p 00000000 103:05 4327957                   /usr/bin/ls`
    pub fn parse_maps_info(line: String) -> Result<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        debug!("Parsing maps line into parts: {:?}", parts);

        if parts.len() < 5 {
         bail!("Failed parsing maps: expected at least 5 fields");
        }

        let addr_range: Vec<&str> = parts[0].split('-').collect();
        if addr_range.len() != 2 {
            bail!("Invalid address range format in maps line");
        }

        let addr_start = u64::from_str_radix(addr_range[0], 16)?;
        let addr_end = u64::from_str_radix(addr_range[1], 16)?;

        let permissions = parts[1];
        let mut read = false;
        let mut write = false;
        let mut execute = false;
        let mut shared = false;
        let mut private = false;

        for ch in permissions.chars() {
            match ch {
                'r' => read = true,
                'w' => write = true,
                'x' => execute = true,
                's' => shared = true,
                'p' => private = true,
                _ => (),
            }
        }

        let file_path = if parts.len() >= 6 {
            parts[5].to_string()
        } else {
            String::new()
        };

        Ok(Map {
            addr_start,
            addr_end,
            read,
            write,
            execute,
            shared,
            private,
            file_path,
        })
    }

    fn get_maps_info(pid: Pid) -> Result<Vec<String>> {
        let file_path = format!("/proc/{}/maps", pid);
        let file = fs::File::open(file_path)?;
        let reader = BufReader::new(file);

        reader.lines().collect::<Result<Vec<String>, _>>().map_err(|e| e.into())
    }
}

impl fmt::Display for Map {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Map {{ addr_start: 0x{:x}, addr_end: 0x{:x}, read: {}, write: {}, execute: {}, shared: {}, private: {}, file_path: '{}' }}",
            self.addr_start,
            self.addr_end,
            self.read,
            self.write,
            self.execute,
            self.shared,
            self.private,
            self.file_path
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    const VALID_MAP_LINE: &str = "622b53609000-622b5360d000 r--p 00000000 103:05 4327957 /usr/bin/ls";
    const VALID_MAP_LINE_NO_PATH: &str = "00400000-00452000 r-xp 00000000 08:02 926459 /bin/cat";
    const INVALID_MAP_LINE_SHORT: &str = "00400000-00452000 r-xp";
    const INVALID_MAP_LINE_BAD_ADDR: &str = "00400000_00452000 r-xp 00000000 08:02 926459 /bin/cat";

    #[test]
    fn test_parse_maps_info_with_file_path() -> Result<()> {
        let map = Map::parse_maps_info(VALID_MAP_LINE.to_string())?;
        assert_eq!(map.addr_start, 0x622b53609000);
        assert_eq!(map.addr_end, 0x622b5360d000);
        assert!(map.read);
        assert!(!map.write);
        assert!(!map.execute);
        assert!(!map.shared); 
        assert!(map.private);
        assert_eq!(map.file_path, "/usr/bin/ls");
        Ok(())
    }

    #[test]
    fn test_parse_maps_info_without_file_path() -> Result<()> {
        let map = Map::parse_maps_info(VALID_MAP_LINE_NO_PATH.to_string())?;
        assert_eq!(map.addr_start, 0x00400000);
        assert_eq!(map.addr_end, 0x00452000);
        assert!(map.read);
        assert!(!map.write);
        assert!(map.execute);
        assert!(!map.shared);
        assert!(map.private);
        assert_eq!(map.file_path, "/bin/cat");
        Ok(())
    }

    #[test]
    fn test_parse_maps_info_invalid_short_line() {
        let err = Map::parse_maps_info(INVALID_MAP_LINE_SHORT.to_string()).unwrap_err();
        assert!(err.to_string().contains("expected at least 5 fields"));
    }

    #[test]
    fn test_parse_maps_info_invalid_addr_range() {
        let err = Map::parse_maps_info(INVALID_MAP_LINE_BAD_ADDR.to_string()).unwrap_err();
        assert!(err.to_string().contains("Invalid address range"));
    }

    #[test]
    fn test_display_format() -> Result<()> {
        let map = Map::parse_maps_info(VALID_MAP_LINE.to_string())?;
        let s = format!("{}", map);
        assert!(s.contains("addr_start: 0x622b53609000"));
        assert!(s.contains("file_path: '/usr/bin/ls'"));
        Ok(())
    }

    #[test]
    fn test_from_pid_reads_maps() -> Result<()> {
        let pid = nix::unistd::getpid();
        let maps = Map::from_pid(pid)?;

        assert!(!maps.is_empty());

        for map in maps {
            assert!(map.addr_start < map.addr_end);
            assert!(map.read || map.write || map.execute || map.shared || map.private);
        }
        Ok(())
    }
}