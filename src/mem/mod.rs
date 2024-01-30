use crate::log;

use std::io::{BufReader, Seek, SeekFrom, Read, Write};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};
use std::os::unix::fs::FileExt;
use std::collections::HashMap;
use std::fs::File;
use std::thread;

use indicatif::ProgressBar;

#[derive(PartialEq, Debug)]
pub enum Perm {
    Read,
    Write,
}

#[derive(Clone, Copy)]
pub enum BitSize {
    Bits32,
    Bits64,
}

impl BitSize {
    pub fn bytes(&self) -> usize {
        match self {
            BitSize::Bits64 => 8,
            BitSize::Bits32 => 4,
        }
    }
}

pub struct PtrMap {
    address: usize,
    children: Vec<PtrMap>,
}

impl PtrMap {
    pub fn dump(&self, indentation: usize) {
        if !self.children.is_empty() {
            log::info(&format!("-- {} --", self.address));
        }

        for ptrmap in &self.children {
            log::info(&format!("{}{} -> {}", " ".repeat(indentation), ptrmap.address, self.address));

            ptrmap.dump(indentation + 1);
        }
    }
}

#[derive(Debug)]
pub struct Map {
    base: usize,
    ceiling: usize,
    perms: Vec<Perm>,
    name: String,
}

pub struct Process {
    pub pid: usize,
    pub name: String,
}

pub struct Lock {
    handle: thread::JoinHandle<Arc<AtomicBool>>,
    should_close: Arc<AtomicBool>,
}

pub struct Memory {
    pub mem: Option<File>,
    pub maps: Vec<Map>,
    pub entries: Vec<usize>,
    pub table: HashMap<String, usize>,
    pub locks: HashMap<usize, Lock>,
    pub process: Process,
}

impl Memory {
    pub fn new() -> Memory {
        Memory {
            mem: None,
            maps: Vec::new(),
            entries: Vec::new(),
            table: HashMap::new(),
            locks: HashMap::new(),
            process: Process {
                pid: 0,
                name: String::new(),
            },
        }
    }

    fn process_maps(&mut self, pid: usize) -> Result<(), Box<dyn std::error::Error>> {
        let raw = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;

        for line in raw.lines() {
            let tokens = line.split(' ').filter(|x| !x.is_empty()).collect::<Vec<&str>>();

            if !tokens.is_empty() {
                let range = tokens[0].split('-').collect::<Vec<&str>>();

                let mut perms: Vec<Perm> = Vec::new();
                {
                    if tokens[1].contains("r") {
                        perms.push(Perm::Read);
                    }

                    if tokens[1].contains("w") {
                        perms.push(Perm::Write);
                    }
                }

                let name = if tokens.len() > 5 {
                    tokens[5].to_string()
                } else {
                    String::new()
                };

                self.maps.push(Map {
                    base: usize::from_str_radix(range[0], 16)?,
                    ceiling: usize::from_str_radix(range[1], 16)?,
                    perms,
                    name,
                });
            }
        }

        Ok(())
    }

    pub fn dump_table(&mut self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut fd = File::create(filename)?;

        for (name, address) in &self.table {
            fd.write_all(format!("{name} -> {address}\n").as_bytes())?;
        }

        Ok(())
    }

    pub fn load_table(&mut self, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
        let raw = std::fs::read_to_string(filename)?;

        for line in raw.lines() {
            let tokens = line
                .split("->")
                .filter(|x| *x != " " && !x.is_empty())
                .collect::<Vec<&str>>();

            if tokens.len() == 2 {
                self.table.insert(tokens[0].to_string(), usize::from_str_radix(tokens[1], 16)?);
            }
        }

        Ok(())
    }

    pub fn attach(&mut self, pid: usize) -> Result<(), Box<dyn std::error::Error>> {
        self.mem = Some(
            File::options()
                .read(true)
                .write(true)
                .open(format!("/proc/{pid}/mem"))?
        );

        self.process.pid = pid;
        self.process.name = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))?;

        self.process_maps(pid)?;

        log::info(&format!("process found {} -- {}", self.process.name, self.process.pid));

        Ok(())
    }

    pub fn detach(&mut self) {
        self.mem = None;
        self.maps.drain(..);
        self.entries.drain(..);
        self.process.pid = 0;
        self.process.name = String::new();
    }

    fn lock_addr(fd: std::os::fd::RawFd, should_close: Arc<AtomicBool>, address: usize, value: usize, bitsize: BitSize) -> Arc<AtomicBool> {
        let mem = unsafe { File::from_raw_fd(fd) };

        while !should_close.load(Ordering::Relaxed) {
            let mut buf = Self::to_bytes(value);
            let read_status = mem.read_at(&mut buf, address as u64);

            let write_status = if buf != Self::to_bytes(value) {
                let bytes = Self::to_bytes(value);

                match bitsize {
                    BitSize::Bits32 => mem.write_at(&bytes[..4], address as u64),
                    BitSize::Bits64 => mem.write_at(&bytes, address as u64),
                }
            } else {
                Ok(0)
            };

            if read_status.is_err() || write_status.is_err() {
                return Arc::new(AtomicBool::new(false));
            }
        }

        Arc::new(AtomicBool::new(true))
    }

    pub fn lock(&mut self, address: usize, value: usize, bitsize: BitSize) {
        if let Some(mem) = &self.mem {
            let should_close: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
            let clone = should_close.clone();
            let fd = mem.as_raw_fd();

            let handle = thread::spawn(move || Self::lock_addr(fd, clone, address, value, bitsize));

            self.locks.insert(address, Lock {
                handle,
                should_close,
            });
        }
    }

    pub fn unlock(&mut self, address: usize) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(lock) = self.locks.remove(&address) {
            lock.should_close.store(true, Ordering::Relaxed);

            if let Ok(result) = lock.handle.join() {
                if result.load(Ordering::Relaxed) {
                    log::info("unlocked successfully");
                } else {
                    log::error("lock failed");
                }
            }

            // prevents: bad file descriptor (os error 9)
            self.mem = Some(
                File::options()
                    .read(true)
                    .write(true)
                    .open(format!("/proc/{}/mem", self.process.pid))?
            );
        }

        Ok(())
    }

    pub fn exec_no_aslr(&mut self, program: &str) -> Result<(), Box<dyn std::error::Error>> {
        // reference: https://man7.org/linux/man-pages/man8/setarch.8.html

        let architecture = Command::new("uname")
            .arg("-m")
            .output()?;

        let child = Command::new("setarch")
            .args([
                &String::from_utf8(architecture.stdout.iter().map(|x| *x).filter(|x| *x != 10).collect())?,
                "-R",
                program
            ])
            .stdout(Stdio::null())
            .stdin(Stdio::null())
            .spawn()?;

        log::info(&format!("{} -- {}", program, child.id()));

        Ok(())
    }

    fn from_bytes32(bytes: [u8; 4]) -> u32 {
        if cfg!(target_endian = "big") {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        }
    }

    fn from_bytes64(bytes: [u8; 8]) -> u64 {
        if cfg!(target_endian = "big") {
            u64::from_be_bytes(bytes)
        } else {
            u64::from_le_bytes(bytes)
        }
    }

    fn to_bytes(integer: usize) -> [u8; 8] {
        if cfg!(target_endian = "big") {
            integer.to_be_bytes()
        } else {
            integer.to_le_bytes()
        }
    }

    pub fn ptrmap(&mut self, address: usize) -> Result<PtrMap, Box<dyn std::error::Error>> {
        let mut ptrmap = PtrMap {
            address,
            children: Vec::new(),
        };

        self.scan(address, BitSize::Bits64, "[none]")?;

        for entry in self.entries.clone() {
            ptrmap.children.push(self.ptrmap(entry)?);
        }

        Ok(ptrmap)
    }

    pub fn read_buffer(&self, reader: &mut BufReader<&File>, address: usize, size: BitSize) -> Result<usize, Box<dyn std::error::Error>> {
        reader.seek(SeekFrom::Start(address as u64))?;

        match size {
            BitSize::Bits32 => {
                let mut buffer = [0u8; 4];
                reader.read_exact(&mut buffer)?;

                Ok(Self::from_bytes32([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize)
            },
            BitSize::Bits64 => {
                let mut buffer = [0u8; 8];
                reader.read_exact(&mut buffer)?;

                Ok(Self::from_bytes64(buffer) as usize)
            },
        }
    }

    pub fn write(&mut self, address: usize, value: usize, size: BitSize) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = Self::to_bytes(value);

        if let Some(mem) = &mut self.mem {
            match size {
                BitSize::Bits32 => { mem.write_at(&bytes[..4], address as u64)?; },
                BitSize::Bits64 => { mem.write_at(&bytes, address as u64)?; },
            }
        }

        Ok(())
    }

    pub fn scan(&mut self, value: usize, size: BitSize, range: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(mem) = &self.mem {
            let mut reader = BufReader::new(mem);

            if self.entries.is_empty() {
                for map in &self.maps {
                    if map.perms.contains(&Perm::Read) &&
                        (map.name == range || range == "[none]") &&
                        !map.name.is_empty() &&
                        !map.name.contains(".so") &&
                        !map.name.contains(&self.process.name) &&
                        !["[vvar]", "[vsyscall]"].contains(&map.name.as_str())
                    {
                        log::info(&format!("scanning map `{}` with range `{}-{}`", map.name, map.base, map.ceiling));

                        let pb = ProgressBar::new((map.ceiling - map.base) as u64);

                        for addr in map.base..map.ceiling - size.bytes() {
                            let output = self.read_buffer(&mut reader, addr, size)?;

                            if output == value {
                                self.entries.push(addr);
                            }

                            pb.inc(1);
                        }

                        pb.finish_and_clear();
                    }
                }
            } else {
                let pb = ProgressBar::new(self.entries.len() as u64);
                let mut next_entries: Vec<usize> = Vec::new();

                for addr in &self.entries {
                    let output = self.read_buffer(&mut reader, *addr, size)?;

                    if output == value {
                        next_entries.push(*addr);
                    }

                    pb.inc(1);
                }

                self.entries = next_entries;

                pb.finish_and_clear();
            }
        }

        Ok(())
    }
}

