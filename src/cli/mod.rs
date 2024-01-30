use crate::BitSize;
use crate::Memory;
use crate::log;

use rustyline::DefaultEditor;
use colored::Colorize;

use std::io::BufReader;

pub struct Cli {
    memory: Memory,
    should_close: bool,
}

impl Cli {
    pub fn new() -> Cli {
        Cli {
            memory: Memory::new(),
            should_close: false,
        }
    }

    fn to_bitsize(&self, string: &str) -> Result<BitSize, Box<dyn std::error::Error>> {
        match string {
            "32" => Ok(BitSize::Bits32),
            "64" => Ok(BitSize::Bits64),
            _ => Err("no such bitsize".into()),
        }
    }

    fn command(&mut self, buffer: &String) -> Result<(), Box<dyn std::error::Error>> {
        let tokens = buffer.split([' ', '\n']).filter(|x| x != &"\n").collect::<Vec<&str>>();

        match tokens[0] {
            "attach" => {
                if tokens.len() != 2 {
                    log::warning("Usage: attach [pid]");
                } else {
                    self.memory.attach(tokens[1].parse::<usize>()?)?;
                }
            },
            "detach" => {
                self.memory.detach();
            },
            "scan" => {
                if tokens.len() != 4 {
                    log::warning("Usage: scan [value] [bitsize] [range]");
                } else {
                    match self.to_bitsize(tokens[2]) {
                        Ok(bitsize) => {
                            self.memory.scan(tokens[1].parse::<usize>()?, bitsize, tokens[3])?;
                            log::info(&format!("{} entries in [`{}`/`{}`]", self.memory.entries.len(), self.memory.process.name, self.memory.process.pid));
                        },
                        Err(err) => log::error(&err.to_string()),
                    }
                }
            },
            "entries" => {
                log::info(&format!("entries found in [`{}`/`{}`]", self.memory.process.name, self.memory.process.pid));

                for addr in &self.memory.entries {
                    log::info(&format!("0x{:x}", addr));
                }
            },
            "read" => {
                if tokens.len() != 3 {
                    log::warning("Usage: read [addr] [bitsize]");
                } else {
                    match self.to_bitsize(tokens[2]) {
                        Ok(bitsize) => {
                            if let Some(mem) = &self.memory.mem {
                                let mut reader = BufReader::new(mem);
                                let addr = usize::from_str_radix(tokens[1], 16)?;
                                let value = self.memory.read_buffer(&mut reader, addr, bitsize)?;

                                log::info(&format!("0x{:x}: {}", addr, value));
                            }
                        },
                        Err(err) => log::error(&err.to_string()),
                    }
                }
            },
            "write" => {
                if tokens.len() != 4 {
                    log::warning("Usage: write [addr] [value] [bitsize]");
                } else {
                    match self.to_bitsize(tokens[3]) {
                        Ok(bitsize) => {
                            let addr = usize::from_str_radix(tokens[1], 16)?;
                            let value = tokens[2].parse::<usize>()?;

                            self.memory.write(addr, value, bitsize)?;
                        },
                        Err(err) => log::error(&err.to_string()),
                    }
                }
            },
            "lock" => {
                if tokens.len() != 4 {
                    log::warning("Usage: lock [address] [value] [bitsize]");
                } else {
                    match self.to_bitsize(tokens[3]) {
                        Ok(bitsize) => {
                            let addr = usize::from_str_radix(tokens[1], 16)?;
                            let value = tokens[2].parse::<usize>()?;

                            self.memory.lock(addr, value, bitsize);
                        },
                        Err(err) => log::error(&err.to_string()),
                    }
                }
            },
            "unlock" => {
                if tokens.len() != 2 {
                    log::warning("Usage: unlock [address]");
                } else {
                    self.memory.unlock(usize::from_str_radix(tokens[1], 16)?)?;
                }
            },
            "ptrmap" => {
                if tokens.len() != 2 {
                    log::warning("Usage: ptrmap [address]");
                } else {
                    self.memory.ptrmap(usize::from_str_radix(tokens[1], 16)?)?.dump(1);
                }
            },
            "exec-no-aslr" => {
                if tokens.len() != 2 {
                    log::warning("Usage: exec-no-aslr [program]");
                } else {
                    self.memory.exec_no_aslr(tokens[1])?;
                }
            },
            "add-table" => {
                if tokens.len() != 3 {
                    log::warning("Usage: add-table [key] [address]");
                } else {
                    self.memory.table.insert(tokens[1].to_string(), usize::from_str_radix(tokens[1], 16)?);
                }
            },
            "dump-table" => {
                if tokens.len() != 3 {
                    log::warning("Usage: dump-table [filename]");
                } else {
                    self.memory.dump_table(tokens[1])?;
                }
            },
            "load-table" => {
                if tokens.len() != 3 {
                    log::warning("Usage: load-table [filename]");
                } else {
                    self.memory.load_table(tokens[1])?;
                }
            },
            "maps" => {
                if self.memory.mem.is_some() {
                    let maps = std::fs::read_to_string(format!("/proc/{}/maps", self.memory.process.pid))?;

                    for line in maps.lines() {
                        log::info(line);
                    }
                } else {
                    log::error("no process attached");
                }
            },
            "procs" => {
                let paths = std::fs::read_dir("/proc")?;

                for path in paths {
                    if let Ok(pid) = path?.file_name().to_str().unwrap_or_default().parse::<usize>() {
                        let name = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))?;

                        if !name.is_empty() {
                            log::info(&format!("{} -- {}", name, pid));
                        }
                    }
                }
            },
            "exit" => {
                self.should_close = true;
            },
            _ => log::error("no such command"),
        }

        Ok(())
    }

    fn welcome(&self) {
        let prompt = r"
.▄▄ ·  ▄▄·  ▄▄▄·  ▐ ▄ • ▌ ▄ ·. ▄▄▄ .• ▌ ▄ ·. 
▐█ ▀. ▐█ ▌▪▐█ ▀█ •█▌▐█·██ ▐███▪▀▄.▀··██ ▐███▪
▄▀▀▀█▄██ ▄▄▄█▀▀█ ▐█▐▐▌▐█ ▌▐▌▐█·▐▀▀▪▄▐█ ▌▐▌▐█·
▐█▄▪▐█▐███▌▐█ ▪▐▌██▐█▌██ ██▌▐█▌▐█▄▄▌██ ██▌▐█▌
 ▀▀▀▀ ·▀▀▀  ▀  ▀ ▀▀ █▪▀▀  █▪▀▀▀ ▀▀▀ ▀▀  █▪▀▀▀

    Easy-to-use memory scanner for linux
        ".magenta();

        println!("{}", prompt);
    }

    pub fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut rl = DefaultEditor::new()?;

        self.welcome();

        while !self.should_close {
            let line = rl.readline(&format!("{}$ ", "[scanmem]".green()))?;
            self.command(&line)?;
            rl.add_history_entry(&line)?;
        }

        Ok(())
    }
}

