use std::str::FromStr;

use anyhow::Result;
use bitflags::bitflags;
use regex::Regex;

use crate::syscall_info::arch::SYSCALL_ARG_TABLE;

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct Tags: u32 {
        /// TRACE_DESC
        const DESC = 0x01;
        /// TRACE_FILE
        const FILE = 0x02;
        /// TRACE_IPC
        const IPC = 0x04;
        /// TRACE_NETWORK
        const NETWORK = 0x08;
        /// TRACE_PROCESS
        const PROCESS = 0x10;
        /// TRACE_SIGNAL
        const SIGNAL = 0x20;
        /// TRACE_MEMORY
        const MEMORY = 0x40;
        /// TRACE_STAT
        const STAT = 0x80;
        /// TRACE_LSTAT
        const LSTAT = 0x100;
        /// TRACE_FSTAT
        const FSTAT = 0x200;
        /// TRACE_STAT_LIKE
        const STAT_LIKE = 0x400;
        /// TRACE_STATFS
        const STATFS = 0x800;
        /// TRACE_FSTATFS
        const FSTATFS = 0x1000;
        /// TRACE_STATFS_LIKE
        const STATFS_LIKE = 0x2000;
        /// TRACE_PURE
        const PURE = 0x4000;
        /// TRACE_SECCOMP_DEFAULT
        const SECCOMP_DEFAULT = 0x8000;
        /// TRACE_CREDS
        const CREDS = 0x10000;
        /// TRACE_CLOCK
        const CLOCK = 0x20000;
    }
}

#[derive(Debug)]
pub struct Filter {
    tags: Tags,
    regex: Vec<Regex>,
    syscall_num: Vec<u64>,
    all: bool,
    is_blacklist: bool,
}

impl Filter {
    pub fn new(expr: Option<&str>) -> Result<Self, String> {
        let expr = match expr {
            Some(e) => e,
            None => {
                return Ok(Self {
                    tags: Tags::empty(),
                    regex: vec![],
                    syscall_num: vec![],
                    all: true,
                    is_blacklist: false,
                })
            }
        };
        let mut is_blacklist = false;
        let expr = if let Some(expr) = expr.strip_prefix('!') {
            is_blacklist = true;
            expr
        } else {
            expr
        };
        let mut tags = Tags::empty();
        let mut regex = vec![];
        let mut syscall_num = vec![];
        let mut all = false;
        for item in expr.split(',') {
            let item = item.trim();
            if item.is_empty() {
                return Err("Expect a filter item".to_string());
            }
            if item.starts_with('%') {
                match item {
                    "%file" => tags |= Tags::FILE,
                    "%ipc" => tags |= Tags::IPC,
                    "%network" => tags |= Tags::NETWORK,
                    "%process" => tags |= Tags::PROCESS,
                    "%signal" => tags |= Tags::SIGNAL,
                    "%memory" => tags |= Tags::MEMORY,
                    "%stat" => tags |= Tags::STAT,
                    "%lstat" => tags |= Tags::LSTAT,
                    "%fstat" => tags |= Tags::FSTAT,
                    "%stat_like" => tags |= Tags::STAT_LIKE,
                    "%statfs" => tags |= Tags::STATFS,
                    "%fstatfs" => tags |= Tags::FSTATFS,
                    "%statfs_like" => tags |= Tags::STATFS_LIKE,
                    "%%statfs" => tags |= Tags::STATFS | Tags::FSTATFS | Tags::STATFS_LIKE,
                    "%pure" => tags |= Tags::PURE,
                    "%seccomp_default" => tags |= Tags::SECCOMP_DEFAULT,
                    "%creds" => tags |= Tags::CREDS,
                    "%clock" => tags |= Tags::CLOCK,
                    _ => return Err(format!("invalid tag: {}", item)),
                }
            } else if let Some(item) = item.strip_prefix('/') {
                regex.push(Regex::new(item).map_err(|e| e.to_string())?);
            } else if item == "all" {
                all = true;
                if is_blacklist {
                    return Err("invalid filter: 'all' in blacklist mode".to_string());
                }
            } else {
                let sysname = crate::Sysno::from_str(item);
                if let Ok(sysname) = sysname {
                    syscall_num.push(sysname.id() as u64);
                } else {
                    return Err(format!("invalid syscall name: {}", item));
                }
            }
        }
        Ok(Self {
            tags,
            regex,
            syscall_num,
            all,
            is_blacklist,
        })
    }
    pub fn check(&self, syscall: u64) -> bool {
        self.all
            || (self.is_blacklist
                ^ (self
                    .tags
                    .intersects(SYSCALL_ARG_TABLE[syscall as usize].tags)
                    || self.syscall_num.contains(&syscall)
                    || self.regex.iter().any(|r| {
                        r.is_match(crate::Sysno::new(syscall as usize).map_or("", |s| s.name()))
                    })))
    }
}
