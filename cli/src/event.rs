use bytes::Bytes;
use colored::Colorize;
use std::fmt::Display;

#[derive(Debug)]
pub struct Event {
    pub tid: u32,
    pub pid: u32,
    pub syscall: u64,
    pub return_value: Option<u64>,
    pub args: [Option<(u64, Bytes)>; 6],
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(target_arch = "x86_64")]
        let sysname = syscalls::x86_64::Sysno::new(self.syscall as usize);
        #[cfg(target_arch = "aarch64")]
        let sysname = syscalls::aarch64::Sysno::new(self.syscall as usize);
        let syscall_name = sysname
            .map(|w| w.name().to_string())
            .unwrap_or_else(|| format!("syscall_{}", self.syscall));

        write!(
            f,
            "[{}:{}] {}(",
            self.pid.to_string().blue(),
            self.tid.to_string().blue(),
            syscall_name.red().bold()
        )?;

        let mut none_start = 6;
        let mut none_end = 6;
        for (i, item) in self.args.iter().enumerate() {
            if item.is_none() {
                if i != none_end + 1 {
                    none_start = i;
                }
                none_end = i;
            }
        }
        for (i, item) in self.args[..none_start].iter().enumerate() {
            let seq = if i == 0 { "" } else { ", " };
            write!(f, "{}", seq)?;
            if let Some((value, str)) = item {
                if str.is_empty() {
                    write!(f, "{}", format!("0x{:x}", value).yellow())?;
                } else {
                    write!(
                        f,
                        "{} = {}",
                        format!("0x{:x}", value).yellow(),
                        format!("{:?}", str).italic()
                    )?;
                }
            } else {
                write!(f, "{}", "?".red())?;
            }
        }

        write!(
            f,
            ") = {}",
            self.return_value.map_or_else(
                || "?".red().bold(),
                |ret| format!("0x{:x}", ret).green().bold()
            )
        )
    }
}
