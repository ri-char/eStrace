use bytes::Bytes;
use colored::Colorize;
use std::fmt::Display;

use crate::syscall_info::formatter::VOID_ARG_FORMATTER;

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
        let sysname = crate::Sysno::new(self.syscall as usize);
        let syscall_name = sysname
            .map(|w| w.name().to_string())
            .unwrap_or_else(|| format!("syscall_{}", self.syscall));
        let syscall_arg_name =
            crate::syscall_info::arch::SYSCALL_ARG_TABLE.get(self.syscall as usize);

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
            if let Some(arg_names) = syscall_arg_name {
                if !arg_names.arg_names[i].is_empty() {
                    write!(f, "{} = ", arg_names.arg_names[i])?;
                }
            }
            if let Some((value, str)) = item {
                let formatter = if let Some(syscall_info) = syscall_arg_name {
                    syscall_info.args[i].2
                } else {
                    &VOID_ARG_FORMATTER
                };
                if !formatter.need_to_print(str) {
                    write!(f, "{}", format!("0x{:x}", value).yellow())?;
                } else {
                    write!(
                        f,
                        "{} = {}",
                        format!("0x{:x}", value).yellow(),
                        formatter.format(str).italic()
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
