use anyhow::Result;
use aya::maps::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, BpfLoader, Btf};
use bytes::{Buf, BytesMut};
use clap::Parser;
use colored::Colorize;
use common::STR_MAX_LENGTH;
use std::collections::HashMap;
use tokio::sync::Mutex;

use crate::event::Event;

#[cfg(target_arch = "aarch64")]
pub use syscalls::aarch64::Sysno;
#[cfg(target_arch = "x86_64")]
pub use syscalls::x86_64::Sysno;

mod event;
mod filter;
mod syscall_info;

#[derive(Parser)]
pub struct Args {
    #[clap(short, long)]
    /// Target pid
    pid: Option<u32>,
    #[clap(short, long)]
    /// Target tid
    tid: Option<u32>,
    #[clap(short, long)]
    /// Target uid
    uid: Option<u32>,
    /// Trace only the specified set of system calls.  syscall_set is defined as [!]value[,value], and value can be one of the following:
    ///
    /// syscall      Trace specific syscall, specified by its name (see syscalls(2) for a reference, but also see NOTES).
    ///
    /// all          Trace all system calls.
    ///
    /// /regex       Trace only those system calls that match the regex.
    ///
    /// %file        Trace all system calls which take a file name as an argument.  You can think of this as an abbreviation for -e trace=open,stat,hmod,unlink,...  which is useful to seeing what files  the  process  is  referencing.  Furthermore, using the abbreviation will ensure that you don't accidentally forget to include a call like lstat(2) in the list.  Betchya woulda forgot that one.  The syntax without a preceding percent
    ///
    /// %process     Trace system calls associated with process lifecycle (creation, exec, termination).
    ///
    /// %net         Trace all the network related system calls.  The syntax without a preceding percent
    ///
    /// %signal      Trace all signal related system calls.  The syntax without a preceding percent
    ///
    /// %ipc         Trace all IPC related system calls.  The syntax without a preceding percent
    ///
    /// %desc        Trace all file descriptor related system calls.  The syntax without a preceding percent
    ///
    /// %memory      Trace all memory mapping related system calls.  The syntax without a preceding percent
    ///
    /// %creds       Trace system calls that read or modify user and group identifiers or capability sets.
    ///
    /// %stat        Trace stat syscall variants.
    ///
    /// %lstat       Trace lstat syscall variants.
    ///
    /// %fstat       Trace fstat, fstatat, and statx syscall variants.
    ///
    /// %%stat       Trace syscalls used for requesting file status (stat, lstat, fstat, fstatat, statx, and their variants).
    ///
    /// %statfs      Trace statfs, statfs64, statvfs, osf_statfs, and osf_statfs64 system calls.  The same effect can be achieved with -e trace=/^(.*_)?statv?fs regular expression.
    ///
    /// %fstatfs     Trace fstatfs, fstatfs64, fstatvfs, osf_fstatfs, and osf_fstatfs64 system calls.  The same effect can be achieved with -e trace=/fstatv?fs regular expression.
    ///
    /// %%statfs     Trace syscalls related to file system statistics (statfs-like, fstatfs-like, and ustat).  The same effect can be achieved with -e trace=/statv?fs|fsstat|ustat regular  expression.
    ///
    /// %clock       Trace system calls that read or modify system clocks.
    ///
    /// %pure        Trace  syscalls  that always succeed and have no arguments.  Currently, this list includes arc_gettls(2), getdtablesize(2), getegid(2), getegid32(2), geteuid(2), geteuid32(2),
    ///             getgid(2), getgid32(2), getpagesize(2), getpgrp(2), getpid(2), getppid(2), get_thread_area(2) (on architectures other than x86), gettid(2), get_tls(2), getuid(2), getuid32(2),
    ///             getxgid(2), getxpid(2), getxuid(2), kern_features(2), and metag_get_tls(2) syscalls.
    ///
    /// %seccomp_default Trace seccomp default actions.
    #[clap(short, long)]
    filter: Option<String>,
}

lazy_static::lazy_static! {
    static ref PROCESSING_EVENTS: Mutex<HashMap<u32, Event>> = Mutex::new(HashMap::new());
}

async fn handle_event(byte: &mut BytesMut) {
    // println!("{:?}", byte);
    let ty = byte.get_u8();
    let tid = byte.get_u32_le();
    let pid = byte.get_u32_le();
    let syscall_or_arg = byte.get_u64_le();
    let addition_size = byte.get_u16_le() as usize;
    if ty & 0xf0 == 0 {
        PROCESSING_EVENTS.lock().await.insert(
            tid,
            Event {
                tid,
                pid,
                syscall: syscall_or_arg,
                return_value: None,
                args: [None, None, None, None, None, None],
            },
        );
    } else if ty & 0xf0 == 0x10 {
        if let Some(w) = PROCESSING_EVENTS.lock().await.get_mut(&tid) {
            w.args[(ty & 0xf) as usize] =
                Some((syscall_or_arg, byte.split_to(addition_size).freeze()));
        }
    } else if ty & 0xf0 == 0x20 {
        if let Some(mut w) = PROCESSING_EVENTS.lock().await.remove(&tid) {
            if addition_size != 8 {
                return;
            }
            w.return_value = Some(byte.get_u64_le());
            println!("{}", w);
        }
    }
}

fn init_bpf(args: &Args) -> Result<()> {
    #[cfg(debug_assertions)]
    let bpf_data = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/ebpf");
    #[cfg(not(debug_assertions))]
    let bpf_data = include_bytes_aligned!("../../target/bpfel-unknown-none/release/ebpf");
    let mut bpf = BpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .set_global("TRAGET_PID", &args.pid.unwrap_or(!0))
        .set_global("TRAGET_TID", &args.tid.unwrap_or(!0))
        .set_global("TRAGET_UID", &args.uid.unwrap_or(!0))
        .set_global("SELF_PID", &std::process::id())
        .load(bpf_data)?;

    let mut syscall_arg_table: aya::maps::HashMap<_, u64, [u16; 6]> =
        aya::maps::HashMap::try_from(bpf.take_map("SYSCALL_ARG_TABLE").unwrap())?;
    let filiter = filter::Filter::new(args.filter.as_deref())?;
    for (sysno, v) in syscall_info::SYSCALL_ARG_TABLE.iter().enumerate() {
        if !filiter.check(sysno as u64) {
            continue;
        }
        let mut map_element: [u16; 6] = [0; 6];
        for (i, element) in v.args.iter().enumerate() {
            map_element[i] = ((element.0.bits() as u16) << 8) | element.1 as u16;
        }
        syscall_arg_table.insert(sysno as u64, map_element, 0)?;
    }

    let mut record: AsyncPerfEventArray<_> = bpf.take_map("RECORD_LOGS").unwrap().try_into()?;

    for cpu_id in online_cpus()? {
        let mut buf = record.open(cpu_id, None)?;
        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(17 + STR_MAX_LENGTH); 50];

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                if events.lost != 0 {
                    println!("{} Lost {} events", "Warning:".yellow().bold(), events.lost);
                }
                for i in buffers.iter_mut().take(events.read) {
                    handle_event(i).await;
                }
            }
        });
    }

    let program: &mut TracePoint = bpf.program_mut("enter_handle").unwrap().try_into()?;
    program.load()?;
    program.attach("raw_syscalls", "sys_enter")?;

    let program: &mut TracePoint = bpf.program_mut("exit_handle").unwrap().try_into()?;
    program.load()?;
    program.attach("raw_syscalls", "sys_exit")?;
    std::mem::forget(bpf);
    Ok(())
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        anyhow::bail!("Failed to increase rlimit");
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    if matches!((args.pid, args.tid, args.uid), (None, None, None)) {
        anyhow::bail!("You must specify at least one of pid, tid, uid");
    }

    bump_memlock_rlimit()?;
    init_bpf(&args)?;
    tokio::signal::ctrl_c().await?;
    Ok(())
}
