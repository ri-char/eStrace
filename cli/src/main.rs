use std::collections::HashMap;

use anyhow::Result;
use aya::maps::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, BpfLoader, Btf};
use bytes::{Buf, BytesMut};
use clap::Parser;
use colored::Colorize;
use common::STR_MAX_LENGTH;
use tokio::sync::Mutex;

use crate::event::Event;

mod event;
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
    for (sysno, v) in syscall_info::SYSCALL_ARG_TABLE.iter().enumerate() {
        let mut map_element: [u16; 6] = [0; 6];
        for (i, element) in v.iter().enumerate() {
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    if matches!((args.pid, args.tid, args.uid), (None, None, None)) {
        println!(
            "{} You must specify at least one of pid, tid, uid",
            "Error:".red().bold()
        );
        return Ok(());
    }
    init_bpf(&args)?;
    tokio::signal::ctrl_c().await?;
    Ok(())
}
