#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_buf,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventByteArray},
    programs::TracePointContext,
};
use common::{ArgType, STR_MAX_LENGTH};
use core::cmp::min;

#[map]
static mut SYSCALL_ARG_TABLE: HashMap<u64, [u16; 6]> = HashMap::with_max_entries(512, 0);
#[map]
pub static mut RECORD_LOGS: PerfEventByteArray = PerfEventByteArray::new(0);

#[map]
static mut CONTEXT: HashMap<u32, [usize; 6]> = HashMap::with_max_entries(64, 0);

#[map]
static mut TRAGET_PID: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);
#[map]
static mut TRAGET_TID: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);
#[map]
static mut TRAGET_UID: HashMap<u32, u8> = HashMap::with_max_entries(64, 0);

#[map]
static mut FLAG: HashMap<u8, u8> = HashMap::with_max_entries(1, 0);

fn enter_syscall_inner(ctx: TracePointContext) -> Result<(), i64> {
    let pid_tid = bpf_get_current_pid_tgid();
    let pid = (pid_tid >> 32) as u32;
    let tid = pid_tid as u32;
    if unsafe {
        FLAG.get(&0).is_some()
            ^ (TRAGET_PID.get(&pid).is_none()
                && TRAGET_TID.get(&tid).is_none()
                && TRAGET_UID
                    .get(&(bpf_get_current_uid_gid() as u32))
                    .is_none())
    } {
        return Ok(());
    }
    let mut send_byte = [0u8; 19 + STR_MAX_LENGTH];
    let syscall_number = unsafe { ctx.read_at::<u64>(8)? };
    send_byte[1..9].copy_from_slice(&pid_tid.to_le_bytes());
    send_byte[9..17].copy_from_slice(&syscall_number.to_le_bytes());
    unsafe { RECORD_LOGS.output(&ctx, &send_byte[..19], 0) };
    let arg_table = unsafe { SYSCALL_ARG_TABLE.get(&syscall_number).ok_or(0) }?;
    let args: [usize; 6] = unsafe { ctx.read_at(16) }?;
    let _ = unsafe { CONTEXT.insert(&tid, &args, 0) };
    for (i, ty_size) in arg_table.iter().enumerate() {
        let ty: ArgType = ArgType::from_bits_retain((*ty_size >> 8) as u8);
        let size_info: u8 = *ty_size as u8;
        if !ty.contains(ArgType::record_before) {
            continue;
        }
        send_byte[0] = 0x10 | (i as u8);
        send_byte[1..9].copy_from_slice(&pid_tid.to_le_bytes());
        send_byte[9..17].copy_from_slice(&args[i].to_le_bytes());
        let mut additional_size = 0;
        if ty.contains(ArgType::is_ptr) {
            if ty.contains(ArgType::is_str) {
                let slice = unsafe {
                    bpf_probe_read_user_str_bytes(
                        args[i] as *const u8,
                        &mut send_byte[19..19 + STR_MAX_LENGTH],
                    )
                };
                // additional_size = slice.map_or(0, |s|s.len());
                additional_size = if let Ok(slice) = slice {
                    slice.len()
                } else {
                    send_byte[17] = 0;
                    send_byte[18] = 0;
                    unsafe { RECORD_LOGS.output(&ctx, &send_byte[..19], 0) };
                    continue;
                }
            } else {
                if ty.contains(ArgType::is_const) {
                    additional_size = size_info as usize;
                } else {
                    let index = size_info as usize;
                    additional_size = if index >= 6 { 0 } else { args[index] }
                }
                additional_size = min(additional_size, STR_MAX_LENGTH);
                if additional_size > 0 {
                    let r = unsafe {
                        bpf_probe_read_buf(
                            args[i] as *const u8,
                            &mut send_byte[19..19 + additional_size],
                        )
                    };
                    if r.is_err() {
                        additional_size = 0;
                    }
                }
            }
        }
        send_byte[17..19].copy_from_slice(&(additional_size as u16).to_le_bytes());
        unsafe { RECORD_LOGS.output(&ctx, &send_byte[..19 + additional_size], 0) };
    }
    Ok(())
}

fn exit_syscall_inner(ctx: TracePointContext) -> Result<(), i64> {
    let pid_tid = bpf_get_current_pid_tgid();
    let pid = (pid_tid >> 32) as u32;
    let tid = pid_tid as u32;
    if unsafe {
        FLAG.get(&0).is_some()
            ^ (TRAGET_PID.get(&pid).is_none()
                && TRAGET_TID.get(&tid).is_none()
                && TRAGET_UID
                    .get(&(bpf_get_current_uid_gid() as u32))
                    .is_none())
    } {
        return Ok(());
    }
    let mut send_byte = [0u8; 19 + STR_MAX_LENGTH];
    let syscall_number = unsafe { ctx.read_at::<u64>(8)? };
    let ret = unsafe { ctx.read_at::<usize>(16)? };
    let send_ret = || {
        let mut send_byte = [0x0u8; 27];
        send_byte[0] = 0x20;
        send_byte[1..9].copy_from_slice(&pid_tid.to_le_bytes());
        send_byte[9..17].copy_from_slice(&syscall_number.to_le_bytes());
        send_byte[17] = 8;
        send_byte[19..27].copy_from_slice(&ret.to_le_bytes());
        unsafe { RECORD_LOGS.output(&ctx, &send_byte, 0) };
    };
    let arg_table = unsafe { SYSCALL_ARG_TABLE.get(&syscall_number).ok_or(0) }?;
    let args: &[usize; 6] = match unsafe { CONTEXT.get(&tid) } {
        Some(args) => args,
        None => {
            send_ret();
            return Ok(());
        }
    };
    for (i, ty_size) in arg_table.iter().enumerate() {
        let ty: ArgType = ArgType::from_bits_retain((*ty_size >> 8) as u8);
        let size_info: u8 = *ty_size as u8;
        if !ty.contains(ArgType::record_after) {
            continue;
        }
        send_byte[0] = 0x10 | (i as u8);
        send_byte[1..9].copy_from_slice(&pid_tid.to_le_bytes());
        send_byte[9..17].copy_from_slice(&args[i].to_le_bytes());
        let mut additional_size = 0;
        if ty.contains(ArgType::is_ptr) {
            if ty.contains(ArgType::is_str) {
                let slice = unsafe {
                    bpf_probe_read_user_str_bytes(
                        args[i] as *const u8,
                        &mut send_byte[19..19 + STR_MAX_LENGTH],
                    )
                };
                additional_size = if let Ok(slice) = slice {
                    slice.len()
                } else {
                    send_byte[17] = 0;
                    send_byte[18] = 0;
                    unsafe { RECORD_LOGS.output(&ctx, &send_byte[..19], 0) };
                    continue;
                }
            } else {
                additional_size = if ty.contains(ArgType::is_const) {
                    size_info as usize
                } else if size_info == 6 {
                    ret
                } else {
                    let index = size_info as usize;
                    if index >= 6 {
                        0
                    } else {
                        args[index]
                    }
                };

                additional_size = min(additional_size, STR_MAX_LENGTH);
                if additional_size > 0 {
                    let r = unsafe {
                        bpf_probe_read_buf(
                            args[i] as *const u8,
                            &mut send_byte[19..19 + additional_size],
                        )
                    };
                    if r.is_err() {
                        additional_size = 0;
                    }
                }
            }
        }
        send_byte[17..19].copy_from_slice(&(additional_size as u16).to_le_bytes());
        unsafe { RECORD_LOGS.output(&ctx, &send_byte[..19 + additional_size], 0) };
    }
    send_ret();
    Ok(())
}

#[tracepoint]
pub fn enter_syscall(ctx: TracePointContext) {
    let _ = enter_syscall_inner(ctx);
}

#[tracepoint]
pub fn exit_syscall(ctx: TracePointContext) {
    let _ = exit_syscall_inner(ctx);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
