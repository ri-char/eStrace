#![allow(dead_code, non_upper_case_globals)]

use self::{
    formatter::{ArgFormatter, BYTES_ARG_FORMATTER, VOID_ARG_FORMATTER},
    structs::{msghdr, sockaddr, time_t},
};
use common::ArgType;
use libc::{
    cpu_set_t, fd_set, sched_param, sigevent, siginfo_t, socklen_t, stat64, timer_t, utimbuf,
};
use linux_raw_sys::general::{
    __kernel_fd_set, __kernel_gid_t, __kernel_loff_t, __kernel_off_t, __kernel_pid_t,
    __kernel_uid_t, epoll_event, iovec, itimerspec, itimerval, pollfd, rlimit, rlimit64, rusage,
    sigaction, sigset_t, stack_t, stat, timespec, timeval, timezone,
};
use macros::syscall;
pub mod arch;
pub mod formatter;
pub mod structs;

pub type ArgInfo = (ArgType, u8, &'static dyn ArgFormatter);

pub struct SyscallInfo {
    pub arg_names: [&'static str; 6],
    pub args: [ArgInfo; 6],
    pub tags: crate::filter::Tags,
}

const ADDR: ArgInfo = (ArgType::record_before, 0, &VOID_ARG_FORMATTER);
const INT: ArgInfo = (ArgType::record_before, 0, &VOID_ARG_FORMATTER);
const STR: ArgInfo = (
    ArgType::from_bits_truncate(0b00001101),
    0,
    &BYTES_ARG_FORMATTER,
);
const OUT_STR: ArgInfo = (
    ArgType::from_bits_truncate(0b00001110),
    0,
    &BYTES_ARG_FORMATTER,
);
macro_rules! input_struct {
    ($struc:ty) => {
        (
            ArgType::from_bits_truncate(0b00010101),
            ::std::mem::size_of::<$struc>() as u8,
            &self::formatter::StructArgFormatter::<$struc>::new(),
        )
    };
}
macro_rules! output_struct {
    ($struc:ty) => {
        (
            ArgType::from_bits_truncate(0b00010110),
            ::std::mem::size_of::<$struc>() as u8,
            &self::formatter::StructArgFormatter::<$struc>::new(),
        )
    };
}
macro_rules! inout_struct {
    ($struc:ty) => {
        (
            ArgType::from_bits_truncate(0b00010111),
            ::std::mem::size_of::<$struc>() as u8,
            &self::formatter::StructArgFormatter::<$struc>::new(),
        )
    };
}

const fn input_struct_ref(r#ref: u8) -> ArgInfo {
    (
        ArgType::from_bits_truncate(0b00000101),
        r#ref,
        &BYTES_ARG_FORMATTER,
    )
}
const fn output_struct_ref(r#ref: u8) -> ArgInfo {
    (
        ArgType::from_bits_truncate(0b00000110),
        r#ref,
        &BYTES_ARG_FORMATTER,
    )
}

syscall!(read, fd = INT, buf = output_struct_ref(2), count = INT; DESC);
syscall!(write, fd = INT, buf = input_struct_ref(6), count = INT; DESC);
syscall!(open, filename = STR, flags = INT, flags = INT; DESC, FILE);
syscall!(close, fd = INT; DESC);
syscall!(stat, filename=STR, statbuf = output_struct!(stat); FILE, STAT, STAT_LIKE);
syscall!(fstat, fd = INT, statbuf = output_struct!(stat); DESC, FSTAT, STAT_LIKE);
syscall!(lstat, filename = STR, statbuf = output_struct!(stat); FILE, LSTAT, STAT_LIKE);
syscall!(poll, ufds = ADDR, nfds = INT, timeout_msecs = INT; DESC);
syscall!(lseek, fd = INT, offset = INT, whence = INT; DESC);
syscall!(mmap, addr = ADDR, len = INT, prot = INT, flags = INT, fd = INT, off = INT; DESC, MEMORY);
syscall!(mprotect, start = ADDR, len = INT, prot = INT; MEMORY);
syscall!(munmap, addr = ADDR, len = INT; MEMORY);
syscall!(brk, brk = ADDR; MEMORY);
syscall!(rt_sigaction, sig = INT, act = input_struct!(sigaction), oact = output_struct!(sigaction), sigsetsize = INT; SIGNAL);
syscall!(rt_sigprocmask, how = INT, nset = input_struct!(sigset_t), oset = output_struct!(sigset_t), sigsetsize = INT; SIGNAL);
syscall!(rt_sigreturn; SIGNAL);
syscall!(ioctl, fd = INT, cmd = INT, arg = ADDR; DESC);
syscall!(pread64, fd = INT, buf = output_struct_ref(6), count = INT, pos = INT; DESC);
syscall!(pwrite64, fd = INT, buf = input_struct_ref(2), count = INT, pos = INT; DESC);
syscall!(readv, fd = INT, vec = input_struct!(iovec), vlen = INT; DESC);
syscall!(writev, fd = INT, vec = input_struct!(iovec), vlen = INT; DESC);
syscall!(access, filename = STR, mode = INT; FILE);
syscall!(pipe, fildes = input_struct!(u64); DESC);
syscall!(select, n = INT, inp = inout_struct!(__kernel_fd_set), outp = inout_struct!(__kernel_fd_set), exp = inout_struct!(__kernel_fd_set), tvp = input_struct!(timeval); DESC);
syscall!(sched_yield;);
syscall!(mremap, old_address = ADDR, old_size = INT, new_size = INT, flags = INT, new_address = ADDR; MEMORY);
syscall!(msync, start = ADDR, len = INT, flags = INT; MEMORY);
syscall!(mincore, start = ADDR, len = INT, vec = ADDR; MEMORY);
syscall!(madvise, start = ADDR, len_in = INT, behavior = INT; MEMORY);
syscall!(shmget, key = INT, size = INT, shmflg = INT; IPC);
syscall!(shmat, shmid = INT, shmaddr = ADDR, shmflg = INT; IPC, MEMORY);
syscall!(shmctl, shmid = INT, cmd = INT, buf = ADDR; IPC);
syscall!(dup, fildes = INT; DESC);
syscall!(dup2, oldfd = INT, newfd = INT; DESC);
syscall!(pause; SIGNAL);
syscall!(nanosleep, rqtp = input_struct!(timespec), rmtp = output_struct!(timespec););
syscall!(getitimer, which = INT, value = output_struct!(itimerval););
syscall!(alarm, seconds = INT;);
syscall!(setitimer, which = INT, ivalue = input_struct!(itimerval), ovalue = output_struct!(itimerval););
syscall!(getpid; PURE);
syscall!(sendfile, out_fd = INT, in_fd = INT, offset = inout_struct!(__kernel_off_t), count = INT; DESC);
syscall!(socket, family = INT, type = INT, protocol = INT; NETWORK);
syscall!(connect, fd = INT, uservaddr = input_struct!(sockaddr), addrlen = INT; NETWORK);
syscall!(accept, fd = INT, upeer_sockaddr = input_struct!(sockaddr), upeer_addrlen = output_struct!(u32); NETWORK);
syscall!(sendto, fd = INT, buff = input_struct_ref(2), len = INT, flags = INT, addr = input_struct!(sockaddr), addr_len = INT; NETWORK);
syscall!(recvfrom, fd = INT, ubuf = output_struct_ref(6), size = INT, flags = INT, addr = inout_struct!(sockaddr), addr_len = output_struct!(u32); NETWORK);
syscall!(sendmsg, fd = INT, msg = input_struct!(msghdr), flags = INT; NETWORK);
syscall!(recvmsg, fd = INT, msg = output_struct!(msghdr), flags = INT; NETWORK);
syscall!(shutdown, fd = INT, how = INT; NETWORK);
syscall!(bind, fd = INT, umyaddr = input_struct!(sockaddr), addrlen = INT; NETWORK);
syscall!(listen, fd = INT, backlog = INT; NETWORK);
syscall!(getsockname, fd = INT, usockaddr = output_struct!(sockaddr), usockaddr_len = inout_struct!(u32); NETWORK);
syscall!(getpeername, fd = INT, usockaddr = output_struct!(sockaddr), usockaddr_len = inout_struct!(u32); NETWORK);
syscall!(socketpair, family = INT, type = INT, protocol = INT, usockvec = input_struct!(u64); NETWORK);
syscall!(setsockopt, fd = INT, level = INT, optname = INT, optval = input_struct_ref(4), optlen = INT; NETWORK);
syscall!(getsockopt, fd = INT, level = INT, optname = INT, optval = ADDR, optlen = inout_struct!(u32); NETWORK);
syscall!(clone, clone_flags = INT, newsp = ADDR, parent_tidptr = output_struct!(__kernel_pid_t), child_tidptr = output_struct!(__kernel_pid_t), tls_val = ADDR; PROCESS);
syscall!(fork; PROCESS);
syscall!(vfork; PROCESS);
syscall!(execve, filename = STR, argv = ADDR, envp = ADDR; PROCESS, FILE, SECCOMP_DEFAULT);
syscall!(exit, error_code = INT; PROCESS);
syscall!(wait4, pid = INT, stat_addr = output_struct!(u32), options = INT, ru = inout_struct!(rusage); PROCESS);
syscall!(kill, pid = input_struct!(__kernel_pid_t), sig = INT; PROCESS);
syscall!(uname, name = ADDR;);
syscall!(semget, key = INT, nsems = INT, semflg = INT; IPC);
syscall!(semop, semid = INT, sops = ADDR, nsops = INT; IPC);
syscall!(semctl, semid = INT, semnum = INT, cmd = INT, arg = INT; IPC);
syscall!(shmdt, shmaddr = ADDR; IPC, MEMORY);
syscall!(msgget, key = INT, msgflg = INT; IPC);
syscall!(msgsnd, msqid = INT, msgp = input_struct_ref(2), msgsz = INT, msgflg = INT; IPC);
syscall!(msgrcv, msqid = INT, msgp = output_struct_ref(6), msgsz = INT, msgtyp = INT, msgflg = INT; IPC);
syscall!(msgctl, msqid = INT, cmd = INT, buf = ADDR; IPC);
syscall!(fcntl, fd = INT, cmd = INT, arg = INT; DESC);
syscall!(flock, fd = INT, operation = INT; DESC);
syscall!(fsync, fd = INT; DESC);
syscall!(fdatasync, fd = INT; DESC);
syscall!(truncate, path = STR, length = INT; FILE);
syscall!(ftruncate, fd = INT, length = INT; DESC);
syscall!(getdents, fd = INT, dirent = output_struct!(libc::dirent), count = INT; DESC);
syscall!(getcwd, buf = output_struct_ref(1), size = INT; FILE);
syscall!(chdir, filename = STR; FILE);
syscall!(fchdir, fd = INT; DESC);
syscall!(rename, oldname = STR, newname = STR; FILE);
syscall!(mkdir, pathname = STR, mode = INT; FILE);
syscall!(rmdir, pathname = STR; FILE);
syscall!(creat, pathname = STR, mode = INT; DESC, FILE);
syscall!(link, oldname = STR, newname = STR; FILE);
syscall!(unlink, pathname = STR; FILE);
syscall!(symlink, oldname = STR, newname = STR; FILE);
syscall!(readlink, path = STR, buf = output_struct_ref(6), bufsiz = INT; FILE);
syscall!(chmod, pathname = STR, mode = INT; FILE);
syscall!(fchmod, fd = INT, mode = INT; DESC);
syscall!(chown, pathname = STR, owner = INT, group = INT; FILE);
syscall!(fchown, fd = INT, owner = INT, group = INT; DESC);
syscall!(lchown, pathname = STR, owner = INT, group = INT; FILE);
syscall!(umask, mask = INT;);
syscall!(gettimeofday, tv = output_struct!(timeval), tz = output_struct!(timezone); CLOCK);
syscall!(getrlimit, resource = INT, rlim = output_struct!(rlimit););
syscall!(getrusage, who = INT, ru = inout_struct!(rusage););
syscall!(sysinfo, info = output_struct!(libc::sysinfo););
syscall!(times, buf = output_struct!(libc::tms););
syscall!(ptrace, request = INT, pid = INT, addr = ADDR, data = ADDR;);
syscall!(getuid; CREDS, PURE);
syscall!(syslog, type = INT, buf = ADDR, len = INT;);
syscall!(getgid; CREDS, PURE);
syscall!(setuid, uid = INT; CREDS);
syscall!(setgid, gid = INT; CREDS);
syscall!(geteuid; CREDS, PURE);
syscall!(getegid; CREDS, PURE);
syscall!(setpgid, pid = INT, pgid = INT;);
syscall!(getppid; PURE);
syscall!(getpgrp; PURE);
syscall!(setsid;);
syscall!(setreuid, ruid = INT, euid = INT; CREDS);
syscall!(setregid, rgid = INT, egid = INT; CREDS);
syscall!(getgroups, gidsetsize = INT, grouplist = ADDR; CREDS);
syscall!(setgroups, gidsetsize = INT, grouplist = ADDR; CREDS);
syscall!(setresuid, ruid = INT, euid = INT, suid = INT; CREDS);
syscall!(getresuid, ruid = output_struct!(__kernel_uid_t), euid = output_struct!(__kernel_uid_t), suid = output_struct!(__kernel_uid_t); CREDS);
syscall!(setresgid, rgid = INT, egid = INT, sgid = INT; CREDS);
syscall!(getresgid, rgid = output_struct!(__kernel_gid_t), egid = output_struct!(__kernel_gid_t), sgid = output_struct!(__kernel_gid_t); CREDS);
syscall!(getpgid, pid = INT;);
syscall!(setfsuid, uid = INT; CREDS);
syscall!(setfsgid, gid = INT; CREDS);
syscall!(getsid, pid = INT;);
syscall!(capget, hdrp = INT, datap = INT; CREDS);
syscall!(capset, hdrp = INT, datap = INT; CREDS);
syscall!(rt_sigpending, set = output_struct!(sigset_t), sigsetsize = INT; SIGNAL);
syscall!(rt_sigtimedwait, uthese = input_struct!(sigset_t), uinfo = output_struct!(siginfo_t), uts = input_struct!(timespec), sigsetsize = INT; SIGNAL);
syscall!(rt_sigqueueinfo, pid = INT, sig = INT, uinfo = output_struct!(siginfo_t); PROCESS, SIGNAL);
syscall!(rt_sigsuspend, unewset = input_struct!(sigset_t), sigsetsize = INT; SIGNAL);
syscall!(sigaltstack, uss = input_struct!(stack_t), uoss = output_struct!(stack_t); SIGNAL);
syscall!(utime, filename = STR, times = output_struct!(utimbuf); FILE);
syscall!(mknod, filename = STR, mode = INT, dev = INT; FILE);
syscall!(uselib, library = STR; FILE);
syscall!(personality, personality = INT;);
syscall!(ustat, dev = INT, ubuf = ADDR; STATFS_LIKE);
syscall!(statfs, pathname = STR, buf = output_struct!(libc::statfs); FILE, STATFS, STATFS_LIKE);
syscall!(fstatfs, fd = INT, buf = output_struct!(libc::statfs); FILE, FSTATFS, STATFS_LIKE);
syscall!(sysfs, option = INT, arg1 = INT, arg2 = INT;);
syscall!(getpriority, which = INT, who = INT;);
syscall!(setpriority, which = INT, who = INT, niceval = INT;);
syscall!(sched_setparam, pid = INT, param = input_struct!(sched_param););
syscall!(sched_getparam, pid = INT, param = output_struct!(sched_param););
syscall!(sched_setscheduler, pid = INT, policy = INT, param = input_struct!(sched_param););
syscall!(sched_getscheduler, pid = INT;);
syscall!(sched_get_priority_max, policy = INT;);
syscall!(sched_get_priority_min, policy = INT;);
syscall!(sched_rr_get_interval, pid = INT, interval = output_struct!(timespec););
syscall!(mlock, start = ADDR, len = INT; MEMORY);
syscall!(munlock, start = ADDR, len = INT; MEMORY);
syscall!(mlockall, flags = INT; MEMORY);
syscall!(munlockall; MEMORY);
syscall!(vhangup;);
syscall!(modify_ldt, func = INT, ptr = ADDR, bytecount = INT;);
syscall!(pivot_root, new_root = STR, put_old = STR; FILE);
syscall!(_sysctl, args = ADDR;);
syscall!(prctl, option = INT, arg2 = INT, arg3 = INT, arg4 = INT, arg5 = INT; CREDS);
syscall!(arch_prctl, task = ADDR, code = INT, addr = ADDR;);
syscall!(adjtimex, buf = ADDR; CLOCK);
syscall!(setrlimit, resource = INT, rlim = input_struct!(rlimit););
syscall!(chroot, filename = STR; FILE);
syscall!(sync;);
syscall!(acct, name = STR; FILE);
syscall!(settimeofday, tv = input_struct!(timeval), tz = input_struct!(timezone); CLOCK);
syscall!(mount, dev_name = STR, dir_name = STR, type = STR, flags = INT, data = ADDR; FILE);
syscall!(umount2, target = STR, flags = INT; FILE);
syscall!(swapon, specialfile = STR, swap_flags = INT; FILE);
syscall!(swapoff, specialfile = STR; FILE);
syscall!(reboot, magic1 = INT, magic2 = INT, cmd = INT, arg = STR;);
syscall!(sethostname, name = STR, len = INT;);
syscall!(setdomainname, name = STR, len = INT;);
syscall!(iopl, level = INT;);
syscall!(ioperm, from = INT, num = INT, on = INT;);
syscall!(create_module, name = STR, size = INT;);
syscall!(init_module, umod = ADDR, len = INT, uargs = STR;);
syscall!(delete_module, name = STR, flags = INT;);
syscall!(get_kernel_syms, table = ADDR;);
syscall!(query_module, name = STR, which = INT, buf = input_struct_ref(3), bufsize = INT, ret = output_struct!(u64););
syscall!(quotactl, cmd = INT, special = STR, id = INT, addr = ADDR; FILE);
syscall!(nfsservctl, cmd = INT, argp = ADDR, resp = ADDR;);
syscall!(getpmsg, fildes = INT, ctlptr = ADDR, dataptr = ADDR, bandp = ADDR, flagsp = ADDR; NETWORK);
syscall!(putpmsg, fildes = INT, ctlptr = ADDR, dataptr = ADDR, band = INT, flags = INT; NETWORK);
syscall!(afs_syscall;);
syscall!(tuxcall;);
syscall!(security;);
syscall!(gettid; PURE);
syscall!(readahead, fd = INT, offset = INT, count = INT; DESC);
syscall!(setxattr, pathname = STR, name = STR, value = ADDR, size = INT, flags = INT; FILE);
syscall!(lsetxattr, pathname = STR, name = STR, value = ADDR, size = INT, flags = INT; FILE);
syscall!(fsetxattr, fd = INT, name = STR, value = ADDR, size = INT, flags = INT; DESC);
syscall!(getxattr, pathname = STR, name = STR, value = ADDR, size = INT; FILE);
syscall!(lgetxattr, pathname = STR, name = STR, value = ADDR, size = INT; FILE);
syscall!(fgetxattr, fd = INT, name = STR, value = ADDR, size = INT; DESC);
syscall!(listxattr, pathname = STR, list = STR, size = INT; FILE);
syscall!(llistxattr, pathname = STR, list = STR, size = INT; FILE);
syscall!(flistxattr, fd = INT, list = STR, size = INT; DESC);
syscall!(removexattr, pathname = STR, name = STR; FILE);
syscall!(lremovexattr, pathname = STR, name = STR; FILE);
syscall!(fremovexattr, fd = INT, name = STR; DESC);
syscall!(tkill, pid = INT, sig = INT; PROCESS, SIGNAL);
syscall!(time, tloc = output_struct!(time_t); CLOCK);
syscall!(futex, uaddr = inout_struct!(u32), op = INT, val = INT, utime = inout_struct!(timespec), uaddr2 = inout_struct!(u32), val3 = INT;);
syscall!(sched_setaffinity, pid = INT, cpusetsize = INT, mask = input_struct!(cpu_set_t););
syscall!(sched_getaffinity, pid = INT, cpusetsize = INT, mask = output_struct!(cpu_set_t););
syscall!(set_thread_area, u_info = ADDR;);
syscall!(io_setup, nr_events = INT, ctxp = ADDR; MEMORY);
syscall!(io_destroy, ctx = INT; MEMORY);
syscall!(io_getevents, ctx_id = INT, min_nr = INT, nr = INT, events = ADDR, timeout = input_struct!(timespec););
syscall!(io_submit, ctx_id = INT, nr = INT, iocbpp = ADDR;);
syscall!(io_cancel, ctx_id = INT, iocb = ADDR, result = ADDR;);
syscall!(get_thread_area, u_info = ADDR;);
syscall!(lookup_dcookie, cookie64 = INT, buf = input_struct_ref(2), len = INT;);
syscall!(epoll_create, size = INT; DESC);
syscall!(epoll_ctl_old, epfd = INT, op = INT, event = ADDR;);
syscall!(epoll_wait_old, epfd = INT, events = ADDR, maxevents = INT;);
syscall!(remap_file_pages, start = INT, size = INT, prot = INT, pgoff = INT, flags = INT; MEMORY);
syscall!(getdents64, fd = INT, dirent = output_struct!(libc::dirent64), count = INT; DESC);
syscall!(set_tid_address, tidptr = inout_struct!(u32););
syscall!(restart_syscall;);
syscall!(semtimedop, semid = INT, tsops = ADDR, nsops = INT, timeout = input_struct!(timespec); IPC);
syscall!(fadvise64, fd = INT, offset = INT, len = INT, advice = INT; DESC);
syscall!(timer_create, which_clock = INT, timer_event_spec = input_struct!(sigevent), created_timer_id = output_struct!(timer_t););
syscall!(timer_settime, timer_id = INT, flags = INT, new_setting = input_struct!(itimerspec), old_setting = output_struct!(itimerspec););
syscall!(timer_gettime, timer_id = INT, setting = output_struct!(itimerspec););
syscall!(timer_getoverrun, timer_id = INT;);
syscall!(timer_delete, timer_id = INT;);
syscall!(clock_settime, which_clock = INT, tp = input_struct!(timespec); CLOCK);
syscall!(clock_gettime, which_clock = INT, tp = output_struct!(timespec); CLOCK);
syscall!(clock_getres, which_clock = INT, tp = output_struct!(timespec); CLOCK);
syscall!(clock_nanosleep, which_clock = INT, flags = INT, rqtp = input_struct!(timespec), rmtp = output_struct!(timespec););
syscall!(exit_group, error_code = INT; PROCESS);
syscall!(epoll_wait, epfd = INT, events = inout_struct!(epoll_event), maxevents = INT, timeout = INT; DESC);
syscall!(epoll_ctl, epfd = INT, op = INT, fd = INT, event = input_struct!(epoll_event); DESC);
syscall!(tgkill, tgid = INT, pid = INT, sig = INT; SIGNAL, PROCESS);
syscall!(utimes, filename = STR, utimes = inout_struct!(timeval); FILE);
syscall!(vserver;);
syscall!(mbind, start = INT, len = INT, mode = INT, nmask = ADDR, maxnode = INT, flags = INT; MEMORY);
syscall!(set_mempolicy, mode = INT, nmask = ADDR, maxnode = INT; MEMORY);
syscall!(get_mempolicy, policy = input_struct!(u32), nmask = inout_struct!(u64), maxnode = INT, addr = ADDR, flags = INT; MEMORY);
syscall!(mq_open, name = STR, oflag = INT, mode = INT, attr = ADDR; DESC);
syscall!(mq_unlink, u_name = STR;);
syscall!(mq_timedsend, mqdes = INT, msg_ptr = STR, msg_len = INT, msg_prio = INT, abs_timeout = input_struct!(timespec); DESC);
syscall!(mq_timedreceive, mqdes = INT, msg_ptr = STR, msg_len = INT, msg_prio = INT, abs_timeout = input_struct!(timespec); DESC);
syscall!(mq_notify, mqdes = INT, notification = input_struct!(sigevent); DESC);
syscall!(mq_getsetattr, mqdes = INT, u_mqstat = ADDR, u_omqstat = ADDR; DESC);
syscall!(kexec_load, entry = INT, nr_segments = INT, segments = ADDR, flags = INT;);
syscall!(waitid, which = INT, pid = INT, infop = output_struct!(siginfo_t), options = INT, ru = output_struct!(rusage); PROCESS);
syscall!(add_key, _type = STR, _description = STR, _payload = ADDR, plen = INT, ringid = INT;);
syscall!(request_key, _type = STR, _description = STR, _callout_info = STR, destringid = INT;);
syscall!(keyctl, option = INT, arg2 = INT, arg3 = INT, arg4 = INT, arg5 = INT;);
syscall!(ioprio_set, which = INT, who = INT, ioprio = INT;);
syscall!(ioprio_get, which = INT, who = INT;);
syscall!(inotify_init; DESC);
syscall!(inotify_add_watch, fd = INT, pathname = STR, mask = INT; DESC, FILE);
syscall!(inotify_rm_watch, fd = INT, wd = INT; DESC);
syscall!(migrate_pages, pid = INT, maxnode = INT, old_nodes = ADDR, new_nodes = ADDR; MEMORY);
syscall!(openat, dfd = INT, filename = STR, flags = INT, mode = INT; DESC, FILE);
syscall!(mkdirat, dfd = INT, pathname = STR, mode = INT; DESC, FILE);
syscall!(mknodat, dfd = INT, filename = STR, mode = INT, dev = INT; DESC, FILE);
syscall!(fchownat, dfd = INT, filename = STR, user = INT, group = INT, flag = INT; DESC, FILE);
syscall!(futimesat, dfd = INT, filename = STR, utimes = input_struct!(timeval); DESC, FILE);
syscall!(newfstatat, dfd = INT, filename = STR, statbuf = output_struct!(stat64), flag = INT; DESC, FILE, FSTAT, STAT_LIKE);
syscall!(unlinkat, dfd = INT, pathname = STR, flag = INT; DESC, FILE);
syscall!(renameat, olddfd = INT, oldname = STR, newdfd = INT, newname = STR; DESC, FILE);
syscall!(linkat, olddfd = INT, oldname = STR, newdfd = INT, newname = STR, flags = INT; DESC, FILE);
syscall!(symlinkat, oldname = STR, newdfd = INT, newname = STR; DESC, FILE);
syscall!(readlinkat, dfd = INT, pathname = STR, buf = output_struct_ref(6), bufsiz = INT; DESC, FILE);
syscall!(fchmodat, dfd = INT, filename = STR, mode = INT; DESC, FILE);
syscall!(faccessat, dfd = INT, filename = STR, mode = INT; DESC, FILE);
syscall!(pselect6, nfds = INT, readfds = inout_struct!(fd_set), writefds = inout_struct!(fd_set), exceptfds = inout_struct!(fd_set), timeout = input_struct!(timespec), sigmask = input_struct!(sigset_t); DESC);
syscall!(ppoll, fds = inout_struct!(pollfd), nfds = INT, timeout = input_struct!(timespec), sigmask = input_struct!(sigset_t), sigsetsize = INT; DESC);
syscall!(unshare, unshare_flags = INT;);
syscall!(set_robust_list, head = ADDR, len = INT;);
syscall!(get_robust_list, pid = INT, head_ptr = ADDR, len_ptr = inout_struct!(usize););
syscall!(splice, fd_in = INT, off_in = inout_struct!(__kernel_loff_t), fd_out = INT, off_out = inout_struct!(__kernel_loff_t), len = INT, flags = INT; DESC);
syscall!(tee, fd_in = INT, fd_out = INT, len = INT, flags = INT; DESC);
syscall!(sync_file_range, fd = INT, offset = INT, nbytes = INT, flags = INT; DESC);
syscall!(vmsplice, fd = INT, iov = input_struct!(iovec), nr_segs = INT, flags = INT; DESC);
syscall!(move_pages, pid = INT, nr_pages = INT, pages = ADDR, nodes = ADDR, status = ADDR, flags = INT; MEMORY);
syscall!(utimensat, dfd = INT, filename = STR, utimes = input_struct!(timespec), flags = INT; DESC, FILE);
syscall!(epoll_pwait, epfd = INT, events = inout_struct!(epoll_event), maxevents = INT, timeout = INT, sigmask = input_struct!(sigset_t), sigsetsize = INT; DESC);
syscall!(signalfd, fd = INT, mask = inout_struct!(sigset_t), sizemask = INT; DESC, SIGNAL);
syscall!(timerfd_create, clockid = INT, flags = INT; DESC);
syscall!(eventfd, count = INT; DESC);
syscall!(fallocate, fd = INT, mode = INT, offset = INT, len = INT; DESC);
syscall!(timerfd_settime, ufd = INT, flags = INT, new_value = input_struct!(itimerspec), old_value = output_struct!(itimerspec); DESC);
syscall!(timerfd_gettime, ufd = INT, curr_value = output_struct!(itimerspec); DESC);
syscall!(accept4, fd = INT, upeer_sockaddr = output_struct!(sockaddr), addrlen = output_struct!(socklen_t), flags = INT; NETWORK);
syscall!(signalfd4, ufd = INT, user_mask = inout_struct!(sigset_t), sizemask = INT, flags = INT; DESC, SIGNAL);
syscall!(eventfd2, count = INT, flags = INT; DESC);
syscall!(epoll_create1, flags = INT; DESC);
syscall!(dup3, oldfd = INT, newfd = INT, flags = INT; DESC);
syscall!(pipe2, fildes = input_struct!(u64), flags = INT; DESC);
syscall!(inotify_init1, flags = INT; DESC);
syscall!(preadv, fd = INT, vec = input_struct!(iovec), vlen = INT, pos_l = INT, pos_h = INT; DESC);
syscall!(pwritev, fd = INT, vec = input_struct!(iovec), vlen = INT, pos_l = INT, pos_h = INT; DESC);
syscall!(rt_tgsigqueueinfo, tgid = INT, pid = INT, sig = INT, uinfo = input_struct!(siginfo_t); PROCESS, SIGNAL);
syscall!(perf_event_open, attr_uptr = ADDR, pid = INT, cpu = INT, group_fd = INT, flags = INT; DESC);
syscall!(recvmmsg, fd = INT, mmesg = ADDR, vlen = INT, flags = INT, timeout = input_struct!(timespec); NETWORK);
syscall!(fanotify_init, flags = INT, event_f_flags = INT; DESC);
syscall!(fanotify_mark, fanotify_fd = INT, flags = INT, mask = INT, fd = INT, pathname = STR; DESC, FILE);
syscall!(prlimit64, pid = INT, resource = INT, new_limit = input_struct!(rlimit64), old_limit = output_struct!(rlimit64););
syscall!(name_to_handle_at, dfd = INT, filename = STR, handle = ADDR, mnt_id = output_struct!(u32), flags = INT; DESC, FILE);
syscall!(open_by_handle_at, mountdirfd = INT, handle = ADDR, flags = INT; DESC);
syscall!(clock_adjtime, which_clock = INT, tx = ADDR; CLOCK);
syscall!(syncfs, fd = INT; DESC);
syscall!(sendmmsg, fd = INT, mmesg = ADDR, vlen = INT, flags = INT; NETWORK);
syscall!(setns, fd = INT, nstype = INT; DESC);
syscall!(getcpu, cpu = output_struct!(u32), node = output_struct!(u32), tcache = ADDR;);
syscall!(process_vm_readv, pid = INT, lvec = input_struct!(iovec), liovcnt = INT, rvec = input_struct!(iovec), riovcnt = INT, flags = INT; MEMORY);
syscall!(process_vm_writev, pid = INT, lvec = input_struct!(iovec), liovcnt = INT, rvec = input_struct!(iovec), riovcnt = INT, flags = INT; MEMORY);
syscall!(kcmp, pid1 = INT, pid2 = INT, type = INT, idx1 = INT, idx2 = INT;);
syscall!(finit_module, fd = INT, uargs = STR, flags = INT; DESC);
syscall!(sched_setattr, pid = INT, attr = ADDR, flags = INT;);
syscall!(sched_getattr, pid = INT, attr = ADDR, size = INT, flags = INT;);
syscall!(renameat2, olddfd = INT, oldname = STR, newdfd = INT, newname = STR, flags = INT; DESC, FILE);
syscall!(seccomp, op = INT, flags = INT, uargs = ADDR;);
syscall!(getrandom, buf = output_struct_ref(1), buflen = INT, flags = INT;);
syscall!(memfd_create, uname = STR, flags = INT; DESC);
syscall!(kexec_file_load, kernel_fd = INT, initrd_fd = INT, cmdline_len = INT, cmdline_ptr = STR, flags = INT; DESC);
syscall!(bpf, cmd = INT, uattr = ADDR, size = INT; DESC);
syscall!(execveat, fd = INT, path = STR, argv = ADDR, envp = ADDR, flags = INT; DESC, PROCESS, FILE);
syscall!(userfaultfd, flags = INT; DESC);
syscall!(membarrier, cmd = INT, flags = INT, cpu_id = INT;);
syscall!(mlock2, addr = ADDR, len = INT, flags = INT; MEMORY);
syscall!(copy_file_range, fd_in = INT, off_in = input_struct!(__kernel_loff_t), fd_out = INT, off_out = input_struct!(__kernel_loff_t), len = INT, flags = INT; DESC);
syscall!(preadv2, fd = INT, vec = input_struct!(iovec), vlen = INT, pos_l = INT, pos_h = INT, flags = INT; DESC);
syscall!(pwritev2, fd = INT, vec = input_struct!(iovec), vlen = INT, pos_l = INT, pos_h = INT, flags = INT; DESC);
syscall!(pkey_mprotect, addr = ADDR, len = INT, prot = INT, pkey = INT; MEMORY);
syscall!(pkey_alloc, flags = INT, init_val = INT;);
syscall!(pkey_free, pkey = INT;);
syscall!(statx, dfd = INT, path = STR, flags = INT, mask = INT, statxbuf = ADDR; DESC, FILE, FSTAT, STAT_LIKE);
syscall!(io_pgetevents, ctx_id = INT, min_nr = INT, nr = INT, events = ADDR, timeout = input_struct!(timespec), rsb = ADDR;);
syscall!(rseq, rseq = ADDR, rseq_len = INT, flags = INT, sig = INT;);
syscall!(fstatat, dirfd = INT, pathname = STR, statbuf = output_struct!(stat), flags = INT; FILE);
syscall!(sync_file_range2, fd = INT, flags = INT, offset = INT, nbytes = INT; FILE);
syscall!(pidfd_send_signal, pidfd = INT, sig = INT, info = input_struct!(siginfo_t), flags = INT; DESC, PROCESS, SIGNAL);
syscall!(io_uring_setup, entries = INT, p = ADDR;);
syscall!(io_uring_enter, fd = INT, to_submit = INT, min_complete = INT, flags = INT, sig = input_struct!(sigset_t), sigsz = INT;);
syscall!(io_uring_register, fd = INT, opcode = INT, arg = ADDR, nr_args = INT;);
syscall!(open_tree, dfd = INT, filename = STR, flags = INT; DESC, FILE);
syscall!(move_mount, from_dfd = INT, from_pathname = STR, to_dfd = INT, to_pathname = STR, flags = INT; DESC, FILE);
syscall!(fsopen, fs_name = STR, flags = INT; DESC);
syscall!(fsconfig, fd = INT, cmd = INT, key = STR, value = ADDR, aux = INT; DESC);
syscall!(fsmount, fs_fd = INT, flags = INT, mttr_flags = INT; DESC);
syscall!(fspick, dirfd = INT, pathname = STR, flags = INT; DESC);
syscall!(pidfd_open, pid = INT, flags = INT; DESC, PROCESS);
syscall!(clone3, uargs = ADDR, size = INT; PROCESS);
syscall!(close_range, fd = INT, max_fd = INT, flags = INT; DESC);
syscall!(openat2, dirfd = INT, pathname = STR, how = ADDR, size = INT; DESC, FILE);
syscall!(pidfd_getfd, pidfd = INT, fd = INT, flags = INT; DESC, PROCESS);
syscall!(faccessat2, dirfd = INT, pathname = STR, mode = INT, flags = INT; DESC, FILE);
syscall!(process_madvise, pid = INT, vec = input_struct!(iovec), vlen = INT, advice = INT, flags = INT; MEMORY);
syscall!(epoll_pwait2, epfd = INT, events = output_struct!(epoll_event), maxevents = INT, timeout = input_struct!(timespec), sigmask = input_struct!(sigset_t), sigsetsize = INT; DESC);
syscall!(mount_setattr, dfd = INT, path = ADDR, flags = INT, uattr = ADDR, usize = INT; DESC);
syscall!(quotactl_fd, fd = INT, cmd = INT, id = INT, addr = ADDR; DESC);
syscall!(landlock_create_ruleset, attr = ADDR, size = INT, flags = INT;);
syscall!(landlock_add_rule, ruleset_fd = INT, rule_type = INT, rule_attr = ADDR, flags = INT;);
syscall!(landlock_restrict_self, ruleset_fd = INT, flags = INT;);
syscall!(memfd_secret, flags = INT; MEMORY);
syscall!(process_mrelease, pidfd = INT, flags = INT; MEMORY, DESC);
syscall!(futex_waitv, waiters = ADDR, nr_futexes = INT, flags = INT, timeout = input_struct!(timespec), clockid = INT;);
syscall!(set_mempolicy_home_node, start = INT, len = INT, home_node = INT, flags = INT; MEMORY);
