#![allow(non_camel_case_types)]
use std::fmt::Debug;

#[repr(C)]
#[derive(Debug)]
pub struct sockaddr {
    inet_addr: u16,
    sa_data: [u8; 12],
}

#[repr(C)]
#[derive(Debug)]
pub struct iovec {
    iov_base: usize,
    iov_len: usize,
}

#[repr(C)]
#[derive(Debug)]
pub struct msghdr {
    pub msg_name: usize,
    pub msg_namelen: u32,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: usize,
    pub msg_control: usize,
    pub msg_controllen: usize,
    pub msg_flags: i32,
}

pub type time_t = i64;
