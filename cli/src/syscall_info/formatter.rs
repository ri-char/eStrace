use std::marker::PhantomData;

use aligners::{alignment, AlignedBytes};
use bytes::Bytes;

pub trait ArgFormatter {
    fn need_to_print(&self, arg: &Bytes) -> bool;
    fn format(&self, arg: &Bytes) -> String;
}

pub struct VoidArgFormatter {}
impl VoidArgFormatter {
    pub const fn new() -> Self {
        VoidArgFormatter {}
    }
}

impl ArgFormatter for VoidArgFormatter {
    fn need_to_print(&self, _arg: &Bytes) -> bool {
        false
    }
    fn format(&self, _arg: &Bytes) -> String {
        "".to_string()
    }
}
pub const VOID_ARG_FORMATTER: VoidArgFormatter = VoidArgFormatter::new();

pub struct BytesArgFormatter {}

impl BytesArgFormatter {
    pub const fn new() -> Self {
        BytesArgFormatter {}
    }
}

impl ArgFormatter for BytesArgFormatter {
    fn need_to_print(&self, _arg: &Bytes) -> bool {
        true
    }
    fn format(&self, arg: &Bytes) -> String {
        format!("{:?}", arg)
    }
}
pub const BYTES_ARG_FORMATTER: BytesArgFormatter = BytesArgFormatter::new();

pub struct StructArgFormatter<T> {
    _p: PhantomData<T>,
}

impl<T> ArgFormatter for StructArgFormatter<T>
where
    T: std::fmt::Debug,
{
    fn need_to_print(&self, arg: &Bytes) -> bool {
        arg.len() == std::mem::size_of::<T>()
    }
    fn format(&self, arg: &Bytes) -> String {
        let aligned = AlignedBytes::<alignment::Eight>::from(arg.to_vec());
        let new_type: &T = unsafe { &*(aligned.as_ptr() as *const T) };
        format!("{:x?}", new_type)
    }
}

impl<T> StructArgFormatter<T>
where
    T: std::fmt::Debug,
{
    pub const fn new() -> Self {
        Self { _p: PhantomData {} }
    }
}
