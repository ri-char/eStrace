#![no_std]

// https://blog.xhyeax.com/2022/04/28/arm64-syscall-table/
// https://filippo.io/linux-syscall-table/

use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Copy)]
    pub struct ArgType: u8 {
        /// whether the argument need to record before syscall
        const record_before = 0b00000001;
        /// whether the argument need to record after syscall
        const record_after = 0b00000010;
        /// whether the argument is a pointer
        const is_ptr = 0b00000100;
        /// whether the argument is a string pointer, works only when is_ptr is set
        const is_str = 0b00001000;
        /// whether the argument is a pointer which point to a const length struct, works only when is_ptr is set
        /// and is_str is not set
        /// if this flag is set, the next u8 bits be used to store the length of the struct
        /// else the next u8 will be used to store the argument index which is the size of the struct
        /// if the argument index is 6, the size is syscall return number(work only when record_after is set)
        const is_const = 0b00010000;
    }
}

pub const STR_MAX_LENGTH: usize = 256;
