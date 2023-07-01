#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("unsupported target architecture");

#[cfg(target_arch = "x86_64")]
pub mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::SYSCALL_ARG_TABLE;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::SYSCALL_ARG_TABLE;
