# eStrace

eStrace(eBPF syscall trace) is a tool that traces system calls using eBPF. Compared to strace, it is more flexible and harder to detect. It currently supports two architectures: x86_64 and aarch64. With eStrace, you can conveniently debug and analyze your Linux/Android applications.

It is recommended to use **kernel version 5.10** or higher when running it.

![screenshot](./imgs/screenshot.png)

## Building

### Setup

```bash
# check lld
ld.lld -v
rustup target add x86_64-unknown-linux-musl
cargo install bpf-linker
```
And for android:
```bash
rustup target add aarch64-unknown-linux-musl
```

### Build
```bash
cargo xtask build
cargo xtask build --arch aarch64-unknown-linux-musl

# release
cargo xtask build --release
cargo xtask build --arch aarch64-unknown-linux-musl --release
```

### Build and Run
```bash
cargo xtask run -- <args>
```

## ToDo

- Support for additional architectures.
