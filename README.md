# eStrace

eStrace(eBPF syscall trace) is a tool that traces system calls using eBPF. Compared to strace, it is more flexible and harder to detect. It currently supports two architectures: x86_64 and aarch64. With eStrace, you can conveniently debug and analyze your Linux/Android applications.

## Usage

```bash
sudo ./estrace --help
Usage: estrace [OPTIONS]

Options:
  -p, --pid <PID>  Target pid
  -t, --tid <TID>  Target tid
  -u, --uid <UID>  Target uid
  -h, --help       Print help
```
![screenshot](./imgs/screenshot.png)

## Building

```
cargo xtask run -- <args>
```

## ToDo

- Display the parameter names of system calls.
- Parse the structure of parameters.
- Support for additional architectures.
