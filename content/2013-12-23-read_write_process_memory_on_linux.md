+++
title = "Using new syscalls for read/write arbitrary memory on Linux."
authors = ["hugsy"]
date = 2013-12-23T00:00:00Z
updated = 2013-12-23T00:00:00Z
aliases = ["/posts/2013/12/23/read-write-process-memory-on-linux.html"]

[taxonomies]
tags = ["linux", "kernel", "seccomp"]
categories = ["research"]
+++

Even though well known methods exist to bypass ptrace deactivation on a process when spawning (fake `ptrace()` preloading, breakpoint on `ptrace()`, etc... ), it is trickier when process is already protected.

Thankfully Linux 3.2+ was generous enough to provide read/write capabilities to another process with 2 new system calls: `sys_process_vm_readv` and `sys_process_vm_writev`. (see [the source code](https://github.com/torvalds/linux/blob/975f3b6da18020f1c8a7667ccb08fa542928ec03/arch/x86/entry/syscalls/syscall_64.tbl#L321)). For our Windows friend, those new syscalls are similar to `ReadProcessMemory()` and `WriteProcessMemory()`.

The manual says:
> These system calls transfer data between the address space of the calling process  ("the  local  process") and the process identified by pid ("the remote process").  The data moves directly  between  the address spaces of the two processes, without passing through kernel space.

A running process can be `ptrace`d like this:

``` c
if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
   perror("[-] is traced\n");
   return 1;
}
```

As such, it would acquire an exclusive lock, preventing any other ptrace instance (say a debugger) to manipulate its memory (that's like ELF anti-debug 101). But it can hence still have its memory read:

``` c
struct iovec local[1], remote[1];
local->iov_base = mybuf;
local->iov_len = size_to_read;
remote->iov_base = (void *) strtoll(argv[2], NULL, 16);
remote->iov_len = to_read;
int nread = process_vm_readv(target_pid, local, 1, remote, 1, 0);
```
Similar call to `process_vm_writev` will tamper remote process memory.

Even though it is not possible to read/write in process memory that don't have the same level of privilege (unless given `CAP_SYS_PTRACE` capability), it is a very reliable way to leak or inject data.

I've added the syscall filtering to my toy sandboxing tool, [`bakassabl`](https://github.com/hugsy/bakassabl).
