date: 2018-03-11 00:00:00
modified: 2018-03-11 00:00:00
title: Fuzzing arbitrary functions in ELF binaries
author: hugsy
cover: assets/images/libfuzzer-lief/header.png
category: research
tags: fuzzing,elf,lief,libfuzzer,cve-2018-6789,exim

I decided to give a descent test to
the [LIEF](https://lief-project.github.io/) project. Executable parsers are
[not](https://github.com/eliben/pyelftools) [a new](https://github.com/erocarrera/pefile) [thing]() but
that one picked my curiosity (just like most Quarkslab projects) because it
also provides dead simple instrumentation functions. To top it up, LIEF is easy
to use and well documented, which is becoming a rare perk in the circus of
infosec tools.

By reading some blog posts about LIEF, I came across [a new
feature](https://lief-project.github.io/doc/latest/tutorials/08_elf_bin2lib.html):
easily adding arbitrary functions to an ELF export table. I highly recommend to
dig through this post if you haven't done so already.

When I was done reading, I realized one of the many good applications to this
feature would be fuzzing. But why not use [AFL](http://lcamtuf.coredump.cx/afl) you
may ask? Well, AFL is an awesome (awesome awesome) tool, but it  fuzzes the
whole binary by providing some local mutated input. This has 2 disadvantages for
precise, targeted function fuzzing:

  1. performance: in default mode (i.e. non persistent), AFL spawns and runs the
     entire binary, which obviously adds the process creation/deletion time,
     along with all the code before reaching the function(s) we're aiming;
  1. modularity: it is not easy to fuzz network service parsing mechanism with
     it. I know
     of [already existing attempts](https://github.com/jdbirdwell/afl) to fix
     this, but I find them too hacky and poorly scalable.

On the other side we have LLVM's own [LibFuzzer](https://llvm.org/docs/LibFuzzer.html), which is an awesome (awesome
awesome) library to fuzz, well... libraries. And fortunately, not everything is a library
(sshd, httpd)

And that's exactly where LIEF kicks in... How about using LIEF to export one (or
many) functions from the ELF binary we target, into a shared object, and then use
LibFuzzer to fuzz it! On top of that, we can also use the
compilers [sanitizers](https://github.com/google/sanitizers/) to track invalid
memory access! But would that even work?

It turns out it did, big time and after successfully playing on simple PoCs, I
realized this technique was relevant to dig into, so I chose to put it to
practice by trying to find real vulnerabilities.


## Concrete example: finding CVE-2018-6789 ##

What better way to illustrate this technique than with a concrete example: earlier this
week, <a class="fa fa-twitter" href="https://twitter.com/mehqq_" target="_blank"> mehqq_</a> released [a great blog post about CVE-2018-6789](https://devco.re/blog/2018/03/06/exim-off-by-one-RCE-exploiting-CVE-2018-6789-en/) detailing the exploit steps for an off-by-one vulnerability she discovered in Exim. The issue was fixed in [cf3cd306062a08969c41a1cdd32c6855f1abecf1](https://github.com/Exim/exim/commit/cf3cd306062a08969c41a1cdd32c6855f1abecf1) and given the CVE 2018-6789.

[Exim](https://github.com/Exim/exim) is a MTA which once compiled is a standalone binary. So AFL would be of little help (network service), but it is a perfect practice case for LIEF + LibFuzzer.

We must compile Exim as PIE (usually done with setting `-fPIC` in CFLAGS and `-pie` in `LDFLAGS`). But we also need the [address sanitizer]() since without them, off-by-one overflow in the heap may go unoticed.

### Compiling the target with ASAN & PIE ###

```bash
# on ubuntu 16.04 lts
$ sudo apt install libdb-dev libperl-dev libsasl2-dev libxt-dev libxaw7-dev
$ git clone https://github.com/Exim/exim.git
# roll back to the last vulnerable version of exim (parent of cf3cd306062a08969c41a1cdd32c6855f1abecf1)
$ cd exim
$ git reset --hard cf3cd306062a08969c41a1cdd32c6855f1abecf1~1
HEAD is now at 38e3d2df Compiler-quietening
# and compile with PIE + ASAN
$ cd src ; cp src/EDITME Local/Makefile && cp exim_monitor/EDITME Local/eximon.conf
# edit Local/Makefile to add a few options like an EXIM_USER, etc.
$ FULLECHO='' LFLAGS+="-L/usr/lib/llvm-6.0/lib/clang/6.0.0/lib/linux/ -lasan -pie" \
  CFLAGS+="-fPIC -fsanitize=address" LDFLAGS+="-lasan -pie -ldl -lm -lcrypt" \
  LIBS+="-lasan -pie" make -e clean all
```

<div markdown="span" class="alert-info"><i class="fa fa-info-circle">&nbsp;Note:</i> in some cases, the use of ASAN fails to create the config file required</div>
for the compilation. So edit `$EXIM/src/scripts/Configure-config.h` shell script
to avoid the premature ending:

```patch
diff --git a/src/scripts/Configure-config.h b/src/scripts/Configure-config.h
index 75d366fc..a82a9c6a 100755

+++ b/src/scripts/Configure-config.h
@@ -37,6 +37,8 @@ st='   '
   "/\\\$/d;s/#.*\$//;s/^[$st]*\\([A-Z][^:!+$st]*\\)[$st]*=[$st]*\\([^$st]*\\)[$st]*\$/\\1=\\2 export \\1/p" \
   < Makefile ; echo "./buildconfig") | /bin/sh
+echo
+
# If buildconfig ends with an error code, it will have output an error
# message. Ensure that a broken config.h gets deleted.
```

The compilation will occur normally and once compiled we can use `checksec` from [pwntools]() on the binary and make
sure it's PIE and ASAN compatible:

```bash
$  checksec ./build-Linux-x86_64/exim
[*] '/vagrant/labs/fuzzing/misc/exim/src/build-Linux-x86_64/exim'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    ASAN:     Enabled
```

### Exporting the targeted functions ###

From the write-up, the vulnerable function is `b64decode()` in `src/base64.c`
whose [prototype](https://github.com/Exim/exim/blob/38e3d2dff7982736f1e6833e06d4aab4652f337a/src/src/base64.c#L152-L153){:target="_blank"} is:

```c
int b64decode(const uschar *code, uschar **ptr)
```

This function is not static and the binary not stripped, so we can spot it
easily with `readelf`:

```bash
$ readelf -a ./build-Linux-x86_64/exim
  1560: 00000000001835b8    37 FUNC    GLOBAL DEFAULT   14 lss_b64decode
  3382: 00000000000cb0bd  2441 FUNC    GLOBAL DEFAULT   14 b64decode
```

So now we know that we want to export the function `b64decode` at PIE offset
0xcb0bd. We can use the following simple script to export the functions using
LIEF (>=0.9):

<script src="https://gist.github.com/hugsy/d48780a2000925902a7e31ff0240479a.js"></script>

We also need to export `store_reset_3()` which is used to free the structures.

```bash
$ ./exe2so.py ./build-Linux-x86_64/exim 0xcb0bd:b64decode 0x220cde:store_reset_3
[+] exporting 'b64decode' to 0xcb0bd
[+] exporting 'store_reset_3' to 0x220cde
[+] writing shared object as './exim.so'
[+] done
```


### Write a LibFuzzer loader to invoke the targeted function ###

First we need a handle to the library:

```c
int LoadLibrary()
{
        h = dlopen("./exim.so", RTLD_LAZY);
        return h != NULL;
}
```

And reconstruct the function `b64decode()` based on its prototype:
```c
typedef int(*b64decode_t)(const char*, char**);
[...]
        b64decode_t b64decode = (b64decode_t)dlsym(h, "b64decode");
        printf("b64decode=%p\n", b64decode);
        int res = b64decode(code, &ptr);
        printf("b64decode() returned %d, result -> '%s'\n", res, ptr);
        free(ptr-0x10); // required to avoid LSan alert (memleak)
```

`b64decode()` can now be called:

```bash
$ clang-6.0 -O1 -g  loader.cpp -no-pie -o runner -ldl
$ echo -n hello world | base64
aGVsbG8gd29ybGQ=
$ LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.4.0.0 ./runner aGVsbG8gd29ybGQ=
b64decode=0x7f06885d50bd
b64decode() returned 11, result -> 'hello world'
```

That works! And we can thank only LIEF for that, by making the instrumention of
arbitrary functions a child game.


### Fuzz da planet! ###

We can now use this skeleton to build a LibFuzzer-based fuzzer around this:

<script src="https://gist.github.com/hugsy/3ef3e4309d1f102aa4318c09b4043b09.js"></script>

Compile it, run it, and be amazed 😎 :

```
$ clang-6.0 -DUSE_LIBFUZZER -O1 -g -fsanitize=fuzzer loader.cpp -no-pie -o fuzzer -ldl
$ LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libasan.so.4.0.0 ./fuzzer
INFO: Loaded 1 modules   (11 inline 8-bit counters): 11 [0x67d020, 0x67d02b),
INFO: Loaded 1 PC tables (11 PCs): 11 [0x46c250,0x46c300),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 3 ft: 3 corp: 1/1b exec/s: 0 rss: 42Mb
#11     NEW    cov: 4 ft: 4 corp: 2/3b exec/s: 0 rss: 43Mb L: 2/2 MS: 4 ShuffleBytes-ChangeBit-InsertByte-ChangeBinInt-
[...]
```

We're running more than 1 million executions/second/core on the function
`b64decode`, not bad eh?

And in less than a 1 second, we get the heap overflow found by <a class="fa fa-twitter" href="https://twitter.com/mehqq_" target="_blank"> @mehqq_</a>, CVE-2018-6789:

![image_alt](/assets/images/libfuzzer-lief/fuzz-result.png)

>
> **Note**: Earlier this week, I was notified by <a class="fa fa-twitter" href="https://twitter.com/mehqq_" target="_blank"> mehqq_</a> that this is OOB read is a different bug. I will post an update soon showcasing the actual bug instead. My bad for the confusion.
>


## Final words ##

Although this technique is not as click-and-play like AFL since it requires a bit more work, it offers non-negligeable pros:

  - excellent reliability, makes easy for fuzzing network services → focus on
    parsing functions (no network stack to handle etc.). perfect for can focus on
    specific points (packet parsing, message processing, etc.)
  - crazy performance: no need to spawn the whole binary
  - there is actually no need for the source code, we can use LibFuzzer on
    black-box binaries
  - low hardware requirements allow to fuzz at very high rate even on weak
    hardware (and transform your RaspberryPis into a fuzzing cluster 😎)

But nothing ever being perfect, there are obviously also cons:

  - need to code almost every fuzzer (so only for C/C++ coding people)
  - specific edge cases you might need to consider (beware of memleaks!!)
  - we must determine the function prototype. This is easy when the source code
    is open (FOSS projects), but black-box binaries may require some prior
    reversing. Tools like [Binary Ninja](https://binary.ninja) Commercial
    License may also be of great help for automating this task.

All in all, it is a pretty neat approach made possible through 2 awesome tools. I do hope LIEF development keeps being active to bring us more goodies like this!

Thanks for reading 😁 !
