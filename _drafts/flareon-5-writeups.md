---
layout: post
title: FlareOn 5 WriteUps
author: hugsy
author_twitter: _hugsy_
author_email: hugsy@[RemoveThisPart]blah.cat
author_github: hugsy
header-img: img/flareon-2018-header.png
tags: [reverse-engineering, flareon, windows, kernel, pe, linux, ida, binaryninja, i8086]
---

It's already been a year, and here I am again, playing
[Flare-On 2018](https://2018.flare-on.com), 5th edition, and what crazy ride it was.
The good fellows at [FireEye](https://fireeye.com) really outdid themselves. A big trend for this year was clearly around virtual machines, but some good new topics were also present (such as WebAssembly).

Just like last year, same formula: 6 weeks, 12 reversing challenges, 12 flags (all ending with `@flare-on.com`). All challenges can be downloaded
[from this Mega.nz repo](https://mega.nz/#!zVRWyKab!Zty1fpEMSwAQMVptObQBQ_PWUrEEPz8espENP4F15F0).

{% include note.html text="This writeup was made mostly for me to keep track of what I did during those challenges. I don't claim any particular technique to be original, and [much better writeups can be found elsewhere](https://bruce30262.github.io/flare-on-challenge-2018-write-up/).
You might also want to check out the [official solution from FireEye](https://www.fireeye.com/blog/threat-research/2018/10/2018-flare-on-challenge-solutions.html)."  %}


# Menu #

For quick jump:

| [Level1](#challenge-1)   | [Level2](#challenge-2)  | [Level3](#challenge-3)  | [Level4](#challenge-4)  |
| [Level5](#challenge-5)   | [Level6](#challenge-6)  | [Level7](#challenge-7)  | [Level8](#challenge-8)  |
| [Level9](#challenge-9)   | [Level10](#challenge-10)  | [Level11](#challenge-11)  | [Level12](#challenge-12)  |


# The Arsenal #

Surprisingly, I did happen to use the same arsenal than the one from
[last year](/2017/10/13/flareon-4-writeups/#the-arsenal) - also because some challenges were inspired from
last year, but we'll get to that - and it just worked like a charm!

**Note**: just like year, I have no claim of my solution being the best. In some cases I ended up doing
some really dirty things to get to my ends. You might want to check out the official solution PDF for
better directives on how the challenge was made. That being said, let's go for FlareOn 5!



# The Challenges #

## Challenge 1 ##

### Instructions ###

#### Minesweeper Championship Registration

```
Welcome to the Fifth Annual Flare-On Challenge! The Minesweeper World Championship is coming soon
and we found the registration app. You weren't officially invited but if you can figure out what the
code is you can probably get in anyway. Good luck!
```


### Solution ###

Trivial quick-off, the flag can be see using any Java decompiler (I like `jadx`):

```java
if (response.equals("GoldenTicket2018@flare-on.com")) {
  [...]
```

[Back to Menu](#menu)


## Challenge 2

### Instruction

#### Ultimate Minesweeper

```
You hacked your way into the Minesweeper Championship, good job. Now its time to compete. Here is
the Ultimate Minesweeper binary. Beat it, win the championship, and we'll move you on to greater
challenges.
```

### Solution

```bash
$ ls -lah ./2/UltimateMinesweeper.exe
-rw-rw-r-- 1 hugsy hugsy 1.2M Jun 25 07:27 ./2/UltimateMinesweeper.exe
$ file ./2/UltimateMinesweeper.exe
./2/UltimateMinesweeper.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows
```

This time as well, not too much of a mysterie: using `dnspy`, it is possible to spot a `GetKey()` static method in
`MainForm` which appears to do some "crypto" to check the following key:

```python
>>> key = [245, 75, 65, 142, 68, 71, 100, 185, 74, 127, 62, 130, 231, 129,
          254, 243, 28, 58, 103, 179, 60, 91, 195, 215, 102, 145, 154, 27,
          57, 231, 241, 86]
```

I noticed that the `GetKey()` method only has 2^32 possibilities for keys (because of the bound limitation of UInt32).
So I copied / pasted into a custom C# program to bruteforce it, and checking whether the result had `@flareon-com` in the
end:

{% include gist.html id="9cc37a8603a6bab816e2d574fca39cec" name="Solve.cs" %}


And after a few minutes:
```bash
$ dotnet run
Success
Ch3aters_Alw4ys_W1n@flare-on.com
```

[Back to Menu](#menu)
## Challenge 3

### Instructions

#### FLEGGO

```
When you are finished with your media interviews and talk show appearances after that crushing
victory at the Minesweeper Championship, I have another task for you. Nothing too serious, as you'll
see, this one is child's play.
```

### Solution

Inside the challenge archive was a total of 48 PEs. Using `dhex` showed that those
binaries were actually *very* similar up until byte 0x2B00. Also using `CFF Explorer`,
I spotted an extra Resource in the Resource Directory `BRICK`, whose content was a UTF-16
string distinct to each executable, that could be revealed by `strings`:

```bash
$ strings  -e l FLEGGO/dnAciAGVdlovQFSJmNiPOdHjkM3Ji18o.exe
@BRICK
%s\%s
IronManSucks
Oh, hello Batman...
I super hate you right now.
What is the password?
%15ls
Go step on a brick!
Oh look a rainbow.
Everything is awesome!
%s => %s
BRICK
ZYNGeumv6QuI7
```

Just running the program doesn't do much, except asking for a password:

```bash
$ wine FLEGGO/dnAciAGVdlovQFSJmNiPOdHjkM3Ji18o.exe
What is the password?
foobar
Go step on a brick!
```

After a few attempts copy/pasting the strings found above, I realized the password
was the strings located in BRICK resource directory. If the password is found,
an PNG file is dumped on disk and the program also outputs a letter.
```bash
➜  wine FLEGGO/dnAciAGVdlovQFSJmNiPOdHjkM3Ji18o.exe
What is the password?
ZYNGeumv6QuI7
Everything is awesome!
15566524.png => e
```

So I made a Python script to automatically dump everything:
```python
import glob, os, subprocess

for exe in glob.glob("FLEGGO/*.exe"):
    # get password
    l = [ x.strip() for x in subprocess.check_output("strings -e l {}".format(exe), shell=True).splitlines() if len(x.strip()) ]
    p = l[-1]
    print("Got password '{}' for '{}'".format(p, exe))
    # replay it to get the png
    os.system("echo {} | wine {}".format(p, exe))
```

If we run that:
```bash
$ py solve.py
Got password 'Z8VCO7XbKUk' for 'FLEGGO/K7HjR3Hf10SGG7rgke9WrRfxqhaGixS0.exe'
What is the password?
Everything is awesome!
72263993.png => h
Got password 'ohj5W6Goli' for 'FLEGGO/SeDdxvPJFHCr7uoQMjwmdRBAYEelHBZB.exe'
What is the password?
Everything is awesome!
65626704.png => 3
[...]
```

So in the end, we've got 48 PNG files, to all of which were assigned a letter, probably
from the final flag:

![](/img/flareon-2018/12268605.png)

So we have a letter associated to an image, and a number (an index) inside that image. So it doesn't
take a genius that we need to gather all that together, and that's it, using some `grep`/`sed`/`awk`-fu
the flag is ours:

```
mor3_awes0m3_th4n_an_awes0me_p0ssum@flare-on.com
```

[Back to Menu](#menu)

## Challenge 4

### Instructions

### binstall

```
It is time to get serious. Reverse Engineering isn't about toys and games. Sometimes its
about malicious software. I recommend you run this next challenge in a VM or someone
else's computer you have gained access to, especially if they are a Firefox user.
```

### Solution

See the hint in the instruction: the binary is doing something fishy, and that
has something to do with Firefox. Let's keep it in mind...

```
$ ls -lah binstall.exe
-rw-rw-r-- 1 hugsy hugsy 182K Aug 21 13:57 ./binstall.exe
$ file binstall.exe
binstall.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
```

So we're facing a not that small .Net PE file (32 bits). Using `dnSpy`, I saw that the binary was mostly doing the following (from a high level point of view):

  1. Decodes a DLL (`browserassist.dll`) hardcoded encoded in array of UInts. The decoded result is stash into `%APPDATA%\Roaming\Microsoft\Internet Explorer\browserassist.dll`.
  1. Deletes the cache of all Web browsers
  1. Disable DLL signature enforcement (`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\RequireSignedAppInit_DLLs` to 0) and enables [`HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\LoadAppInit_DLLs`](http://support.microsoft.com/kb/197571) and defines `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` with the path to this DLL in the registry hive.

At this point we have a DLL that will be injected by the Windows loader into all processes, so I started analyzing it. When facing a DLL I usually like to create a small loader in C. That allows me to easily interact with any function (exported or not from the binary), set breakpoints, etc. and looks something like this (its name is important, as we'll see later):

{% include gist.html  id="de61415fb3bb9edb81dd7db8e4807a5b" name="firefox.c" %}

The DLL is a hooking library that starts by sending an HTTP request to http://pastebin.com/raw/hvaru8NU, generates a decoding key partially built with the loader  image name: if the image name is `firefox.exe` then the generated key (`FL@R3ON.EXE`), will decode correctly the data and proceed. Therefore this hooking library only targets Firefox (remember the hint?). Once decoded, we get the JSON file:

{% include gist.html  id="15453d36db4183ebe59d0d606db508f9" %}

Then the DLL will look up the functions `PR_Read()` and `PR_Write()` from `nss3.dll` and `nspr4.dll`, responsible for the SSL/TLS encryption of Firefox, and install hooks on them to allow the JSON rules to take effect. Knowing what the DLL did, I moved to examining the JSON itself which was quite explicit as to which pages were hooked:

```
[...]
        "path": "/js/model.js",
        "host": "*flare-on.com"
[...]
```

And what should be replaced:

```
[...]
            "before": "function askPassword(){model.curIndex++, ...
[...]
            "after": "else if (d === (27).toString(36).toLowerCase().split('')...
[...]
```

[Beautifying and then decoding](https://gist.github.com/fb6daa910ef8191098f3e13333792f1a) each block of JavaScript from the plugin reveals a new command on Flare-On website, `su` which takes a password that can be found statically too, from the plugin. Ultimately we could call `de(InputData, password="k9btBW7k2y")` which gives the flag:

```
c0Mm4nD_inJ3c7ioN@flare-on.com
```


[Back to Menu](#menu)

## Challenge 5

### Instructions

#### web2.0

```
The future of the internet is here, again. This next challenge will showcase some the exciting new technologies paving the information super-highway for the next generation.
```


### Solution


This challenge was much easier than the level 4. We're left with a WASM file `test.wasm`. Having worked on WASM recently, I knew there were several approaches, but I decided to be lazy and use {% include link.html text="wasm2c" href="https://pepyakin.github.io/wabt/wasm2c/index.html" %} online to generate a pseudo-C file for me. Once cleaned up, I had a compilable C file

{% include gist.html  id="f17ed2ce301cca2cfe8526c4ef0d2e8b" name="decompiled.c" %}

The C file was not easy to read or reverse.
WebAssembly is a very simplistic VM, and a single simple C instruction (like `int x = a + b`) has to be translated into plenty of instructions. So the idea behind my approach was to benefit from compilers optimizations to simplify the heavy C file, which I could then provide to IDA's Hex-Rays, and get me a more simple form to RE.

![](https://i.imgur.com/wo8Uy5z.png)

It was then trivial to isolate what the indirect functions called were doing (`or`, `not`, `add`, `sub`, `copy_byte`, `xor`)

![](https://i.imgur.com/4cYDDFD.png)

The key is 32 characters long compared one-by-one, and by tracing the execution reveals what values it was compared against:

{% include image.html src="/img/flareon-2018/L5-flag.png" %}

Revealing the flag
```
wasm_rulez_js_droolz@flare-on.com
```
And ending this challenge.


[Back to Menu](#menu)

## Challenge 6

### Instructions

#### magic

```
Wow you are a really good reverse engineer! Keep it up! You can do it!

How to tell if your child is a computer hacker:
1. They are using Lunix, an illegal hacker operating system
2. Are they struggling to maintain contact with the outside world, due to spending their time reading gibberish on the computer screen
```


### Solution

This challenge reveals `magic`, an obfuscated ELF file that requires to enter 666 valid keys. Each of those keys is divided into 33 sub-parts, given by 33 functions which appeared (wrongly) to be different. Actually by taking a close look at the assembly, I realized that there are (only) 8 unique functions performing crypto operations. So the program operates roughly like this

```
EncodedBlockAtFixedAddress = {...};
while i < 33
{
  DecodeBlock(i, KeyPart[i])
}
```

If everything goes well and the key is valid, the binary got self-mutated by the input of the key. Since those addresses are static, it was possible to create a tool to

 1. Load the code and data into its own memory
 2. Unxor the initial code buffer
 3. Bruteforce each character to get the 1/33th part of the _i_th key
 4. Loop 33 times to get a whole key

{% include gist.html id="69551c411acd779f67c379108b1f0237" name="solve.c" %}

Since `solve.c` is capable of bruteforcing one key, another wrapper was necessary to bruteforce the 666 keys, and take into consideration the mutations:

{% include gist.html id="36bb1dc6f3d99da5c7db491111a93a38" name="final.py" %}

Then was time for a good coffee while watching the monitor:

<video width="800" height="600" controls>
  <source src="/img/flareon-2018/L6-flag.webm" type="video/webm">
  Your browser does not support the video tag.
</video>



Validating the ultimate key would grant us the flag:
```
Congrats! Here is your price:
mag!iC_mUshr00ms_maY_h4ve_g!ven_uS_Santa_ClaUs@flare-on.com
```

Half of the challenges, done!


[Back to Menu](#menu)

## Challenge 7

### Instruction

#### Wow

```
Wow, just.... Wow.
```


### Solution

wow != worldofwarcraft
windows over windows64

embedded xor-ed (x64) dll with key 0xdeedeeb
binwalk spotted another dll in the dll
the unxored dll contains a x86 dll that can be extracted with

```bash
$ dd if=unxored.dll of=pe2.dll ibs=1 skip=14640
```

```python
>>> v4 = bytearray(b"A_l1ttl3_P1C_0f_h3aV3n")
>>> v5 = bytearray(b'\x157]B+E\x1fl+8\x02\x1c(BV1\x0fl\neJ1')
>>> x = "".join( map(chr, [v5[i] ^ v4[i] for i in range(len(v4))]))
>>> print x
Th1s_1s_th3_wr0ng_k3y_
```

hashes
worldofwarcraft.exe:
0x3E2005A -> worldofwarcraft.exe
0x2801B0 -> ntdll.exe


unxored.dll
0xA5D0A5E -> Ntdll_base
0x7C6F7D7D -> NtAllocateVirtualMemory
0x77797C83 -> LdrGetProcedureAddress

struct funcptr_t
{
0x00 pBaseNtdll
0x08 pLdrGetProcedureAddress
0x10 pNtQueryInformationProcess
0x18
0x20 pNtCreateThread
0x28 pRtlGetVersion
0x30
0x38 pNtDeviceIoControl
0x40
0x48
0x50 bIsWow64
0x54
0x58
0x5c
0x60
}


worldofwarcraft -> unxor s0.dll -> x64call()
_____________________________________|
|
V
calls s0_2() (function of ordinal 2 in s0.dll)
|
V
load some functions pointers from ntdll



[Back to Menu](#menu)

## Challenge 8

### Instruction

#### Doogie Hacker

```
You are absolutely crushing this. Saved off the first few sectors from a hard
drive that some computer genius had back in the 90s. People say the kid used
to write his own computer software but that sounds crazy. This little
prankster left us a secret message I think.

7zip password: infected
```


### Solution

Interestingly, this challenge was rather easy considering it's a level 8.
8086
input written @0x000087f4

```
gef➤  db 0x87EE+6 l128
0x000087f4     41 41 41 41 41 41 41 41 41 41 00 00 00 00 00 00     AAAAAAAAAA......
0x00008804     00 00 00 00 00 29 9e 02 1e 32 90 06 44 39 87 07     .....)...2..D9..
0x00008814     02 3a da 13 09 25 98 47 1d 3d 9b 0b 17 3d 86 04     .:...%.G.=...=..
0x00008824     0e 39 85 1d 1a 32 94 1b 14 30 94 5a 0c 2c 8c 1d     .9...2...0.Z.,..
0x00008834     15 2d 88 06 14 39 9b 0f 12 2f 81 17 09 21 85 4d     .-...9.../...!.M
0x00008844     02 1b ae 13 17 37 88 18 06 48 9e 02 44 2a cc 06     .....7...H..D*..
0x00008854     1e 47 87 07 7b 2c 86 49 11 3d 80 05 13 3d 9b 0b     .G..{,.I.=...=..
0x00008864     17 3d 9e 1c 16 39 85 1d 7b 32 94 00 4d 71 d5 41     .=...9..{2..M
```

today's date written at 0x87EE
```
gef➤  db 0x87EE l6
0x000087ee     20 18 09 04 14 00                                   .....
```

0 < keylength <= 20

decoded_message_length = 1178
```
0x00008809     68 df 43 5f 73 d1 47 05 78 c6 46 43 7b 9b 52 48     h.C_s.G.x.FC{.RH
0x00008809     68 df 43 5e 73 d1 47 04 78 c6 46 42 7b 9b 52 49     h.C^s.G.x.FB{.RI
```
xored code is at  0x8809


hijack
68 df 43 5e 73 d1

unxor the shellcode using the proper date -> 19 90 02 06 -> `3.dec`

can deduct the flag:
```python
>>> print xor(f, "ioperateonmalware")
```

can see
```
R3_PhD@flare-on.com
```

[Back to Menu](#menu)

## Challenge 9

### Instruction

#### last editr
```
Its getting to the very late stage challenges now, so its probably a good
point to just turn back, stop this insanity. What's that? You wanted more
ASCII art? Ask and ye shall receive.
```


### Solution


```
$ strings -e l leet_editr.exe
You are about to run the coolest
ASCII Art editor on earth. Continue?
Caution: Explosively Neat Program
createtextfile
gimmethatsweetsweetcrazylove
getspecialfolder
wimmymebrah
```

```javascript
g_interval2 = setInterval( function()
{
  if ((title.value.indexOf('title') != -1) && \
  (title.value.indexOf('FLARE')!=-1) && \
  (strhash(title.value)==-1497458761))
  {
    hint('That\'s a nice title');
  }
} );
```

with `strhash()` from JS

```javascript
function hint(s) {
    document.getElementById('status').innerText = 'You\'re on to something!' + s;
}

function strhash2(s) {
    var hash = 0, i;
    for (i=0; i<s.length; i++) {
        var c = s.charCodeAt(i);
        hash = ((hash << 5) - hash) + c;
        hash |= 0;
    }
    return hash;
}

function strhash(s) {
    var hash = 0, i, c;
    s = s.replace(/\s+/g, '')
    for (i=0; i<s.length; i++) {
        c = s.charCodeAt(i);
        hash = ((hash << 5) - hash) + c;
        hash |= 0;
    }
    return hash;
```

Creates a COM object

From 004019F0, dispId
```
0x10101010 : getspecialfolder
0xDEADBEEF : run
0x1337     : gimmethatsweetsweetlove
0xCAFEBABE : createtextfile
```

Invoke() is at 401B30


CreateTextFile("WimmyMeBrah", "sn00gle-fl00gle-p00dlekins") --> {
  WimmyMeBrah(byte_40F110, dword_40F10C, pVarResult1.bstrVal, (int *)&pdispparams);
    --> out2.b64
      --> KillProcesses.vbs (aka PetMeLikeATurtle)
}

GetSpecialFolder(250)  --> Sleep(250);

Run --> Memory[0]();


gimmethatsweetsweetlove() --> {
  GimmeThatSweetSweetLove(dispIDMember, 0x1337, wFlags, pdispparams, pvarg, puArgErr);
  decodeflag?
}

0x00
0x04
0x08 SectionSize
0x10
0x18
0x20 SectionStartAddress

clean data dump --> `dump1.txt`

http://www.blog.codereversing.com/membp.pdf
https://www.codeproject.com/Articles/17038/COM-in-plain-C-part-8
https://www.codeproject.com/Articles/17038/COM-in-plain-C-part-8#VAR
https://www.codeproject.com/Articles/13601/COM-in-plain-C

use the loader to hook DoDecodeEncode() on the 6 code blocks + 1 data block
used processhacker to dump strings from memory (grep for FLARE)

```
If I were to title this piece, it would be 'A_FLARE_f0r_th3_Dr4m4t1(C)'
```

And get the final flag in ascii art

```
scr1pt1ng_sl4ck1ng_and_h4ck1ng@flare-on.com
```

[Back to Menu](#menu)

## 10 - golf

### challenge

```
How about a nice game of golf? Did you bring a visor? Just kidding, you're not
going outside any time soon. You're going to be sitting at your computer all
day trying to solve this.
```


### Solution

```
$ a golf.exe
-rw-rw-r-- 1 vagrant vagrant 297K Aug 23 13:42 golf.exe
$ file golf.exe
golf.exe: PE32+ executable (console) x86-64, for MS Windows
$ strings golf.exe
[...]
SYSTEM\CurrentControlSet\Control
SystemStartOptions
TESTSIGNING
ZwLoadDriver
ntdll
SeLoadDriverPrivilege
SYSTEM\CurrentControlSet\services\fhv
ErrorControl
Start
Type
\??\%s\fhv.sys
ImagePath
C:\fhv.sys
ZwUnloadDriver
Too bad so saddd %x
%s@flare-on.com
RSDS|78.VR
t:\objchk_win7_amd64\amd64\golf.pdb
[...]
```




#### RE

##### golf.exe

takes an argv[1]
length should be 24
then makes a checksum of unk_10004B140, should be 0x5C139D95
then checks if testsigning
dumps file as "C:\fhv.sys"

cpuid 0x40000001 -> HV_HYPERVISOR_INTERFACE_INFO
https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/hvilib/hviintel/hypervisor_interface_info.htm


 hypercalls issued:
  - 0x13687060
  - 0x13687061
  - 0x13687062
  - 0x13687063
  - 0x13687451
  - 0x13687453

order (each check must return 1 to proceed to the next):

```
do_check_0(arg)
{
vmcall (0x13687060, lpAddress)   // dexor buffer
vmcall (0x13687451, lpAddress, 0), lpAddress
lpAddress(arg)
vmcall 0x13687453   // cleanup
}

do_check_1(arg)
{
vmcall 0x13687061
vmcall (0x13687451, lpAddress, 0)
lpAddress(arg)
vmcall 0x13687453 // cleanup
}

do_check_2(arg)
{
vmcall 0x13687062
vmcall (0x13687451, lpAddress, 0)
lpAddress(arg)
vmcall0x13687453  // cleanup
}


do_check_3(arg)
{
vmcall 0x13687063
vmcall (0x13687451, lpAddress, 0)
lpAddress(arg)
vmcall 0x13687453 // cleanup
}
```


calls 4 check functions
each check must return != 0

if all pass, the argv[1] is valid (and the key)

keylen = 24



##### fhv.sys


Hypercall dispatcher is at 00140003810

arg1 = virtualaddr
arg2 = len


struct __vcpu (QWORD*)
{
  0x00 : id
  0x04 : ???

  0x38 : GuestAddrSpaceLen
  0x68 : GuestAddrSpaceStart
  0x70 : vmcall_num
  0x78 : HI(RDTSCP)
  0x88 : ???
}


see vmcs_field.h


after 2 days of RE hyper-v part, {% include icon-twitter.html username="@0xcpu" %} hinted me that reversing the hyper-v is irrelevant so I focused on the VM itself.

identified interesting opcodes
-> 41 does comparaison (cmp + push eflags)
  -> we can see the 1st valid chars from flags in the 1st decoded blob
    -> 'We4r_'


[Back to Menu](#menu)

## 11 - malware skillz


### challenge

```
We captured some malware traffic, and the malware we think was responsible. You know
the drill, if you reverse engineer and decode everything appropriately you will
reveal a hidden message. This challenge thinks its the 9th but it turned out too hard,
so we made it the 11th.
```


### solution

LaunchAccelerator.exe: PE32 executable (GUI) Intel 80386, for MS Windows

display `launch.exe.png` and drop `crackme.exe` on the desktop



#### timeline

cli1 = 192.168.221.91 (johnjackson-pc\\john.jackson)
cli2 = 192.168.221.105 (larryjohnson-pc\\larry.johnson)
dnssrv =  192.168.221.2
c2srv = 52.0.104.200

-----------
dns2tcp like from cli1  ->  dnssrv
notatallsuspicio.us TXT packets
b64 payload extracted in dns-out.b64
looks encrypted ( TODO )

-----------

then at pkts[3281] cli1 -> DNS A to analytics.notatallsuspicio.us (replies with ip c2srv)
cli1 -> tcp conn to :9443
looks encrypted too (not ssl tho)

custom protocol

struct _header {
  DWORD type

}
51


-----------

then cli1 -> SMB2 to cli2

```
3500 protocol: tcp 192.168.221.91:49159 > 192.168.221.105:445
NTLMv2 complete hash is: larry.johnson::JOHNJACKSON-PC:15c9b6f978c45b07:0A4A1E976908775CA70AB5743F671D5E:01010000000000003AC1C5B4BD30D40129CEDDDE8C28D71D0000000002001E004C0041005200520059004A004F0048004E0053004F004E002D005000430001001E004C0041005200520059004A004F0048004E0053004F004E002D005000430004001E006C0061007200720079006A006F0068006E0073006F006E002D007000630003001E006C0061007200720079006A006F0068006E0073006F006E002D0070006300070008003AC1C5B4BD30D40106000400020000000800300030000000000000000100000000200000EFA3F8175876645337B546B72C668C1194A8B47491EEDCFF429CCA6C9B803E010A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003200320031002E00310030003500000000000000000000000000
```

192.168.221.105 larry.johnson n3v3rgunnag1veUup



OperServiceW( LaunchAccelerator.exe ) -> fails
CreateFile( LaunchAccelerator.exe ) : copies to cli2


another smb2 connection
writes (encrypted?) data to pip malaproppie <- seems same proto than tcp.stream 1

at pkts[4040] cli1 sends a command
then cli2 opens a ftp (tcp/21) conn to c2srv and pushes (pkts[4070]) /upload/level9.crypt (starts with cryptar20180810)



#### re

dnsapi!dnsqueryex_a

looks for file launchassist.exe
create key in SOFTWARE\Microsoft\Windows\CurrentVersion\Run  called  C:\Users\user\AppData\Local\launchassist.exe (copy of LaunchAccelerator.exe)

at 4108EB , execute shellcode in a rwx-malloc-ed location
dns download file -> `popup.exe` (decoded)

pe32 file that's unxor with key 0xAA and dumps `crackme.exe` to desktop

hidden exported procedure  at 712c3030

used fakedns to replay the dns part
dumped binary in `dump2.dll`


```
dump2.dll: PE32 executable (DLL) (GUI) Intel 80386, for MS Windows
```

bp ws2_32!socket
bp ws2_32!connect
bp ws2_32!send

loader3.run -> this = 10ad10c8
ttd a3c3:20

at 402830 <<- handshake
{
  generates 48 random bytes
  sends to c2
  recv 48 random bytes from serv
}


challenge based of 2017 L12 challenge

did not reverse the crypto, RE the `dump2.dll` DLL to see that it can both handle client & server
comm.

hardpatch dump2.dll to create a PE exec -> dump6.exe

with frida + socat + npiperelay I managed to expose the service on 9443/tcp
then I could simply send any packet of data and hook 402B09 to dump decoded data

comm HTTP, visit of web page -> leak password to level9.zip

then smb comm embeds the same protocol, but nonces are also exchanged so I could still reuse my
tool chain

-> dumped cryptor.exe (.Net bin) that simply AES encrypt data (+ control checks on files added)

it leaked the key+iv location on Github
wrote `decrypt.py` -> got level9.zip

unzipped with password found in HTML page (MoinMoin wiki)
-> got level9.exe and level9.png (appears blank - all white)

level9.exe is a simple "stegano" tool that will output an image with a password in it
assuming level9.png was generated with it, simply wrote `decode-image.py` to spot non white pixel ,
make then appear black

result in -> `final-flag.png`

[Back to Menu](#menu)

## Challenge 12

### Instructions

#### Suspicious Floppy Disk

```
Now for the final test of your focus and dedication. We found a floppy disk that was given to spies
to transmit secret messages. The spies were also given the password, we don't have that information,
but see if you can figure out the message anyway. You are saving lives.
```

### Solution


```
$ qemu-system-x86_64 -s -drive file=suspicious_floppy_v1.0.img,index=0,if=floppy
```

unobfuscated code in `TMP.dat`
-> 8086 code

subleq code starts at TMP.dat+0x266
size 23386


(r0) base + 0 -> ??
(r1) base + 2 -> ??
(r2) base + 4 -> char_to_print
(r3) base + 6 -> retcode
(r4) base + 8 -> trigger int10h
base + 10 -> code_start

self modified code starts at 0xfea
index for it is 0x0xbb8

one char adds 1147 insn to the inner VM

```
Av0cad0_Love_2018@flare-on.com
```

[Back to Menu](#menu)


# Conclusion notes

Another year of fun challenges. Thank you to {% include icon-twitter.html username="@0xcpu" %},
{% include icon-twitter.html username="@daubsi" %} and {% include icon-twitter.html username="@GradiusX" %} for keeping me on track, you've helped me not waste time on unimportant stuff.

Admittedly this edition was tough, but I learnt tons along the way. Reading the official writeup, it appears that (only?) 114 people made it to the end, out of the 3374 who scored at least one flag. And reading this:

> We plan to reduce the difficulty next year, so it may be that the 114 people who solved this year’s challenge solved not only the most difficult Flare-On to date, but the most difficult Flare-On there ever will be.

Kindda made me happy about next year's edition (why not a 3rd level on VM inception?!?)

And if I were to tell my next year's self some advices before entering the game, it would be:

 - *everything* can be solved statically
 - **always reverse everything**: don't leave anything out
 - don't make (too much) assumptions
 - difficulty increases progressively, but some "high number" challenges are easy, so don't
   overthink too much

Thank you [FireEye](), and especially the whole [FlareOn team]() for those imaginative challenges.
You've deprived me of many sleep hours, and turned them into moments of pure fun which reminds me
why I love reversing.

See you in 11 months for FlareOn 6, I'll be there!