+++
title = "Some toying with the Self-Reference PML4 Entry"
author = "hugsy"
date = 2020-06-15T00:00:00Z
updated = 2024-07-01T00:00:00Z

[taxonomies]
categories = ["research"]
tags = ["windows","kernel", "mmu", "x64"]

[extra]
header_img = "/img/f7803990-4baa-4a9a-a09b-0cde30694fa6.png"
+++

Sometimes you read about an awesome exploitation technique ([#1](#links)), so you want to go deeper. So this is my notes about how trying to totally understand the exploitation of CVE-2020-0796 ([#2](#links)), I ended up struggling finding good explanation about a critical structure of Windows paging mechanism: the "Self-Reference PML4 Entry".
_Disclaimer_: If you came here for new stuff, so let me put your mind at peace: There's nothing new here, I don't claim to find anything what's being found and said by people way smarter, and I have probably understood it wrong anyway so don't judge/quote me. Also the post will only talk be about x64 and Windows here (and having a (L)KD open can help to follow along).



## MMU 101

Although this post won't be only about the MMU (there's a book for that [#3](#links)), some background is required for understanding why there is a need for the so-called Self-Reference PML4 entry. The root question for that is a simple (but not trivial) one: how does the processor read/write a block of physical memory, **only** by knowing the virtual address, or in layman's term, how to go from Virtual Address to Physical Address?


### Segmentation

On Intel and AMD processors, a virtual address is a combination of a _segment number_ **and** _a linear address_, or `segment_number:linear_address` and even on 64b architecture segmentation is still necessary. So in long mode, a code virtual address is never just `0xLinearAddress` but always `cs:0xLinearAddress`, data is `ds:0xLinearAddress`, stack is `ss:0xLinearAddress`, and so on, where `cs`, `ds`, `ss` register holds a WORD value corresponding to an index (with the 2 least significant bit OR-ed, designating the CPL) . The segment number will be added to the value of the register `gdtr` and will get the segment descriptor:

```txt
kd> r cs, rip, gdtr
cs=0010 rip=fffff80041e811e0, gdtr=fffff80044b5dfb0
kd> dd @gdtr + @cs l2
fffff800`44b5dfc0  00000000 00209b00
kd> .formats 00209b00
[...]
Binary:  [..] 00000000 00100000 10011011 00000000
```

Which we can parse combined with the format given by the AMD manual:

{{ img(src="https://i.ibb.co/NNgJdgz/image.png" title="image_alt") }}
(Src: AMD Programmer's Manual Volume 2)

```txt
0x00209b00   = 0000 0000 ‭ 0010 0000 1001 1011 0000 0000‬
               [BaseL  ]  gdLa      P| 1 1CRA [BaseM  ]
                                     |
                                     ↳ DPL=0

0x00000000   = 0000 0000  0000 0000  0000 0000  0000 0000
               [ BaseAddress 15:0 ]  [  Seg Limit 15:0  ]
```

The current CPL being given by the 2 lowest bytes of CS, it is now easy to understand how the CPU performs privilege check: by simply comparing the CPL from CS register and DPL from the segment descriptor, or if you prefer a visual diagram from the AMD manual:

{{ img(src="https://i.ibb.co/kDFzxB8/image.png" title="image_alt") }}
(Src: AMD Programmer's Manual Volume 2)

As we saw earlier, the `Address` and `Limit` parts of the descriptor are equal to 0 in Long-Mode (64-bit) - this may be the source of confusion I read in some blog posts (but no name shaming, it's not the point 😋).

Also if you're lazy (like me) and addicted to WinDbg (like me), the `dg` command will pretty-print all those info for you:
```txt
kd> dg @cs
                                                    P Si Gr Pr Lo
Sel        Base              Limit          Type    l ze an es ng Flags
0010 00000000`00000000 00000000`00000000 Code RE Ac 0 Nb By P  Lo 0000029b

kd> dg @ds
                                                    P Si Gr Pr Lo
Sel        Base              Limit          Type    l ze an es ng Flags
002B 00000000`00000000 00000000`ffffffff Data RW Ac 3 Bg Pg P  Nl 00000cf3
```

There is plenty more to say about the segmentation mechanism on x86, but for our purpose (reminder: _how does the CPU goes from VA to PA?_), we'll stick to those basic highlights.


### Paging

Preparing this post, I came across [this blog post](https://connormcgarr.github.io/paging/) that [@33y0re](https://twitter.com/33y0re) wrote recently, and where he did a really good job summarizing how paging works on x86-64 long-mode, and how to explore it on Windows. Therefore I will send you reader to his article, and assume from then on you know of PML4, PDPT, PD, PT and what a canonical linear address is.

The best summary can be given by this diagram (again from AMD's manual)

{{ img(src="https://i.ibb.co/k5TDWgw/image.png" title="image_alt") }}
_Source: AMD Programmer's Manual Volume 2_



## What & why the hell is "Self-Reference PML4 entry" ?

Back to the problem at hand, i.e. understand how does the CPU go from VA to PA, there is an intrinsic problem: the CPU only uses virtual address so how could the processor manipulates the permissions, flags, etc. of those PTEs which are physical? Simply by mapping the PTE tables in VAS, right? But that creates a recursive problem, because we still don't know how to go from VA to PA. And that's precisely where "Self-Reference PML4 entry" comes in. But let's go back a bit.

When a new process is created, a new PML4 is also allocated holding the physical root address for our process address space. From that physical root address and with all the offsets from the VA itself, the MMU can crawl down the physical page directories until getting the wanted data (see "Paging" above). This physical address is stored in the [`nt!_KPROCESS`](https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/2004%2020H1%20(May%202020%20Update)/_KPROCESS) structure of the process, precisely in `_KPROCESS.DirectoryTableBase`.

To experiment this behavior, we can create a simple program that will only `int3` so that KD gets the hand while still in user-mode:

```c
void main() {__asm__("int3;"); }
```

Compile and execute, and as expected KD notifies the breakpoint:

```txt
Break instruction exception - code 80000003 (first chance)
int3+0x6d08:
0033:00007ff7`83f26d08 cc              int     3
kd> dx @$curprocess.KernelObject.Pcb.DirectoryTableBase
@$curprocess.KernelObject.Pcb.DirectoryTableBase : 0x762ec002 [Type: unsigned __int64]
kd> dx @$curprocess.KernelObject.Pcb.DirectoryTableBase == @cr3
@$curprocess.KernelObject.Pcb.DirectoryTableBase == @cr3 : true
```

So when a process switch occurs, the kernel can move `nt!_EPROCESS.KernelObject.Pcb.DirectoryTableBase` into `cr3` (that `mov` operation forcing the TLB cache being flushed), given the newly running process the illusion of having a clean full virtual address space, and by the same way physically isolating processes.

But we slightly digressed, back to the topic: in order to map in the VAS our PML4 which is in physical address space, the kernel needs a way to always know at least one entry of the PML4: this is the <u>"Self-Reference Entry"</u>. Also seen to be called "auto-entry", the *Self-Reference Entry* (or "self-ref entry" for short) is a special PML4 index (so then only 9-bit in size) that only the kernel knows (hence between 0x100-0x1ff), and whose content points the physical address of the PML4 itself. By doing so, Windows kernel gives itself an easy way to reach by a virtual address, any directory (PML4, PDPT, PDE, etc.).

On Windows 7, the self-ref entry index is a static value (0x1ed) whereas Windows 10 randomizes it on boot. So to understand why this Self-Reference Entry is helpful, let's process a virtual address like the MMU would: the PML4 index corresponds to the 39:47 bits of a VA, so the value 0x1ed (or 0b111101101) would be as follow:

```txt
Bi| 6   ...  4444 4444 3333  ...
t#| 3   ...  7654 3210 9876  ...
Va|          1111 0110 1xxx     <<-- 0x1ed
lu|
```

So for all Windows from 7 to 10 TH2, the PML4 table of **all processes** was always mapped **at the same range** 0xFFFFF680\`00000000 → 0xFFFFF6FF\`FFFFFFFF. The randomization was added by Windows 10 RS1.

So let's translate a special VA 0xFFFFF6FB\`7DBED000‬ to a physical address (PA): by decomposing its indexes we get:

```txt
 *   pml4e_offset     : 0x1ed
 *   pdpe_offset      : 0x1ed
 *   pde_offset       : 0x1ed
 *   pte_offset       : 0x1ed
 *   offset           : 0x000
```

<div markdown="span" class="alert-info"><i class="fa fa-info-circle">&nbsp;Note:</i> the output is from my [`PageExplorer.js`](https://github.com/hugsy/windbg_js_scripts/blob/master/scripts/PageExplorer.js) WinDbg script.</div>

The PML4E of the current process can be reached at `CR3 + 0x1ed*@$ptrsize`: but the content is the base physical address of the PML4 itself again! So the PDPE will itself also translate to the PML4 and so on until we read the `PTE+offset` which again will return the base address of the PML4 (because `offset=0`)! So what we get is an easy way to read the content of not just the PML4 itself, but any page directory, and all simply by knowing that 9-bit value (and therefore, calculating the corresponding PXE)! So you can artificially create VA simply by their offset, for instance to read the PageTable instead?

```txt
 *   pml4e_offset     : 0x1ed
 *   pdpe_offset      : 0x000
 *   pde_offset       : 0x000
 *   pte_offset       : 0x000
 *   offset           : 0x000
```

And build the address as
```txt
0xffff<<48 | $pml4e_offset<<39 | $pdpe_offset<<30 | $pde_offset<<21 | $pte_offset<<12 | $offset
 => 0xffff<<48 | 0x1ed<<39 | 0<<30 | 0<<21 | 0<<12 | 0
```

And you get the value: 0xFFFFF680\`00000000.

That's why older versions of Windows (which did not randomized the Self-Reference entry and had it hardcoded at 0x1ed) offered a great avenue for defeating KASLR even remotely because you knew for sure always where the PageTable was, and there was a way to browse all pages of a process without ever faulting. And even on modern recent Windows 10, it still means with an arbitrary write you can defeat KASLR and SMEP/SMAP together.

To summarize (or if you just jumped to the end of this section), what's awesome about the *Self-Reference PML4 Entry* is that knowing only 9 bits (for example 0x1ed) we can **easily dump physical memory**!


## What about Windows 10 RS1+?

Up until Windows 10 TH2, the magic index for the Self-Reference PML4 entry was 0x1ed as mentioned above. But what about Windows 10 from 1607? Well Microsoft uped their game, as a [constant battle for improving Windows security](https://www.blackhat.com/docs/us-16/materials/us-16-Weston-Windows-10-Mitigation-Improvements.pdf) the index is randomized at boot-time, so 0x1ed is now one of the 512 possible values (i.e. 9-bit index) that the Self-Reference entry index can have. And side effect, it also broke some of their own tools, like the `!pte2va` WinDbg command.

On Windows 2004 x64, 0xFFFFF680`00000000 points to nothing (at least most of the times 🤓)
```txt
kd> db 0xFFFFF680`00000000 l20
fffff680`00000000  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
fffff680`00000010  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
```

But is it really 512 values for the entry? Well no, because the most significant bit must be set to 1 for the Sign-Extension to properly make it a kernel canonical address. So it is more 256 values (from 0x100 to 0x1ff). If we're in KD, this index can be retrieved by a new global symbol `nt!MmPteBase`, and so the self-reference entry can be known as:

```txt
kd> dq nt!MmPteBase l1
fffff804`29e29388  fffff880`00000000
kd> ? (poi(nt!MmPteBase) >> 0n39) & 0x1ff
Evaluate expression: 497 = 00000000`000001f1
```

In our current KD session on a Windows 2004 (on Hyper-V), the self-reference entry has the index of 0x1f1. So now we have the PML4 index, we can craft the virtual address to get its physical address:

 - calculate the PTE VA
```txt
kd> ? 0xffff<<0n48 | 0x1f1<<0n39 | 0x1f1<<0n30 | 0x1f1<<0n21 | 0x1f1<<0n12 | 000
Evaluate expression: -7711643201536 = fffff8fc`7e3f1000
```

 - get the entry info
```txt
kd> !pte 0xfffff8fc7e3f1000
@$pte(0xfffff8fc7e3f1000)                 : VA=0xfffff8fc7e3f1000, PA=0x4c7d1000, Offset=0x0
    va               : -7711643201536
    cr3              : 0x4c7d1000
    pml4e_offset     : 0x1f1
    pdpe_offset      : 0x1f1
    pde_offset       : 0x1f1
    pte_offset       : 0x1f1
    offset           : 0x0
    pml4e            : PDE(PA=4c7d1000, PFN=4c7d1, Flags=PRwK--AD-eX)
    pdpe             : PDE(PA=4c7d1000, PFN=4c7d1, Flags=PRwK--AD-eX)
    pde              : PDE(PA=4c7d1000, PFN=4c7d1, Flags=PRwK--AD-eX)
    pte              : PTE(PA=4c7d1000, PFN=4c7d1, Flags=PRwK--AD-eX)
    pa               : 0x4c7d1000
    kernel_pxe       : 0xfffff8fc7e3f1f88
```

As we see, for each entry (PML4E, PDPTE, etc.) the base address found is always the same **and** matches the content of `CR3`.
We can also easily prove this is the self-reference entry index: as stated above, the entry index (in our example 0x1f1) has to be the same for all processes, meaning that if we break into another process context, the kernel PXE will be the same. Let's try with our `int3.exe` again:

```txt
Break instruction exception - code 80000003 (first chance)
0033:00007ff6`2ac36d08 cc              int     3
kd> !pte 0xfffff8fc7e3f1000
@$pte(0xfffff8fc7e3f1000)                 : VA=0xfffff8fc7e3f1000, PA=0x1b1f7000, Offset=0x0
    va               : -7711643201536
    cr3              : 0x1b1f7000
    pml4e_offset     : 0x1f1
    pdpe_offset      : 0x1f1
    pde_offset       : 0x1f1
    pte_offset       : 0x1f1
    offset           : 0x0
    pml4e            : PDE(PA=1b1f7000, PFN=1b1f7, Flags=PRwK--AD-eX)
    pdpe             : PDE(PA=1b1f7000, PFN=1b1f7, Flags=PRwK--AD-eX)
    pde              : PDE(PA=1b1f7000, PFN=1b1f7, Flags=PRwK--AD-eX)
    pte              : PTE(PA=1b1f7000, PFN=1b1f7, Flags=PRwK--AD-eX)
    pa               : 0x1b1f7000
    kernel_pxe       : 0xfffff8fc7e3f1f88
```

And to confirm the VA points to the correct PA:
```txt
kd> db 0xfffff8fc7e3f1000
fffff8fc`7e3f1000  67 28 16 62 00 00 00 8a-67 58 c8 11 00 00 00 8a  g(.b....gX......
fffff8fc`7e3f1010  00 00 00 00 00 00 00 00-67 f8 40 77 00 00 00 8a  ........g.@w....

kd> !db 0x1b1f7000 l20
#1b1f7000 67 28 16 62 00 00 00 8a-67 58 c8 11 00 00 00 8a g(.b....gX......
#1b1f7010 00 00 00 00 00 00 00 00-67 f8 40 77 00 00 00 8a ........g.@w....
```

Same data, the VA to PA conversion was successful, and the recursive page entries always point to the same PML4 table, at the physical address 0x1b1f7000. It all goes full circle, pretty nice.

Last, one can ask: is there any kind of randomization of the allocation of the physical pages themselves? Legit question, and I experimented using some LINQ querying:

```txt
kd> dx -g @$cursession.Processes.Select( p => new { ProcessName = p.Name, Pml4Base = p.KernelObject.Pcb.DirectoryTableBase & 0xfffffffffff000})
```

Across several reboots in my VM labs, only 2 matches are shown consistently

 * Windows 2004 x64 Generation 1 (i.e. BIOS)

| PID | Process Name | Pml4Base |
|:--:|:--:|:--:|
| 0x0 | Idle | 0x1aa000 |
| 0x4 | System | 0x1aa000 |

 * Windows 2004 x64 Generation 2 (i.e. UEFI)

| PID | Process Name | Pml4Base |
|:--:|:--:|:--:|
| 0x0 | Idle | 0x6d4000 |
| 0x4 | System | 0x6d4000 |


0x1aa000 for the physical address of a Gen1 (BIOS) Hyper-V VM, and 0x6d4000 for a Gen2 (UEFI). This seems to partially coincide with what was said in Ricerca's article (see [#1](#links)) about the fact that the PML4 for System is at unrandomized physical address in most cases. From my limited testing the following physical addresses were found consistently (for Windows 2004 x64 with Kd):


|      Platform       | PML4 Base |
| :-----------------: | :-------: |
|    Native (UEFI)    | 0x1ba000  |
| Hyper-V Gen1 (BIOS) | 0x1aa000  |
| Hyper-V Gen2 (UEFI) | 0x6d4000  |
|  VirtualBox (BIOS)  | 0x1aa000  |
|  VirtualBox (UEFI)  | 0x1ad000  |



<div markdown="span" class="alert-info"><i class="fa fa-info-circle">&nbsp;Note:</i> if you have other values on your environment (Qemu, VMware), feel free to contact me and I'll update the table with the result of the KD command</div>

```txt
dx @$cursession.Processes.Where( p => p.Name == "System").First().KernelObject.Pcb.DirectoryTableBase & ~0xfff
```


And this is really the subtlety of Ricerca's exploit: they showed that only with a fixed physical address (associated to the SYSTEM process), and a fixed virtual area (the `nt!_KUSER_SHARED_DATA` section at 0xfffff780\`00000000) that is always at a known location since NT4, one can create an MDL used in Direct Memory Access, and achieve arbitrary read to virtual addresses simply by recursing through the PML4E, the PDPTE, etc. just like the MMU does. Since they could read the PML4 entirely at a fixed physical address, say 0x1aa000, they could determine the index of the "Self-Reference Entry" from a simple for-loop going through the PML4 page (very approximate pseudo-code):

```python
system_pml4_root = 0x1aa000
size_of_page = 0x1000
size_of_entry = 8

# loop in the PML4
for index in range(system_pml4_root, system_pml4_root+size_of_page, size_of_entry):
  # get the entry
  entry = u64( read_physical_memory(index) )
  # compare to the root (after trimming the 12 lsb)
  if (entry >> 12) == (system_pml4_root >> 12):
    print("self-reference entry is at index: %d" % index)
```

I hope not to make it sound simple, it is not and took me quite some time to figure out, so massive props to [`@hugeh0ge`](https://twitter.com/hugeh0ge) and [`@_N4NU_`](https://twitter.com/_N4NU_) for the technique, and [`@chompie1337`](https://web.archive.org/web/20220619035731/twitter.com/chompie1337) for the implementation. This technique provides a somewhat reliable way to defeat KASLR, SMEP & SMAP with no other vulnerability, but by mere knowledge of Intel processors and Windows memory management inner workings, for the vulnerability CVE-2020-0796, which, due to Microsoft's effort, made it tough.

Thanks for reading...✌

_Update_: A `@$selfref()` function was added to `PageExplorer.js`, allowing to easily retrieve the PML4 self-reference (tested 8 -> 11)

```txt
0: kd> dx @$selfref()
@$selfref()      : 0x1ec
0: kd> dx @$ptview().pml4_table[ @$selfref() ].PhysicalPageAddress ==  @$ptview().pml4_table[ @$selfref() ].Children[ @$selfref() ].PhysicalPageAddress
@$ptview().pml4_table[ @$selfref() ].PhysicalPageAddress ==  @$ptview().pml4_table[ @$selfref() ].Children[ @$selfref() ].PhysicalPageAddress : true
0: kd> dx @$ptview().pml4_table[ @$selfref() ]
@$ptview().pml4_table[ @$selfref() ]                 : PML4 Entry(PA=7d5000, Flags=[P RW K - - A D - -])
    address          : 0x7d5f60
    value            : 0x80000000007d5063
    Flags            : Flags=[P RW K - - A D - -]
    PageFrameNumber  : 0x7d5
    Pfn              [Type: _MMPFN]
    PhysicalPageAddress : 0x7d5000
    Pte              : 0xfffff67b3d9ecf60 [Type: _MMPTE *]
    Level            : PML4
    Children
```


# Links

What started picking my curiosity:

  - [1] [Ricerca Security on exploiting the same bug](https://ricercasecurity.blogspot.com/2020/04/ill-ask-your-body-smbghost-pre-auth-rce.html)
  - [2] [Chompie1337's CVE-2020-0796 exploit](https://github.com/chompie1337/SMBGhost_RCE_PoC/blob/master/exploit.py)


The whole series of " Getting Physical: Extreme abuse of Intel based Paging Systems" by N. Economou & E. Nissim (CoreSecurity) is a must read/watch:

  - CoreSecurity Getting Physical: [The talk (es)](https://www.youtube.com/watch?v=QGf0-jHFulg&vl=en) // [The slides](http://docplayer.net/44469150-Windows-smep-bypass-u-s-nicolas-a-economou-enrique-e-nissim-p-a-g-e.html)
  - [Part 2 - Windows](https://www.coresecurity.com/core-labs/articles/getting-physical-extreme-abuse-of-intel-based-paging-systems-part-2-windows)
  - [Part 3 - Windows HAL's Heap](https://www.coresecurity.com/core-labs/articles/getting-physical-extreme-abuse-of-intel-based-paging-systems)


Other useful resources:

  - [3] ["What Makes It Page? The Windows 7 x64 Virtual Memory Manager" - M. Martignetti](https://www.amazon.com/What-Makes-Page-Windows-Virtual/dp/1479114294)
  - ["Gynvael's Hacking Livestream #30: Windows Kernel Debugging Part III" - A. "honorary_bot" Shishkin](https://www.youtube.com/watch?v=7zTtVYjjquA)
  - ["Windows 8 Kernel Memory Protections Bypass" - J. Fetiveau](https://labs.f-secure.com/archive/windows-8-kernel-memory-protections-bypass/)

*[CPL]: Current Privilege Level
*[DPL]: Descriptor Privilege Level
*[MDL]: Memory Descriptor List
*[MMU]: Memory Management Unit
*[PA]: Physical Address
*[PAS]: Physical Address Space
*[PD]: Page Descriptor
*[PDE]: Page Descriptor Entry
*[PDPT]: Page Directory Pointer Table
*[PDPTE]: Page Directory Pointer Table Entry
*[PML4]: Page Map Level 4
*[PML4E]: Page Map Level 4 Entry
*[PT]: Page Table
*[PTE]: Page Table Entry
*[VA]: Virtual Address
*[VAS]: Virtual Address Space
