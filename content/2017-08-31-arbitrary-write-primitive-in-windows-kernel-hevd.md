date: 2017-08-31 00:00:00
modified: 2017-08-31 00:00:00
title: Arbitrary Write primitive in Windows kernel (HEVD)
author: hugsy
category: tutorial
cover: assets/images/win-kernel-debug/hevd-www-hal-interrupt.png
tags: pwn,windows,hevd,kernel,exploit,write-what-where

Back again to modern Windows kernel exploitation!

After understanding [how to build shellcodes for Windows 64-bit](/posts/2017/08/14/a-primer-to-windows-x64-shellcoding) and applying this knowledge on [a trivial kernel stack overflow vulnerability](/posts/2017/08/18/first-exploit-in-windows-kernel-hevd) we
are ready to start moving towards more real-life types of vulnerabilities, such
as Type Confusion or Kernel Pool exploit, but for now we'll cover the case of
*Arbitrary Write*  (aka *Write-What-Where*) vulnerabilities.

We'll use the same configuration than the one used before (target is up-to-date
Windows 8.1 x64 VM with HEVD v.1.20 driver installed). For more info about the
setup, refer to the first post of this Windows Kernel exploitation series.

# Recon

## IDA to the rescue

After not that much effort in IDA by tracing down the IOCTL dispatching function
callgraph, we spot the function `TriggerArbitraryOverwrite()` which can be
reached via a IOCTL with a code of 0x22200B. The vulnerability is easy to spot:

![image_alt](/assets/images/win-kernel-debug/hevd-www-ida-vuln-spotting.png)

After checking the address we passed and printing some kernel debug messages,
the function copies the value dereferenced from `rbx` (which is the function
parameter which we control) into the 32-bit register `r11d`. This value is then
written at the address pointed by `rdi`.

Or better summarized in assembly - `rcx` holds the function first argument
(see [[2](#related-links)] for a good reminder about calling conventions):

```text
0000000000015B89 mov     r12, rcx
[...]
0000000000015B95 call    cs:__imp_ProbeForRead
0000000000015B9B mov     rbx, [r12]
0000000000015B9F mov     rdi, [r12+8]
[...]
0000000000015BEC mov     r11d, [rbx]
0000000000015BEF mov     [rdi], r11d
```

So as we can observe at 0x15BEF, we do have an  arbitrary write, but a partial one as we only
can write one DWORD at a time. No big deal, since we fully control the
destination location, we can write a QWORD by simply performing 2 writes at `ADDR_DEST` then
`ADDR_DEST+4`.

This is pretty much it for the vulnerability: classic case of an **Arbitrary
Write** (aka **Write-What-Where**). Although we are in kernel-land, we'll see that the
exploitation approach stays the same as when such situation occurs in user-land.


## Write what ?

So what can we do with an Arbitrary Write?

Well, just like in usermode, one of the most common approach is to transform
this situation into a code execution, which can be done by overwriting a
writable location in the kernel, which we'll then force a call to.
By overwriting a function pointer with the location of our
shellcode placed in userland, and then triggering this call from userland would
be enough to reach our goal (and of course, assuming SMEP is off).

But in kernel-land, this is not the only approach. Another one would be to
overwrite the current process' token by overwriting directly the
`_SEP_TOKEN_PRIVILEGES` and for example, provide it with the `SeDebugPrivilege` allowing it
to perform any further privileged operation on the system (naturally it is
assumed here that we know the current process structure's address - through an
infoleak or else). Back in 2012, {%include icon-twitter.html
username="@cesarcer"%} covered this very situation in his Black Hat
presentation
[Easy Local Windows Kernel Exploitation](https://media.blackhat.com/bh-us-12/Briefings/Cerrudo/BH_US_12_Cerrudo_Windows_Kernel_WP.pdf).

Although this second way would allow to work around SMEP, for the sake of
this post we'll go with the first approach as it is the most commonly used.


## Write where ?

The kernel has plenty of function pointer arrays that we could
use for our purpose. One of the first we could think of would be the system calls table. The
_System Service Descriptor Table_ (SSDT) is usually known for being hooked, as
this table contains the service tables in use when processing system calls. In
KD, we can reach it at with the following symbol: `nt!KeServiceDescriptorTable`


```text
kd> dps nt!KeServiceDescriptorTable
fffff802`f8b57a80  fffff802`f895ad00 nt!KiServiceTable
fffff802`f8b57a88  00000000`00000000
fffff802`f8b57a90  00000000`000001b1
fffff802`f8b57a98  fffff802`f895ba8c nt!KiArgumentTable
fffff802`f8b57aa0  00000000`00000000
fffff802`f8b57aa8  00000000`00000000
fffff802`f8b57ab0  00000000`00000000
fffff802`f8b57ab8  00000000`00000000
fffff802`f8b57ac0  fffff802`f895ad00 nt!KiServiceTable
[...]
```

I've actually decided to use another way described very well on [Xst3nZ](http://poppopret.blogspot.ca/2011/07/windows-kernel-exploitation-basics-part.html)'s blog, by overwriting the `HalDispatchTable`. The reason this table is particularly interesting, is that it can be fetched from userland by mapping `ntoskrnl.exe` and using `GetProcAddr("HalDispatch")` to know its offset. As a result, we'll have a much more portable exploit code (rather than hardcoding the offset by hand).

But why `HalDispatchTable` in particular? Because we can call from userland the undocumented
function [`NtQueryIntervalProfile`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/profile/queryinterval.htm), that will in turn invoke `nt!KeQueryIntervalProfile` in the kernel, which to
finally perform a `call` instruction to the address in `nt!HalDispatchTable[1]`:

```text
kd>  u nt!KeQueryIntervalProfile+0x9 l7
nt!KeQueryIntervalProfile+0x9:
fffff802`f8cbc23d ba18000000      mov     edx,18h
fffff802`f8cbc242 894c2420        mov     dword ptr [rsp+20h],ecx
fffff802`f8cbc246 4c8d4c2450      lea     r9,[rsp+50h]
fffff802`f8cbc24b 8d4ae9          lea     ecx,[rdx-17h]
fffff802`f8cbc24e 4c8d442420      lea     r8,[rsp+20h]
fffff802`f8cbc253 ff15af83deff    call    qword ptr [nt!HalDispatchTable+0x8 (fffff802`f8aa4608)]  <-- this is interesting!
fffff802`f8cbc259 85c0            test    eax,eax
fffff802`f8cbc25b 7818            js      nt!KeQueryIntervalProfile+0x41 (fffff802`f8cbc275)
```

So if we use the WWW vulnerability to overwrite `nt!HalDispatchTable[1]` with
the address of our shellcode mapped in a RWX location in userland, then
use the undocumented `NtQueryIntervalProfile` to trigger it, we will make the
kernel execute our shellcode! And game over :)

For those unfamiliar with the [Hardware Abstraction Layer (or HAL)](wiki.osdev.org/Hardware_Abstraction_Layer),
it is a software layer aiming to provide a common unified interface to heterogeneous hardware (motherboard, CPUs, network cards, etc.). On Windows, it resides in [`hal.dll`](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/windows-kernel-mode-hal-library) that is invoked by `ntoskrnl.exe`:

```bash
~/tmp/win81/mnt/Windows/System32/ [hugsy@ph0ny]  [02:43]
➜  py list_imports.py ./ntoskrnl.exe
Listing IMPORT table for './ntoskrnl.exe'
[...]
[+] HAL.dll
        0x140349070 : HalGetVectorInput
        0x140349078 : HalSetEnvironmentVariable
        0x140349080 : HalGetEnvironmentVariable
        0x140349088 : HalInitializeOnResume
        0x140349090 : HalAllocateCrashDumpRegisters
        0x140349098 : HalGetMemoryCachingRequirements
        0x1403490a0 : HalProcessorIdle
        0x1403490a8 : HalGetInterruptTargetInformation
        0x1403490b0 : KeFlushWriteBuffer
[...]
```

Speaking of the HAL, `hal.dll` has some very interesting properties
exploitation-wise. Among others, my first attempt was to overwrite the
pointers table located at `0xFFD00000` (on x86 and x64). Actually the range
`0xFFD00000-0xFFE00000` is interesting because since the HAL driver is loaded so early (actually
even before the Windows memory manager) during the boot process, it'll require
known static addresses to map and store information collected about the hardware
in memory. Researchers such as
{%include icon-twitter.html username="@d_olex"%} have explored this path as early as 2011 to use it as an exploit vector as Win7
SP1 used to have this section static and with Read/Write/Execute permission
(although it exists on Windows 8 and up, it is "only" Read/Write)

![Windows 8.1 HAL section](/assets/images/win-kernel-debug/hevd-www-hal-interrupt.png)

__Note__: Looking for references about HAL interrupt table corruption, I came across this recent and fantastic
[blog post](https://labs.bluefrostsecurity.de/blog/2017/05/11/windows-10-hals-heap-extinction-of-the-halpinterruptcontroller-table-exploitation-technique/) by {%include icon-twitter.html username="@NicoEconomou"%} that covers exactly this approach. I might dedicate a future post applying this technique to HEVD as this table is also an excellent target for WWW scenario.


# Building the exploit

__Note__: Some convenience functions of this exploit are located in
the [`KePwnLib.h`](https://github.com/hugsy/hevd/blob/master/KePwnLib.h) library I wrote. Feel free to use it!

The very first part of the exploit is very similar to what we did in the former post, with the new IOCTL code:

```c
// Get the device handle
#define IOCTL_HEVD_ARBITRARY_OVERWRITE 0x22200b

HANDLE hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", ...);

// Also prepare our shellcode in userland
ULONG_PTR lpShellcode = AllocatePageWithShellcode();
```

And when sending the IOCTL, pass in a buffer of 2 ULONG_PTR (index 0 is the
*What*, 1 is the *Where*).

```c
// Overwrite the 1st DWORD pointed by WHERE
ULONG_PTR lpBufferIn[2] = {WHAT, WHERE};
DeviceIoControl(hDevice, IOCTL_HEVD_ARBITRARY_OVERWRITE, lpBufferIn, sizeof(lpBufferIn), ...);

// Overwrite the 2nd DWORD pointed by WHERE
lpBufferIn[2] = {WHAT+4, WHERE+4};
DeviceIoControl(hDevice, IOCTL_HEVD_ARBITRARY_OVERWRITE, lpBufferIn, sizeof(lpBufferIn), ...);
```

And if we test with dummy values:
![exploit-test](/assets/images/win-kernel-debug/hevd-www-testing-exploit.png)

The `WHAT` corresponds to our shellcode (`lpShellcode`), which we know. Now we need the
`WHERE` (i.e. `nt!HalDispatchTable[1]`)... which a kernel address! As we know, any
mapped address can be translated to `MmappedAddress = ImageBase + offset`.

## Get the Kernel Image Base Address from undocumented SystemInformationClass

By reading [Alex Ionescu - I got 99 problems but a kernel pointer ain't one (REcon 2013)](https://recon.cx/2013/slides/Recon2013-Alex%20Ionescu-I%20got%2099%20problems%20but%20a%20kernel%20pointer%20ain%27t%20one.pdf) I discovered that by passing a System Information Class of [`SystemModuleInformation` (0xb)](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/class.htm) to [`NtQuerySystemInformation`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms724509(v=vs.85).aspx), Windows will leak all kernel modules information (full path, image base address, etc.), including the kernel itself! So finding the image base of the kernel `ntoskrnl.exe` can be done as follow (in very approximate pseudo-code - just to give an idea):

```c
#define SystemModuleInformation  (SYSTEM_INFORMATION_CLASS)0xb

Modules = malloc(0x100000);
status = NtQuerySystemInformation(SystemModuleInformation, Modules, 0x100000, ...);
if (NT_SUCCESS(status)){
  for (int i=0; i<Modules->NumberOfModules; i++){
    if (strstr(Modules->Modules[i].FullPathName, "ntoskrnl.exe")!=0){
       info("Found Kernel as Module[%d] -> %s (%p)\n", i, Modules->Modules[i].FullPathName, Modules->Modules[i].ImageBase);
       KernelImageBaseAddress = Modules->Modules[i].ImageBase;
    }
  }
}
```

All structures used are very well defined and documented in the [`Process Hacker tool source code`](http://processhacker.sourceforge.net/doc/ntldr_8h_source.html#l00511). If you go with your implementation of the exploit, you might want to read that first.

Now we've got the `ImageBase` component.

## Get the offset from the kernel image

This step is actually much easier. All we need to do is to :

  1. load the kernel image `ntoskrnl.exe` and store its base adress
  1. retrieve the address of `HalDispatchTable`
  1. subtract the two pointers found above

Or again, in very pseudo-C:

```c
HMODULE hNtosMod = LoadLibrary("ntoskrnl.exe");
ULONG lNtHalDispatchTableOffset = (ULONG)GetProcAddress(hNtosMod, "HalDispatchTable") - (ULONG)hNtosMod;
```

And yeah, that's all! Now that we've also got the offset, we know that
`HalDispatchTableInKernel = KernelImageBaseAddress + lNtHalDispatchTableOffset`,
which is the `WHERE` condition we needed above! Therefore, we have everything to
overwrite `nt!HalDispatchTable[1]`.


## Triggering the corrupted HAL entry

Now that we've successfully overwritten the `HalDispatchTable`, we need a way
to force a call to the corrupted pointer in `nt!HalDispatchTable[1]`.
As aforementioned, that can be done with the undocumented
`nt!NtQueryIntervalProfile`. So the last piece of our exploit can be written
as simply as

```c
NtQueryIntervalProfile = GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")));
ULONG dummy1=1, dummy2;
NtQueryIntervalProfile(dummy1, &dummy2);
```


## Assembling all the pieces

The clean final exploit can be found {%include link.html href="https://github.com/hugsy/hevd/blob/master/ArbitraryOverwrite/exploit.c" title="here"%}

![image_alt](/assets/images/win-kernel-debug/hevd-www-final-exploit.png)

You can now enjoy the privileged shell so well deserved!


## About PatchGuard

Windows XP/2003 and up use
[Kernel Patch Protection (aka PatchGuard)](https://en.wikipedia.org/wiki/Kernel_Patch_Protection) to
protect sensitive locations, including the SSDT and HAL (among other). Since this
technique will modify the HAL table, PG will detect it and force a

Although PG bypass is not the subject of this post, it should be noted that
[several](http://uninformed.org/index.cgi?v=3&a=3&p=7) [public](http://uninformed.org/index.cgi?v=6&a=1&p=25) [papers](http://fyyre.ru/vault/bootloader_v2.txt) and
[tools](https://github.com/hfiref0x/UPGDSED) cover ways to bypass it.


# Conclusion

In this chapter we've covered how to exploit Arbitrary Write conditions in the
kernel to achieve code execution, by leveraging undocumented procedures and
functions that leak valuable kernel information straight from userland. Many
more leaks exist, and I definitely recommend watching {%include
icon-twitter.html username="@aionescu"%}'s
REcon 2013 talk [I got 99 problems but a kernel pointer ain't one](https://www.youtube.com/watch?v=5HbmpPBKVFg).

See you next time ✌


## Related links

  1. [Abusing GDI for Ring0 exploit primitives](https://www.coresecurity.com/blog/abusing-gdi-for-ring0-exploit-primitives):
    Another interesting way to exploit WWW conditions by Diego Juarez through GDI
  1. [Calling conventions for different C++ compilers and operating systems](http://www.agner.org/optimize/calling_conventions.pdf)
  1. [An excellent reference of Windows internal structures by Geoff Chappell](https://www.geoffchappell.com/studies/windows/km)
  1. [Uninformed - PatchGuard & SSDT](http://uninformed.org/index.cgi?v=3&a=3&p=9)
  1. [Bypassing Windows 7 Kernel ASLR](https://dl.packetstormsecurity.net/papers/bypass/NES-BypassWin7KernelAslr.pdf)
