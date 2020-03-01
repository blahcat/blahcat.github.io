---
layout: post
title: Small dumps in the big pool
subheading: Or, on how to use the (Windows 10) new field `_ETHREAD.ThreadName` to stabilize kernel RW primitives
author: hugsy
header-img: img/f4300721f56d68c92db76aa03c3bbd54.png
tags: [windows, kernel]
---




## SetThreadDescription() as a way to allocate controlled kernel pools

Keeping on with experimenting with Windows 10 I noticed a field part of the `nt!_ETHREAD` structure, called `ThreadName`.
For a minute, the field name misled me to think threads were now
[Named Objects](https://docs.microsoft.com/en-us/windows/desktop/sync/object-names) on Windows. What it is instead, is a
convenient and native way to name a thread, any thread by attaching a `UNICODE_STRING` structure to it. Thanks to
{% include icon-twitter.html username="@PetrBenes" %}'s invaluable [`ntdiff`](https://ntdiff.github.io/) it became clear
that this field was introduced with Windows 10, more specifically 1607.

![ntdiff](/img/small-pool/ntdiff.png)

[Source](https://ntdiff.github.io/#versionLeft=Win8.1_U1%2Fx64%2FSystem32&filenameLeft=ntoskrnl.exe&typeLeft=Standalone%2F_ETHREAD&versionRight=Win10_1607_RS1%2Fx64%2FSystem32&filenameRight=ntoskrnl.exe&typeRight=Standalone%2F_ETHREAD)

So how to use it? Is it even reachable? The answer was as immediate as [Googling "windows set thread name"](http://lmgtfy.com/?q=windows+10+set+thread+name) which
leads to an [MSDN article](https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-set-a-thread-name-in-native-code?view=vs-2017). This
article mentions the [`SetThreadDescription()`](https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-setthreaddescription) in `processthreadsapi.h`. Disassembling `kernelbase.dll` shows that this function is merely a wrapper around the syscall `NtSetInformationThread()` with a
`ThreadInformationClass` set to 0x26 (`ThreadNameInformation`).

![ida-setthreaddescription](/img/small-pool/ida-setthreaddescription.png)

Once in `ntoskrnl` (IDA), the syscall performs various checks (is the `_ETHREAD.ThreadName` already allocated, is the input size and buffer correct etc.),
and then call `ExAllocatePoolWithTag()` with a tag of `ThNm` and as `NonPagedPoolNx`, and the size provided by the `UNICODE_STRING` structure, plus `sizeof(UNICODE_STRING)`.
Finally, the user buffer will be `memmove`-ed into this new pool.

![ntsetinformationthread-1](/img/small-pool/ntsetinformationthread-1.png)

Since the unicode buffer and its size are fully user controlled, this means that the syscall `NtSetInformationThread(0x26)` provides a way to allocate an
arbitrary sized pool in the kernel, for each thread we create and/or can open a handle to via `OpenThread()`.

{% include note.html text="The code was tested on Windows 10 RS5 x64. To work on x32 one might need to adjust the offsets. Also Windows must be at least 1607." %}

The following code is enough to populate the `_ETHREAD.ThreadName` of a designed thread:

{% include gist.html id="8df0843e8556f557308cd014fec0fda3" name="SimpleSetThreadName.c" %}

The accute observer may notice that only `THREAD_SET_LIMITED_INFORMATION` class information is used. Therefore setting thread name with `ThreadNameInformation` is an operation that is not considered privileged and should work very reliably, just like `THREAD_QUERY_LIMITED_INFORMATION` to retrieve the thread name.

{% include image.html src="/img/small-pool/setthreadname-1.png" alt="setthreadname-1.png" %}


From WinDbg, the `!poolfind` command can be used to filter by tag name, in this case `ThNm` (0x6d4e6854), or query `!pool` with the
address from the field `_ETHREAD!ThreadName`. This confirms that we fully control the content and size of pools. To be in the large pool, the chunk must be of at least 0x1000 bytes, making the minimum actual pool data size of 0x1000-0x10 bytes (for the header). And for the maxiumum allocatable size, during this experiment it was shown possible to allocate thread name up to 0xfff0 bytes (65520):

```
C:\Users\IEUser\Desktop>pslist -nobanner -d notepad
Thread detail for MSEDGEWIN10:

notepad 6828:
 Tid Pri    Cswtch            State     User Time   Kernel Time   Elapsed Time
5488  10     28743     Wait:UserReq  0:00:00.093   0:00:00.609   85:44:03.789

C:\Users\IEUser\Desktop>AllocateLargePool.exe 5488 65520
tid=5488
data stored at FFFFDD07B6F8C010
```

{% include image.html src="/img/small-pool/setthreadname-2.png" alt="setthreadname-2.png" %}

Which makes sense, since larger size would overflow the `Length` field of the `UNICODE_STRING` (i.e. `sizeof(WORD)`), which is checked during the `NtSetInformationThread(ThreadNameInformation)` syscall.

We have a reliable way to write from userland a large pool chunk and predict accurately its location in the kernel. Additionally the allocation operation is done per-thread, meaning that for more space it is possible to create more threads (`CreateThread()` locally or `OpenProcess()` + `CreateRemoteThread()` remotely).

Ok cool, but so what?


## Leverage as exploit primitive

Although there's no vulnerability there, one could use this technique to dump some data in the kernel in a vulnerability exploitation
scenario such as an arbitrary write. One possible use case would be to store the addresses of a ROP sequence to disable SMEP.
However, to achieve this
the attacker must know the address where this pool in the kernel. Luckily we found the answer in the kernel "Large Pool" allocator.
[Former analysis on the big pool allocator](http://www.alex-ionescu.com/?p=231) have shown some interesting properties, but what
makes it perfect is the
[`NtQuerySystemInformation()`](https://docs.microsoft.com/en-us/windows/desktop/api/winternl/nf-winternl-ntquerysysteminformation)
syscall with the undocumented
[`SystemBigPoolInformation`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool_entry.htm)(0x42)
as class information, which provides **exactly** what we were looking for: the enumeration of all large pools with their kernel
addresses, their size, and their tag.

This is enough to dump such information:

```c
#define SystemBigPoolInformation 0x42

[...]
DWORD dwBufSize = 1024*1024;
DWORD dwOutSize;
LPVOID pBuffer = LocalAlloc(LPTR, dwBufSize);
HRESULT hRes = NtQuerySystemInformation(
  SystemBigPoolInformation,
  pBuffer,
  dwBufSize,
  &dwOutSize
);
```

If large enough the buffer `pBuffer` will be populated by the kernel by `N` entries of `SYSTEM_BIGPOOL_ENTRY` structured as follow:
```
0x00 NumberOfEntries

Entry0
{
0x08 ULONG_PTR Entry0.Address
0x10 DWORD Entry0.PoolSize
0x18 DWORD Entry0.PoolTag
}

Entry1
{
0x20 Entry1.Address
[...]
```

Which becomes trivial to parse to get the thread kernel address, simply by looking up for the entry that would match the condition `strncmp( info->PoolTag, "ThNm", 4)==0`. In the case of multi-threaded process with many ThreadName entries, it is possible to refine the search by using the size as a secondary search index:

```c
typedef struct
{
  DWORD64 Address;
  DWORD64 PoolSize;
  char PoolTag[4];
  char Padding[4];
}
BIG_POOL_INFO, *PBIG_POOL_INFO;

ULONG_PTR LookForThreadNamePoolAddress(PVOID pSystemBigPoolInfoBuffer, DWORD64 dwExpectedSize)
{
  ULONG_PTR StartAddress = (ULONG_PTR)pSystemBigPoolInfoBuffer;
  ULONG_PTR EndAddress = StartAddress + 8 + *( (PDWORD)StartAddress ) * sizeof(BIG_POOL_INFO);
  ULONG_PTR ptr = StartAddress + 8;
  while (ptr < EndAddress)
  {
    PBIG_POOL_INFO info = (PBIG_POOL_INFO) ptr;
    //printf("Name:%s Size:%llx Address:%llx\n", info->PoolTag, info->PoolSize, info->Address);

    if( strncmp( info->PoolTag, "ThNm", 4)==0 && dwExpectedSize==info->PoolSize )
    {
      return (((ULONG_PTR)info->Address) & 0xfffffffffffffff0) + sizeof(UNICODE_STRING);
    }
    ptr += sizeof(BIG_POOL_INFO);
  }
  return 0;
}
```

That's pretty much it. [Put it all together](https://gist.github.com/hugsy/d89c6ee771a4decfdf4f088998d60d19) and you get:

```
z:\> AllocateLargePool.exe 26948 4096
[*] Target TID=26948
[+] Data from buffer 000001BCD71A0000 (16 bytes) written at FFFFD8001E966010
```

Some more advanced feng-shui can be achieved using `NtSetInformationThread(ThreadNameInformation)` which will be
covered in a later post. Although convienent and really stealth, this technique is not bullet-proof since the syscall (if successful) is logged and may be exposed with ETW (see `nt!EtwTraceThreadSetName`).

What about local DoS? Well yes, it is a pretty simple to destabilize the system by resource exhaustion by creating a loop of `CreateThread()` + `AllocateBigPool($newThread)`: since it is possible to make each thread of a process allocate a chunk of 0x10000 bytes, simple math will show that creating a somewhat acceptable number of threads, say 0x1000 will bring the total allocation to 0x10000000 bytes (268MB). Not only can the number of threads per process be increased, but the same process can be launched many times. As mentioned earlier, the `_ETHREAD!ThreadName` field is allocated as
[`NonPagedPoolNx`](https://docs.microsoft.com/en-us/windows/desktop/memory/memory-pools) so all those chunks will never be paged out or freed until the thread (or process) is finished/terminated. Although this DoS is pretty dummy and useless, the only annoying part is that it can be triggered by even low integrity/privilege processes. Running [it](https://gist.github.com/hugsy/a94392e6aeaf87335d06d06a0c05ff96) leads to an interesting scenario of memory pressure where the CPUs are not used but the system is unusable since pool allocation request will fail.

As a side note, on my test VM (Windows 10 RS5 with 2 vCpus and 2GB of RAM), I could force a process to spawn ~0xb900 threads before the system became unusable.

{% include image.html src="/img/small-pool/dos-1.png" alt="dos-1.png" %}

## Final words

This post has shown that the apparently innocent new field `_ETHREAD.ThreadName` that appeared in Windows 1607
can be subverted to do a lot more than intended. But that's definitely not all, some more esoteric (*cough* malware)
could use this for stealth data persistence, or even covert channel (writing a tiny chat application based on the code
above was fairly simple, and is left as an exercise to the reader).
The thread name pool stays reachable in memory either until the thread is terminated, or another call to
`NtSetInformationThread(ThreadNameInformation)` is done to this thread. This is convenient because some threads
should unlikely die during the time of a session making such nice syscall a good place for hiding *stuff*.

That's it for this little daily experiment.
Until next time, cheers ☕️


### Some links for further reading

 - [BlackHat DC 2011 - Mandt - Kernel Pool exploitation](https://media.blackhat.com/bh-dc-11/Mandt/BlackHat_DC_2011_Mandt_kernelpool-wp.pdf)
 - [Exploiting a Windows 10 PagedPool off-by-one](https://j00ru.vexillium.org/2018/07/exploiting-a-windows-10-pagedpool-off-by-one/)
 - [Sheep Year Kernel Heap Fengshui: Spraying in the Big Kids’ Pool](http://www.alex-ionescu.com/?p=231)
