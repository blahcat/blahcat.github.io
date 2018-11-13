---
layout: post
title: Some Time Travel musings
author: hugsy
author_twitter: _hugsy_
author_email: hugsy@[RemoveThisPart]blah.cat
author_github: hugsy
header-img: img/windbg-ttd/header.png
tags: [windows, time-travel-debugging, windbg, malware]
---

If WinDbg was already setting the standard of what modern debuggers should be like, no doubt [WinDbg Preview](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-using-windbg-preview) brings it to a next level. The JavaScript API is not perfect yet but already very efficient, so we don't have to rely on PyKd for proper (and portable) WinDbg scripting (I won't even mention WDS). As a start, I could not recommend enough reading {% include icon-twitter.html username="@0vercl0k" %}'s {% include link.html title="article on the Debugger Data Model" href="https://doar-e.github.io/blog/2017/12/01/debugger-data-model/" %} if you haven't already read it, which not only covers TTD but a lot more.


# Time-Travel Debugging

## Introduction

Since the feature got publicly available last year, there's not that many coverage, and I finally took some time to fiddle with it for various cases (from malware analysis to CTF) I figured I could contribute with a quick write-up.

As the name implies, Time-Travel Debugging is a tool that will allow to travel through the runtime of process that you create or attach to. It'll monitor everything then store it a separate indexed database file, that can be fed to WinDbg Preview. The debugger will then have a Read-Only access on the execution, allowing to jump back and forth to desired points of the runtime. That's already quite nice, but what makes it more powerful is the integration with the Data Model (via the `dx` command) and the JS API.


## Time Travel + Data Model

### TTD 101: Moving around

I was curious to see what could be done so I decided to record via WinDbg a simple Notepad session. TTD is as simple as it gets: start WinDbg (as Admin), and launch the target executable after checking the `Record process with Time Travel Debugging`

![](/img/windbg-ttd/startrecord.png)

Typed some stuff and closed notepad. WinDbg starts by reading the trace and indexing the database, and breaks at the loader entry point. The indexes (look like `XX:YY` where `X` and `Y` are hex-digits) are like coordinates that can be used to travel around so we can move to an absolute position like

```
0:000> !tt 7213:36
Setting position: 7213:36
(12c4.1dcc): Break instruction exception - code 80000003 (first/second chance not available)
Time Travel Position: 7213:36
KERNELBASE!VirtualAlloc:
00007ffe`15c433a0 4053            push    rbx
```

It is also possible to simply step-over backwards (`p-`), step-into backwards (`t-`), or go backwards (`g-`) - one can notice that commands for backwards are the same as for forward, with a `-` suffixed to the command. All the other commands, like for breakpoints, or accessing memory/registers work just the same.

That's already quite fun, but WinDbg can go a lot further.


### Enter the Debugger Data Model...

WinDbg can use LINQ to query the TTD database, to synthetize a lot more of runtime information in a very painless way. To do so, a new attribute `TTD` was added to the runtime variables `$curprocess`

```
0:000> dx @$curprocess.TTD
@$curprocess.TTD
    Lifetime         : [2C:0, 2EB0F:0]
    Threads
    Events
```

and `$cursession`

```
0:000> dx @$cursession.TTD
@$cursession.TTD                 : [object Object]
    Calls            [Returns call information from the trace for the specified set of methods: TTD.Calls("module!method1", "module!method2", ...) For example: dx @$cursession.TTD.Calls("user32!SendMessageA")]
    Memory           [Returns memory access information for specified address range: TTD.Memory(startAddress, endAddress [, "rwec"])]
    DefaultParameterCount : 0x4
    AsyncQueryEnabled : false
    Resources
    Data             : Normalized data sources based on the contents of the time travel trace
    Utility          : Methods that can be useful when analyzing time travel traces
```

{% include note.html text="You might want to enable DML too (by running the command `.prefer_dml 1`) if you want to click your way through those methods." %}

Among some of the most interesting parts, we can now query function calls, like

```
0:000> dx @$cursession.TTD.Calls("ntdll!mem*").Count()
@$cursession.TTD.Calls("ntdll!mem*").Count() : 0x2ef8
```

Will count the number of calls to function matching `ntdll!mem*` pattern, or even filter function calls per parameter

```
0:000> dx @$cursession.TTD.Calls("Kernel*!VirtualAlloc*").Where( c => c.Parameters[3] == 0x40 ).Count()
$cursession.TTD.Calls("Kernel*!VirtualAlloc*").Where( c => c.Parameters[3] == 0x40).Count() : 0x1
```

Which will filter the calls to function matching `Kernel*!VirtualAlloc*` pattern, where the 4th parameter is `PAGE_EXECUTE_READWRITE` (0x40).


Another useful feature is the memory access, exposed by

```
0:000> dx $cursession.TTD
  [...]
  Memory       [Returns memory access information for specified address range: TTD.Memory(startAddress, endAddress [, "rwec"])]
```

To take the real life example of a self-decrypting packer, that would allocate some memory (likely in RWX), then decrypt the code and finally jump to it. If we were to reverse such packer, we don't care much about how the payload is decrypted (could be a simple XOR, could be AES, could be custom crypto, etc.), what we only care about is what the code looks like once decrypted. And that becomes stupidly easy with TTD + DDM:

```
// Isolate the address(es) newly allocated as RWX
0:000> dx @$cursession.TTD.Calls("Kernel*!VirtualAlloc*").Where( f => f.Parameters[3] == 0x40 ).Select( f => new {Address : f.ReturnValue } )

// Time-Travel to when the 1st byte is executed
0:000> dx @$cursession.TTD.Memory(0xAddressFromAbove, 0xAddressFromAbove+1, "e")[0].TimeStart.SeekTo()​
```

Done! Then you can `.writemem` that code into a file that IDA can disassemble.

And since all this goodness can be used from JavaScript (via the `host.namespace.Debugger` namespace), it's really not far to write scripts for automatically dump such payloads, track heap allocations, enumerate all files created etc. And it came to me a surprise (not really actually, {% include icon-twitter.html username="@0vercl0k" %} just told me), that when using the `ttd.exe` binary as a standalone, one can pass the `-children` flag allowing TTD to also record children processes.

<blockquote class="twitter-tweet" data-partner="tweetdeck"><p lang="en" dir="ltr">The Time-Travel Debugging tool from <a href="https://twitter.com/hashtag/WinDbg?src=hash&amp;ref_src=twsrc%5Etfw">#WinDbg</a> Preview can be used as a standalone binary (ttd.exe)<br><br>Copy the TTD\ directory and you can use TTD without <a href="https://twitter.com/hashtag/WinDbg?src=hash&amp;ref_src=twsrc%5Etfw">#WinDbg</a>, allowing you to script your <a href="https://twitter.com/hashtag/TTD?src=hash&amp;ref_src=twsrc%5Etfw">#TTD</a> recording useful for:<br>- <a href="https://twitter.com/hashtag/fuzzing?src=hash&amp;ref_src=twsrc%5Etfw">#fuzzing</a> crash replay<br>- <a href="https://twitter.com/hashtag/malware?src=hash&amp;ref_src=twsrc%5Etfw">#malware</a> analysis<br>- bug tracking <a href="https://t.co/yYZrkNRmD1">pic.twitter.com/yYZrkNRmD1</a></p>&mdash; windbgtips (@windbgtips) <a href="https://twitter.com/windbgtips/status/1061684978612789248?ref_src=twsrc%5Etfw">November 11, 2018</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>


### Nothing is forgotten

Back to the notepad session. Even though no file was saved to disk, I did type some stuff on the keyboard, so I figured that they must have been recorded somewhere by TTD. Let's hunt them down!

Notepad uses Windows' Messaging mechanism so that when a key is stroke, an event is passed down to notepad (or any other app fwiw) who decides whether to pick it up or not (the Windows Message internals is not the focus of this post but [this is a pretty good introduction](https://en.wikibooks.org/wiki/Windows_Programming/Message_Loop_Architecture)), to know whether the canvas must be redrawn, the window close, etc. This messaging system being articulated around fetching messages (via [`user32!GetMessage`](https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-getmessage)) and pushing them (via [`user32!SendMessage`](https://docs.microsoft.com/en-us/windows/desktop/api/winuser/nf-winuser-sendmessage)). The `GetMessage()` function prototype is :

```c
BOOL GetMessage(
  LPMSG lpMsg,
  HWND  hWnd,
  UINT  wMsgFilterMin,
  UINT  wMsgFilterMax
);
```

It is easily possible to filter those calls as mentioned earlier:
```
0:000> dx @$cursession.TTD.Calls("user32!GetMessage*")
@$cursession.TTD.Calls("user32!GetMessage*").Count() : 0x1e8
```

One way I found to narrow so many calls down is to see is to focus rather on the message itself, which is Parameters[0] of the function call:

![](/img/windbg-ttd/notepad1.png)

It seems that the message is always stored at 0xa30fb6fc00, and has the [following structure](https://docs.microsoft.com/en-us/windows/desktop/api/winuser/ns-winuser-tagmsg)

```c
typedef struct tagMSG {
  HWND   hwnd;
  UINT   message;
  WPARAM wParam;
  LPARAM lParam;
  DWORD  time;
  POINT  pt;
  DWORD  lPrivate;
} MSG, *PMSG, *NPMSG, *LPMSG;
```

We can now monitor all the memory accesses to the address 0xa30fb6fc00

```
0:000> dx -r1 -nv (*((wintypes!MSG *)0xa30fb6fc00))
(*((wintypes!MSG *)0xa30fb6fc00))                 : {msg=0x102 wp=0x74 lp=0x140001} [Type: MSG]
    [+0x000] hwnd             : 0x12044a [Type: HWND__ *]
    [+0x008] message          : 0x102 [Type: unsigned int]
    [+0x010] wParam           : 0x74 [Type: unsigned __int64]
    [+0x018] lParam           : 1310721 [Type: __int64]
    [+0x020] time             : 0x0 [Type: unsigned long]
    [+0x024] pt               [Type: tagPOINT]
```


`MSG.wParam` in particular will hold the value of the keycode when the key is stroke, so we can also narrow it to ASCII characters

```
0:000> dx -g @$cursession.TTD.Memory(0xa30fb6fc10, 0xa30fb6fc10+8, "w").Where(m => m.Value >= 0x20 && m.Value < 0x80)
===============================================================================================================================================================================
=           = (+) EventType   = (+) ThreadId = (+) UniqueThreadId = (+) TimeStart = (+) TimeEnd = (+) AccessType = (+) IP            = (+) Address     = (+) Size = (+) Value =
===============================================================================================================================================================================
= [0x5e]    - MemoryAccess    - 0x1dcc       - 0x2                - A04C:6A       - A04C:6A     - Write          - 0x7ffe169066ae    - 0xa30fb6fc10    - 0x8      - 0x54      =
= [0x5f]    - MemoryAccess    - 0x1dcc       - 0x2                - A050:7        - A050:7      - Write          - 0x7ffe16911b4f    - 0xa30fb6fc10    - 0x8      - 0x74      =
= [0x60]    - MemoryAccess    - 0x1dcc       - 0x2                - A695:6A       - A695:6A     - Write          - 0x7ffe169066ae    - 0xa30fb6fc10    - 0x8      - 0x74      =
= [0x61]    - MemoryAccess    - 0x1dcc       - 0x2                - A70E:6A       - A70E:6A     - Write          - 0x7ffe169066ae    - 0xa30fb6fc10    - 0x8      - 0x48      =
= [0x64]    - MemoryAccess    - 0x1dcc       - 0x2                - A72D:7        - A72D:7      - Write          - 0x7ffe16911b4f    - 0xa30fb6fc10    - 0x8      - 0x68      =
= [0x65]    - MemoryAccess    - 0x1dcc       - 0x2                - ABE3:6A       - ABE3:6A     - Write          - 0x7ffe169066ae    - 0xa30fb6fc10    - 0x8      - 0x68      =
[...]
```

That's a lot more interesting so we use LINQ even further to print the characters directly by casting the Value to `char` and we get

```
0:000> dx -g @$cursession.TTD.Memory(0xa30fb6fc10, 0xa30fb6fc10+8, "w").Where(m => m.Value >= 0x20 && m.Value < 0x80).Select( c => (char)c.Value )
====================
=                  =
====================
= [0x5e] : 84 'T'  =
= [0x5f] : 116 't' =
= [0x60] : 116 't' =
= [0x61] : 72 'H'  =
= [0x64] : 104 'h' =
= [0x65] : 104 'h' =
= [0x66] : 84 'T'  =
= [0x67] : 73 'I'  =
= [0x68] : 105 'i' =
= [0x69] : 105 'i' =
= [0x6a] : 72 'H'  =
= [0x6d] : 83 'S'  =
= [0x6e] : 115 's' =
= [0x6f] : 115 's' =
= [0x70] : 73 'I'  =
= [0x71] : 32 ' '  = // Reads 'This '
[...]
```

Here we see multiple times the same character: the reason being that for one key stroke, multiple events are raised (`WM_KEYDOWN`, `WM_KEYUP`). Since we haven't done any filtering at the DDM level, notepad captures all the events. It would be fairly easy from that point to create a JS script to only get one type of message, but this will be left at the curiosity of the reader (focus on capturing only the messages of type [`WM_KEYDOWN`](https://docs.microsoft.com/en-us/windows/desktop/inputdev/wm-keydown) (0x100).


## Last words

This concludes this light post about TTD and its DDM integration.

TTD brings a new approach to traditional debugging which is a huge plus. Not only that, but its integration in WinDbg with LINQ and DDM makes it even more powerful, and I hope this small post helped in making those tools more approachable.

In the mean time, I'll leave you with some links to dig deeper:
- {% include link.html href="https://doar-e.github.io/blog/2017/12/01/debugger-data-model/" title="Debugger data model, Javascript & x64 exception handling" %}
- {% include link.html href="https://www.youtube.com/watch?v=5U73Vxb4Jk8" title="Channel9 - Introduction to Time Travel Debugging" %}
- {% include link.html href="https://channel9.msdn.com/Shows/Defrag-Tools/Defrag-Tools-186-Time-Travel-Debugging-Advanced"  title="Channel9 - Advanced Time Travel Debugging" %}
- {% include link.html href="https://www.youtube.com/playlist?list=PLjAuO31Rg973XOVdi5RXWlrC-XlPZelGn" title="WinDbg YouTube Playlist" %}

Cheers!