+++
title = "Scripting with Windows Root Directory Object"
author = "hugsy"
date = 2019-01-30T00:00:00Z
updated = 2019-01-30T00:00:00Z

[taxonomies]
categories = [" research"]
tags = ["windows","kernel","windbg","javascript","object-manager"]

[extra]
header_img = "/img/{1910FC37-E777-418F-83EC-2A2543969515}.jpg"
+++

Still on my way to learning of Windows kernel, I spend considerable amount of time on [WinDbg Preview](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugging-using-windbg-preview). I've been [scripting my way](https://github.com/hugsy/windbg_js_scripts) to understand its components, the last in date was `nt!ObpRootDirectoryObject`. This pointer is well documented, especially {{ twitter(user="ivanlef0u") }}'s article [about it](https://www.ivanlef0u.tuxfamily.org/?p=34) (french) is a good place to start.


## The Status Quo

Tools like [WinObj](https://docs.microsoft.com/en-us/sysinternals/downloads/winobj) or [WinObjEx64](https://github.com/hfiref0x/WinObjEx64/) are crazy useful. Since they are userland specific they can rely most on already existing `ntdll` functions to dynamically query to object directory, such as:

```c
NTSTATUS NtOpenDirectoryObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS NtQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength);
```

[source](https://github.com/hfiref0x/WinObjEx64/blob/6f6d4480d724e3430b49ff15da1b01c12793c499/Source/WinObjEx64/ntos/ntos.h#L8583-L8598)


Those tools are excellent, I use them big time but I was curious if it was possible to extend the data model to expose object tree in a similar fashion. Because the problem in KM (as we can see in Ivan's post) is that the structures hold a lot of pointers, `LIST_ENTRY`s and other goodies that must be dereferenced manually which turns out to be a tedious task. Also that approach prevents from easily querying the directory object.

But hold your breath, here comes the Debugger Data Model...


## Extending WinDbg data model to expose the directory objects

With the [help of Alex Ionescu pointing out my shortcomings](https://github.com/hugsy/windbg_js_scripts/pull/1) - but always for my benefit -, I ended up with writing [`ObjectExplorer.js`](https://github.com/hugsy/windbg_js_scripts/blob/45926ab380ba6185cc8e210d77f1a7c56ec05323/scripts/ObjectExplorer.js), a surprisingly short JS scripts for WinDbg, which parses and exposes in a structured way the content of `nt!ObpRootDirectoryObject`.

{{ img(src="/img/{D1BF677A-5CFD-4C16-8ABA-1492397D7E17}.jpg" title="image_alt") }}


Not only it's all click-friendly when I'm feeling it's too complicated to type on a keyboard, but the absolute awesome thing is the total integration with LINQ, so you can actually search those objects programmatically (which is impossible with `WinObj` for instance). Say you want to enumerate the `nt!_OBJECT_TYPE` keys of all the `ObjectTypes` on your version of Windows, well...

```txt
lkd> dx -g -r1 @$cursession.Objects.Children.Where( obj => obj.Name == "ObjectTypes" ).First().Children.Select(o => new { Name = o.RawObjectHeader.Name, Key = (char*)&o.RawObjectHeader.Key})
```

which produces something like:

```txt
==============================================================================================
=           = (+) Name                              = (+) Key                                =
==============================================================================================
= [0x0]     - "TmTm"                                - 0xffffbe8458913b90 : "TmTm"            =
= [0x1]     - "Desktop"                             - 0xffffbe8458903fe0 : "Desk"            =
= [0x2]     - "Process"                             - 0xffffbe8458880480 : "Proc???"         =
= [0x3]     - "EnergyTracker"                       - 0xffffbe8458998fe0 : "Ener"            =
= [0x4]     - "RegistryTransaction"                 - 0xffffbe845899efe0 : "Regi"            =
= [0x5]     - "DebugObject"                         - 0xffffbe8458863a10 : "Debu???"         =
= [0x6]     - "VRegConfigurationContext"            - 0xffffbe8459f43fe0 : "VReg"            =
= [0x7]     - "TpWorkerFactory"                     - 0xffffbe845887ba70 : "TpWo???"         =
[...]
```

Or enumerate all processes owning an ALPC port object from the `\RPC Control` directory can be seen as easily as

```txt
lkd> dx -r0 @$AlpcPorts = @$cursession.Objects.Children.Where( obj => obj.Name == "RPC Control" ).First().Children.Where( rpc => rpc.Type == "ALPC Port")
lkd> dx -g @$AlpcPorts.Select( alpc => new { AlpcName= alpc.Name, ProcessOwnerName= (char*) alpc.Object.OwnerProcess->ImageFileName })
```

and we get:

{{ img(src="/img/{68EB5886-B508-4F69-81E2-DDC726638542}.png" title="image_alt") }}


You get the gist. Pretty cool, right?

Although it's already fully functional, [`ObjectExplorer.js`](https://github.com/hugsy/windbg_js_scripts/blob/main/scripts/ObjectExplorer.js) script will be improved gradually. If you have feedbacks or suggestions, I'd be happy to hear about them.

Cheers ☕️
