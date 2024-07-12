+++
title = "Cheap sandboxing with AppContainers"
authors = ["hugsy"]
date = 2020-12-29T00:00:00Z
updated = 2020-12-29T00:00:00Z

[taxonomies]
categories = ["research"]
tags = ["windows", "sandbox", "appcontainer"]
+++

## Background

This is a short blog post that I decided to finish recently after looking for a way to sandbox Win32 apps, but lazy as I am, I wanted something that
 1. was free/open-source & robustly tested
 2. easily hackable to my need (custom permissions on file/folder/registry, on network access, on device access etc.)
 3. little to no modification to my system
So off-the-shelf sandboxing products were disregarded immediately because they almost always fail on point #2 and **always** fail on point #1 as they'll tend to increase attack surface (which is kindda the opposite of the objective here). So quickly Google turned me to [Windows AppContainers](https://docs.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) which the MSDN details the [implementation](https://docs.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer) well-enough.

AppContainers are not new and by the look of it, they are here to stay. They were introduced in Windows 8 as an in-kernel isolation mechanism (a-la seccomp for Linux) and are the default model for UWP applications which a simple look at the new Calculator in Process Hacker shows immediately:

{{ img(src="/img/4f110a8b-5af4-4f03-8c8d-6fe8e297fffe.png" title="image_alt") }}

As the MSDN mentions, AppContainers operates on 6 levels of isolation, each programmatically customizable:

 - The **[File isolation](https://docs.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation#file-isolation)**
    operates by creating for the AppContained process its own sandbox and named object subtree. This allows the kernel to finely control access to the FS by the contained process.
 - The **[Network isolation](https://docs.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation#network-isolation)**
    will prevent any communication from/to the process over the network unless explicitly given permissions (and they have relatively explicit names, for instance `WinCapabilityInternetClientSid` to allow Internet access as a client - see [[WELL_KNOWN_SID_TYPE enumeration]](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-well_known_sid_type))
 - The **[Process isolation](https://docs.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation#process-isolation)**
    makes the process unable to get a handle to any process outside the sandbox
 - And **[Window isolation](https://docs.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation#window-isolation)** which
    makes the process unable to target the Window of other processes.
 - There's also [**Device isolation**](https://docs.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation#device-isolation) and [**Credential isolation**](https://docs.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation#credential-isolation) but I haven't played too much around those yet... Maybe a next post...

A useful feature added is the DllCharacteristics flag [`IMAGE_DLLCHARACTERISTICS_APPCONTAINER` - 0x1000](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics) that will prevent a specific DLL image from being located outside an AppContained environment.


## AppContainer, where are you?

AppContainers being session specific, they are linked to the Session Id: more precisely objects of the container will reside in the `\Sessions\<SessionId>\AppContainerNamedObjects\<AppContainerSid>`

```txt
lkd> dx @$cursession.Objects.Children.Where( x => x.Name == "Sessions").First().Children[2].Children
@$cursession.Objects.Children.Where( x => x.Name == "Sessions").First().Children[2].Children                 : [object Generator]
    [0x0]            : \Sessions\2\AppContainerNamedObjects
    [0x1]            : \Sessions\2\Windows
    [0x2]            : \Sessions\2\DosDevices
    [0x3]            : \Sessions\2\BaseNamedObjects
```

As for file/folder objects, they will be located in `%LOCALAPPDATA%\Packages\<NameOfTheContainer>`, easily deletable. With each container within the same session being isolated from each other, no real damage can be done outside the sandbox* as everything will be un-done when deleting it (* permissions given depending). So AppContainers was perfect for my case, I just needed a small tool to create AppContainers on-demand - as I couldn't find any pre-existing provided by MS.



## Building an AppContainer Process

<br>
{% note() %}
All the snippets below are C/C++ used in my [`pwn++`](https://github.com/hugsy/pwn--) library. Refer to the source code for the full implementation. Additionally, as I was already implementing my own version, I stumbled upon [@zodiacon](https://twitter.com/zodiacon)'s article[[1]](#ref_1) and implementation[[2]](#ref_2). You might prefer reading/using it if you want a serious implementation.
{% end %}


### Create an AppContainer profile

That's as simple as it gets: there's an API exactly for that [`CreateAppContainerProfile`](https://docs.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile)
```c++
PSID AppContainerSid;
std::string ContainerName("MyContainer");
::CreateAppContainerProfile(
    ContainerName.c_str(),
    ContainerName.c_str(),
    ContainerName.c_str(),
    nullptr,
    0,
    &AppContainerSid
);
```

### Add the desired capabilities

This was slightly trickier: to expose a specific capability or file/folder access to the container we must rely on [Windows object ACL mechanism](https://docs.microsoft.com/en-us/windows/win32/secauthz/modifying-the-acls-of-an-object-in-c--).

```c++
    // Saved the old ACL - you don't want to skip this step 😉
    ::GetNamedSecurityInfo(ObjectName, ObjectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pOldAcl, nullptr, &pSD);

    // Add the new access mode & mask entry
    Access.grfAccessMode = AccessMode;
    Access.grfAccessPermissions = AccessMask;
    Access.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
    Access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    Access.Trustee.pMultipleTrustee = nullptr;
    Access.Trustee.ptstrName = (PWSTR)AppContainerSid.c_str();
    Access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    Access.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    ::SetEntriesInAcl(1, &Access, pOldAcl, &pNewAcl);

    // Apply the new ACLs
    ::SetNamedSecurityInfo(ObjectName, ObjectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, pNewAcl, nullptr);
```

### Insert the capability set to the startup info

Not unlike [process reparenting](https://github.com/hugsy/pwn--/tree/main/Tools/Win32/ProcessReparent), appcontainerization requires to define a set of attribute as part of the extended startup information structure:

```c++
    SIZE_T size;
    m_StartupInfo.StartupInfo.cb = sizeof(STARTUPINFOEX);
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    StartupInfo.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)::new byte[size];
    ::InitializeProcThreadAttributeList(StartupInfo.lpAttributeList, 1, 0, &size);
    ::UpdateProcThreadAttribute(StartupInfo.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &SecurityCapabilities, sizeof(SecurityCapabilities), nullptr, nullptr);
```


### Start the process

All that's left now, is simply to invoke [`CreateProcess`](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) and we get the AppContained process.

```c++
    ::CreateProcessW(
        nullptr,
        (LPWSTR)lpwCmdLine.get(),
        nullptr,
        nullptr,
        false,
        EXTENDED_STARTUPINFO_PRESENT,
        nullptr,
        nullptr,
        (LPSTARTUPINFO)&StartupInfo,
        &ProcessInfo
    );
```

Surprisingly not hard to implement in C/C++ (and by extension also in C#), I'm surprised to see this rather efficient sandbox mechanism not being more broader to encapsulate legacy Win32 apps which functionally require only a small set of permissions available.


## Result

The ~~complete~~ functional command line tool AppContainMe[[3]](#ref_3) that uses the AppContainer implementation allows to launch contained process:

```txt
PS> d:\code\pwn++\x64\release\appcontainme.exe
[-]  syntax
        appcontainme.exe 'process_to_run.exe arg1 arg2' [d:\allowed\path1 d:\allowed\path2] [c:Capability1 c:Capability2] [r:regkey1 r:regkey2]
```

It's not complete but does the trick for me: without any option, the process will be spawn without any access to the FS (except the subtree allocated to the container in LocalAppData), no network access, no capability etc. So for example, we can start a totally harmless `powershell` session and obverse the process runs without any privilege (`powershell` cannot even get to our home directory).

```powershell
PS> AppContainMe powershell
```

{{ img(src="/img/29d17988-bf1f-4a1c-8b63-b01e97e6b53f.png" title="image_alt") }}

It won't also have any network access:

```txt
PS C:\WINDOWS\System32\WindowsPowerShell\v1.0> Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('http://google.com'))

Exception calling "DownloadString" with "1" argument(s): "The remote name could not be resolved:
'google.com'"
At line:1 char:1
+ Invoke-Expression ((New-Object System.Net.WebClient).DownloadString(' ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
+ CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
+ FullyQualifiedErrorId : WebException
```

Or process listing:

```txt
PS C:\WINDOWS\System32\WindowsPowerShell\v1.0> ps

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
      0       0       60          8                 0   0 Idle
    705      32    79932      92600       0.73   7676   2 powershell
```

So that confirms all the "isolation" points that are stated in the MSDN. It also works perfectly well for Win32 GUI apps, for PDF Readers
{{ img(src="/img/1e3a7b9c-7ef6-481d-a803-d0a969b3eab4.png" title="PDF Reader") }}

Also, for having lightweight web browsing sessions (like with [`qtweb.exe`](http://www.qtweb.net/))
{{ img(src="/img/283fd853-c2c7-4846-9b7c-242bfe1b02a1.png" title="Web browser") }}

That's pretty much it for this small post about AppContainers. If you want to play out-of-the-box with `AppContainMe`, a release archive with all the files is [here](https://github.com/hugsy/pwn--/releases).


## Credits & Links

Shout out to Pavel Yosivovich for his article and tool on AppContainer. And credits to COVID lockdown for giving me time to get back to finishing writing articles. More to come 😉...

 - <a name="ref_1">[1]</a> [Fun with AppContainers](https://scorpiosoftware.net/2019/01/15/fun-with-appcontainers/)
 - <a name="ref_2">[2]</a> [zodiacon/RunAppContainer - Github](https://github.com/zodiacon/RunAppContainer)
 - <a name="ref_3">[3]</a> [hugsy/pwn++ - Github](https://github.com/hugsy/pwn--/tree/main/Tools/Win32/AppContainMe)


Peace ✌
