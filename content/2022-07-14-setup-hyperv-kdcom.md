+++
title = "Setup KDCOM for 2 Hyper-V VMs"
authors = ["hugsy"]
date = 2022-07-14T00:00:00Z
updated = 2022-07-14T00:00:00Z
aliases = ["/posts/2022/07/14/setup-kdcom-for-2-hyper-v-vms.html"]

[taxonomies]
categories = ["minis"]
tags = ["windows", "hyperv", "kdcom"]
+++

How to use Hyper-V to debug using KdCOM from 2 VMs, one debugging the other.

## Debuggee

Follow the setup [here](https://blahcat.github.io/posts/2017/08/07/setting-up-a-windows-vm-lab-for-kernel-debugging.html) to setup a BCD profile for KdCom in the VM. Shutdown the VM and in a privileged prompt on the host (here assigned to COM1):

```powershell
Set-VMComPort MyDebuggedVM  1 \\.\pipe\win7x64-kdcom
```


## Debugger

Still on a privileged prompt on the host, choose a COM port number and connect it to the same pipe:

```powershell
Set-VMComPort MyDebuggerVM 1 \\.\pipe\win7x64-kdcom
```

Boot the debugger and make WinDbgX listen to that port

```powershell
windbgx -k com:pipe,port=\\.\com1,resets=0,reconnect
```

Enjoy

{{ img(src="https://user-images.githubusercontent.com/590234/179017302-76f5a1ca-acc3-48fb-a6d1-e7d13ba74a45.png" title="image") }}
