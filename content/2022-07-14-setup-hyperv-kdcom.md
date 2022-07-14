date: 2022-07-14 00:00:00
modified: 2022-07-14 00:00:00
title: Enumerating processes from KD
author: hugsy
category: minis
tags: windows, hyperv, kdcom

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
windbgx -k com:pipe,port=\\.\pipe\com1,resets=0,reconnect
```

