date: 2022-08-06 00:00:00
modified: 2022-08-06 00:00:00
title: Install Hyper-V & Sandbox on Windows 10 Home
author: hugsy
category: minis
tags: windows, hyper-v, sandbox

Contrarily to what [even Microsoft says](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v#check-requirements), both Hyper-V and Windows Sandbox are available for Windows 10 Home. The procedures are simple, and just require an admin powershell prompt (note that a reboot will be required):

Get your copy/paste skills ready!

## Install Hyper-V on Windows 11 Home

```powershell
Get-ChildItem $env:SystemRoot\Servicing\Packages\*Hyper-V*.mum | ForEach-Object { dism -Online -NoRestart -add-package:"$_" }
Enable-WindowsOptionalFeature -All -Online -LimitAccess -FeatureName Microsoft-Hyper-V 
```

## Install Windows Sandbox on Windows 10 Home

```powershell
Get-ChildItem  $env:SystemRoot\Servicing\Packages\*DisposableClientVM*.mum | ForEach-Object { dism -Online -NoRestart -add-package:"$_" }
Enable-WindowsOptionalFeature  -All -Online -FeatureName Containers-DisposableClientVM
```

Another useful miniz! 👋
