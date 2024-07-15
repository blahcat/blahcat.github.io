+++
title = "Install Hyper-V & Sandbox on Windows 10/11 Home"
authors = ["hugsy"]
date = 2022-08-06T00:00:00Z
updated = 2022-08-06T00:00:00Z
aliases = ["/posts/2022/08/06/install-hyper-v-sandbox-on-windows-1011-home.html"]

[taxonomies]
categories = ["minis"]
tags = ["windows", "hyper-v", "sandbox"]
+++

Another lie, probably put in place from MS marketing team to force the hand and make more people purchase Windows 10/11 Professional licenses: Hyper-V and Windows Sandbox **can** be installed on Windows 10/11 Home Edition, not just Professional/Entreprise. Contrarily to what [even Microsoft documentation says](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v#check-requirements), both Hyper-V and Windows Sandbox can be set in a quite simple manner, and just require an admin powershell prompt (note that a reboot will be required):

Get your copy/paste skills ready!

## Install Hyper-V on Windows 10/11 Home

```powershell
Get-ChildItem $env:SystemRoot\Servicing\Packages\*Hyper-V*.mum | ForEach-Object { dism -Online -NoRestart -add-package:"$_" }
Enable-WindowsOptionalFeature -All -Online -LimitAccess -FeatureName Microsoft-Hyper-V
```

## Install Windows Sandbox on Windows 10/11 Home

```powershell
Get-ChildItem  $env:SystemRoot\Servicing\Packages\*DisposableClientVM*.mum | ForEach-Object { dism -Online -NoRestart -add-package:"$_" }
Enable-WindowsOptionalFeature  -All -Online -FeatureName Containers-DisposableClientVM
```

{{ img(src="https://user-images.githubusercontent.com/590234/183723930-583c191c-d67a-43d1-8c5a-8c6dd6d4c78a.png" title="image") }}


Another useful miniz! 👋
