+++
title = "Goodbye VirtualBox, hello Hyper-V"
author = "hugsy"
date = 2018-12-30T00:00:00Z
updated = 2018-12-30T00:00:00Z

[taxonomies]
categories = ["research"]
tags = ["windows","hyperv","virtualbox","cheatsheet"]

[extra]
header-img = "assets/images/vbox-to-hyperv-header.png"
+++

A few scrap notes about my migration from VirtualBox to Hyper-V (in case I attempt to do the same again in the future 😁)


## Moving a VirtualBox VM to Hyper-V

Hyper-V doesn't support OVF/OVA format, but it is possible to convert a VBox VDI to HV VHD by:

 1. In VirtualBox: copy the hard drive from **File** → **Virtual Media Manager**. Select the target image and **Copy** it making sure that the output format is VHD
 2. In Hyper-V, open the **Edit Disk** wizard from the selected host. Select the VHD created above and choose to convert to VHDX.
 3. Still in Hyper-V, when creating the VM, simply point to that VHDX in the Hard Drive section.

Done.


## Enabling "Enhanced Session" mode for Ubuntu or Arch Linux

Creating a (recent) Windows VM in Hyper-V will automatically build a smooth environment, but with Linux not much. This is because the "Enhanced Session" is not available, preventing to do simple stuff like:

- Clipboard support
- Dynamic desktop resizing
- Shared folders & drive redirection
- Seamless mouse sharing

MS rectified the shoot by releasing the [Linux VM Tools](https://github.com/Microsoft/linux-vm-tools) last October. Quick how-to:

 1. Git-Clone https://github.com/Microsoft/linux-vm-tools
```bash
# for ubuntu 18.04
$ git clone https://github.com/Microsoft/linux-vm-tools
$ cd linux-vm-tools/ubuntu/18.04
$ chmod +x ./install.sh
$ sudo ./install.sh
```
 2. Wait for the install to finish
 3. Disable the autologin (**User settings** → **Autologin** set to Off)
 4. Shutdown the VM
 5. On the host, open a Powershell as Administrator and change the session transport type:
```powershell
PS C:\Users\hugsy> Set-VM "Ubuntu 18.04 x64" -EnhancedSessionTransportType HvSocket
```
 4. Start the VM. When switching to the RDP session, Hyper-V Manager will prompt the desired resolution and show the XRDP prompt.
    ![image_alt](https://github.com/Microsoft/linux-vm-tools/raw/master/wiki/media/xorglogin.PNG)
 5. Login as usual and enjoy the enhanced mode.

For Fedora/RedHat, it [may also be working](https://bugzilla.redhat.com/show_bug.cgi?id=1553453).

> Update (2019/04/28):
> If you're using a different WM, you may also need to edit your `~/.xsession` to set proper WM value. For instance

```text
env -u SESSION_MANAGER -u DBUS_SESSION_BUS_ADDRESS mate-session  # for mate (could be unity, xfce4-session, gnome3, etc.)
```

<div markdown="span" class="alert-info"><i class="fa fa-info-circle">&nbsp;Note:</i><br>
To switch back to the regular view, simply click on **View** → uncheck **Enhanced session**.
</div>


## Sharing folders

This is easily done using SMB: on the host, simply share (right-click on folder → **Properties** → **Share** tab)

### Windows guest

Well it's Windows, so just
```bash
C:\> net use * \\HOST_HOSTNAME\SharedFolder /user:hugsy
```

### Linux guest

Use [Samba](https://samba.org):
```bash
$ sudo apt install cifs-utils -y # for the first time, just in case
$ mkdir -p ~/Desktop/Shared
$ sudo mount.cifs //HOST_HOSTNAME/SharedFolder ~/Desktop/Shared -o user=hugsy,uid=1000,gid=1000
```

And the best part is that it will all rely on Windows DACL which allows a much finer granularity in permissions than VirtualBox did.


## Side note

Hyper-V has become really good so maybe that post will help other former Linux people like myself to reconsider, test it and maybe make the move too. That move was the last one to date for me, after moving from Linux to Windows 10 as main host OS, and then switching from my beloved Emacs to Visual Studio Code.

And I must say, I've been nothing but happy about those changes... Huge kudos to Microsoft! A few pros for Hyper-V are that it is totally free and integrated to the OS (assuming you have a Pro version), supports Nested Virtualization, VMs are always running headlessly, can be programmed in [C#](https://blogs.technet.microsoft.com/richard_macdonald/2008/08/11/programming-hyper-v-with-wmi-and-c-getting-started/) or scripted in [PowerShell](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/try-hyper-v-powershell) easily... Also I personally don't like Oracle, so if I can't make a change to not using any of their software, it's all for the best.

And this will conclude my pesky rant 😀


Some links to conclude:

 - [https://github.com/Microsoft/linux-vm-tools](https://github.com/Microsoft/linux-vm-tools){:target="_blank"}
 - [https://blogs.technet.microsoft.com/virtualization/2018/02/28/sneak-peek-taking-a-spin-with-enhanced-linux-vms/](https://blogs.technet.microsoft.com/virtualization/2018/02/28/sneak-peek-taking-a-spin-with-enhanced-linux-vms/){:target="_blank"}
 - [https://nbsoftsolutions.com/blog/linux-virtualization-with-a-mounted-windows-share-on-client-hyper-v](https://nbsoftsolutions.com/blog/linux-virtualization-with-a-mounted-windows-share-on-client-hyper-v){:target="_blank"}


Cheatsheet over...
