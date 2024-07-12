+++
title = "Some Qemu images to play with"
authors = ["hugsy"]
date = 2017-06-25T00:00:00Z
updated = 2017-06-25T00:00:00Z

[taxonomies]
categories = ["misc"]
tags = ["linux","pwn","debug","arm","mips","aarch64","powerpc","sparc"]

[extra]
header_img = "img/qemu-img.png"
+++

> **TL;DR**
> Ready-to-play Qemu images for under-rated architectures (ARM, MIPS, PowerPC,
> SPARC, AARCH64) to play with, with all the tools builtin to understand memory
> corruption on non x86 environments
> [here](https://mega.nz/#F!oMoVzQaJ!iS73iiQQ3t_6HuE-XpnyaA).

> **Update _(2018/05/15)_**
> The Mega.NZ repository was cloned to Google Drive, available
> [here](https://drive.google.com/drive/folders/107uMlL_DS8yD2TS_0yrHXBDnLOj44a8P?usp=sharing).


## Become a ninja on non-x86 architectures !

A few weeks back, I came across  [`@Fox0x01`](https://twitter.com/Fox0x01) [tutorial](https://azeria-labs.com/writing-arm-assembly-part-1/) to get started with learning debugging and exploitation techniques on ARM. If you haven't checked it out, make sure you add this on your to-read list.

I have been initially developing [`gef`](https://github.com/hugsy/gef.git) for the same reason, to learn more about non-x86 architectures. So in the same spirit of openness that Azeria has shown, I am releasing a few Qemu virtual machines to start immediately playing with ARM, MIPS, PowerPC and AARCH64 architectures!

All you need is [Qemu](http://www.qemu.org). Then download the link to your image, and unzip the archive.

If you are on Linux/OSX, run in a terminal (or double-click) on the `./start.sh` script, when our Windows friend would simply need to double-click the `./start.bat`.

Each VM will also TCP forward its SSH port for easy interaction. On Linux/OSX, just run `./ssh.sh`. Windows users will need tools like [`PuTTY`](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html).

Those images are battery-included, development tools, compilation and debugging tools too. Ever wondered what SPARC assembly looks like? Always feeling itchy to learn about memory corruption on PowerPC? Wait no more!


## Links

Without further ado:

  * [Link to Mega.nz](https://mega.nz/#F!oMoVzQaJ!iS73iiQQ3t_6HuE-XpnyaA)
  * [Link to Google Drive](https://drive.google.com/drive/folders/107uMlL_DS8yD2TS_0yrHXBDnLOj44a8P?usp=sharing")

Unless stated otherwise, `root` password is `root`, and an low privilege account called `user` is created.

> **Update**: the current ARMv6 image is based on a Raspberry Pi image. Therefore, the username is `pi` , password `raspberry` and is sudoer NOPASSWD. I will update the image soon to fix this.

{{ img(src="/img/vbox.png" title="vbox-qemu") }}


## But why ?

Already existing fantastic projects such as [Vagrant](https://app.vagrantup.com/boxes/search) for Linux/*nix and [modern.ie](https://web.archive.org/web/20170306074002/https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/) for Windows help us getting quickly functional environments we can use in labs. But they are only providing Intel-based images.

The closest thing to what I wanted when I started exploring exotic architectures was [aurel32 (now Debian Quick Image Baker) Qemu pages](https://people.debian.org/~gio/dqib/), which provides great Qemu images. Unfortunately, they are using extremely old kernels and/or Linux distributions, making it too hard for a quick plug-n-play experience.

Interestingly when developing `gef`, I talked with many people interested in learning about non-x86 architectures but felt like they _don't know where to start_. So my hope is that those images will be the start to a lot of fun.

All the VMs come with 2 compiled ELF binaries: a very simple `hello-world` to start easy with the new architecture, run it, start `gdb`-ing around it to understand the architecture basics (memory layout, function call convention, GOT+PLT, stack canary, etc.) and a `simple-bof`, which is a simple Stack Overflow ELF to start on the way of understanding memory corruption.


## But I just wanna play with assembly...

So take a look at [this](https://github.com/hugsy/cemu).


## Ok so what's next ?

Well, those VMs were built from scratch using Qemu, which takes forever. I will add some more VMs on other arch soon (MIPS64, S390x, etc.), but if you like that, simply drop me a line on Twitter, to keep me boosted.

Hope you'll enjoy it!

{{ img(src="https://i.imgflip.com/1ri3fi.jpg" title="buzz-qemu") }}

Oh and if you happen to be wandering in Black Hat Las Vegas 2017, come say hi at [the Black Hat Arsenal booth](https://www.blackhat.com/us-17/arsenal/schedule/index.html#gdb-enhanced-features-gef-8048)

Cheers!
