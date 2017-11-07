---
layout: post
title: Some Qemu images to play with
author: hugsy
author_twitter: _hugsy_
author_email: hugsy@[RemoveThisPart]blah.cat
author_github: hugsy
tags: linux exploit debug arm mips aarch64 powerpc sparc
header-img: "img/qemu-img.png"
---

> **TL;DR**
> Ready-to-play Qemu images for under-rated architectures (ARM, MIPS, PowerPC,
> SPARC, AARCH64) to play with, with all the tools builtin to understand memory
> corruption on non x86 environments
> {%include link.html title="here" href="https://mega.nz/#F!oMoVzQaJ!iS73iiQQ3t_6HuE-XpnyaA"%}.

## Become a ninja on non-x86 architectures !

A few weeks back, I came across {%include icon-twitter.html
username="@Fox0x01"%} {%include link.html title="awesome tutorial"
href="https://azeria-labs.com/writing-arm-assembly-part-1/"%} to get
started with learning debugging and exploitation techniques on ARM. If you
haven't checked it out, make sure you add this on your to-read list.

I have been initially developping [`gef`](https://github.com/hugsy/gef.git) for
the same reason, to learn more about non-x86 architectures. So in the same
spirit of openness that Azeria has shown, I am releasing a few Qemu virtual
machines to start immediately playing with ARM, MIPS, PowerPC and AARCH64
architectures!

All you need is [Qemu](http://www.qemu.org). Then download the link to your
image, and unzip the archive.

If you are on Linux/OSX, run in a terminal (or double-click) on the `./start.sh`
script, when our Windows friend would simply need to double-click the `./start.bat`.

Each VM will also TCP forward its SSH port for easy interaction. On Linux/OSX, just
run `./ssh.sh`. Windows users will need tools like [`PuTTY`](http://www.putty.org).

Those images are battery-included, development tools, compilation and debugging
tools too. Ever wondered what SPARC assembly looks like? Always feeling itchy to
learn about memory corruption on PowerPC? Wait no more!


## Links

Without further ado:

  * {%include link.html title="Link to Mega.nz" href="https://mega.nz/#F!oMoVzQaJ!iS73iiQQ3t_6HuE-XpnyaA"%}

Unless stated otherwise, `root` password is `root`, and an low privilege account
called `user` is created.

> **Update**: the current ARMv6 image is based on a Raspberry Pi
> image. Therefore, the username is `pi` , password `raspberry` and is sudoer
> NOPASSWD. I will update the image soon to fix this.


{%include image.html alt="vbox-qemu" src="/img/vbox.png"%}


## But why ?

Already existing fantastic projects such
as [Vagrant](https://atlas.hashicorp.com/boxes/search) for Linux/*nix
and [modern.ie](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)
for Windows help us getting quickly functional environments we can use in
labs. But they are only providing Intel-based images.

The closest thing to what I wanted when I started exploring exotic architectures
was {%include link.html href="https://people.debian.org/~aurel32/qemu/"
title="aurel32 Qemu pages"%}, which provides great Qemu images. Unfortunately,
they are using extremely old kernels and/or Linux distributions, making it too
hard for a quick plug-n-play experience.

Interestingly when developing `gef`, I talked with many people interested in
learning about non-x86 archs but felt like they _don't know where to
start_. So my hope is that those images will be the start to a lot of
fun.

All the VMs come with 2 compiled ELF binaires: a very simple `hello-world`
to start easy with the new architecture, run it, start `gdb`-ing around it to understand the architecture basics (memory layout, function call convention, GOT+PLT, stack canary, etc.) and a `simple-bof`, which is a simple
Stack Overflow ELF to start on the way of understanding memory corruption.


## But I just wanna play with assembly...

So take a look at {%include link.html title="this" href="https://github.com/hugsy/cemu"%}.


## Ok so what's next ?

Well, those VMs were built from scratch using Qemu, which takes forever. I will
add some more VMs on other arch soon (MIPS64, S390x, etc.), but if you like
that, simply drop me a line on Twitter, to keep me boosted.

Hope you'll enjoy it!

![buzz-qemu](https://i.imgflip.com/1ri3fi.jpg)

Oh and if you happen to be wandering in Black Hat Las Vegas 2017, come say hi at
{%include link.html title="the Black Hat Arsenal booth" href="https://www.blackhat.com/us-17/arsenal/schedule/index.html#gdb-enhanced-features-gef-8048"%}

Cheers!
