date: 2018-01-07 00:00:00
modified: 2018-01-07 00:00:00
title: Building a Debian Stretch QEMU image for AARCH64
author: hugsy
category: tutorial
tags: gef,qemu,aarch64
cover: assets/images/qemu-img.png

## Introduction

After [releasing my QEMU
images](/posts/2017/06/25/qemu-images-to-play-with.html) and then publishing a post on [how to build a QEMU image for Debian MIPSel](/posts/2017/07/14/building-a-debian-stretch-qemu-image-for-mipsel.html), I still received many demands for information on building more VMs, and among those, the most popular one was AARCH64 (or ARM64).

If you're just interested in downloading the ready-to-use AARCH64 image, just go to the [Mega](https://mega.nz/#F!oMoVzQaJ!iS73iiQQ3t_6HuE-XpnyaA) repository.


## Pre-requisite

Just like [we did earlier in the former post](), we will proceed with the Debian
Net Installer, so you will require:

- an Internet connection
- a recent QEMU (generally `{apt,dnf} install qemu` will suffice)
- the initrd of the Debian installer


```bash
$ wget http://ftp.debian.org/debian/dists/Debian9.13/main/installer-arm64/current/images/netboot/debian-installer/arm64/initrd.gz
```

- the kernel to boot on for the installation:

```bash
$ wget http://ftp.debian.org/debian/dists/Debian9.13/main/installer-arm64/current/images/netboot/debian-installer/arm64/linux
```

You also need a hard drive to install the OS on:
```bash
$ qemu-img create -f qcow2 disk.qcow2 20G
```


## Installation steps

<div markdown="span" class="alert-info"><i class="fa fa-info-circle">&nbsp;Note:</i> since most steps are similar with the ones described in the post before, I'll simply show the commands I've used so they can be copy/pasted for reproduction.</div>

Start with running the installer (with 2 vCPUs and 1GB Ram):

```bash
$ qemu-system-aarch64 -smp 2 -M virt -cpu cortex-a57 -m 1G \
    -initrd initrd.gz \
    -kernel linux -append "root=/dev/ram console=ttyAMA0" \
    -global virtio-blk-device.scsi=off \
    -device virtio-scsi-device,id=scsi \
    -drive file=disk.qcow2,id=rootimg,cache=unsafe,if=none \
    -device scsi-hd,drive=rootimg \
    -netdev user,id=unet -device virtio-net-device,netdev=unet \
    -net user \
    -nographic
```


![1.debian.installer.png](https://i.imgur.com/PAExOmJ.png)

Then, go grab a coffee while the installer does its magic:

![2.debian.installer.png](https://i.imgur.com/1Mgoscl.png)

And finally:

![3.debian.installer.png](https://i.imgur.com/IfvQpTC.png)


Now we must shutdown the VM, and extract the initrd and kernel from the image, as follow:

```bash
$ sudo apt install nbd-client
$ sudo modprobe nbd max_part=8
$ sudo qemu-nbd --connect=/dev/nbd0 disk.qcow2
$ mkdir mnt
$ sudo mount /dev/nbd0p1 mnt
$ cp mnt/initrd.img-4.9.0-4-arm64 mnt/vmlinuz-4.9.0-4-arm64 .
$ sync
$ sudo umount /dev/nbd0p1
$ sudo nbd-client -d /dev/nbd0
```

And run your VM with the kernel and initrd copied from installer:

```bash
$ qemu-system-aarch64 -smp 2 -M virt -cpu cortex-a57 -m 1G \
    -initrd initrd.img-4.9.0-4-arm64 \
    -kernel vmlinuz-4.9.0-4-arm64 \
    -append "root=/dev/sda2 console=ttyAMA0" \
    -global virtio-blk-device.scsi=off \
    -device virtio-scsi-device,id=scsi \
    -drive file=disk.qcow2,id=rootimg,cache=unsafe,if=none \
    -device scsi-hd,drive=rootimg \
    -device e1000,netdev=net0 \
    -net nic \
    -netdev user,hostfwd=tcp:127.0.0.1:2222-:22,id=net0 \
    -nographic
```

And that's it!

![4.debian.installer.png](https://i.imgur.com/519SOdy.png)

The ready-to-use image (with gcc, gdb, gef, etc.) is available [here](https://mega.nz/#F!oMoVzQaJ!iS73iiQQ3t_6HuE-XpnyaA).

Adios ☕
