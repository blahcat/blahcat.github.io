---
layout: post
title: Quick visualization of a binary file
date: 2018-12-02 13:59 -0800
author: hugsy
author_twitter: _hugsy_
author_email: hugsy@[RemoveThisPart]blah.cat
author_github: hugsy
tags: cheatsheet binary visualization
---


Here's a simple trick that I learned from the amazing  {% include icon-twitter.html username="@scanlime" %} to quickly (and universally) visualize the distribution of byte of any binary file, using the [Portable Graymap Format (PGM)](https://en.wikipedia.org/wiki/Netpbm_format) format.

On Windows:
```batch
C:\> echo P5 512 4096 255 > %TEMPDIR%\visu.pgm & ^
     type \path\to\file\to\visualize.whatever >> %TEMPDIR%\visu.pgm
```

Or on Linux/OSX:
```bash
$ (echo "P5 512 4096 255";
   cat /path/to/file/to/visualize.whatever) > /tmp/visu.pgm
```

Then open the file with any image viewer like `feh` or `IrFanView`.

![evil.dll.pgm](/img/quick-visualization/evil.dll.pgm.png)