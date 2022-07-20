date: 2018-12-02 00:00:00
modified: 2018-12-02 00:00:00
title: Quick visualization of a binary file
author: hugsy
category: minis
tags: binary,visualization


Here's a simple trick that I learned from the amazing  <a class="fa fa-twitter" href="https://twitter.com/@scanlime" target="_blank"> @scanlime</a> to quickly (and universally) visualize the distribution of byte of any binary file, using the [Portable Graymap Format (PGM)](https://en.wikipedia.org/wiki/Netpbm_format) format.

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

![evil.dll.pgm](/assets/images/quick-visualization/evil.dll.pgm.png){:width="750px"}
