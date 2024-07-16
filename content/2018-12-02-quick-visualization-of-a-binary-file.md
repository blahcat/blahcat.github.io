+++
title = "Quick visualization of a binary file"
authors = ["hugsy"]
date = 2018-12-02T00:00:00Z
updated = 2018-12-02T00:00:00Z
aliases = ["/posts/2018/12/02/quick-visualization-of-a-binary-file.html"]

[taxonomies]
categories = ["minis"]
tags = ["binary","visualization"]
+++


Here's a simple trick that I learned from the amazing  {{ twitter(user="scanlime") }} to quickly (and universally) visualize the distribution of byte of any binary file, using the [Portable Graymap Format (PGM)](https://en.wikipedia.org/wiki/Netpbm_format) format.

On Windows:
```bat
C:\> echo P5 512 4096 255 > %TEMPDIR%\visu.pgm & ^
     type \path\to\file\to\visualize.whatever >> %TEMPDIR%\visu.pgm
```

Or on Linux/OSX:
```bash
$ (echo "P5 512 4096 255";
   cat /path/to/file/to/visualize.whatever) > /tmp/visu.pgm
```

Then open the file with any image viewer like `feh` or `IrFanView`.

{{ img(src="/img/quick-visualization/evil.dll.pgm.png" title="evil.dll.pgm") }}
