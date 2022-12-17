# hashgen
Hashgen is a simple CLI hash generator that is cross compiled for linux, Windows & Mac.

Set your mode and wordlist with a simple command line, press enter and hashgen writes hashes to stdout.

In addition to multiple hashing functions, hashgen can also encode / decode base64.

Example Usage:
 - ./hashgen -m md5 -w wordlist.txt
 - ./hashgen -m md5 -w wordlist.txt > output.txt

Currently Supported functions:
- base64decode
- base64encode
- bcrypt
- crc32
- md4
- md5
- ntlm
- sha1
- sha256
- sha512

Written in go 1.19.4 and cross compiled for linux, Windows & Mac.

### Hash generator benchmarks
 - Head to head comparison of different hash generators
 - All testing was performed hashing rockyou.txt (15,053,568 lines) to md5
 - All hashing stdout was written to /dev/null
 - Benchmarks are an average of 5x runtimes

### Test rig specs:
 - OS: Linux 5.15.64-1 (Debian 10.2.1-6)
 - CPU: AMD Ryzen 7 3700X 8-Core Processor @ 3600MHz (16 Threads)
 - RAM: 64gb DDR4

### Results: (slowest to fastest)
5. Linux Bash (for loop using md5sum command): https://github.com/cyclone-github/hashgen/blob/main/benchmarks/hashgen.sh
  - 2h+ (proccess stopped after 10 minutes as it was estimated to take 2h30m)
4. Python 3.9.2 https://github.com/cyclone-github/hashgen/blob/main/benchmarks/hashgen.py
  - 19.985s
3. mdxfind https://github.com/cyclone-github/mdxfind
  - 13.0463s
2. go v1.19.4 (hashgen) https://github.com/cyclone-github/hashgen/releases/tag/Initial
  - 8.076s
1. Php v8.2 https://github.com/cyclone-github/hashgen/blob/main/benchmarks/hashgen.php
  - 5.293s
