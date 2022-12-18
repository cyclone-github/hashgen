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
https://github.com/cyclone-github/hashgen/tree/main/benchmarks
