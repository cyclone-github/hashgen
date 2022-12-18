# hashgen
Hashgen is a simple CLI hash generator written in go and cross compiled for Linux, Windows & Mac.

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
- plaintext

Hashgen is not very fast at the moment, but it has been a fun project to work on.

### Hash generator benchmarks
https://github.com/cyclone-github/hashgen/tree/main/benchmarks
