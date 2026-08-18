[![Readme Card](https://github-readme-stats-fast.vercel.app/api/pin/?username=cyclone-github&repo=hashgen&theme=gruvbox)](https://github.com/cyclone-github/hashgen/)

[![Go Report Card](https://goreportcard.com/badge/github.com/cyclone-github/hashgen)](https://goreportcard.com/report/github.com/cyclone-github/hashgen)
[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/hashgen.svg)](https://github.com/cyclone-github/hashgen/issues)
[![License](https://img.shields.io/github/license/cyclone-github/hashgen.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/hashgen.svg)](https://github.com/cyclone-github/hashgen/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/cyclone-github/hashgen.svg)](https://pkg.go.dev/github.com/cyclone-github/hashgen)

### Install latest from source code:
```
go install github.com/cyclone-github/hashgen@main
```

# hashgen - Cyclone's hash generator
```
$ hashgen -m md5 -w rockyou.txt -b
2026/08/18 18:26:09 Starting...
2026/08/18 18:26:09 Processing file: /media/ramdisk/rockyou.txt
2026/08/18 18:26:09 Hash function: 0
2026/08/18 18:26:09 CPU Threads: 16
2026/08/18 18:26:10 Finished processing 14344391 lines in 0.443 sec (32.346 M lines/sec)
```
Hashgen has a top recorded hashrate of 32.346 million md5/sec on the test rig's Ryzen 7 3700X CPU. (see benchmarks) Much faster hashrates have been seen on newer / faster CPUs.

Hashgen is a CLI hash generator written in Go and can be cross-compiled for Linux, Raspberry Pi, Windows & Mac, although testing and compiling is mainly done on Debian 12 Linux.

To use hashgen, type your mode, wordlist input & hash output files with a simple command line.

### Features:
- Maintains original input order [PR 10](https://github.com/cyclone-github/hashgen/pull/10)
- Supports 130+ modes/functions (see list below)
- Encode / decode base64, base58, base32
- Hex / dehex wordlists
- Supports ASCII, UTF-8 and $HEX[] input
- Supports UTF-8 (default) or $HEX[] output
- Supports multiple salted modes
- Also supports HMAC, KDF, scrypt, bcrypt, Linux shadow modes, checksums, morsecode, etc

| Usage Examples | Command Line |
|-----------|-----------|
| read wordlist.txt, hash to md5 and write to output.txt | ./hashgen -m md5 -w wordlist.txt -o output.txt |
| pipe wordlist into hashgen and write to stdout | cat wordlist.txt \| ./hashgen -m md5 |
| decode $HEX[] wordlist to plaintext | ./hashgen -m plaintext -w hex_wordlist.txt |
| convert wordlist to $HEX[] | ./hashgen -m hex -w wordlist.txt |
| output hash:plain | ./hashgen -m md5 -w wordlist.txt -hashplain |
| benchmark md5 | ./hashgen -m md5 -w wordlist.txt -b |

### Supported Options:
| Flag: | Description: |
|-----------|-----------|
| -m  | {mode} |
| -w  | {wordlist input} |
| -t  | {cpu threads} |
| -o  | {wordlist output} |
| -b  | {benchmark mode} |
| -i  | {iterations - PBKDF2} |
| -cost  | {bcrypt} |
| -hashplain  | {generates hash:plain pairs} |
| -help  | {help menu} |
| -version  | {version info} |

### Supported Functions:
| Function: | Hashcat Mode: |
|-----------------|----------------|
| **`Plaintext & Encoding`** | |
| plaintext/dehex | 99999 (decode $HEX[]) |
| hex | (encode to $HEX[]) |
| base32decode | |
| base32encode | |
| base58decode | |
| base58encode | |
| base64decode | |
| base64encode | |
| morsecode | (ITU-R M.1677-1) |
| morsedecode | (ITU-R M.1677-1) |
| | |
| **`Checksums`** | |
| crc32 | |
| 11500 | (CRC32 Hashcat format) |
| crc64 | |
| | |
| **`MDx`** | |
| md4 | 900 |
| md5 | 0 |
| halfmd5 | 5100 |
| md5passsalt | 10 |
| md5saltpass | 20 |
| md5utf16passsalt | 30 |
| md5utf16saltpass | 40 |
| hmacmd5pass | 50 |
| hmacmd5salt | 60 |
| md5utf16le | 70 |
| md5md5 | 2600 |
| 3500 | (md5(md5(md5($pass)))) |
| 4300 | (md5(strtoupper(md5($pass)))) |
| 4400 | (md5(sha1($pass))) |
| 32800 | (md5(sha1(md5($pass)))) |
| | |
| **`MD6`** | |
| md6128 | |
| md6224 | |
| md6256 | 34600 |
| md6384 | |
| md6512 | |
| | |
| **`SHA1`** | |
| sha1 | 100 |
| ldapsha | 101 (Netscape LDAP {SHA}) |
| sha1passsalt | 110 |
| ssha | 111 (NSLDAPS SSHA-1) |
| sha1saltpass | 120 |
| sha1utf16passsalt | 130 |
| sha1utf16saltpass | 140 |
| hmacsha1pass | 150 |
| hmacsha1salt | 160 |
| sha1utf16le | 170 |
| sha1sha1 | 4500 |
| 4700 | (sha1(md5($pass))) |
| 18500 | (sha1(md5(md5($pass)))) |
| 18501 | (sha1(md5(sha1($pass)))) |
| | |
| **`SHA2`** | |
| sha224 | 1300 |
| sha224passsalt | 1310 |
| sha224saltpass | 1320 |
| 34400 | (sha224(sha224($pass))) |
| 34500 | (sha224(sha1($pass))) |
| sha256 | 1400 |
| sha256passsalt | 1410 |
| ssha256 | 1411 (LDAP {SSHA256}) |
| sha256saltpass | 1420 |
| sha256utf16passsalt | 1430 |
| sha256utf16saltpass | 1440 |
| hmacsha256pass | 1450 |
| hmacsha256salt | 1460 |
| sha256utf16le | 1470 |
| 20800 | (sha256(md5($pass))) |
| 35900 | (sha256(sha1($pass))) |
| sha384 | 10800 |
| sha384passsalt | 10810 |
| sha384saltpass | 10820 |
| sha384utf16passsalt | 10830 |
| sha384utf16saltpass | 10840 |
| sha384utf16le | 10870 |
| sha512 | 1700 |
| sha512passsalt | 1710 |
| ssha512 | 1711 (LDAP {SSHA512}) |
| sha512saltpass | 1720 |
| sha512utf16passsalt | 1730 |
| sha512utf16saltpass | 1740 |
| hmacsha512pass | 1750 |
| hmacsha512salt | 1760 |
| sha512utf16le | 1770 |
| sha512224 | |
| sha512256 | |
| | |
| **`SHA3`** | |
| sha3224 | 17300 |
| sha3256 | 17400 |
| sha3384 | 17500 |
| sha3512 | 17600 |
| | |
| **`Keccak`** | |
| keccak224 | 17700 |
| keccak256 | 17800 |
| keccak384 | 17900 |
| keccak512 | 18000 |
| | |
| **`BLAKE2`** | |
| blake2s256 | |
| 31000 | (BLAKE2s-256 $BLAKE2$ format) |
| hmacblake2spass | 33300 |
| blake2b256 | |
| 34800 | (BLAKE2b-256 $BLAKE2$ format) |
| blake2b256passsalt | 34810 |
| blake2b256saltpass | 34820 |
| blake2b384 | |
| blake2b512 | |
| 600 | (BLAKE2b-512 $BLAKE2$ format) |
| blake2b512passsalt | 610 |
| blake2b512saltpass | 620 |
| | |
| **`Other Hashes`** | |
| ntlm | 1000 (Windows NT) |
| mysql4/mysql5 | 300 |
| ripemd160 | 6000 |
| hmacripemd160pass | 6050 |
| hmacripemd160salt | 6060 |
| | |
| **`Streebog / GOST R 34.11-2012`** | |
| streebog256 | 11700 |
| hmacstreebog256pass | 11750 |
| hmacstreebog256salt | 11760 |
| streebog512 | 11800 |
| hmacstreebog512pass | 11850 |
| hmacstreebog512salt | 11860 |
| | |
| **`Crypt / KDF`** | |
| argon2id | 34000 |
| bcrypt | 3200 |
| bcryptmd5 | 25600 |
| bcryptsha1 | 25800 |
| bcryptsha512 | 28400 |
| bcryptsha256 | 30600 |
| wpbcrypt | 35500 (WordPress bcrypt-HMAC-SHA384) |
| md5crypt | 500 (Linux shadow $1$) |
| sha1crypt | 15100 (NetBSD/Juniper SHA1 crypt) |
| sha256crypt | 7400 (Linux shadow $5$) |
| sha512crypt | 1800 (Linux shadow $6$) |
| sm3crypt | 35100 (Unix $sm3$) |
| phpass/phpbb3 | 400 ($P$ / $H$) |
| scrypt | 8900 |
| pbkdf2sha256 | 10900 |
| pbkdf2md5 | 11900 |
| pbkdf2sha1 | 12000 |
| pbkdf2sha512 | 12100 |
| yescrypt | (Linux shadow $y$) |
| gostyescrypt | (Linux shadow $gy$) |
| cmiyc | (KoreLogic CMIYC 2026 contest algorithm) |

### Benchmarks:
- https://github.com/cyclone-github/hashgen-testing/tree/main/benchmarks
- In addition to hashgen (Go), I have also written hashgen in Python, PHP, C, and Rust, although Rust and C need a lot of work to unlock their full performance potential. If you speak C or Rust, I'd be curious to see how fast you can push hashgen!
  - https://github.com/cyclone-github/hashgen-testing

### Compile from source:
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/hashgen.git`  # clone repo
  - `cd hashgen`                                               # enter project directory
  - `go mod tidy`                                              # download dependencies
  - `go build -ldflags="-s -w" .`                              # compile binary in current directory
  - `go install -ldflags="-s -w" .`                            # compile binary and install to $GOPATH
- Compile from source code how-to:
  - https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt

### Changelog:
- https://github.com/cyclone-github/hashgen/blob/main/CHANGELOG.md

### Mentions:
- Go Package Documentation: https://pkg.go.dev/github.com/cyclone-github/hashgen
- hashcat wiki: https://hashcat.net/wiki/
- hashkiller forum: https://forum.hashkiller.io/index.php?threads/cyclone-hashgen.63140/
- hashpwn forum: https://forum.hashpwn.net/post/89
- MajorGeeks: https://www.majorgeeks.com/files/details/hashgen.html
- Softpedia: https://www.softpedia.com/get/System/File-Management/hashgen-go.shtml

### Antivirus False Positives:
- Several antivirus programs on VirusTotal incorrectly detect hashgen as a false positive. This issue primarily affects the Windows executable binary, but is not limited to it. If this concerns you, I recommend carefully reviewing hashgen's source code, then proceed to compile the binary yourself.
- Uploading your compiled hashgen binaries to https://virustotal.com and leaving an upvote or a comment would be helpful.

### Thoughts:
- Why write hashgen? hashgen is nothing new (to me) as this project started several years ago while needing a way to quickly convert wordlists to md5 or sha1 on a Linux terminal. Several versions of hashgen have been written over the years in several languages: Python, PHP, Go, C and Rust. While the actively maintained version is hashgen (Go), which offers enhanced features and superior performance, the "hashgen-testing" repository linked below contains testing versions of hashgen in different programming languages:
  - https://github.com/cyclone-github/hashgen-testing
- Why write hashgen in Go instead of xyz language? I did this to push my Go coding skills while also seeing how fast I could push Go. During early testing, I was not expecting hashgen to be all that fast, but I have been pleasantly surprised!
- When I realized hashgen (Go) was competitively fast compared to other publicly available hash generators, I decided to publish hashgen's code and binaries for others to use. I've really enjoyed this project and I hope you find it useful.
- If you found hashgen to be helpful, please consider giving this repository a star!
