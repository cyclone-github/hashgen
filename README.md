[![Readme Card](https://github-readme-stats-fast.vercel.app/api/pin/?username=cyclone-github&repo=hashgen&theme=gruvbox)](https://github.com/cyclone-github/hashgen/)

[![Go Report Card](https://goreportcard.com/badge/github.com/cyclone-github/hashgen)](https://goreportcard.com/report/github.com/cyclone-github/hashgen)
[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/hashgen.svg)](https://github.com/cyclone-github/hashgen/issues)
[![License](https://img.shields.io/github/license/cyclone-github/hashgen.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/hashgen.svg)](https://github.com/cyclone-github/hashgen/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/cyclone-github/hashgen.svg)](https://pkg.go.dev/github.com/cyclone-github/hashgen)

### Install latest published release:
```
go install github.com/cyclone-github/hashgen@latest
```
### Install latest source code (bleeding edge):
```
go install github.com/cyclone-github/hashgen@main
```

# hashgen - Cyclone's hash generator
```
$ hashgen -m md5 -w rockyou.txt -b
2026/04/11 12:28:58 Starting...
2026/04/11 12:28:58 Processing file: /media/ramdisk/rockyou.txt
2026/04/11 12:28:58 Hash function: 0
2026/04/11 12:28:58 CPU Threads: 16
2026/04/11 12:28:58 Finished processing 14344391 lines in 0.446 sec (32.127 M lines/sec)
```
Hashgen has a top recorded hashrate of 32.127 million md5/sec on the test rig's Ryzen 7 3700X CPU. (see benchmarks) Much faster hashrates have been seen on newer / faster CPU's.

Hashgen is a CLI hash generator written in Go and can be cross compiled for Linux, Raspberry Pi, Windows & Mac, although testing and compiling is mainly done on debian 12 linux.

To use hashgen, type your mode, wordlist input & hash output files with a simple command line.

### Features:
- Maintains original input order [PR 10](https://github.com/cyclone-github/hashgen/pull/10)
- Supports 100+ modes/functions (see list below)
- Encode / decode base64, base58, base32
- Hex / dehex wordlists
- Supports ASCII, UTF-8 and $HEX[] input
- Supports UTF-8 (default) or $HEX[] output
- Supports multiple salted modes
- Supports HMAC, KDF, scrypt, bcrypt, linux shadow modes, checksums, morsecode, etc

| Useage Examples | Command Line |
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
| plaintext / dehex | 99999 (decode $HEX[]) |
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
| 11500 | (hashcat compatible CRC32) |
| crc64 | |
| | |
| **`MDx`** | |
| md4 | 900 |
| md5 | 0 |
| md5md5 | 2600 |
| halfmd5 | 5100 |
| md5passsalt | 10 |
| md5saltpass | 20 |
| 30 | (hashcat compatible md5 utf16le($pass).$salt) |
| 40 | (hashcat compatible md5 $salt.utf16le($pass)) |
| 50 | (hashcat compatible HMAC-MD5 key = $pass) |
| 60 | (hashcat compatible HMAC-MD5 key = $salt) |
| 70 | (hashcat compatible md5 utf16le($pass)) |
| | |
| **`MD6`** | |
| md6-128 | |
| md6-224 | |
| md6-256 | 34600 |
| md6-384 | |
| md6-512 | |
| **`SHA1`** | |
| sha1 | 100 |
| sha1sha1 | 4500 |
| sha1passsalt | 110 |
| sha1saltpass | 120 |
| 130 | (hashcat compatible sha1 utf16le($pass).$salt) |
| 140 | (hashcat compatible sha1 $salt.utf16le($pass)) |
| 150 | (hashcat compatible HMAC-SHA1 key = $pass) |
| 160 | (hashcat compatible HMAC-SHA1 key = $salt) |
| 170 | (hashcat compatible sha1 utf16le($pass)) |
| | |
| **`SHA2`** | |
| sha224 | 1300 |
| sha224passsalt | 1310 |
| sha224saltpass | 1320 |
| sha256 | 1400 |
| sha256passsalt | 1410 |
| sha256saltpass | 1420 |
| 1430 | (hashcat compatible sha256 utf16le($pass).$salt) |
| 1440 | (hashcat compatible sha256 $salt.utf16le($pass)) |
| 1450 | (hashcat compatible HMAC-SHA256 key = $pass) |
| 1460 | (hashcat compatible HMAC-SHA256 key = $salt) |
| 1470 | (hashcat compatible sha256 utf16le($pass)) |
| sha384 | 10800 |
| sha384passsalt | 10810 |
| sha384saltpass | 10820 |
| sha512 | 1700 |
| sha512passsalt | 1710 |
| sha512saltpass | 1720 |
| 1730 | (hashcat compatible sha512 utf16le($pass).$salt) |
| 1740 | (hashcat compatible sha512 $salt.utf16le($pass)) |
| 1750 | (hashcat compatible HMAC-SHA512 key = $pass) |
| 1760 | (hashcat compatible HMAC-SHA512 key = $salt) |
| 1770 | (hashcat compatible sha512 utf16le($pass)) |
| sha512-224 | |
| sha512-256 | |
| | |
| **`SHA3`** | |
| sha3-224 | 17300 |
| sha3-256 | 17400 |
| sha3-384 | 17500 |
| sha3-512 | 17600 |
| | |
| **`Keccak`** | |
| keccak-224 | 17700 |
| keccak-256 | 17800 |
| keccak-384 | 17900 |
| keccak-512 | 18000 |
| | |
| **`BLAKE2`** | |
| blake2s-256 | |
| 31000 | (hashcat compatible BLAKE2s-256) |
| 33300 | (hashcat compatible HMAC-BLAKE2s key = $pass) |
| blake2b-256 | |
| 34800 | (hashcat compatible BLAKE2b-256) |
| blake2b-384 | |
| blake2b-512 | |
| 600 | (hashcat compatible BLAKE2b-512) |
| 610 | (hashcat compatible BLAKE2b-512 pass.salt) |
| 620 | (hashcat compatible BLAKE2b-512 salt.pass) |
| 34810 | (hashcat compatible BLAKE2b-256 pass.salt) |
| 34820 | (hashcat compatible BLAKE2b-256 salt.pass) |
| | |
| **`Other Hashes`** | |
| ntlm | 1000 (Windows NT) |
| mysql4/mysql5 | 300 |
| ripemd-160 | 6000 |
| 6050 | (hashcat compatible HMAC-RIPEMD160 key = $pass) |
| 6060 | (hashcat compatible HMAC-RIPEMD160 key = $salt) |
| | |
| **`Crypt / KDF`** | |
| argon2id | 34000 |
| bcrypt | 3200 |
| wpbcrypt | (WordPress bcrypt-HMAC-SHA384) |
| md5crypt | 500 (`Linux shadow $1$`) |
| sha256crypt | 7400 (`Linux shadow $5$`) |
| sha512crypt | 1800 (`Linux shadow $6$`) |
| phpass | 400 (`PHP/WordPress $P$/phpBB3 $H$`) |
| gost-yescrypt | (`Linux shadow $gy$`) |
| yescrypt | (`Linux shadow $y$`) |
| scrypt | 8900 |
| 10900 | (hashcat compatible PBKDF2-HMAC-SHA256) |
| 11900 | (hashcat compatible PBKDF2-HMAC-MD5) |
| 12000 | (hashcat compatible PBKDF2-HMAC-SHA1) |
| 12100 | (hashcat compatible PBKDF2-HMAC-SHA512) |

### Benchmarks:
- https://github.com/cyclone-github/hashgen-testing/tree/main/benchmarks
- In addition to hashgen (go), I have also written hashgen in python, php, C, and Rust, although Rust and C need a lot of work to unlock their full performance potential. If you speak C or Rust, I'd be curious to see how fast you can push hashgen!
  - https://github.com/cyclone-github/hashgen-testing

### Compile from source:
- This assumes you have Go and Git installed
  - `git clone https://github.com/cyclone-github/hashgen.git`  # clone repo
  - `cd hashgen`                                               # enter project directory
  - `go mod init hashgen`                                      # initialize Go module (skips if go.mod exists)
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
- Why write hashgen? hashgen is nothing new (to me) as this project started several years ago while needing a way to quickly convert wordlists to md5 or sha1 on linux terminal. Several versions of hashgen have been written over the years in several languages: python, php, Go, C and Rust. While the actively maintained version is hashgen (go), which offers enhanced features and superior performance, the "hashgen-testing" repository linked below contains testing versions of hashgen in different programming languages:
  - https://github.com/cyclone-github/hashgen-testing
- Why write hashgen in Go instead of xyz language? I did this to push my Go coding skills while also seeing how fast I could push Go. During early testing, I was not expecting hashgen to be all that fast, but I have been pleasantly surprised!
- When I realized hashgen (go) was competitively fast compared to other publicly available hash generators, I decided to publish hashgen's code and binaries for others to use. I've really enjoyed this project and I hope you find it useful.
- If you found hashgen to be helpful, please consider giving this repository a star!
