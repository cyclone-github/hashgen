[![Readme Card](https://github-readme-stats.vercel.app/api/pin/?username=cyclone-github&repo=hashgen&theme=gruvbox)](https://github.com/cyclone-github/hashgen/)

<!-- [![Go Report Card](https://goreportcard.com/badge/github.com/cyclone-github/hashgen)](https://goreportcard.com/report/github.com/cyclone-github/hashgen) -->
[![GitHub issues](https://img.shields.io/github/issues/cyclone-github/hashgen.svg)](https://github.com/cyclone-github/hashgen/issues)
[![License](https://img.shields.io/github/license/cyclone-github/hashgen.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/release/cyclone-github/hashgen.svg)](https://github.com/cyclone-github/hashgen/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/cyclone-github/hashgen.svg)](https://pkg.go.dev/github.com/cyclone-github/hashgen)

# hashgen - Cyclone's hash generator
```
$ ./hashgen_amd64.bin -m 0 -w rockyou.txt -o /dev/null
2024/12/10 19:07:31 Starting...
2024/12/10 19:07:31 Processing file: rockyou.txt
2024/12/10 19:07:31 Hash function: 0
2024/12/10 19:07:31 CPU Threads: 16
2024/12/10 19:07:31 Finished processing 14344391 lines in 0.475 sec (30.228 M lines/sec)
```
**As of the this writing, hashgen (go) has a 2,519% faster md5 hashrate vs the next fastest publicly available CPU based hash generator (see benchmarks).** While this is extremely fast, these hashrates can be beat by improved code optimization and/or coding in faster programming languages (I'm looking at you C, Rust and Zig).

Since version `v2023-10-30.1600`, hashgen has a top recorded hasharate of 30,228,048 md5/sec on the test rig's Ryzen 7 3700X CPU! Much faster hashrates have been seen on higher end CPU's.

Hashgen is a CLI hash generator written in Go and can be cross compiled for Linux, Raspberry Pi, Windows & Mac, although testing and compiling is mainly done on debian 12 linux.

To use hashgen, type your mode, wordlist input & hash output files with a simple command line.

### Features:
- Supports multiple hashing functions (see list below)
- Encode / decode base64 & base58
- Supports ASCII, UTF-8 and $HEX[] wordlist input
  - Can also be used to dehex a wordlist by setting mode to "-m plaintext" which will output wordlist to plaintext

| Useage Examples | Command Line |
|-----------|-----------|
| read wordlist.txt, hash to md5 and write to output.txt | ./hashgen -m md5 -w wordlist.txt -o output.txt |
| pipe wordlist into hashgen and write to stdout | cat wordlist.txt \| ./hashgen -m md5 |
| dehex hex_wordlist to plaintext wordlist | ./hashgen -m plaintext -w hex_wordlist.txt -o wordlist.txt |

### Supported Functions:
| Function: | Hashcat Mode: |
|-----------|-----------|
| argon2id | |
| base58encode | |
| base58decode | |
| base64encode | |
| base64decode | |
| bcrypt | 3200 |
| morsecode | (ITU-R M.1677-1) |
| crc32 | |
| 11500 | 11500 (hashcat compatible CRC32)|
| crc64 | |
| md4 | 900 |
| md5 | 0 |
| ntlm| 1000|
| plaintext | 99999 (can be used to dehex wordlist) |
| ripemd-160| 6000|
| sha1| 100 |
| sha2-224| 1300|
| sha2-256| 1400|
| sha2-384| 10800 |
| sha2-512| 1700|
| sha2-512-224| |
| sha2-512-256| |
| sha3-224| 17300 |
| sha3-256| 17400 |
| sha3-384| 17500 |
| sha3-512| 17600 |
| keccak-256| 17800 |
| keccak-512| 18000 |
| yescrypt | |

### Benchmarks:
- https://github.com/cyclone-github/hashgen-testing/tree/main/benchmarks
- In addition to hashgen (go), I have also written hashgen in python, php, C, and Rust, although Rust and C need a lot of work to unlock their full performance potential. If you speak C or Rust, I'd be curious to see how fast you can push hashgen!
  - https://github.com/cyclone-github/hashgen-testing

### Compile hashgen from source:
- If you want the latest features, compiling from source is the best option since the release version may run several revisions behind the source code.
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
