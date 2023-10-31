# hashgen (Go) - Cyclone's hash generator
![image](https://i.imgur.com/n11gZHM.png)

As of the this writing, hashgen (Go) has the fastest md5 hash rate of any publicly available CPU based hash generator I've tested (this isn't a race, just an observation -- see benchmarks). These hashrates can be easily beat by improved code optimization and/or coding in faster programming languages.

Hashgen is a CLI hash generator written in Go and can be cross compiled for Linux, Raspberry Pi, Windows & Mac, although testing and compiling is mainly done on debian 12 linux.

To use hashgen, type your mode, wordlist input & hash output files with a simple command line.
```
$ ./hashgen.bin -m md5 -w rockyou.txt -o /dev/null
2023/08/19 20:04:15 Starting...
2023/08/19 20:04:15 Processing file: wordlist/rockyou.txt
2023/08/19 20:04:15 Hash function: md5
2023/08/19 20:04:19 Finished hashing 15053568 lines in 3.760 sec (4.003 M lines/sec)
```
### Features
- Supports multiple hashing functions (see list below)
- Encode & decode base64
- Supports ASCII, UTF-8 and $HEX[] wordlist input
- - Can also be used to dehex a wordlist by setting mode to "-m plaintext" which will output wordlist to plaintext

| Useage Examples | Command Line |
|-----------|-----------|
| read wordlist.txt, hash to md5 and write to output.txt | ./hashgen -m md5 -w wordlist.txt -o output.txt |
| pipe wordlist into hashgen and write to stdout | cat wordlist.txt \| ./hashgen -m md5 |
| dehex hex_wordlist to plaintext wordlist | ./hashgen -m plaintext -w hex_wordlist.txt -o wordlist.txt |
| bcrypt is very slow, but is POF | ./hashgen -m bcrypt -cost 8 -w wordlist.txt -o output.txt |

### Supported Functions

| Function: | Hashcat Mode: |
|-----------|-----------|
| argon2id | |
| base64encode | |
| base64decode | |
| bcrypt | 3200 |
| blake2b-256 | |
| blake2b-384 | |
| blake2b-512 | 600 |
| blake2s-256 | |
| crc32 | 11500 |
| crc64 | |
| md4 | 900 |
| md5 | 0 |
| ntlm | 1000 |
| plaintext | 99999 |
| ripemd-160 | 6000 |
| sha1 | 100 |
| sha2-224 | 1300 |
| sha2-256 | 1400 |
| sha2-384 | 10800 |
| sha2-512 | 1700 |
| sha2-512-224 | |
| sha2-512-256 | |
| sha3-224 |17300 |
| sha3-256 | 17400 |
| sha3-384 | 17400 |
| sha3-512 | 17400  |

Note, bcrypt and especially argon2id modes are very slow (see benchmarks) and are only included as a POC.

### Hash generator benchmarks
- https://github.com/cyclone-github/hashgen/tree/main/benchmarks
- In addition to hashgen (Go), I have also written hashgen in python, php, C, and Rust, although Rust and C need a lot of work to unlock their full performance potential.

### compile hashgen from source
- If you want the latest hashgen features, compiling from source is the best option since the release version may run several revisions behind the source code.
- Compile from source code info:
- https://github.com/cyclone-github/scripts/blob/main/intro_to_go.txt

### version history
- v2022-12-15.2030; initial github release
- v2022-12-16.1800; fixed ntlm hash function, tweaked -w flag to be less restrictive, clean up code
- v2022-12-17.2100; fixed typo in wordlist tag, added '-m plaintext' output mode (prints -w wordlist file to stdout)
- v2022-12-20.1200; cleaned up bcrypt code
- v2022-12-20.1430-goroutine; complete rewrite using goroutines & read/write buffers
- v2022-12-21.1400-goroutine; added multiple new algo's including hashcat mode equivalents
- v2022-12-24.1800-optimize; optimized all hashing functions, tweaked buffer size
- v2023-03-15.0900-optimize; added "stdout", edited "lines/sec" to show "M lines/sec", tweaked output buffer for stdout, tweaked sha2xxx flags
- v2023-03-28.1155-optimize; added "stdin"
- v2023-05-13.0000-optimize; optimized code all hashing functions for better performance (version not released on github)
- v2023-08-15.1900-hashplain; added: -hashplain flag for hash:plain output, support for $HEX[] wordlist, -cost flag for bcrypt, tweaked: write buffers & custom buffers for argon & bcrypt, tweaked logging outputs
- v2023-08-16.1200-hashplain; added error correction to 'fix' improperly formatted $HEX[] lines

### thoughts
- Why write hashgen? hashgen is nothing new (to me) as this project started several years ago while needing a way to quickly convert wordlists to md5 or sha1 on linux terminal. Several versions of hashgen have been written over the years in several languages: python, php, C and Go. All versions are included in this github repository, although hashgen (Go) is the only maintained version as it includes more features and better performance. 
- Why write hashgen in Go instead of xyz language? I did this to push my Go coding skills while also seeing how fast I could push Go. During early testing, I was not expecting hashgen to be all that fast, but I have been pleasantly surprised... and there is still a lot of room for improvement.
- When I realized hashgen (Go) was competitively fast compared to other publicly available hash generators, I decided to publish hashgen's code and binaries for others to use. I've really enjoyed this project and I hope you find it useful. 
