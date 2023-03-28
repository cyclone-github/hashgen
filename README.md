# hashgen (Go) - Cyclone's hash generator
As of the latest release, hashgen (Go) has the fastest md5 hash rate of any publicly available CPU based hash generator I've tested (this isn't a race, just an observation -- see benchmarks). These hashrates can be easily beat by improved code optimization and/or coding in faster programming languages. 
I plan to add more features and code optimizations as time allows. Bcrypt and especially argon2id modes are very slow (see benchmarks).

Hashgen is a simple CLI hash generator written in Go and can be cross compiled for Linux, Windows & Mac, although testing and compiling is mainly done on debian linux.

To use hashgen, simply type your mode, wordlist input & hash output files with a simple command line and press enter.

In addition to supporting multiple hashing functions, hashgen (Go) can also encode / decode base64.

Example Usage:

./hashgen -m md5 -w wordlist.txt -o output.txt

or

cat wordlist.txt | ./hashgen -m md5 -w stdin -o stdout

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

### Hash generator benchmarks
- https://github.com/cyclone-github/hashgen/tree/main/benchmarks
- In addition to hashgen (Go), I have also written hashgen in python, php and C, although hashgen (C) needs a lot of work to unlock its performance potential. 

### compile hashgen from source
- If you want the latest hashgen features, compiling from source is the best option since the release version may run several revisions behind the source code.
- Download and install go https://go.dev/doc/install
- Download hashgen.go and open a terminal / command prompt in that directory
- Type "go run hashgen.go -version". You should see the current version of hashgen print out (Cyclone hash generator v2023-xx-xx.xxxx).
- Now type "go build hashgen.go" to compile hashgen.go.
- You will notice your binary is much larger than the ones I've uploaded. This is due to the flags used during compiling and my binaries are stripped, then compressed with upx.
- Some Windows antivirus software may block hashgen.exe from running. If this happens, you can add an exception to your antivirus software.

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

### thoughts
- Why write hashgen? hashgen is nothing new (to me) as this project started several years ago while needing a way to quickly convert wordlists to md5 or sha1 on linux terminal. Several versions of hashgen have been written over the years in several languages: python, php, C and Go. All versions are included in this github repository, although hashgen (Go) is the only maintained version as it includes more features and better performance. 
- Why write hashgen in Go instead of xyz language? I did this to push my Go coding skills while also seeing how fast I could push Go. During early testing, I was not expecting hashgen to be all that fast, but I have been pleasantly surprised... and there is still a lot of room for improvement.
- When I realized hashgen (Go) was competitively fast compared to other publicly available hash generators, I decided to publish hashgen's code and binaries for others to use. I've really enjoyed this project and I hope you find it useful. 
