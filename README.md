# hashgen
Hashgen is a simple CLI hash generator written in go and cross compiled for Linux, Windows & Mac.

Set your mode and wordlist with a simple command line, press enter and hashgen writes hashes to stdout.

In addition to multiple hashing functions, hashgen can also encode / decode base64.

Example Usage:
- ./hashgen -help
- ./hashgen -version
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

While hashgen is not super fast at the moment, it has been a fun project to work on.
I plan on adding more features and optimizing the code as time allows. 

### Hash generator benchmarks
https://github.com/cyclone-github/hashgen/tree/main/benchmarks

### Compile hashgen from source
- If you want the latest hashgen features, compiling from source is the best option since the release version may run several revisions behind the source code.
- Download and install go https://go.dev/doc/install
- Download hashgen.go and open a terminal / command prompt in that directory
- Type "go run hashgen.go -version". You should see the current version of hashgen print out (Cyclone hash generator v2022-12-xx.xxxx).
- Now type "go build hashgen.go" to compile hashgen.go.
- You will notice your binary is much larger than the ones I've uploaded. This is due to the flags used during compiling and my binaries are compressed with upx.
- Some antivirus software on Windows may block hashgen-x64.exe from running. If this happens, you can add an exception to your antivirus software.
