# Benchmarks

### Test rig specs:
 - OS: Linux 5.15.64-1 (Debian 10.2.1-6)
 - CPU: AMD Ryzen 7 3700X 8-Core Processor @ 3600MHz
 - RAM: 64gb DDR4
 
### hashgen benchmarks for all supported modes

| Mode  | h/s |
| ------------- | ------------- | 
| plaintext | 2,886,221 |
| base64encode	| 2,298,489 |
| crc32	| 2,233,798 |
| base64decode	| 2,161,109 |
| md5	| 1,847,139 |
| sha1	| 1,716,028 |
| sha256	| 1,497,619 |
| sha512	| 1,318,753 |
| md4	| 1,190,664 |
| ntlm	| 1,017,752 |
| bcrypt	| 159 |

### Hash generator benchmarks
 - Head to head comparison of different hash generators
 - All testing was performed hashing rockyou.txt (15,053,568 lines) to md5
 - All hashing stdout was written to /dev/null
 - Benchmarks are an average of 5x runtimes

### Results:
| Program  | Time/s | h/s |
| ------------- | ------------- | ------------- |
| php8.2		| 5.293s | 2,844,052 |
| go (hashgen)	| 8.150s | 1,847,063 |
| mdxfind		| 13.0463s | 1,153,857 |
| Python3.9	| 19.985s | 753,243 |
| bash | 2h+ | N/A |

- php v8.2 https://github.com/cyclone-github/hashgen/blob/main/benchmarks/hashgen.php
- go v1.19.4 (hashgen) https://github.com/cyclone-github/hashgen/releases/tag/Initial
- mdxfind https://github.com/cyclone-github/mdxfind
- Python 3.9.2 https://github.com/cyclone-github/hashgen/blob/main/benchmarks/hashgen.py
- Linux Bash https://github.com/cyclone-github/hashgen/blob/main/benchmarks/hashgen.sh
