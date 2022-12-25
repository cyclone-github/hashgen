# Benchmarks (v2022-12-24.1800-optimize)

### Test rig specs:
 - OS: Linux 5.15.64-1 (Debian 10.2.1-6)
 - CPU: AMD Ryzen 7 3700X 8-Core Processor @ 3600MHz
 - RAM: 64gb DDR4
 
### hashgen benchmarks for all 26 supported modes

| Mode  | h/s |
| ------------- | ------------- | 
| plaintext	|	15,713,183 |
| base64decode	|	7,871,970 |
| crc64	|	7,746,863 |
| crc32	|	7,664,947 |
| base64encode	|	7,612,708 |
| md5	|	3,614,079 |
| sha1	|	3,079,162 |
| sha2-224	|	3,034,407 |
| blake2s-256	|	2,730,162 |
| md4	|	2,460,707 |
| sha2-256	|	2,459,661 |
| blake2b-256	|	2,416,962 |
| sha2-384	|	2,406,333 |
| blake2b-384	|	2,286,107 |
| sha2-512-224	|	2,282,302 |
| sha2-512-256	|	2,263,304 |
| blake2b-512	|	2,153,610 |
| sha2-512	|	2,025,476 |
| ripemd-160	|	1,746,941 |
| ntlm	|	1,654,819 |
| sha3-224	|	1,273,333 |
| sha3-384	|	1,271,204 |
| sha3-256	|	1,270,070 |
| sha3-512	|	1,269,211 |
| bcrypt (MinCost)	|	1,281.2 |
| argon2id	|	12.2 |

### Hash generator benchmarks
 - Head to head comparison of different hash generators
 - All testing was performed hashing rockyou.txt (15,053,568 lines) to md5
 - All hashing stdout was written to /dev/null
 - Benchmarks are an average of 5x runtimes

### Results:
| Program  | Time/s | h/s |
| ------------- | ------------- | ------------- |
| hashgen	| 4.165s | 3,614,079 |
| php8.2	| 5.293s | 2,844,052 |
| mdxfind	| 13.0463s | 1,153,857 |
| Python3.9	| 19.985s | 753,243 |
| ULM | 129s | 116,694 |
| bash | 2h+ | N/A |

- go v1.19.4 (hashgen) https://github.com/cyclone-github/hashgen/commit/1b73f08b095138ab3274de20a0e74a8e3a087fc0
- php v8.2 https://github.com/cyclone-github/hashgen/blob/main/benchmarks/hashgen.php
- mdxfind https://github.com/cyclone-github/mdxfind
- Python 3.9.2 https://github.com/cyclone-github/hashgen/blob/main/benchmarks/hashgen.py
- ULM v1E139 https://github.com/cyclone-github/hashgen/blob/main/benchmarks/ulm_results.txt (tested using wine on debian linux)
- Linux Bash https://github.com/cyclone-github/hashgen/blob/main/benchmarks/hashgen.sh

### Test rig specs:
 - OS: Linux 5.15.64-1 (Debian 10.2.1-6)
 - CPU: AMD Ryzen 7 3700X 8-Core Processor @ 3600MHz
 - RAM: 64gb DDR4
