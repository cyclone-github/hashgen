# Benchmarks

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
| md5	|	3,805,250 |
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
 - Hashing was written to /dev/null where applicable, or to an ssd zpool (this was to keep write speed from being a bottleneck)
 - Benchmarks are an average of 5x runtimes

### Results:
| Program  | Time/s | h/s |
| ------------- | ------------- | ------------- |
| hashgen (go)	| 3.956s | 3,805,250 |
| hashgen (php)	| 5.293s | 2,844,052 |
| hashgen (c)	| 5.436s | 2,769,024 |
| mdxfind	| 13.0463s | 1,153,857 |
| hashgen (python)	| 19.985s | 753,243 |
| hashcat test.pl	| 23.086s | 653,840 |
| ULM | 129s | 116,694 |
| bash | 2h+ | N/A |

- hashgen (go) https://github.com/cyclone-github/hashgen/releases
- hashgen (php) https://github.com/cyclone-github/hashgen/tree/main/hashgen_php
- hashgen (c) https://github.com/cyclone-github/hashgen/tree/main/hashgen_c
- mdxfind https://github.com/cyclone-github/mdxfind
- hashgen (python) https://github.com/cyclone-github/hashgen/tree/main/hashgen_python
- hashcat test.pl https://github.com/hashcat/hashcat/blob/master/tools/test.pl
- ULM v1E139 https://github.com/cyclone-github/hashgen/blob/main/benchmarks/ulm_results.txt (tested using wine on debian linux, so take this with a grain of salt)
- Linux Bash https://github.com/cyclone-github/hashgen/blob/main/benchmarks/hashgen.sh
