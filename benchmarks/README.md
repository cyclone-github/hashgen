# Benchmarks

### Test rig specs:
 - OS: Linux pve 6.2.16-4-pve (Debian 12.1)
 - CPU: AMD Ryzen 7 3700X 8-Core Processor @ 3600MHz
 - RAM: 64gb DDR4
 
### hashgen benchmarks for all 26 supported modes

| Mode  | h/s |
| ------------- | ------------- | 
| plaintext | 18,006,660 |
| base64decode | 8,062,972 |
| crc64 | 7,746,863 |
| crc32 | 7,664,947 |
| base64encode | 7,612,708 |
| md5 | 4,031,486 |
| sha2-224 | 4,868,554 |
| sha2-256 | 4,125,395 |
| sha1 | 3,513,905 |
| blake2s-256 | 3,034,994 |
| md4 | 2,901,613 |
| blake2b-256 | 2,860,264 |
| sha2-384 | 2,573,259 |
| blake2b-384 | 2,286,107 |
| sha2-512-224 | 2,447,337 |
| sha2-512-256 | 2,516,898 |
| blake2b-512 | 2,538,544 |
| sha2-512 | 2,257,922 |
| ripemd-160 | 1,689,135 |
| ntlm | 1,846,610 |
| sha3-224 | 1,350,096 |
| sha3-384 | 1,307,869 |
| sha3-256 | 1,374,755 |
| sha3-512 | 1,333,000 |
| bcrypt (MinCost) | 1,281.2 |
| argon2id | 12.2 |

### Hash generator benchmarks
 - Head to head comparison of different hash generators
 - All testing was performed hashing rockyou.txt (15,053,568 lines) to md5
 - Hashing was written to /dev/null where applicable, or to an ssd zpool (this was to keep write speed from being a bottleneck)
 - Benchmarks are an average of 5x runtimes

### Results:
| Program  | Time/s | h/s |
| ------------- | ------------- | ------------- |
| hashgen (go)	| 3.734s | 4,031,486 |
| hashgen (c)	| 4.120s | 3,652,047 |
| hashgen (php)	| 5.293s | 2,844,052 |
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
