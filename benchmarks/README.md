# Benchmarks
 
### Latest Version: 
- hashgen v2023-10-30.1600 
- Test rig specs:
  - OS: Linux pve 6.2.16-14-pve (Debian 12.1)
  - CPU: AMD Ryzen 7 3700X 8-Core (16 Thread) Processor @ 3600MHz
  - RAM: 64gb DDR4
- Benchmarks for all 14 supported modes:

| Mode  | h/s |
| ------------- | ------------- | 
| plaintext | 50,178,560 |
| base64encode | 40,036,085 |
| base64decode | 37,823,035 |
| md5 | 30,228,048 |
| sha2-256 | 24,319,173 |
| sha1 | 23,818,937 |
| md4 | 18,935,306 |
| ntlm | 14,282,323 |
| ripemd-160 | 13,823,295 |
| sha2-512 | 12,410,196 |
| sha3-256 | 7,332,473 |
| sha3-224 | 7,206,112 |
| sha3-384 | 6,256,678 |
| sha3-512 | 6,069,987 |

### Hash generator benchmarks
 - Head to head comparison of different hash generators
 - All testing was performed hashing rockyou.txt (15,053,568 lines) to md5
 - Hashing was written to /dev/null where applicable, or to an ssd zpool (this was to keep write speed from being a bottleneck)

### Results:
| Program  | Time/s | h/s |
| ------------- | ------------- | ------------- |
| hashgen (go)  | 0.498s | 30,228,048 |
| hashgen (php) | 3.877s | 3,876,788 |
| hashgen (rust)    | 3.924s | 3,836,281 |
| hashgen (c)   | 4.120s | 3,652,047 |
| hashgen (python)  | 8.611s | 1,748,178 |
| mdxfind	| 13.0463s | 1,153,857 |
| hashcat test.pl	| 23.086s | 653,840 |
| ULM | 129s | 116,694 |
| bash | 2h+ | N/A |

### Previous Version: 
- hashgen v2023-09-28.1730
- Test rig specs:
  - OS: Linux pve 6.2.16-4-pve (Debian 12.1)
  - CPU: AMD Ryzen 7 3700X 8-Core (16 Thread) Processor @ 3600MHz
  - RAM: 64gb DDR4
- Benchmarks for all 26 supported modes

| Mode  | h/s |
| ------------- | ------------- | 
| plaintext | 18,006,660 |
| base64decode | 8,062,972 |
| crc64 | 7,746,863 |
| crc32 | 7,664,947 |
| base64encode | 7,612,708 |
| sha2-224 | 4,868,554 |
| sha2-256 | 4,125,395 |
| md5 | 4,031,486 |
| sha1 | 3,513,905 |
| blake2s-256 | 3,034,994 |
| md4 | 2,901,613 |
| blake2b-256 | 2,860,264 |
| sha2-384 | 2,573,259 |
| blake2b-512 | 2,538,544 |
| sha2-512-256 | 2,516,898 |
| sha2-512-224 | 2,447,337 |
| blake2b-384 | 2,286,107 |
| sha2-512 | 2,257,922 |
| ntlm | 1,846,610 |
| ripemd-160 | 1,689,135 |
| sha3-256 | 1,374,755 |
| sha3-224 | 1,350,096 |
| sha3-512 | 1,333,000 |
| sha3-384 | 1,307,869 |
| bcrypt (MinCost) | 1,281.2 |
| argon2id | 12.2 |

### Links:
- hashgen (go) https://github.com/cyclone-github/hashgen/releases
- hashgen (php) https://github.com/cyclone-github/hashgen/tree/main/hashgen_php
- hashgen (rust) https://github.com/cyclone-github/hashgen/tree/main/hashgen_rust
- hashgen (c) https://github.com/cyclone-github/hashgen/tree/main/hashgen_c
- hashgen (python) https://github.com/cyclone-github/hashgen/tree/main/hashgen_python
- mdxfind https://github.com/cyclone-github/mdxfind
- hashcat test.pl https://github.com/hashcat/hashcat/blob/master/tools/test.pl
- ULM v1E139 https://github.com/cyclone-github/hashgen/blob/main/benchmarks/ulm_results.txt
- Linux Bash https://github.com/cyclone-github/hashgen/blob/main/benchmarks/hashgen.sh