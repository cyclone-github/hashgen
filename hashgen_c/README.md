### hashgen (c)
- this is a complete rewrite of hashgen in C
- other than micro controller / embedded systems, I have little coding experience with C
- hashgen (Go) will remain my primary implementation of hashgen and I do not expect hashgen (C) to be maintained
- hashgen (C) uses openssl for all hashing functions

## usage example:
- ./hashgen.bin -m md5 -w wordlist.txt -o output.txt
- cat wordlist.txt | ./hashgen.bin -m md5 > output.txt

### version history
- v2023-03-18.1945; initial github release
- v2023-03-27.1945; removed mutex locks for better performance
- v2023-04-25.1020; handle memory allocations using malloc, count processed lines using atomic_size for thread safety
- v2023-06-05.1810; default to stdin if -w not specified and stdout if -o not specified

### compile from source:
- gcc -o hashgen_c.bin hashgen.c -lcrypto -lpthread -O3