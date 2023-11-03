### hashgen (php)
- this is a simplified version of hashgen written in php
- hashgen (php) has been surprisingly fast and has always remained a top performer during benchmarks 
  - https://github.com/cyclone-github/hashgen/tree/main/benchmarks
- hashgen (go) will remain my primary implementation of hashgen and I do not expect hashgen (php) to be maintained

## usage example:
- php hashgen.php -m md5 -w wordlist.txt -o output.txt

### version history
- v2022-12-16.0900; github release
- v2023-03-15.1445; updated github version to include all php supported algo's, and add program flags for wordlist, algo, output file, version, help, etc
- v2023-10-30.1615; added write buffer; tweaked read buffer