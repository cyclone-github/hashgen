### hashgen (python)
- this is a simplified version of hashgen written in python3
- fun fact, python3 is the first language hashgen was written in
- hashgen (go) will remain my primary implementation of hashgen and I do not expect hashgen (python) to be maintained

## usage example:
- python3 hashgen.py -m md5 -w wordlist.txt -o output.txt

### version history
- v2022.12.16-0900; initial github release
- v2023.03.15-1445; updated github version to include all hashlib supported algo's, and add program flags for wordlist, algo, output file, version, help, etc
- v2023.10.30-1615; added multiprocessing support; added write buffer