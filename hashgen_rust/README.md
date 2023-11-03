### hashgen (rust)
- this is a complete (simplified) rewrite of hashgen in Rust
- this was a fun challenge as I have not previously developed in Rust
- if you have a faster implimentation of hashgen in Rust, please contact me and I'll be glad to post your code!
- hashgen (go) will remain my primary implementation of hashgen and I do not expect hashgen (rust) to be maintained

## usage example:
- ./hashgen.bin -m md5 -w wordlist.txt -o output.txt

### version history
- v2023-10-30.1615; initial github release

### compile from source:
- cargo build --release