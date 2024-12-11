### v1.0.0; 2024-12-10
```
v1.0.0 release
```
### v2024-11-04.1445-threaded
```
fixed https://github.com/cyclone-github/hashgen/issues/5
added CPU threaded info to -help
cleaned up code and print functions
```
### v2024-11-01.1630-threaded
```
added thread flag "-t" to allow user to specity CPU threads, ex: -t 16 // fixed default to use max CPU threads
added modes: sha2-224, sha2-384, sha2-512-224, sha2-512-256, keccak-256, keccak-512
```
### v2024-08-24.2000-threaded
```
added mode "morsecode" which follows ITU-R M.1677-1 standard
```
### v2023-11-04.1330-threaded
```
tweaked -m 11500
tweaked HEX error correction
added reporting when encountering HEX decoding errors
```
### v2023-11-03.2200-threaded
```
added hashcat -m 11500 (CRC32 w/padding)
re-added CRC32 / CRC64 modes
fixed stdin
```
### v2023-10-30.1600-threaded
```
rewrote code base for multi-threading support
some algos have not been implemented from previous version
```