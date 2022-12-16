# hashgen
Cyclone hash generator.

Example Usage:

./hashgen -m md5 -w wordlist.txt

./hashgen -m md5 -w wordlist.txt > output.txt

Supported functions:

base64decode, base64encode, bcrypt, crc32, md4, md5, sha1, sha256, sha512

Written in go 1.19.4 and cross compiled for linux, Windows & Mac.
