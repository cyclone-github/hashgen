package main

import (
    "bufio"
    "golang.org/x/crypto/md4"
    "golang.org/x/crypto/bcrypt"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/binary"
    "encoding/base64"
    "encoding/hex"
    "unicode/utf16"
    "flag"
    "fmt"
    "log"
    "hash/crc32"
    "os"
    "io"
    "strconv"
)
// version history
// v2022-12-15.2030; initial release
// v2022-12-16.1800; fixed ntlm hash function
func versionFunc() {
    funcBase64Decode("Q3ljbG9uZSBoYXNoIGdlbmVyYXRvciB2MjAyMi0xMi0xNi4xODAwCg==")
}
// help function
func helpFunc() {
    versionFunc()
    str := "Prints to stdout.\n"+
            "\nExample Usage:"+
            "\n./hashgen -m md5 -w wordlist.txt"+
            "\n./hashgen -m md5 -w wordlist.txt > output.txt\n"+
            "\nSupported functions:\nbase64decode\nbase64encode\nbcrypt\ncrc32\nmd4\nmd5\nntlm\nsha1\nsha256\nsha512\n"
    fmt.Println(str)
    os.Exit(0)
} 
// main function
func main() {
    m := flag.String("m", "", "Mode:")
    w := flag.String("w", "", "Path to wordlist:")
    version := flag.Bool("version", false, "Prints program version:")
    cyclone := flag.Bool("cyclone", false, "")
    help := flag.Bool("help", false, "Prints help:")
    flag.Parse()
// run sanity checks for version & help
    if *version == true {
        versionFunc()
        os.Exit(0)
    } else if *cyclone == true {
        funcBase64Decode("Q29kZWQgYnkgY3ljbG9uZSA7KQo=")
        os.Exit(0)
    } else if *help == true {
        helpFunc()
    }
// run sanity checks on algo input (m)
    if len(*m) < 3 {
        fmt.Println("--> missing '-m algo' <--\n")
        helpFunc()
        os.Exit(0)
    }
// run sanity checks on wordlist input (w)
    if len(*w) < 1 {
        fmt.Println("--> missing '-m wordlist' <--\n")
        helpFunc()
        os.Exit(0)
    } 
    
// call on readWordlistLines
var wordlistFile string = *w
file, err := os.Open(wordlistFile)
if err != nil {
    fmt.Println("--> Wordlist not read <--\n")
    helpFunc()
    os.Exit(0)
}
defer file.Close()
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        // call hash functions for line scanner
        line := scanner.Text()
        if *m == "md5" {
            funcMd5(line)
        } else if *m == "md4" {
            funcMd4(line)
        } else if *m == "ntlm" {
            funcNtlm(line)
        } else if *m == "sha1" {
            funcSha1(line)
        } else if *m == "sha256" {
            funcSha256(line)
        } else if *m == "sha512" {
            funcSha512(line)
        } else if *m == "crc32" {
            funcCrc32(line)
        } else if *m == "bcrypt" {
            funcBcrypt(line)
        } else if *m == "base64encode" {
            funcBase64Encode(line)
        } else if *m == "base64decode" {
            funcBase64Decode(line)
        }
    }
    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }
}
// hashing functions

// md4 hashing function
func funcMd4(line string) {
	hash := md4.New()
	io.WriteString(hash, line)
	fmt.Printf("%x\n", hash.Sum(nil))
}
// ntlm hashing function
// code modified from https://github.com/tv42/ntlmv2hash/blob/master/nthash.go
func funcNtlm(line string) {
    input := utf16.Encode([]rune(line))
    hash := md4.New()
    if err := binary.Write(hash, binary.LittleEndian, input); err != nil {
        panic(fmt.Errorf("Failed NTLM hashing password: %w", err))
    }
    outputHash := hash.Sum(nil)
    // encode to conventional uppercase hex
    fmt.Printf("%X\n", outputHash)
}
// md5 hashing function
func funcMd5(line string) {
	hash := md5.Sum([]byte(line))
	outputHash := hex.EncodeToString(hash[:])
    fmt.Println(outputHash)
}
// sha1 hashing function
 func funcSha1(line string) {
	hash := sha1.Sum([]byte(line))
	outputHash := hex.EncodeToString(hash[:])
    fmt.Println(outputHash)
}
// sha256 hashing function
func funcSha256(line string) {
	hash := sha256.Sum256([]byte(line))
	outputHash := hex.EncodeToString(hash[:])
    fmt.Println(outputHash)
}
// sha256 hashing function
func funcSha512(line string) {
    hash := sha512.Sum512([]byte(line))
    outputHash := hex.EncodeToString(hash[:])
    fmt.Println(outputHash)
}
// bcrypt cost 10 (DefaultCost) hashing function
// https://pkg.go.dev/golang.org/x/crypto/bcrypt
func funcBcrypt(line string) {
    pwd := []byte(line)
    hash := hashAndSalt(pwd)
    fmt.Println(hash)
}
func hashAndSalt(pwd []byte) string {
hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost )
if err != nil {
    log.Println(err)
}
return string(hash)
}
// crc32 hashing function
func funcCrc32(line string) {
    hash := crc32.ChecksumIEEE([]byte(line))
    outputHash := strconv.FormatUint(uint64(hash), 16)
    fmt.Println(outputHash)
}
// base64 encode function
func funcBase64Encode(line string) {
    str := base64.StdEncoding.EncodeToString([]byte(line))
    fmt.Println(str)
}
// base64 decode function
func funcBase64Decode(line string) {
    str, err := base64.StdEncoding.DecodeString(line)
    if err != nil {
		fmt.Println("Wordlist doesn't appear to be base64 encoded.")
        os.Exit(0)
    }
    fmt.Printf("%s\n", str)
}
