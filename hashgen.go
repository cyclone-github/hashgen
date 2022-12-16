package main

import (
    "bufio"
    "golang.org/x/crypto/md4"
    "golang.org/x/crypto/bcrypt"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/base64"
    "encoding/hex"
    "flag"
    "fmt"
    "log"
    "hash/crc32"
    "os"
    "io"
    "strconv"
)
// version
func versionFunc() {
    wordlistBase64Decode("Q3ljbG9uZSBoYXNoIGdlbmVyYXRvciB2MjAyMi0xMi0xNS4yMDMwCg==")
}
// help function
func helpFunc() {
    versionFunc()
    str := "Prints to stdout.\n"+
            "\nExample Usage:"+
            "\n./hashgen -m md5 -w wordlist.txt"+
            "\n./hashgen -m md5 -w wordlist.txt > output.txt\n"+
            "\nSupported functions:\nbase64decode\nbase64encode\nbcrypt\ncrc32\nmd4\nmd5\nsha1\nsha256\nsha512\n"
    fmt.Println(str)
    os.Exit(0)
} 
// main function
func main() {
    m := flag.String("m", "algo", "Mode:")
    w := flag.String("w", "wordlist.txt", "Path to wordlist:")
    version := flag.Bool("version", false, "Prints program version:")
    cyclone := flag.Bool("cyclone", false, "")
    help := flag.Bool("help", false, "Prints help:")
    flag.Parse()
// run sanity checks for version & help
    if *version == true {
        versionFunc()
        os.Exit(0)
    } else if *cyclone == true {
        wordlistBase64Decode("Q29kZWQgYnkgY3ljbG9uZSA7KQo=")
        os.Exit(0)
    } else if *help == true {
        helpFunc()
    }
// run sanity checks on algo input (m)
    if len(*m) < 3 {
        fmt.Println("--> -m input not read <--\n")
        helpFunc()
        os.Exit(0)
    }
// run sanity checks on wordlist input (w)
    if len(*w) < 3 {
        fmt.Println("--> -w input not read <--\n")
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
// optionally, resize scanner's capacity for lines over 64K, see next example
    for scanner.Scan() {
        // do stuff with lines scanned
        line := scanner.Text()
        if *m == "md5" {
            wordlistMd5(line)
        } else if *m == "md4" {
            wordlistMd4(line)
        } else if *m == "ntlm" {
            wordlistNtlm(line)
        } else if *m == "sha1" {
            wordlistSha1(line)
        } else if *m == "sha256" {
            wordlistSha256(line)
        } else if *m == "sha512" {
            wordlistSha512(line)
        } else if *m == "crc32" {
            wordlistCrc32(line)
        } else if *m == "bcrypt" {
            wordlistBcrypt(line)
        } else if *m == "base64encode" {
            wordlistBase64Encode(line)
        } else if *m == "base64decode" {
            wordlistBase64Decode(line)
        }
    }
    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }
}
// hashing functions

// md4 hashing function
func wordlistMd4(line string) {
	hash := md4.New()
	io.WriteString(hash, line)
	fmt.Printf("%x\n", hash.Sum(nil))
}
// ntlm hashing function
// go does not have an ntlm hash function
// we use some hacky logic to convert the 
// plaintext to UTF16, then call the md4 function
func wordlistNtlm(line string) {
	u := ""
    _ = 0
	for i, c := range line {
		u = u + string(c) + "\x00"
		_ = i
	}
    h := md4.New()
    h.Write([]byte(u))
    md4 := h.Sum(nil)
    fmt.Printf("%x\n", md4)
}
// md5 hashing function
func wordlistMd5(line string) {
	hash := md5.Sum([]byte(line))
	wordlistHash := hex.EncodeToString(hash[:])
    fmt.Println(wordlistHash)
}
// sha1 hashing function
 func wordlistSha1(line string) {
	hash := sha1.Sum([]byte(line))
	wordlistHash := hex.EncodeToString(hash[:])
    fmt.Println(wordlistHash)
}
// sha256 hashing function
func wordlistSha256(line string) {
	hash := sha256.Sum256([]byte(line))
	wordlistHash := hex.EncodeToString(hash[:])
    fmt.Println(wordlistHash)
}
// sha256 hashing function
func wordlistSha512(line string) {
    hash := sha512.Sum512([]byte(line))
    wordlistHash := hex.EncodeToString(hash[:])
    fmt.Println(wordlistHash)
}
// bcrypt cost 10 hashing function
func wordlistBcrypt(line string) {
    getBcrypt(line)
}
// crc32 hashing function
func wordlistCrc32(line string) {
    hash := crc32.ChecksumIEEE([]byte(line))
    wordlistHash := strconv.FormatUint(uint64(hash), 16)
    fmt.Println(wordlistHash)
}
// base64 encode function
func wordlistBase64Encode(line string) {
    str := base64.StdEncoding.EncodeToString([]byte(line))
    fmt.Println(str)
}
// base64 decode function
func wordlistBase64Decode(line string) {
    str, err := base64.StdEncoding.DecodeString(line)
    if err != nil {
		fmt.Println("Wordlist doesn't appear to be base64 encoded.")
        os.Exit(0)
    }
    fmt.Printf("%s\n", str)
}

// bcrypt encode function
// https://pkg.go.dev/golang.org/x/crypto/bcrypt
func getBcrypt(line string) {
    pwd := []byte(line)
    hash := hashAndSalt(pwd)
    fmt.Println(hash)
}
func getPwd() []byte {
var pwd string
_, err := fmt.Scan(&pwd)
if err != nil {
    log.Println(err)
}
return []byte(pwd)
}
func hashAndSalt(pwd []byte) string {
hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost )
if err != nil {
    log.Println(err)
}
return string(hash)
}
