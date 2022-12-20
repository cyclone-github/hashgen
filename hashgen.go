package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"unicode/utf16"
	"flag"
	"fmt"
	"log"
	"hash"
	"os"
	"time"
	"hash/crc32"
	"strconv"
	"golang.org/x/crypto/md4"
  "golang.org/x/crypto/bcrypt"
)

// version history
// v2022-12-15.2030; initial release
// v2022-12-16.1800; fixed ntlm hash function, tweaked -w flag to be less restrictive, clean up code
// v2022-12-17.2100; fixed typo in wordlist tag, added '-m plaintext' output mode (prints -w wordlist file to stdout)
// v2022-12-20.1200; cleaned up bcrypt code
// v2022-12-20.1430-goroutine; complete rewrite using goroutines & read/write buffers

func versionFunc() {
    funcBase64Decode("Q3ljbG9uZSBoYXNoIGdlbmVyYXRvciB2MjAyMi0xMi0yMC4xNDMwLWdvcm91dGluZQo=")
}

// help function
func helpFunc() {
    versionFunc()
    str := "Example Usage:\n"+
			"\n./hashgen -m md5 -w wordlist.txt -o output.txt\n"+
			"\nSupported functions:\n"+
			"base64decode\n"+
			"base64encode\n"+
			"bcrypt\n"+
			"crc32\n"+
			"md4\n"+
			"md5\n"+
			"ntlm\n"+
			"plaintext\n"+
			"sha1\n"+
			"sha256\n"+
			"sha512\n"
    fmt.Println(str)
    os.Exit(0)
} 

// main function
func main() {
	var hashFunc string
	flag.StringVar(&hashFunc, "m", "", "Hash function to use")
	var inputFile string
	flag.StringVar(&inputFile, "w", "", "Input file to process")
	var outputFile string
	flag.StringVar(&outputFile, "o", "", "Output file to write hashes to")
	version := flag.Bool("version", false, "Program version:")
    cyclone := flag.Bool("cyclone", false, "hashgen")
    help := flag.Bool("help", false, "Prints help:")
	flag.Parse()

	// run sanity checks for -version & -help
    if *version == true {
        versionFunc()
        os.Exit(0)
    } else if *cyclone == true {
        funcBase64Decode("Q29kZWQgYnkgY3ljbG9uZSA7KQo=")
        os.Exit(0)
    } else if *help == true {
        helpFunc()
    }
	// run sanity checks on algo input (-m)
    if len(hashFunc) < 1 {
        fmt.Println("--> missing '-m algo' <--\n")
        helpFunc()
        os.Exit(0)
    }
	// run sanity checks on wordlist input (-w)
    if len(inputFile) < 1 {
        fmt.Println("--> missing '-w wordlist' <--\n")
        helpFunc()
        os.Exit(0)
    }
	// run sanity checks on output (-o)
    if len(outputFile) < 1 {
        fmt.Println("--> missing '-o filename' <--\n")
        helpFunc()
        os.Exit(0)
    } 
	// open input file
	input, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("--> Error opening input file: %v <--\n", err)
		os.Exit(1)
	}
	defer input.Close()
	// open output file
	output, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("--> Error opening output file: %v <--\n", err)
		os.Exit(1)
	}
	defer output.Close()
	// create hash functions from flag -m
	var h hash.Hash
	switch hashFunc {
	case "md5":
		h = md5.New()
	case "md4":
		h = md4.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	case "base64encode":
	case "base64decode":
	case "bcrypt":
	case "crc32":
	case "ntlm":
	case "plaintext":
	default:
		fmt.Printf("--> Invalid hash function: %s <--\n", hashFunc)
		helpFunc()
        os.Exit(0)
	}
	
	// create read / write buffers
	inputBuffer := bufio.NewScanner(input)
	outputBuffer := bufio.NewWriter(output)
	
	// create goroutine bool channel
	done := make(chan bool)
	go func() {
		log.Println("Starting...")
		fmt.Println("Processing file:", inputFile)
		fmt.Println("Hash function:", hashFunc)
		startTime := time.Now()
		linesHashed := 0
		if hashFunc == "bcrypt" {
			// bcrypt hash function
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				pwd := []byte(line)
				hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost )
				if err != nil {
					log.Println(err)
				}
				hashString := string(hash)
				outputBuffer.WriteString(fmt.Sprintf("%v\n", hashString))
				linesHashed++
			}
		} else if hashFunc == "crc32" {
			// hash crc32 function
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				h := crc32.ChecksumIEEE([]byte(line))
				hash := strconv.FormatUint(uint64(h), 16)
				outputBuffer.WriteString(fmt.Sprintf("%v\n", hash))
				linesHashed++
			}
		} else if hashFunc == "base64encode" {
			// base64encode
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				str := base64.StdEncoding.EncodeToString([]byte(line))
				outputBuffer.WriteString(fmt.Sprintf("%v\n", str))
				linesHashed++
			}
		} else if hashFunc == "base64decode" {
			// base64encode
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				str, err := base64.StdEncoding.DecodeString(line)
				if err != nil {
					fmt.Println("--> Text doesn't appear to be base64 encoded. <--")
					//os.Exit(0)
				}
				outputBuffer.WriteString(fmt.Sprintf("%s\n", str))
				linesHashed++
			}
		} else if hashFunc == "ntlm" {
			// ntlm hash function
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				input := utf16.Encode([]rune(line))
				hash := md4.New()
				if err := binary.Write(hash, binary.LittleEndian, input); err != nil {
					panic(fmt.Errorf("--> Failed NTLM hashing: %w <--", err))
				}
				outputHash := hash.Sum(nil)
				outputBuffer.WriteString(fmt.Sprintf("%X\n", outputHash))
				linesHashed++
			}
		} else if hashFunc == "plaintext" {
			// print plaintext
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				outputBuffer.WriteString(fmt.Sprintf("%v\n", line))
				linesHashed++
			}
		} else { // other hash functions defined in switch
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				h.Reset()
				h.Write([]byte(line))
				hash := h.Sum(nil)
				outputBuffer.WriteString(fmt.Sprintf("%x\n", hash))
				linesHashed++
			}
		}
		elapsedTime := time.Since(startTime)
		linesPerSecond := float64(linesHashed) / elapsedTime.Seconds() *0.000001 // convert to million hashes per second
		log.Printf("Finished hashing %d lines in %v (%.3fM lines/sec)\n", linesHashed, elapsedTime, linesPerSecond)
		done <- true
	}()

	// wait for goroutine to finish
	<-done

	// flush output buffer
	outputBuffer.Flush()
}

// base64 decode function
func funcBase64Decode(line string) {
    str, err := base64.StdEncoding.DecodeString(line)
    if err != nil {
		log.Println("--> Text doesn't appear to be base64 encoded. <--")
        os.Exit(0)
    }
    fmt.Printf("%s\n", str)
}
