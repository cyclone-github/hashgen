package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"unicode/utf16"
	"flag"
	"fmt"
	"log"
	"hash"
	"os"
	"sync"
	"time"
	"hash/crc32"
	"hash/crc64"
	"strconv"
	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/blake2b"
)

// version history
// v2022-12-15.2030; initial release
// v2022-12-16.1800; fixed ntlm hash function, tweaked -w flag to be less restrictive, clean up code
// v2022-12-17.2100; fixed typo in wordlist tag, added '-m plaintext' output mode (prints -w wordlist file to stdout)
// v2022-12-20.1200; cleaned up bcrypt code
// v2022-12-20.1430-goroutine; complete rewrite using goroutines & read/write buffers
// v2022-12-21.1400-goroutine; added multiple new algo's including hashcat mode equivalents
// v2022-12-23.1200-goroutine; added argon2id (very slow), added sync / wait group for future use, change h/s readout from millions to thousands,
// v2022-12-24.1800-optimize; optimized all hashing functions, tweaked buffer size

// TODO: 
// continue to add more hash functions
// add "-o stdout" flag to print hashes to stdout
// continue optimizing hash functions for better performance (ex: ntlm is currently slower than md5)
// fine tune goroutines for better performance with read --> hash function --> write
// add feature to allow hash cracking in addition to hash generation (future program: hashgenie)

func versionFunc() {
    funcBase64Decode("Q3ljbG9uZSBoYXNoIGdlbmVyYXRvciB2MjAyMi0xMi0yNC4xODAwLW9wdGltaXplCg==")
}

// help function
func helpFunc() {
    versionFunc()
    str := "Example Usage:\n"+
	"\n./hashgen -m md5 -w wordlist.txt -o output.txt\n"+
	"\nFunction: \t Hashcat Mode:\n"+
	"argon2id (very slow!)\n"+
	"base64encode\n"+
	"base64decode\n"+
	"bcrypt \t\t 3200\n"+
	"blake2s-256\n"+
	"blake2b-256\n"+
	"blake2b-384\n"+
	"blake2b-512 \t 600\n"+
	"crc32 \t\t 11500\n"+
	"crc64\n"+
	"md4 \t\t 900\n"+
	"md5 \t\t 0\n"+
	"ntlm \t\t 1000\n"+
	"plaintext \t 99999\n"+
	"ripemd-160 \t 6000\n"+
	"sha1 \t\t 100\n"+
	"sha2-224 \t 1300\n"+
	"sha2-384 \t 10800\n"+
	"sha2-256 \t 1400\n"+
	"sha2-512 \t 1700\n"+
	"sha2-512-224\n"+
	"sha2-512-256\n"+
	"sha3-224 \t 17300\n"+
	"sha3-256 \t 17400\n"+
	"sha3-384 \t 17400\n"+
	"sha3-512 \t 17400\n"
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
	case "argon2id":
		hashFunc = "argon2id"
	case "md5", "0":
		h = md5.New()
	case "md4", "900":
		h = md4.New()
	case "sha1", "100":
		h = sha1.New()
	case "sha2-224", "sha2_224", "sha2224", "1300":
		hashFunc = "sha2-224"
	case "sha2-384", "sha2_384", "sha2384","10800":
		hashFunc = "sha2-384"
	case "sha2-256", "sha2_256", "sha2256", "1400":
		h = sha256.New()
	case "sha2-512", "sha2_512", "sha2512", "1700":
		h = sha512.New()
	case "sha2-512-224", "sha2_512_224", "sha2512224":
		h = sha512.New512_224()
	case "sha2-512-256", "sha2_512_256" , "sha2512256":
		h = sha512.New512_256()
	case "ripemd-160", "ripemd_160", "ripemd160", "6000":
		h = ripemd160.New()
	case "blake2s-256", "blake2s_256", "blake2s256":
		hashFunc = "blake2s-256"
	case "blake2b-256", "blake2b_256", "blake2b256":
		hashFunc = "blake2b-256"
	case "blake2b-384", "blake2b_384", "blake2b384":
		hashFunc = "blake2b-384"
	case "blake2b-512", "blake2b_512", "blake2b512":
		hashFunc = "blake2b-512"
	case "sha3-224", "sha3_224", "sha3224", "17300":
		h = sha3.New224()
	case "sha3-256", "sha3_256", "sha3256", "17400":
		h = sha3.New256()
	case "sha3-384", "sha3_384", "sha3384", "17500":
		h = sha3.New384()
	case "sha3-512", "sha3_512", "sha3512", "17600":
		h = sha3.New512()
	case "base64encode", "base64-e", "base64e":
		hashFunc = "base64encode"
	case "base64decode", "base64-d", "base64d":
		hashFunc = "base64decode"
	case "bcrypt", "3200":
		hashFunc = "bcrypt"
	case "crc32", "11500":
		hashFunc = "crc32"
	case "crc64":
		hashFunc = "crc64"
	case "ntlm", "1000":
		hashFunc = "ntlm"
	case "plaintext", "plain", "99999":
		hashFunc = "plaintext"
	default:
		fmt.Printf("--> Invalid hash function: %s <--\n", hashFunc)
		helpFunc()
        os.Exit(0)
	}
	
	// create read / write buffers
	// input buffer
	inputBuffer := bufio.NewScanner(input)
	// set buffer capacity to 10mb
	const maxCapacity = 10*1024*1024
	buf := make([]byte, maxCapacity)
	inputBuffer.Buffer(buf, maxCapacity)
	// set output buffer to 100mb
	outputBuffer := bufio.NewWriterSize(output, 100*1024*1024)

	// create buffered channels to receive lines <-- not currently emplimented
	//lines := make(chan string, 10*1024*1024)
	//linesHash := make(chan string, 10*1024*1024)

	// create WaitGroup to wait for goroutines to finish
	var wg sync.WaitGroup
	
	// create goroutine bool channel
	done := make(chan bool)
	// start hashgen goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Println("Starting...")
		fmt.Println("Processing file:", inputFile)
		fmt.Println("Hash function:", hashFunc)
		startTime := time.Now()
		linesHashed := 0
		if hashFunc == "bcrypt" {
			// bcrypt hash function <-- slow
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				pwd := []byte(line)
				hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost) // <-- cost can be adjusted here
				if err != nil {
					log.Println(err)
				}
				hashString := string(hash)
				outputBuffer.WriteString(string(hashString) + "\n")
				linesHashed++
			}
		} else if hashFunc == "argon2id" {
			// argon2id hash function <-- very slow!
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				params := &argon2id.Params{
					Memory:      128 * 1024,
					Iterations:  4,
					Parallelism: 4,
					SaltLength:  16,
					KeyLength:   32,
				}
				hash, err := argon2id.CreateHash(line, params)
				if err != nil {
					log.Fatal(err)
				}
				// Print argon2id hash
				outputBuffer.WriteString(string(hash) + "\n")
				linesHashed++
			}
		} else if hashFunc == "blake2b-256" {
			// hash blake2b_256 function
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				lineByte := []byte(line)
				hash, _ := blake2b.New256(nil)
				hash.Write(lineByte)
				hashValue := hash.Sum(nil)
				outputBuffer.WriteString(hex.EncodeToString(hashValue) + "\n")
				linesHashed++
			}
		} else if hashFunc == "blake2b-384" {
			// hash blake2b_384 function
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				lineByte := []byte(line)
				hash, _ := blake2b.New384(nil)
				hash.Write(lineByte)
				hashValue := hash.Sum(nil)
				outputBuffer.WriteString(hex.EncodeToString(hashValue) + "\n")
				linesHashed++
			}
		} else if hashFunc == "blake2b-512" {
			// hash blake2b_512 function
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				lineByte := []byte(line)
				hash, _ := blake2b.New512(nil)
				hash.Write(lineByte)
				hashValue := hash.Sum(nil)
				outputBuffer.WriteString(hex.EncodeToString(hashValue) + "\n")
				linesHashed++
			}
		} else if hashFunc == "blake2s-256" {
			// hash blake2s_256 function
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				lineByte := []byte(line)
				hash, _ := blake2s.New256(nil)
				hash.Write(lineByte)
				hashValue := hash.Sum(nil)
				outputBuffer.WriteString(hex.EncodeToString(hashValue) + "\n")
				linesHashed++
			}
		} else if hashFunc == "crc32" {
			// hash crc32 function
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				h := crc32.ChecksumIEEE([]byte(line))
				hash := strconv.FormatUint(uint64(h), 16)
				outputBuffer.WriteString(string(hash) + "\n")
				linesHashed++
			}
		} else if hashFunc == "crc64" {
			// hash crc64 function
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				password := []byte(line)
				table := crc64.MakeTable(crc64.ECMA)
				hash := crc64.Checksum(password, table)
				hashString := strconv.FormatUint(hash, 16)
				outputBuffer.WriteString(hashString + "\n")
				linesHashed++
			  }
		} else if hashFunc == "base64encode" {
			// base64encode
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				str := base64.StdEncoding.EncodeToString([]byte(line))
				outputBuffer.WriteString(string(str) + "\n")
				linesHashed++
			}
		} else if hashFunc == "base64decode" {
			// base64encode
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				str, err := base64.StdEncoding.DecodeString(line)
				if err != nil {
					fmt.Println("--> Text doesn't appear to be base64 encoded. <--")
					os.Exit(0) // <-- uncomment this line to stop on error or leave commented to skip non-base64 lines and continue
				}
				outputBuffer.WriteString(string(str) + "\n")
				linesHashed++
			}
		} else if hashFunc == "ntlm" {
			// ntlm hash function TODO: optimize ntlm hash function for better performance
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				input := utf16.Encode([]rune(line))
				hash := md4.New()
				if err := binary.Write(hash, binary.LittleEndian, input); err != nil {
					panic(fmt.Errorf("--> Failed NTLM hashing: %w <--", err))
				}
				outputBuffer.WriteString(hex.EncodeToString(hash.Sum(nil)) + "\n")
				linesHashed++
			}
		} else if hashFunc == "plaintext" {
			// print plaintext
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				outputBuffer.WriteString(string(line) + "\n")
				linesHashed++
			}
		} else if hashFunc == "sha2-224" {
			// sha2_224 hash function
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				hash := sha256.Sum224([]byte(line))
				outputBuffer.WriteString(hex.EncodeToString(hash[:]) + "\n")
				linesHashed++
			}
		} else if hashFunc == "sha2-384" {
			// sha2_384 hash function
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				hash := sha512.Sum384([]byte(line))
				outputBuffer.WriteString(hex.EncodeToString(hash[:]) + "\n")
				linesHashed++
			}
		} else { // other hash functions defined in switch
			for inputBuffer.Scan() {
				line := inputBuffer.Text()
				h.Reset()
				h.Write([]byte(line))
				hash := h.Sum(nil)
				outputBuffer.WriteString(hex.EncodeToString(hash) + "\n")
				linesHashed++
			}
		}
		elapsedTime := time.Since(startTime)
		linesPerSecond := float64(linesHashed) / elapsedTime.Seconds() *0.001 // convert to thousand hashes per second
		log.Printf("Finished hashing %d lines in %v (%.3f lines/sec)\n", linesHashed, elapsedTime, linesPerSecond)
		done <- true
	}()

	// Wait for goroutine to finish
	<-done

	// Flush output buffer
	outputBuffer.Flush()

	// Wait for sync wait groupto finish <-- doesn't need sync / wait group yet due to having channels, but implimented for future use
	wg.Wait()
}

// base64 decode function used for displaying encoded messages
func funcBase64Decode(line string) {
    str, err := base64.StdEncoding.DecodeString(line)
    if err != nil {
		log.Println("--> Text doesn't appear to be base64 encoded. <--")
        os.Exit(0)
    }
    fmt.Printf("%s\n", str)
}
