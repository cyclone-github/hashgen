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
	"flag"
	"fmt"
	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
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
// v2023-03-15.0900-optimize; added "stdout", fixed "lines/sec" to show "M lines/sec", tweaked output buffer for stdout, tweaked sha2xxx flags to allow "shaxxx", ex: "sha512"
// v2023-03-28.1155-optimize; added "stdin"
// v2023-05-13.0000-optimize; optimized code all hashing functions for better performance
// v2023-08-15.1900-hashplain; added: -hashplain flag for hash:plain output, support for $HEX[] wordlist, -cost flag for bcrypt, tweaked: write buffers & custom buffers for argon & bcrypt, tweaked logging outputs

func versionFunc() {
	funcBase64Decode("Q3ljbG9uZSBoYXNoIGdlbmVyYXRvciB2MjAyMy0wOC0xNS4xOTAwLWhhc2hwbGFpbgo=")
}

// help function
func helpFunc() {
	versionFunc()
	str := "Example Usage:\n" +
		"\n./hashgen -m md5 -w wordlist.txt -o output.txt\n" +
		"./hashgen -m bcrypt -cost 8 -w wordlist.txt\n" +
		"cat wordlist | ./hashgen -m md5 -hashplain\n" +
		"\nSupported Options:\n-m {mode} -w {wordlist} -o {output_file} -hashplain {generates hash:plain pairs} -cost {bcrypt}\n" +
		"\nIf -w is not specified, defaults to stdin\n" +
		"If -o is not specified, defaults to stdout\n" +
		"\nModes:\t\tHashcat Mode Equivalent:\n" +
		"\nargon2id (very slow!)\n" +
		"base64encode\n" +
		"base64decode\n" +
		"bcrypt \t\t 3200\n" +
		"blake2s-256\n" +
		"blake2b-256\n" +
		"blake2b-384\n" +
		"blake2b-512 \t 600\n" +
		"crc32 \t\t 11500\n" +
		"crc64\n" +
		"md4 \t\t 900\n" +
		"md5 \t\t 0\n" +
		"ntlm \t\t 1000\n" +
		"plaintext \t 99999 \t (can be used to dehex wordlist)\n" +
		"ripemd-160 \t 6000\n" +
		"sha1 \t\t 100\n" +
		"sha2-224 \t 1300\n" +
		"sha2-384 \t 10800\n" +
		"sha2-256 \t 1400\n" +
		"sha2-512 \t 1700\n" +
		"sha2-512-224\n" +
		"sha2-512-256\n" +
		"sha3-224 \t 17300\n" +
		"sha3-256 \t 17400\n" +
		"sha3-384 \t 17400\n" +
		"sha3-512 \t 17400\n"
	fmt.Fprintln(os.Stderr, str)
	os.Exit(0)
}

// dehex wordlist line
func checkForHex(line string) string {
	// check if line is in $HEX[] format
	if strings.HasPrefix(line, "$HEX[") && strings.HasSuffix(line, "]") {
		hexContent := line[5 : len(line)-1]
		// if hex has an odd length, handle it by shifting and adding a zero nibble
		if len(hexContent)%2 != 0 {
			hexContent = "0" + hexContent
		}
		decoded, err := hex.DecodeString(hexContent)
		if err != nil {
			log.Printf("Error decoding $HEX[] content: %v", err)
		} else {
			return string(decoded) // return dehexed line
		}
	}
	return line // return original line if not in $HEX[] format or if an error occurs
}

const (
	Stdin  = "stdin"
	Stdout = "stdout"
)

// main function
func main() {
	var hashFunc string
	flag.StringVar(&hashFunc, "m", "", "Hash function to use")
	var inputFile string
	flag.StringVar(&inputFile, "w", "stdin", "Input file to process (use 'stdin' to read from standard input)")
	var outputFile string
	flag.StringVar(&outputFile, "o", "stdout", "Output file to write hashes to (use 'stdout' to print to console)")
	var hashPlainOutput bool
	flag.BoolVar(&hashPlainOutput, "hashplain", false, "Enable hashplain output (hash:plain)")
	var bcryptCost int
	flag.IntVar(&bcryptCost, "cost", bcrypt.MinCost, "Bcrypt cost factor (valid range 4-31)")
	version := flag.Bool("version", false, "Program version:")
	cyclone := flag.Bool("cyclone", false, "hashgen")
	help := flag.Bool("help", false, "Prints help:")
	flag.Parse()

	// run sanity checks for special flags
	if *version {
		versionFunc()
		os.Exit(0)
	}
	if *cyclone {
		funcBase64Decode("Q29kZWQgYnkgY3ljbG9uZSA7KQo=")
		os.Exit(0)
	}
	if *help {
		helpFunc()
	}

	// run sanity checks on algo input (-m)
	if hashFunc == "" {
		log.Fatalf("--> missing '-m algo' <--\n")
		helpFunc()
	}

	// open input file
	var input io.Reader
	if inputFile == Stdin {
		input = os.Stdin
	} else {
		file, err := os.Open(inputFile)
		if err != nil {
			log.Fatalf("--> Error opening input file: %v <--\n", err)
		}
		defer file.Close()
		input = file
	}

	// open output file
	var output io.Writer
	if outputFile == Stdout {
		output = os.Stdout
	} else {
		file, err := os.Create(outputFile)
		if err != nil {
			log.Fatalf("--> Error opening output file: %v <--\n", err)
		}
		defer file.Close()
		output = file
	}

	// create hash functions from flag -m
	var h hash.Hash
	switch hashFunc {
	case "argon2id", "argon2", "argon":
		hashFunc = "argon2id"
	case "md5", "0":
		h = md5.New()
	case "md4", "900":
		h = md4.New()
	case "sha1", "100":
		h = sha1.New()
	case "sha2-224", "sha2_224", "sha2224", "sha224", "1300":
		hashFunc = "sha2-224"
	case "sha2-384", "sha2_384", "sha2384", "sha384", "10800":
		hashFunc = "sha2-384"
	case "sha2-256", "sha2_256", "sha2256", "sha256", "1400":
		h = sha256.New()
	case "sha2-512", "sha2_512", "sha2512", "sha512", "1700":
		h = sha512.New()
	case "sha2-512-224", "sha2_512_224", "sha2512224", "sha512224":
		h = sha512.New512_224()
	case "sha2-512-256", "sha2_512_256", "sha2512256", "sha512256":
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
		log.Printf("--> Invalid hash function: %s <--\n", hashFunc)
		helpFunc()
		os.Exit(0)
	}

	// create read / write buffers

	// input buffer
	inputBuffer := bufio.NewScanner(input)
	// read buffer for all hash functions
	const maxCapacity = 20 * 1024 * 1024
	buf := make([]byte, maxCapacity)
	inputBuffer.Buffer(buf, maxCapacity)

	// set output buffer
	var bufferSize int
	if hashFunc == "argon2id" {
		bufferSize = 2 * 1024 // 2KB buffer for argon2id
	} else if hashFunc == "bcrypt" {
		bufferSize = 64 * 1024 // 64kB buffer for bcrypt
	} else {
		bufferSize = 20 * 1024 * 1024 // 20MB buffer for all other hash functions
	}
	outputBuffer := bufio.NewWriterSize(output, bufferSize)

	// create goroutine bool channel
	done := make(chan bool)

	// start hashgen goroutine
	go func() {
		log.Println("Starting...")
		log.Println("Processing file:", inputFile)
		log.Println("Hash function:", hashFunc)
		startTime := time.Now()
		linesHashed := 0

		lineSeparator := []byte("\n")
		colonSeparator := []byte(":")

		if hashFunc == "bcrypt" {
			// sanity check for -cost flag
			if bcryptCost < 4 || bcryptCost > 31 {
				log.Fatalf("--> Invalid bcrypt cost: %d (must be in range 4-31) <--\n", bcryptCost)
			}
			// bcrypt hash function <-- slow
			for inputBuffer.Scan() {
				line := checkForHex(inputBuffer.Text())
				pwd := []byte(line)
				hash, err := bcrypt.GenerateFromPassword(pwd, bcryptCost) // use dynamic cost
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
				hashString := string(hash)
				if hashPlainOutput {
					outputBuffer.WriteString(hashString + ":" + line + "\n")
				} else {
					outputBuffer.WriteString(hashString + "\n")
				}
				linesHashed++
			}
		} else if hashFunc == "argon2id" {
			// argon2id hash function <-- very slow!
			params := &argon2id.Params{
				Memory:      128 * 1024,
				Iterations:  4,
				Parallelism: 4,
				SaltLength:  16,
				KeyLength:   32,
			}
			for inputBuffer.Scan() {
				line := checkForHex(inputBuffer.Text())
				hash, err := argon2id.CreateHash(line, params)
				if err != nil {
					log.Fatal(err)
				}
				// print argon2id hash
				outputBuffer.WriteString(hash)
				if hashPlainOutput {
					outputBuffer.Write(colonSeparator)
					outputBuffer.WriteString(line)
				}
				outputBuffer.Write(lineSeparator)
				linesHashed++
			}
		} else if hashFunc == "blake2b-256" || hashFunc == "blake2b-384" || hashFunc == "blake2b-512" || hashFunc == "blake2s-256" {
			// blake2 hash functions
			var hash hash.Hash
			switch hashFunc {
			case "blake2b-256":
				hash, _ = blake2b.New256(nil)
			case "blake2b-384":
				hash, _ = blake2b.New384(nil)
			case "blake2b-512":
				hash, _ = blake2b.New512(nil)
			case "blake2s-256":
				hash, _ = blake2s.New256(nil)
			}
			for inputBuffer.Scan() {
				line := checkForHex(inputBuffer.Text())
				lineByte := []byte(line)
				hash.Write(lineByte)
				hashValue := hex.EncodeToString(hash.Sum(nil))
				outputBuffer.WriteString(hashValue)
				if hashPlainOutput {
					outputBuffer.Write(colonSeparator)
					outputBuffer.WriteString(line)
				}
				outputBuffer.Write(lineSeparator)
				linesHashed++
			}
		} else if hashFunc == "crc32" || hashFunc == "crc64" {
			// CRC hash functions
			var table *crc64.Table
			if hashFunc == "crc64" {
				table = crc64.MakeTable(crc64.ECMA) // create table once outside for loop to improve performance
			}
			for inputBuffer.Scan() {
				line := checkForHex(inputBuffer.Text())
				lineBytes := []byte(line)
				var hashString string
				if hashFunc == "crc32" {
					h := crc32.ChecksumIEEE(lineBytes)
					hashString = strconv.FormatUint(uint64(h), 16)
				} else { // crc64
					hash := crc64.Checksum(lineBytes, table)
					hashString = strconv.FormatUint(hash, 16)
				}
				outputBuffer.WriteString(hashString)
				if hashPlainOutput {
					outputBuffer.Write(colonSeparator)
					outputBuffer.WriteString(line)
				}
				outputBuffer.Write(lineSeparator)
				linesHashed++
			}
		} else if hashFunc == "base64encode" || hashFunc == "base64decode" {
			// base64 encode/decode
			for inputBuffer.Scan() {
				line := checkForHex(inputBuffer.Text())
				lineBytes := []byte(line)
				var str string
				if hashFunc == "base64encode" {
					str = base64.StdEncoding.EncodeToString(lineBytes)
				} else { // base64decode
					decodedStr, err := base64.StdEncoding.DecodeString(line)
					if err != nil {
						fmt.Fprintln(os.Stderr, "--> Text doesn't appear to be base64 encoded. <--")
						//os.Exit(0) // uncomment this line to stop on error, or leave commented to skip non-base64 lines and continue
					}
					str = string(decodedStr)
				}
				outputBuffer.WriteString(str)
				if hashFunc == "base64encode" && hashPlainOutput {
					outputBuffer.Write(colonSeparator)
					outputBuffer.WriteString(line)
				}
				outputBuffer.Write(lineSeparator)
				linesHashed++
			}
		} else if hashFunc == "ntlm" {
			// ntlm hash function
			hash := md4.New()
			var input []uint16
			for inputBuffer.Scan() {
				line := checkForHex(inputBuffer.Text())
				input = utf16.Encode([]rune(line))
				hash.Reset()
				if err := binary.Write(hash, binary.LittleEndian, input); err != nil {
					panic(fmt.Errorf("--> Failed NTLM hashing: %w <--", err))
				}
				hashBytes := hash.Sum(nil)
				hashString := hex.EncodeToString(hashBytes)
				outputBuffer.WriteString(hashString)
				if hashPlainOutput {
					outputBuffer.WriteString(":" + line)
				}
				outputBuffer.Write(lineSeparator)
				linesHashed++
			}
		} else if hashFunc == "plaintext" {
			// print plaintext
			for inputBuffer.Scan() {
				line := checkForHex(inputBuffer.Text())
				outputBuffer.WriteString(line)
				outputBuffer.Write(lineSeparator)
				linesHashed++
			}
		} else if hashFunc == "sha2-224" || hashFunc == "sha2-384" {
			// sha hash functions
			for inputBuffer.Scan() {
				line := checkForHex(inputBuffer.Text())
				lineBytes := []byte(line)
				var hashString string
				if hashFunc == "sha2-224" {
					hash := sha256.Sum224(lineBytes)
					hashString = hex.EncodeToString(hash[:])
				} else { // sha2-384
					hash := sha512.Sum384(lineBytes)
					hashString = hex.EncodeToString(hash[:])
				}
				outputBuffer.WriteString(hashString)
				if hashPlainOutput {
					outputBuffer.Write(colonSeparator)
					outputBuffer.WriteString(line)
				}
				outputBuffer.Write(lineSeparator)
				linesHashed++
			}
		} else { // all other hash functions defined in switch
			hashBuffer := make([]byte, h.Size()) // buffer for hash
			for inputBuffer.Scan() {
				line := checkForHex(inputBuffer.Text())
				lineBytes := []byte(line)
				h.Reset()
				h.Write(lineBytes)
				h.Sum(hashBuffer[:0]) // write the sum into the buffer
				hashString := hex.EncodeToString(hashBuffer)
				outputBuffer.WriteString(hashString)
				if hashPlainOutput {
					outputBuffer.Write(colonSeparator)
					outputBuffer.WriteString(line)
				}
				outputBuffer.Write(lineSeparator)
				linesHashed++
			}
		}

		elapsedTime := time.Since(startTime)
		runTime := float64(elapsedTime.Seconds())
		linesPerSecond := float64(linesHashed) / elapsedTime.Seconds() * 0.000001 // convert to thousand hashes per second
		log.Printf("Finished hashing %d lines in %.3f sec (%.3f M lines/sec)\n", linesHashed, runTime, linesPerSecond)
		done <- true
	}()

	// Wait for goroutine to finish
	<-done

	// Flush output buffer
	outputBuffer.Flush()
}

// base64 decode function used for displaying encoded messages
func funcBase64Decode(line string) {
	str, err := base64.StdEncoding.DecodeString(line)
	if err != nil {
		fmt.Fprintln(os.Stderr, "--> Text doesn't appear to be base64 encoded. <--")
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "%s\n", str)
}

// end code
