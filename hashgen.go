package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
	"hash/crc32"
	"hash/crc64"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
)

/*
version history
v2022-12-15.2030; initial release
v2022-12-16.1800; fixed ntlm hash function, tweaked -w flag to be less restrictive, clean up code
v2022-12-17.2100; fixed typo in wordlist tag, added '-m plaintext' output mode (prints -w wordlist file to stdout)
v2022-12-20.1200; cleaned up bcrypt code
v2022-12-20.1430-goroutine; complete rewrite using goroutines & read/write buffers
v2022-12-21.1400-goroutine; added multiple new algo's including hashcat mode equivalents
v2022-12-23.1200-goroutine; added argon2id (very slow), added sync / wait group for future use, change h/s readout from millions to thousands,
v2022-12-24.1800-optimize; optimized all hashing functions, tweaked buffer size
v2023-03-15.0900-optimize; added "stdout", fixed "lines/sec" to show "M lines/sec", tweaked output buffer for stdout, tweaked sha2xxx flags to allow "shaxxx", ex: "sha512"
v2023-03-28.1155-optimize; added "stdin"
v2023-05-13.0000-optimize; optimized code all hashing functions for better performance
v2023-08-15.1900-hashplain; added: -hashplain flag for hash:plain output, support for $HEX[] wordlist, -cost flag for bcrypt, tweaked: write buffers & custom buffers for argon & bcrypt, tweaked logging outputs
v2023-08-16.1200-hashplain; added error correction to 'fix' improperly formatted $HEX[] lines
v2023-09-28.1730-hashplain; modify -hashplain flag to be encoding-agnostic
v2023-10-30.1600-threaded; rewrote code base for multi-threading support, some algos have not been implemented from previous version
v2023-11-03.2200-threaded; added hashcat 11500 (CRC32 w/padding), re-added CRC32 / CRC64, fix stdin
*/

func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone hash generator v2023-11-03.2030-threaded")
}

// help function
func helpFunc() {
	versionFunc() // some algos are commented out due to not being implemented into this package
	str := "\nExample Usage:\n" +
		"\n./hashgen -m md5 -w wordlist.txt -o output.txt\n" +
		//"./hashgen -m bcrypt -cost 8 -w wordlist.txt\n" +
		"cat wordlist | ./hashgen -m md5 -hashplain\n" +
		//"\nSupported Options:\n-m {mode} -w {wordlist} -o {output_file} -hashplain {generates hash:plain pairs} -cost {bcrypt}\n" +
		"\nSupported Options:\n-m {mode} -w {wordlist} -o {output_file} -hashplain {generates hash:plain pairs}\n" +
		"\nIf -w is not specified, defaults to stdin\n" +
		"If -o is not specified, defaults to stdout\n" +
		"\nModes:\t\tHashcat Mode Equivalent:\n" +
		//"\nargon2id (very slow!)\n" +
		"base64encode\n" +
		"base64decode\n" +
		//"bcrypt \t\t 3200\n" +
		//"blake2s-256\n" +
		//"blake2b-256\n" +
		//"blake2b-384\n" +
		//"blake2b-512 \t 600\n" +
		"crc32\n" +
		"11500\t\t (hashcat compatible CRC32)\n" +
		"crc64\n" +
		"md4 \t\t 900\n" +
		"md5 \t\t 0\n" +
		"ntlm \t\t 1000\n" +
		"plaintext \t 99999 \t (can be used to dehex wordlist)\n" +
		"ripemd-160 \t 6000\n" +
		"sha1 \t\t 100\n" +
		//"sha2-224 \t 1300\n" +
		//"sha2-384 \t 10800\n" +
		"sha2-256 \t 1400\n" +
		"sha2-512 \t 1700\n" +
		//"sha2-512-224\n" +
		//"sha2-512-256\n" +
		"sha3-224 \t 17300\n" +
		"sha3-256 \t 17400\n" +
		"sha3-384 \t 17500\n" +
		"sha3-512 \t 17600\n"
	fmt.Fprintln(os.Stderr, str)
	os.Exit(0)
}

// dehex wordlist line
func checkForHex(line string) (string, string) {
	// check if line is in $HEX[] format
	if strings.HasPrefix(line, "$HEX[") && strings.HasSuffix(line, "]") {
		// find first '[' and last ']'
		startIdx := strings.Index(line, "[")
		endIdx := strings.LastIndex(line, "]")
		hexContent := line[startIdx+1 : endIdx]

		decoded, err := hex.DecodeString(hexContent)
		// error handling
		if err != nil {
			// remove blank spaces
			hexContent = strings.ReplaceAll(hexContent, " ", "")

			// remove invalid hex characters
			hexContent = strings.Map(func(r rune) rune {
				if strings.ContainsRune("0123456789abcdefABCDEF", r) {
					return r
				}
				return -1 // remove invalid hex character
			}, hexContent)

			// if hex has odd length, add zero nibble
			if len(hexContent)%2 != 0 {
				hexContent = "0" + hexContent
			}

			decoded, err = hex.DecodeString(hexContent)
			if err != nil {
				log.Printf("Error decoding $HEX[] content: %v", err)
			}
		}

		return string(decoded), "$HEX[" + hexContent + "]" // return dehexed line and formatted hex content
	}
	return line, line // return original line for both if not in $HEX[] format or if non-correctable error occurs
}

// supported hash algos
func hashString(hashFunc string, str string) string {
	switch hashFunc {
	case "md4", "900":
		h := md4.New()
		h.Write([]byte(str))
		return hex.EncodeToString(h.Sum(nil))
	case "md5", "0":
		h := md5.Sum([]byte(str))
		return hex.EncodeToString(h[:])
	case "sha1", "100":
		h := sha1.Sum([]byte(str))
		return hex.EncodeToString(h[:])
	case "sha2-256", "sha2_256", "sha2256", "sha256", "1400":
		h := sha256.Sum256([]byte(str))
		return hex.EncodeToString(h[:])
	case "sha2-512", "sha2_512", "sha2512", "sha512", "1700":
		h := sha512.Sum512([]byte(str))
		return hex.EncodeToString(h[:])
	case "ripemd-160", "ripemd_160", "ripemd160", "6000":
		h := ripemd160.New()
		h.Write([]byte(str))
		return hex.EncodeToString(h.Sum(nil))
	case "sha3-224", "sha3_224", "sha3224", "17300":
		h := sha3.New224()
		h.Write([]byte(str))
		return hex.EncodeToString(h.Sum(nil))
	case "sha3-256", "sha3_256", "sha3256", "17400":
		h := sha3.New256()
		h.Write([]byte(str))
		return hex.EncodeToString(h.Sum(nil))
	case "sha3-384", "sha3_384", "sha3384", "17500":
		h := sha3.New384()
		h.Write([]byte(str))
		return hex.EncodeToString(h.Sum(nil))
	case "sha3-512", "sha3_512", "sha3512", "17600":
		h := sha3.New512()
		h.Write([]byte(str))
		return hex.EncodeToString(h.Sum(nil))
	case "11500": // hashcat compatible crc32 mode
		h := crc32.ChecksumIEEE([]byte(str))
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, h)
		hashString := hex.EncodeToString(b)
		return hashString + ":00000000"
	case "crc32":
		h := crc32.ChecksumIEEE([]byte(str))
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, h)
		return hex.EncodeToString(b)
	case "crc64":
		table := crc64.MakeTable(crc64.ECMA)
		h := crc64.Checksum([]byte(str), table)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, h)
		return hex.EncodeToString(b)
	case "ntlm", "1000":
		h := md4.New()
		input := utf16.Encode([]rune(str))
		if err := binary.Write(h, binary.LittleEndian, input); err != nil {
			panic("Failed NTLM hashing")
		}
		hashBytes := h.Sum(nil)
		return hex.EncodeToString(hashBytes)
	case "base64encode", "base64-e", "base64e":
		return base64.StdEncoding.EncodeToString([]byte(str))
	case "base64decode", "base64-d", "base64d":
		decodedStr, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return "Invalid Base64 string"
		}
		return string(decodedStr)
	case "plaintext", "plain", "99999":
		return str
	default:
		log.Printf("--> Invalid hash function: %s <--\n", hashFunc)
		helpFunc()
		os.Exit(0)
		return ""
	}
}

// process wordlist chunks
func processChunk(chunk []byte, count *int64, hashFunc string, writer *bufio.Writer, hashPlainOutput bool) {
	reader := bytes.NewReader(chunk)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		decodedLine, hexContent := checkForHex(line)
		hash := hashString(hashFunc, decodedLine)
		writer.WriteString(hash)
		if hashPlainOutput {
			writer.WriteString(":" + hexContent)
		}
		writer.WriteString("\n")
		atomic.AddInt64(count, 1) // thread safe counter
	}
	writer.Flush()
}

// process logic
func startProc(hashFunc string, inputFile string, outputPath string, hashPlainOutput bool) {
	const readBufferSize = 1024 * 1024         // read buffer
	const writeBufferSize = 2 * readBufferSize // write buffer (larger than read buffer)
	numGoroutines := runtime.NumCPU()          // use all available CPU threads

	var linesHashed int64 = 0
	var procWg sync.WaitGroup
	var readWg sync.WaitGroup
	var writeWg sync.WaitGroup

	readChunks := make(chan []byte, 1000) // channel for reading chunks of data
	writeData := make(chan string, 1000)  // channel for writing processed data

	// determine input source
	var file *os.File
	var err error
	if inputFile == "" {
		file = os.Stdin // default to stdin if no input flag is provided
	} else {
		file, err = os.Open(inputFile)
		if err != nil {
			log.Printf("Error opening file: %v\n", err)
			return
		}
		defer file.Close()
	}

	// print start stats
	log.Println("Starting...")
	if inputFile != "" {
		log.Println("Processing file:", inputFile)
	} else {
		log.Println("Reading from stdin...")
	}
	log.Println("Hash function:", hashFunc)
	log.Println("CPU Threads:", numGoroutines)

	startTime := time.Now()

	// read goroutine
	readWg.Add(1)
	go func() {
		defer readWg.Done()
		var remainder []byte
		reader := bufio.NewReaderSize(file, readBufferSize)
		for {
			chunk := make([]byte, readBufferSize)
			n, err := reader.Read(chunk)
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Println(os.Stderr, "Error reading chunk:", err)
				return
			}
			// logic to split chunks properly
			chunk = chunk[:n]
			chunk = append(remainder, chunk...)

			lastNewline := bytes.LastIndexByte(chunk, '\n')
			if lastNewline == -1 {
				remainder = chunk
			} else {
				readChunks <- chunk[:lastNewline+1]
				remainder = chunk[lastNewline+1:]
			}
		}
		if len(remainder) > 0 {
			readChunks <- remainder
		}
		close(readChunks)
	}()

	// processing goroutine
	for i := 0; i < numGoroutines; i++ {
		procWg.Add(1)
		go func() {
			defer procWg.Done()
			for chunk := range readChunks {
				localBuffer := bytes.NewBuffer(nil)
				writer := bufio.NewWriterSize(localBuffer, writeBufferSize)
				processChunk(chunk, &linesHashed, hashFunc, writer, hashPlainOutput)
				writer.Flush()
				writeData <- localBuffer.String()
			}
		}()
	}

	// write goroutine
	writeWg.Add(1)
	go func() {
		defer writeWg.Done()
		var writer *bufio.Writer
		if outputPath != "" {
			outFile, err := os.Create(outputPath)
			if err != nil {
				fmt.Println(os.Stderr, "Error creating output file:", err)
				return
			}
			defer outFile.Close()
			writer = bufio.NewWriterSize(outFile, writeBufferSize)
		} else {
			writer = bufio.NewWriterSize(os.Stdout, writeBufferSize)
		}

		for data := range writeData {
			writer.WriteString(data)
		}
		writer.Flush()
	}()

	// wait for sync.waitgroups to finish
	procWg.Wait()
	readWg.Wait()
	close(writeData)
	writeWg.Wait()

	// print stats
	elapsedTime := time.Since(startTime)
	runTime := float64(elapsedTime.Seconds())
	linesPerSecond := float64(linesHashed) / elapsedTime.Seconds() * 0.000001
	log.Printf("Finished hashing %d lines in %.3f sec (%.3f M lines/sec)\n", linesHashed, runTime, linesPerSecond)
}

// main func
func main() {
	hashFunc := flag.String("m", "", "Hash function to use")
	inputFile := flag.String("w", "", "Input file to process (use 'stdin' to read from standard input)")
	outputFile := flag.String("o", "", "Output file to write hashes to (use 'stdout' to print to console)")
	hashPlainOutput := flag.Bool("hashplain", false, "Enable hashplain output (hash:plain)")
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
	if *hashFunc == "" {
		log.Fatalf("--> missing '-m algo' <--\n")
		helpFunc()
	}

	runtime.GOMAXPROCS(runtime.NumCPU()) // Use all available CPUs

	startProc(*hashFunc, *inputFile, *outputFile, *hashPlainOutput)
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
