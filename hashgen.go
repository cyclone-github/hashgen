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
hashgen is a CLI hash generator which can be cross compiled for Linux, Raspberry Pi, Windows & Mac
https://github.com/cyclone-github/hashgen
written by cyclone

GNU General Public License v2.0
https://github.com/cyclone-github/hashgen/blob/main/LICENSE

version history
v2023-10-30.1600-threaded; rewrote code base for multi-threading support, some algos have not been implemented from previous version
v2023-11-03.2200-threaded; added hashcat -m 11500 (CRC32 w/padding), re-added CRC32 / CRC64, fixed stdin
v2023-11-04.1330-threaded; tweaked -m 11500, tweaked HEX error correction and added reporting when encountering HEX decoding errors
*/

func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone hash generator v2023-11-04.1330-threaded")
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
/* note:
the checkForHex() function below gives a best effort in decoding all HEX strings and applies error correction when needed
if your wordlist contains HEX strings that resemble alphabet soup, don't be surprised if you find "garbage in" still means "garbage out"
the best way to fix HEX decoding issues is to correctly parse your wordlists so you don't end up with foobar HEX strings
if you have suggestions on how to better handle HEX decoding errors, contact me on github
*/
func checkForHex(line string) ([]byte, string, int) {
	// check if line is in $HEX[] format
	if strings.HasPrefix(line, "$HEX[") {
		// attempt to correct improperly formatted $HEX[] entries
		// if it doesn't end with "]", add the missing bracket
		var hexErrorDetected int
		if !strings.HasSuffix(line, "]") {
			line += "]"          // add missing trailing "]"
			hexErrorDetected = 1 // mark as error since the format was corrected
		}

		// find first '[' and last ']'
		startIdx := strings.Index(line, "[")
		endIdx := strings.LastIndex(line, "]")
		hexContent := line[startIdx+1 : endIdx]

		// decode hex content into bytes
		decodedBytes, err := hex.DecodeString(hexContent)
		// error handling
		if err != nil {
			hexErrorDetected = 1 // mark as error since there was an issue decoding

			// remove blank spaces and invalid hex characters
			cleanedHexContent := strings.Map(func(r rune) rune {
				if strings.ContainsRune("0123456789abcdefABCDEF", r) {
					return r
				}
				return -1 // remove invalid hex character
			}, hexContent)

			// if hex has an odd length, add a zero nibble to make it even
			if len(cleanedHexContent)%2 != 0 {
				cleanedHexContent = "0" + cleanedHexContent
			}

			decodedBytes, err = hex.DecodeString(cleanedHexContent)
			if err != nil {
				log.Printf("Error decoding $HEX[] content: %v", err)
				// if decoding still fails, return original line as bytes
				return []byte(line), line, hexErrorDetected
			}
		}

		// return decoded bytes and formatted hex content
		return decodedBytes, "$HEX[" + hexContent + "]", hexErrorDetected
	}
	// return original line as bytes if not in $HEX[] format
	return []byte(line), line, 0
}

// supported hash algos
func hashBytes(hashFunc string, data []byte) string {
	switch hashFunc {
	case "md4", "900":
		h := md4.New()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	case "md5", "0":
		h := md5.Sum(data)
		return hex.EncodeToString(h[:])
	case "sha1", "100":
		h := sha1.Sum(data)
		return hex.EncodeToString(h[:])
	case "sha2-256", "sha2_256", "sha2256", "sha256", "1400":
		h := sha256.Sum256(data)
		return hex.EncodeToString(h[:])
	case "sha2-512", "sha2_512", "sha2512", "sha512", "1700":
		h := sha512.Sum512(data)
		return hex.EncodeToString(h[:])
	case "ripemd-160", "ripemd_160", "ripemd160", "6000":
		h := ripemd160.New()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	case "sha3-224", "sha3_224", "sha3224", "17300":
		h := sha3.New224()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	case "sha3-256", "sha3_256", "sha3256", "17400":
		h := sha3.New256()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	case "sha3-384", "sha3_384", "sha3384", "17500":
		h := sha3.New384()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	case "sha3-512", "sha3_512", "sha3512", "17600":
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	case "11500": // hashcat compatible crc32 mode
		const hcCRCPad = ":00000000"
		h := crc32.ChecksumIEEE(data)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, h)
		hashString := hex.EncodeToString(b)
		return hashString + hcCRCPad
	case "crc32":
		h := crc32.ChecksumIEEE(data)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, h)
		return hex.EncodeToString(b)
	case "crc64":
		table := crc64.MakeTable(crc64.ECMA)
		h := crc64.Checksum(data, table)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, h)
		return hex.EncodeToString(b)
	case "ntlm", "1000":
		h := md4.New()
		input := utf16.Encode([]rune(string(data))) // Convert byte slice to string, then to rune slice
		if err := binary.Write(h, binary.LittleEndian, input); err != nil {
			panic("Failed NTLM hashing")
		}
		hashBytes := h.Sum(nil)
		return hex.EncodeToString(hashBytes)
	case "base64encode", "base64-e", "base64e":
		return base64.StdEncoding.EncodeToString(data)
	case "base64decode", "base64-d", "base64d":
		decodedBytes := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, err := base64.StdEncoding.Decode(decodedBytes, data)
		if err != nil {
			return "Invalid Base64 string"
		}
		return string(decodedBytes[:n]) // Convert the decoded bytes to a string
	case "plaintext", "plain", "99999":
		return string(data) // Convert byte slice to string
	default:
		log.Printf("--> Invalid hash function: %s <--\n", hashFunc)
		helpFunc()
		os.Exit(0)
		return ""
	}
}

// process wordlist chunks
func processChunk(chunk []byte, count *int64, hexErrorCount *int64, hashFunc string, writer *bufio.Writer, hashPlainOutput bool) {
	reader := bytes.NewReader(chunk)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		decodedBytes, hexContent, hexErrCount := checkForHex(line)
		hash := hashBytes(hashFunc, decodedBytes)
		writer.WriteString(hash)
		if hashPlainOutput {
			writer.WriteString(":" + hexContent)
		}
		writer.WriteString("\n")
		atomic.AddInt64(count, 1)                          // line count
		atomic.AddInt64(hexErrorCount, int64(hexErrCount)) // hex error count
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
	var hexDecodeErrors int64 = 0 // hex error counter

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
				processChunk(chunk, &linesHashed, &hexDecodeErrors, hashFunc, writer, hashPlainOutput)
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
	if hexDecodeErrors > 0 {
		log.Printf("HEX decode errors: %d\n", hexDecodeErrors)
	}
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
