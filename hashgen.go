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

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

/*
hashgen is a CLI hash generator which can be cross compiled for Linux, Raspberry Pi, Windows & Mac
https://github.com/cyclone-github/hashgen
written by cyclone

GNU General Public License v2.0
https://github.com/cyclone-github/hashgen/blob/main/LICENSE

version history
v2023-10-30.1600-threaded;
	rewrote code base for multi-threading support
	some algos have not been implemented from previous version
v2023-11-03.2200-threaded;
	added hashcat -m 11500 (CRC32 w/padding)
	re-added CRC32 / CRC64 modes
	fixed stdin
v2023-11-04.1330-threaded;
	tweaked -m 11500
	tweaked HEX error correction
	added reporting when encountering HEX decoding errors
v2024-08-24.2000-threaded;
	added mode "morsecode" which follows ITU-R M.1677-1 standard
v2024-11-01.1630-threaded;
	added thread flag "-t" to allow user to specity CPU threads, ex: -t 16 // fixed default to use max CPU threads
	added modes: sha2-224, sha2-384, sha2-512-224, sha2-512-256, keccak-256, keccak-512
v2024-11-04.1445-threaded;
	fixed https://github.com/cyclone-github/hashgen/issues/5
	added CPU threaded info to -help
	cleaned up code and print functions
v1.0.0; 2024-12-10
    v1.0.0 release
*/

func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone hash generator v1.0.0; 2024-12-10")
}

// help function
func helpFunc() {
	versionFunc() // some algos are commented out due to not being implemented into this package
	str := "\nExample Usage:\n" +
		"\n./hashgen -m md5 -w wordlist.txt -o output.txt\n" +
		//"./hashgen -m bcrypt -cost 8 -w wordlist.txt\n" +
		"cat wordlist | ./hashgen -m md5 -hashplain\n" +
		//"\nSupported Options:\n-m {mode} -w {wordlist} -o {output_file} -hashplain {generates hash:plain pairs} -cost {bcrypt}\n" +
		"\nSupported Options:\n-m {mode} -w {wordlist} -t {cpu threads} -o {output_file} -hashplain {generates hash:plain pairs}\n" +
		"\nIf -w is not specified, defaults to stdin\n" +
		"If -o is not specified, defaults to stdout\n" +
		"If -t is not specified, defaults to max available CPU threads\n" +
		"\nModes:\t\tHashcat Mode Equivalent:\n" +
		//"\nargon2id (very slow!)\n" +
		"base64encode\n" +
		"base64decode\n" +
		//"bcrypt \t\t 3200\n" +
		//"blake2s-256\n" +
		//"blake2b-256\n" +
		//"blake2b-384\n" +
		//"blake2b-512 \t 600\n" +
		"morsecode\t (ITU-R M.1677-1)\n" +
		"crc32\n" +
		"11500\t\t (hashcat compatible CRC32)\n" +
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
		"sha3-384 \t 17500\n" +
		"sha3-512 \t 17600\n" +
		//"keccak-224\t 17700\n" +
		"keccak-256\t 17800\n" +
		//"keccak-384\t 17900\n" +
		"keccak-512\t 18000\n"
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

// ITU-R M.1677-1 standard morse code mapping
// https://www.itu.int/dms_pubrec/itu-r/rec/m/R-REC-M.1677-1-200910-I!!PDF-E.pdf
// both upper and lowercase alpha were included due to using byte arrays for speed optimization
var morseCodeMap = map[byte]string{
	// lowercase alpha
	'a': ".-", 'b': "-...", 'c': "-.-.", 'd': "-..", 'e': ".",
	'f': "..-.", 'g': "--.", 'h': "....", 'i': "..", 'j': ".---",
	'k': "-.-", 'l': ".-..", 'm': "--", 'n': "-.", 'o': "---",
	'p': ".--.", 'q': "--.-", 'r': ".-.", 's': "...", 't': "-",
	'u': "..-", 'v': "...-", 'w': ".--", 'x': "-..-", 'y': "-.--",
	'z': "--..",
	// uppercase alpha
	'A': ".-", 'B': "-...", 'C': "-.-.", 'D': "-..", 'E': ".",
	'F': "..-.", 'G': "--.", 'H': "....", 'I': "..", 'J': ".---",
	'K': "-.-", 'L': ".-..", 'M': "--", 'N': "-.", 'O': "---",
	'P': ".--.", 'Q': "--.-", 'R': ".-.", 'S': "...", 'T': "-",
	'U': "..-", 'V': "...-", 'W': ".--", 'X': "-..-", 'Y': "-.--",
	'Z': "--..",
	// digits
	'0': "-----", '1': ".----", '2': "..---", '3': "...--", '4': "....-",
	'5': ".....", '6': "-....", '7': "--...", '8': "---..", '9': "----.",
	// special char
	'.': ".-.-.-", ',': "--..--", '?': "..--..", '\'': ".----.", '!': "-.-.--",
	'/': "-..-.", '(': "-.--.", ')': "-.--.-", '&': ".-...", ':': "---...",
	';': "-.-.-.", '=': "-...-", '+': ".-.-.", '-': "-....-", '_': "..--.-",
	'"': ".-..-.", '$': "...-..-", '@': ".--.-.", ' ': " ",
	// procedural signs were intentionally omitted
}

// encode byte slice to Morse Code
func encodeToMorseBytes(input []byte) []byte {
	var encoded bytes.Buffer
	for _, char := range input {
		if code, exists := morseCodeMap[char]; exists {
			encoded.WriteString(code)
			encoded.WriteByte(' ') // add space after each Morse Code sequence
		}
	}

	// remove trailing space
	result := encoded.Bytes()
	if len(result) > 0 && result[len(result)-1] == ' ' {
		return result[:len(result)-1]
	}
	return result
}

// supported hash algos / modes
func hashBytes(hashFunc string, data []byte) string {
	switch hashFunc {
	case "morsecode":
		return string(encodeToMorseBytes(data))
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
	case "sha2-224", "sha2_224", "sha2224", "sha224", "1300":
		h := sha256.New224()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	case "sha2-256", "sha2_256", "sha2256", "sha256", "1400":
		h := sha256.Sum256(data)
		return hex.EncodeToString(h[:])
	case "sha2-384", "sha384", "10800":
		h := sha512.New384()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	case "sha2-512", "sha2_512", "sha2512", "sha512", "1700":
		h := sha512.Sum512(data)
		return hex.EncodeToString(h[:])
	case "sha2-512-224", "sha512_224", "sha512224":
		h := sha512.New512_224()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	case "sha2-512-256", "sha512_256", "sha512256":
		h := sha512.New512_256()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
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
	case "keccak-256", "keccak256", "17800":
		h := sha3.NewLegacyKeccak256()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	case "keccak-512", "keccak512", "18000":
		h := sha3.NewLegacyKeccak512()
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
		// convert byte slice to string assuming UTF-8, then encode as UTF-16LE
		// this may not work as expected if plaintext contains non-ASCII/UTF-8 encoding
		input := utf16.Encode([]rune(string(data))) // convert byte slice to string, then to rune slice
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
			fmt.Fprintln(os.Stderr, "Invalid Base64 string")
			return ""
		}
		return string(decodedBytes[:n]) // convert the decoded bytes to a string
	case "plaintext", "plain", "99999":
		return string(data) // convert byte slice to string
	default:
		log.Printf("--> Invalid hash function: %s <--\n", hashFunc)
		helpFunc()
		os.Exit(1)
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
func startProc(hashFunc string, inputFile string, outputPath string, hashPlainOutput bool, numGoroutines int) {
	const readBufferSize = 1024 * 1024         // read buffer
	const writeBufferSize = 2 * readBufferSize // write buffer (larger than read buffer)

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
				fmt.Fprintln(os.Stderr, "Error reading chunk:", err)
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
				fmt.Fprintln(os.Stderr, "Error creating output file:", err)
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
	log.Printf("Finished processing %d lines in %.3f sec (%.3f M lines/sec)\n", linesHashed, runTime, linesPerSecond)
}

// main func
func main() {
	hashFunc := flag.String("m", "", "Hash function to use")
	inputFile := flag.String("w", "", "Input file to process (use 'stdin' to read from standard input)")
	outputFile := flag.String("o", "", "Output file to write hashes to (use 'stdout' to print to console)")
	hashPlainOutput := flag.Bool("hashplain", false, "Enable hashplain output (hash:plain)")
	threads := flag.Int("t", 0, "Number of CPU threads to use")
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
		decodedStr, err := base64.StdEncoding.DecodeString("Q29kZWQgYnkgY3ljbG9uZSA7KQo=")
		if err != nil {
			fmt.Fprintln(os.Stderr, "--> Cannot decode base64 string. <--")
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, string(decodedStr))
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

	// determine CPU threads to use
	numThreads := *threads
	maxThreads := runtime.NumCPU()

	// thread sanity check (can't use <= 0 or > available CPU threads)
	if numThreads <= 0 {
		numThreads = maxThreads
	} else if numThreads > maxThreads {
		numThreads = maxThreads
	}

	runtime.GOMAXPROCS(numThreads) // set CPU threads

	startProc(*hashFunc, *inputFile, *outputFile, *hashPlainOutput, numThreads)
}

// end code
