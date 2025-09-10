package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
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

	"github.com/cyclone-github/base58"
	"github.com/ebfe/keccak" // keccak 224/384
	"github.com/openwall/yescrypt-go"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
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
v1.1.0; 2025-03-19
    added modes: base58, bcrypt w/custom cost factor, argon2id (https://github.com/cyclone-github/argon_cracker)
v1.1.1; 2025-03-20
    added mode: yescrypt (https://github.com/cyclone-github/yescrypt_crack)
	tweaked read/write buffers for per-CPU thread
v1.1.2; 2025-04-08
    switched base58 lib to "github.com/cyclone-github/base58" for greatly improved base58 performance
v1.1.3; 2025-06-30
	added mode "hex" for $HEX[] formatted output
	added alias "dehex" to "plaintext" mode
	improved "plaintext/dehex" logic to decode both $HEX[] --> and raw base-16 input <-- (removed decoding raw base 16, see changes for v1.1.5)
v1.1.4; 2025-08-23
	added modes: keccak-224, keccak-384, blake2b-256, blake2b-384, blake2b-512, blake2c-256
	added benchmark flag, -b (to benchmark current mode, disables output)
	compiled with Go v1.25.0 which gives a small performance boost to multiple algos
	added notes concerning some NTLM hashes not being crackable with certain hash cracking tools due to encoding gremlins
v1.1.5-dev; 2025-09-10.1000
	addressed raw base-16 issue https://github.com/cyclone-github/hashgen/issues/8
	added feature: "keep-order" from https://github.com/cyclone-github/hashgen/issues/7
	added dynamic lines/sec from https://github.com/cyclone-github/hashgen/issues/11
*/

func versionFunc() {
	fmt.Fprintln(os.Stderr, "Cyclone hash generator v1.1.5-dev; 2025-09-10.1000\nhttps://github.com/cyclone-github/hashgen")
}

// help function
func helpFunc() {
	versionFunc() // some algos are commented out due to not being implemented into this package
	str := "\nExample Usage:\n" +
		"\n./hashgen -m md5 -w wordlist.txt -o output.txt\n" +
		"./hashgen -m bcrypt -cost 8 -w wordlist.txt\n" +
		"cat wordlist | ./hashgen -m md5 -hashplain\n" +
		"\nAll Supported Options:\n-m {mode}\n-w {wordlist input}\n-t {cpu threads}\n-o {wordlist output}\n-b {benchmark mode}\n-cost {bcrypt}\n-hashplain {generates hash:plain pairs}\n" +
		"\nIf -w is not specified, defaults to stdin\n" +
		"If -o is not specified, defaults to stdout\n" +
		"If -t is not specified, defaults to max available CPU threads\n" +
		"\nModes:\t\tHashcat Mode Equivalent:\n" +
		"argon2id\t34000 (slow algo)\n" +
		"base58decode\n" +
		"base58encode\n" +
		"base64decode\n" +
		"base64encode\n" +
		"bcrypt\t\t3200 (slow algo)\n" +
		"blake2s-256\n" +
		"31000\t\t(hashcat compatible blake2s-256)\n" +
		"blake2b-256\n" +
		"blake2b-384\n" +
		"blake2b-512\n" +
		"600\t\t(hashcat compatible blake2b-512)\n" +
		"crc32\n" +
		"11500\t\t(hashcat compatible CRC32)\n" +
		"crc64\n" +
		"hex\t\t(encode to $HEX[])\n" +
		"dehex/plaintext\t99999\t(decode $HEX[])\n" +
		"keccak-224\t17700\n" +
		"keccak-256\t17800\n" +
		"keccak-384\t17900\n" +
		"keccak-512\t18000\n" +
		"md4\t\t900\n" +
		"md5\t\t0\n" +
		"morsecode\t(ITU-R M.1677-1)\n" +
		"ntlm\t\t1000\n" +
		"ripemd-160\t6000\n" +
		"sha1 \t\t100\n" +
		"sha2-224\t1300\n" +
		"sha2-256\t1400\n" +
		"sha2-384\t10800\n" +
		"sha2-512\t1700\n" +
		"sha2-512-224\n" +
		"sha2-512-256\n" +
		"sha3-224\t17300\n" +
		"sha3-256\t17400\n" +
		"sha3-384\t17500\n" +
		"sha3-512\t17600\n" +
		"yescrypt\t(slow algo)\n"
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
func hashBytes(hashFunc string, data []byte, cost int) string {
	switch hashFunc {
	// $HEX[]
	case "hex":
		buf := make([]byte, 6+hex.EncodedLen(len(data))+1) // "$HEX[" + hex + "]"
		copy(buf, "$HEX[")
		hex.Encode(buf[5:], data)
		buf[len(buf)-1] = ']'
		return string(buf)
	// yescrypt
	case "yescrypt":
		salt := make([]byte, 8) // random 8-byte salt
		if _, err := rand.Read(salt); err != nil {
			fmt.Fprintln(os.Stderr, "Error generating salt:", err)
			return ""
		}
		key, err := yescrypt.Key(data, salt, 32768, 8, 1, 32) // use default yescrypt parameters: N=32768, r=8, p=1, keyLen=32
		if err != nil {
			fmt.Fprintln(os.Stderr, "yescrypt error:", err)
			return ""
		}
		const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" // custom yescrypt base64 alphabet
		encode64 := func(src []byte) string {
			var dst []byte
			var value uint32
			bits := 0
			for i := 0; i < len(src); i++ {
				value |= uint32(src[i]) << bits
				bits += 8
				for bits >= 6 {
					dst = append(dst, itoa64[value&0x3f])
					value >>= 6
					bits -= 6
				}
			}
			if bits > 0 {
				dst = append(dst, itoa64[value&0x3f])
			}
			return string(dst)
		}
		encodedSalt := encode64(salt)
		encodedKey := encode64(key)
		return fmt.Sprintf("$y$jC5$%s$%s", encodedSalt, encodedKey)
	// argon2id
	case "argon2id", "argon2", "argon":
		salt := make([]byte, 16) // random 16-byte salt
		if _, err := rand.Read(salt); err != nil {
			fmt.Fprintln(os.Stderr, "Error generating salt:", err)
			return ""
		}
		// use default argon2id parameters
		t := uint32(4)       // time (iterations)
		m := uint32(65536)   // memory cost in KiB
		p := uint8(1)        // parallelism (number of threads)
		keyLen := uint32(16) // key length in bytes
		key := argon2.IDKey(data, salt, t, m, p, keyLen)
		saltB64 := base64.RawStdEncoding.EncodeToString(salt)
		keyB64 := base64.RawStdEncoding.EncodeToString(key)
		return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, t, p, saltB64, keyB64)
	// bcrypt -m 3200
	case "bcrypt", "3200":
		hashed, err := bcrypt.GenerateFromPassword(data, cost)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bcrypt error:", err)
			return ""
		}
		return string(hashed)
	// morsecode
	case "morsecode", "morse":
		return string(encodeToMorseBytes(data))
	// md4 -m 900
	case "md4", "900":
		h := md4.New()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// md5 -m 0
	case "md5", "0":
		h := md5.Sum(data)
		return hex.EncodeToString(h[:])
	// sha1 -m 100
	case "sha1", "100":
		h := sha1.Sum(data)
		return hex.EncodeToString(h[:])
	// sha2-224 -m 1300
	case "sha2-224", "sha2_224", "sha2224", "sha224", "1300":
		h := sha256.New224()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// sha2-256 -m 1400
	case "sha2-256", "sha2_256", "sha2256", "sha256", "1400":
		h := sha256.Sum256(data)
		return hex.EncodeToString(h[:])
	// sha2-384 -m 10800
	case "sha2-384", "sha384", "10800":
		h := sha512.New384()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// sha2-512 -m 1700
	case "sha2-512", "sha2_512", "sha2512", "sha512", "1700":
		h := sha512.Sum512(data)
		return hex.EncodeToString(h[:])
	// sha2-512-224
	case "sha2-512-224", "sha512_224", "sha512224":
		h := sha512.New512_224()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// sha2-512-256
	case "sha2-512-256", "sha512_256", "sha512256":
		h := sha512.New512_256()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// ripemd-160 -m 6000
	case "ripemd-160", "ripemd_160", "ripemd160", "6000":
		h := ripemd160.New()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// sha3-224 -m 17300
	case "sha3-224", "sha3_224", "sha3224", "17300":
		h := sha3.New224()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// sha3-256 om 17400
	case "sha3-256", "sha3_256", "sha3256", "17400":
		h := sha3.New256()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// sha3-384 om 17500
	case "sha3-384", "sha3_384", "sha3384", "17500":
		h := sha3.New384()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// sha3-512 om 17600
	case "sha3-512", "sha3_512", "sha3512", "17600":
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// keccak-224 -m 17700 (raw hex)
	case "keccak-224", "keccak224", "17700":
		h := keccak.New224()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// keccak-256 -m 17800
	case "keccak-256", "keccak256", "17800":
		h := sha3.NewLegacyKeccak256()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// keccak-384 -m 17900 (raw hex)
	case "keccak-384", "keccak384", "17900":
		h := keccak.New384()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// keccak-512 -m 18000
	case "keccak-512", "keccak512", "18000":
		h := sha3.NewLegacyKeccak512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))
	// crc32 -m 11500
	case "11500": // hashcat compatible crc32 mode
		const hcCRCPad = ":00000000"
		h := crc32.ChecksumIEEE(data)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, h)
		hashString := hex.EncodeToString(b)
		return hashString + hcCRCPad
	// crc32 (standard, non-hashcat compatible)
	case "crc32":
		h := crc32.ChecksumIEEE(data)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, h)
		return hex.EncodeToString(b)
	// crc64
	case "crc64":
		table := crc64.MakeTable(crc64.ECMA)
		h := crc64.Checksum(data, table)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, h)
		return hex.EncodeToString(b)
	// ntlm -m 1000
	case "ntlm", "1000":
		h := md4.New()
		// convert byte slice to string assuming UTF-8, then encode as UTF-16LE
		// this may not work as expected if plaintext contains non-ASCII/UTF-8 encoding
		// due to encoding gremlins, not all NTLM hashes generated with hashgen are recoverable
		// recovery test results on rockyou.txt (14,344,391 lines):
		// mdxfind	recovered: 99.998%		missed: 218 	/ 14,344,391
		// hashpwn	recovered: 99.993%		missed: 1,025	/ 14,344,391
		// jtr		recovered: 99.961%		missed: 5,631	/ 14,344,391
		// hashcat	recovered: 99.862%		missed: 19,824	/ 14,344,391
		input := utf16.Encode([]rune(string(data))) // convert byte slice to string, then to rune slice
		if err := binary.Write(h, binary.LittleEndian, input); err != nil {
			panic("Failed NTLM hashing")
		}
		hashBytes := h.Sum(nil)
		return hex.EncodeToString(hashBytes)
	// blake2b-256 (raw hex)
	case "blake2b-256", "blake2b256":
		h := blake2b.Sum256(data)
		return hex.EncodeToString(h[:])
	// blake2b-384 (raw hex)
	case "blake2b-384", "blake2b384":
		h := blake2b.Sum384(data)
		return hex.EncodeToString(h[:])
	// blake2b-512 (raw hex)
	case "blake2b-512", "blake2b512":
		h := blake2b.Sum512(data)
		return hex.EncodeToString(h[:])
	// blake2s-256 (raw hex)
	case "blake2s-256", "blake2s256":
		h := blake2s.Sum256(data)
		return hex.EncodeToString(h[:])
	// hashcat mode -m 600 BLAKE2b-512, $BLAKE2$<hex>
	case "600":
		h := blake2b.Sum512(data)
		const pB = "$BLAKE2$"
		buf := make([]byte, len(pB)+hex.EncodedLen(len(h)))
		copy(buf, pB)
		hex.Encode(buf[len(pB):], h[:])
		return string(buf)
	// hashcat mode -m 31000 BLAKE2s-256, $BLAKE2$<hex>
	case "31000":
		h := blake2s.Sum256(data)
		const pS = "$BLAKE2$"
		buf := make([]byte, len(pS)+hex.EncodedLen(len(h)))
		copy(buf, pS)
		hex.Encode(buf[len(pS):], h[:])
		return string(buf)

	// base64 encode
	case "base64encode", "base64-e", "base64e":
		return base64.StdEncoding.EncodeToString(data)
	// base64 decode
	case "base64decode", "base64-d", "base64d":
		decodedBytes := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, err := base64.StdEncoding.Decode(decodedBytes, data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid Base64 string")
			return ""
		}
		return string(decodedBytes[:n]) // convert the decoded bytes to a string
	// base58 encode
	case "base58encode", "base58-e", "base58e":
		return base58.StdEncoding.EncodeToString(data)

	// base58 decode
	case "base58decode", "base58-d", "base58d":
		trimmedData := bytes.TrimSpace(data)
		decodedBytes, err := base58.StdEncoding.DecodeString(string(trimmedData))
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid Base58 string:", err)
			return ""
		}
		return string(decodedBytes)

		// plaintext, dehex, -m 99999
	case "plaintext", "plain", "99999", "dehex", "unhex":
		// passthrough & run checkForHex
		return string(data)

	default:
		log.Printf("--> Invalid hash function: %s <--\n", hashFunc)
		helpFunc()
		os.Exit(1)
		return ""
	}
}

// process wordlist chunks
func processChunk(chunk []byte, count *int64, hexErrorCount *int64, hashFunc string, writer *bufio.Writer, hashPlainOutput bool, cost int) {
	reader := bytes.NewReader(chunk)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		decodedBytes, hexContent, hexErrCount := checkForHex(line)
		hash := hashBytes(hashFunc, decodedBytes, cost)
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
func startProc(hashFunc string, inputFile string, outputPath string, hashPlainOutput bool, numGoroutines int, cost int) {
	//var readBufferSize = 1024 * 1024 // read buffer
	var readBufferSize = numGoroutines + 16*32*1024 // variable read buffer

	// lower read buffer for bcrypt (varies with -cost)
	if hashFunc == "bcrypt" || hashFunc == "3200" {
		readBufferSize = numGoroutines/cost + 32*2
	}
	// lower read buffer for argon2id, yescrypt
	if hashFunc == "argon2id" || hashFunc == "argon2" || hashFunc == "argon" || hashFunc == "yescrypt" {
		readBufferSize = numGoroutines + 8*2
	}

	var writeBufferSize = 2 * readBufferSize // write buffer (larger than read buffer)

	var linesHashed int64 = 0
	var procWg sync.WaitGroup
	var readWg sync.WaitGroup
	var writeWg sync.WaitGroup
	var hexDecodeErrors int64 = 0 // hex error counter

	type chunk struct {
		index int
		data  []byte
	}
	type writeItem struct {
		index int
		data  string
	}

	readChunks := make(chan chunk, 1000)    // channel for reading chunks of data
	writeData := make(chan writeItem, 1000) // channel for writing processed data

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
		chunkIndex := 0
		for {
			chunkBuf := make([]byte, readBufferSize)
			n, err := reader.Read(chunkBuf)
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error reading chunk:", err)
				return
			}
			// logic to split chunks properly
			chunkBuf = chunkBuf[:n]
			chunkBuf = append(remainder, chunkBuf...)

			lastNewline := bytes.LastIndexByte(chunkBuf, '\n')
			if lastNewline == -1 {
				remainder = chunkBuf
			} else {
				readChunks <- chunk{index: chunkIndex, data: chunkBuf[:lastNewline+1]}
				chunkIndex++
				remainder = chunkBuf[lastNewline+1:]
			}
		}
		if len(remainder) > 0 {
			readChunks <- chunk{index: chunkIndex, data: remainder}
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
				processChunk(chunk.data, &linesHashed, &hexDecodeErrors, hashFunc, writer, hashPlainOutput, cost)
				writer.Flush()
				writeData <- writeItem{index: chunk.index, data: localBuffer.String()}
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

		pending := make(map[int]string)
		next := 0
		for item := range writeData {
			pending[item.index] = item.data
			for {
				data, ok := pending[next]
				if !ok {
					break
				}
				writer.WriteString(data)
				writer.Flush() // flush after each write
				delete(pending, next)
				next++
			}
		}

		for {
			data, ok := pending[next]
			if !ok {
				break
			}
			writer.WriteString(data)
			writer.Flush()
			delete(pending, next)
			next++
		}
	}()

	// wait for sync.waitgroups to finish
	procWg.Wait()
	readWg.Wait()
	close(writeData)
	writeWg.Wait()

	// print stats
	elapsedTime := time.Since(startTime)
	runTime := elapsedTime.Seconds()

	lps := float64(linesHashed) / runTime // raw lines/sec

	unit := ""    // < 1 K (oh, so slow)
	scaled := lps // lines per second
	switch {
	case lps >= 1e12: // Trillion (not likely!)
		unit = "T"
		scaled = lps / 1e12
	case lps >= 1e9: // Billion (what CPU is this?)
		unit = "B"
		scaled = lps / 1e9
	case lps >= 1e6: // Million (yep)
		unit = "M"
		scaled = lps / 1e6
	case lps >= 1e3: // Thousand (still so slow)
		unit = "K"
		scaled = lps / 1e3
	}

	if hexDecodeErrors > 0 {
		log.Printf("HEX decode errors: %d\n", hexDecodeErrors)
	}

	if unit == "" {
		log.Printf("Finished processing %d lines in %.3f sec (%.3f lines/sec)\n", linesHashed, runTime, scaled) // < 1 K
	} else {
		log.Printf("Finished processing %d lines in %.3f sec (%.3f %s lines/sec)\n", linesHashed, runTime, scaled, unit) // K +
	}
}

// main func
func main() {
	hashFunc := flag.String("m", "", "Hash function to use")
	inputFile := flag.String("w", "", "Input file to process (use 'stdin' to read from standard input)")
	outputFile := flag.String("o", "", "Output file to write hashes to (use 'stdout' to print to console)")
	hashPlainOutput := flag.Bool("hashplain", false, "Enable hashplain output (hash:plain)")
	benchmark := flag.Bool("b", false, "Benchmark mode (disables output)")
	threads := flag.Int("t", 0, "Number of CPU threads to use")
	costFlag := flag.Int("cost", 8, "Bcrypt cost (4-31)")
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

	// block output flags when benchmarking
	if *benchmark {
		if *outputFile != "" {
			log.Fatalf("Error: -o flag cannot be used with -b (benchmark mode)")
		}
		// force discard output
		*outputFile = os.DevNull
	}

	// run sanity check for bcrypt / cost
	var costProvided bool
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "cost" {
			costProvided = true
		}
	})
	if costProvided && *hashFunc != "bcrypt" && *hashFunc != "3200" {
		log.Fatalf("Error: -cost flag is only allowed for bcrypt")
	}
	if *hashFunc == "bcrypt" || *hashFunc == "3200" {
		if *costFlag < bcrypt.MinCost || *costFlag > bcrypt.MaxCost {
			log.Fatalf("Invalid bcrypt cost: must be between %d and %d", bcrypt.MinCost, bcrypt.MaxCost)
		}
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

	startProc(*hashFunc, *inputFile, *outputFile, *hashPlainOutput, numThreads, *costFlag)
}

// end code
