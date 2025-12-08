package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"io"
	"log"
	"math/bits"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unicode/utf8"

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

full changelog
https://github.com/cyclone-github/hashgen/blob/main/CHANGELOG.md

latest changelog
v1.2.0; 2025-11-08
	addressed raw base-16 issue https://github.com/cyclone-github/hashgen/issues/8
	added feature: "keep-order" from https://github.com/cyclone-github/hashgen/issues/7
	added dynamic lines/sec from https://github.com/cyclone-github/hashgen/issues/11
	added modes: mysql5 (300), phpass (400), md5crypt (500), sha256crypt (7400), sha512crypt (1800), Wordpress bcrypt-HMAC-SHA384 (wpbcrypt)
	added hashcat salted modes: -m 10, 20, 110, 120, 1410, 1420, 1310, 1320, 1710, 1720, 10810, 10820
	added hashcat modes: -m 2600, 4500
	added encoding modes: base32encode, base32decode
	cleaned up hashFunc aliases, algo typo, hex mode, hashBytes case switch, base64 and base58 decoders
	fixed ntlm encoding issue
	added sanity check to not print blank / invalid hash lines (part of ntlm fix, but applies to all hash modes)
	converted checkForHex from string to byte
	updated yescrypt parameters to match debian 12 (libxcrypt) defaults
v1.2.1; 2025-12-08
	added mode: morsedecode (Morse Code decoder)
*/

func versionFunc() {
	fmt.Fprintln(os.Stderr, "hashgen v1.2.1; 2025-12-08\nhttps://github.com/cyclone-github/hashgen")
}

// help function
func helpFunc() {
	versionFunc()
	str := "\nExample Usage:\n" +
		"\n./hashgen -m md5 -w wordlist.txt -o output.txt\n" +
		"./hashgen -m bcrypt -cost 8 -w wordlist.txt\n" +
		"cat wordlist | ./hashgen -m md5 -hashplain\n" +
		"\nAll Supported Options:\n-m {mode}\n-w {wordlist input}\n-t {cpu threads}\n-o {wordlist output}\n-b {benchmark mode}\n-cost {bcrypt, default=10}\n-hashplain {generates hash:plain pairs}\n" +
		"\nIf -w is not specified, defaults to stdin\n" +
		"If -o is not specified, defaults to stdout\n" +
		"If -t is not specified, defaults to max available CPU threads\n" +
		"\nModes:\t\tHashcat Mode (notes):\n" +
		"argon2id\t34000\n" +
		"base32decode\n" +
		"base32encode\n" +
		"base58decode\n" +
		"base58encode\n" +
		"base64decode\n" +
		"base64encode\n" +
		"bcrypt\t\t3200\n" +
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
		"md5passsalt\t10\n" +
		"md5saltpass\t20\n" +
		"md5md5\t\t2600\n" +
		"md5crypt\t500 (Linux shadow $1$)\n" +
		"mysql4/mysql5\t300\n" +
		"morsecode\t(ITU-R M.1677-1)\n" +
		"morsedecode\n" +
		"ntlm\t\t1000 (Windows NT)\n" +
		"phpass\t\t400\n" +
		"ripemd-160\t6000\n" +
		"sha1\t\t100\n" +
		"sha1sha1\t4500\n" +
		"sha1passsalt\t110\n" +
		"sha1saltpass\t120\n" +
		"sha224\t\t1300\n" +
		"sha224passsalt\t1310\n" +
		"sha224saltpass\t1320\n" +
		"sha256\t\t1400\n" +
		"sha256passsalt\t1410\n" +
		"sha256saltpass\t1420\n" +
		"sha256crypt\t7400 (Linux shadow $5$)\n" +
		"sha384\t\t10800\n" +
		"sha384passsalt\t10810\n" +
		"sha384saltpass\t10820\n" +
		"sha512\t\t1700\n" +
		"sha512passsalt\t1710\n" +
		"sha512saltpass\t1720\n" +
		"sha512crypt\t1800 (Linux shadow $6$)\n" +
		"sha512-224\n" +
		"sha512-256\n" +
		"sha3-224\t17300\n" +
		"sha3-256\t17400\n" +
		"sha3-384\t17500\n" +
		"sha3-512\t17600\n" +
		"wpbcrypt\t(WordPress bcrypt-HMAC-SHA384)\n" +
		"yescrypt\t(Linux shadow $y$)\n"
	fmt.Fprintln(os.Stderr, str)
	os.Exit(0)
}

var (
	cryptBase64 = []byte("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
)

// dehex wordlist line
/* note:
the checkForHex() function below gives a best effort in decoding all HEX strings and applies error correction when needed
if your wordlist contains HEX strings that resemble alphabet soup, don't be surprised if you find "garbage in" still means "garbage out"
the best way to fix HEX decoding issues is to correctly parse your wordlists so you don't end up with foobar HEX strings
if you have suggestions on how to better handle HEX decoding errors, contact me on github
*/
func checkForHex(line []byte) ([]byte, []byte, int) {
	// check if line is in $HEX[] format
	const prefix = "$HEX["
	if len(line) >= len(prefix) && bytes.HasPrefix(line, []byte(prefix)) {
		// attempt to correct improperly formatted $HEX[] entries
		// if it doesn't end with "]", add the missing bracket
		var hexErrorDetected int
		hasClose := bytes.HasSuffix(line, []byte("]"))
		if !hasClose {
			hexErrorDetected = 1 // mark as error since the format was corrected
		}

		// find first '[' and last ']'
		startIdx := bytes.IndexByte(line, '[')
		endIdx := bytes.LastIndexByte(line, ']')
		if endIdx == -1 {
			endIdx = len(line) // pretend ']' is at end
		}
		hexContent := line[startIdx+1 : endIdx]

		// decode hex content into bytes
		var decodedBytes []byte
		if n := len(hexContent); n > 0 && (n&1) == 0 {
			decodedBytes = make([]byte, n/2)
			if _, err := hex.Decode(decodedBytes, hexContent); err == nil {
				disp := make([]byte, 5+len(hexContent)+1) // "$HEX[" + hex + "]"
				copy(disp, prefix)
				copy(disp[5:], hexContent)
				disp[len(disp)-1] = ']'
				return decodedBytes, disp, hexErrorDetected
			}
			hexErrorDetected = 1
		} else {
			hexErrorDetected = 1
		}

		// error handling: remove invalid hex chars
		clean := make([]byte, 0, len(hexContent))
		for _, c := range hexContent {
			lc := c | 0x20
			if (c >= '0' && c <= '9') || (lc >= 'a' && lc <= 'f') {
				clean = append(clean, c)
			}
		}
		// if hex has an odd length, add a zero nibble to make it even
		if len(clean)%2 != 0 {
			clean = append([]byte{'0'}, clean...)
		}

		decodedBytes = make([]byte, len(clean)/2)
		if len(clean) == 0 || func() bool {
			_, err := hex.Decode(decodedBytes, clean)
			return err != nil
		}() {
			log.Printf("Error decoding $HEX[] content")
			// if decoding still fails, return original line as bytes
			disp := make([]byte, 5+len(hexContent)+1)
			copy(disp, prefix)
			copy(disp[5:], hexContent)
			disp[len(disp)-1] = ']'
			return line, disp, hexErrorDetected
		}

		// return decoded bytes and formatted hex content
		disp := make([]byte, 5+len(hexContent)+1)
		copy(disp, prefix)
		copy(disp[5:], hexContent)
		disp[len(disp)-1] = ']'
		return decodedBytes, disp, hexErrorDetected
	}
	// return original line as bytes if not in $HEX[] format
	return line, line, 0
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

/*
decode Morse Code to bytes
rules:
- single space between codes -> next character
- 3 or more spaces           -> word separator (space - matches -m morsecode encoder style)
*/
func decodeMorseBytes(input []byte) []byte {
	var out bytes.Buffer
	var token bytes.Buffer
	spaces := 0

	flushToken := func() {
		if token.Len() == 0 {
			return
		}
		code := token.String()
		if ch, ok := morseDecodeMap[code]; ok {
			out.WriteByte(ch)
		}
		token.Reset()
	}

	for _, b := range input {
		if b == ' ' || b == '\t' {
			spaces++
			continue
		}

		// non-space
		if spaces > 0 {
			flushToken()
			if spaces >= 3 {
				out.WriteByte(' ') // word separator
			}
			spaces = 0
		}
		token.WriteByte(b)
	}

	flushToken()
	return out.Bytes()
}

// reverse lookup for Morse Code -> byte (prefer uppercase letters)
var morseDecodeMap = func() map[string]byte {
	m := make(map[string]byte)
	for ch, code := range morseCodeMap {
		if code == " " {
			continue
		}
		// store as uppercase
		up := ch
		if up >= 'a' && up <= 'z' {
			up -= 32
		}
		m[code] = up
	}
	return m
}()

// phpassMD5 -m 400
func phpassMD5(password []byte, mode string, countLog2 int, saltRaw []byte) string {
	prefix := byte('P')
	if mode == "phpbb3" {
		prefix = 'H'
	}
	if countLog2 <= 0 {
		countLog2 = 11
	}
	if saltRaw == nil || len(saltRaw) < 6 {
		saltRaw = make([]byte, 6)
		if _, err := rand.Read(saltRaw); err != nil {
			fmt.Fprintln(os.Stderr, "phpass salt error:", err)
			return ""
		}
	} else if len(saltRaw) > 6 {
		saltRaw = saltRaw[:6]
	}
	encode64 := func(src []byte, outLen int) []byte {
		dst := make([]byte, 0, outLen)
		for i := 0; i < len(src); {
			var v uint32 = uint32(src[i])
			i++
			dst = append(dst, cryptBase64[v&0x3f])
			if i < len(src) {
				v |= uint32(src[i]) << 8
			}
			dst = append(dst, cryptBase64[(v>>6)&0x3f])
			if i >= len(src) {
				break
			}
			i++
			if i < len(src) {
				v |= uint32(src[i]) << 16
			}
			dst = append(dst, cryptBase64[(v>>12)&0x3f])
			if i >= len(src) {
				break
			}
			i++
			dst = append(dst, cryptBase64[(v>>18)&0x3f])
			if len(dst) >= outLen {
				break
			}
		}
		if len(dst) > outLen {
			return dst[:outLen]
		}
		return dst
	}
	saltEnc := encode64(saltRaw, 8)
	h := md5.New()
	h.Write(saltEnc)
	h.Write(password)
	sum := h.Sum(nil)
	rounds := 1 << countLog2
	for i := 0; i < rounds; i++ {
		h.Reset()
		h.Write(sum)
		h.Write(password)
		sum = h.Sum(nil)
	}
	digestEnc := encode64(sum, 22)
	out := make([]byte, 3+1+8+22)
	out[0], out[1], out[2] = '$', prefix, '$'
	out[3] = cryptBase64[countLog2]
	copy(out[4:12], saltEnc)
	copy(out[12:], digestEnc)
	return string(out)
}

// md5crypt - linux shadow "$1$<salt>$<hash>"
func md5crypt(password []byte) string {
	const magic = "$1$"
	salt := make([]byte, 8)
	rb := make([]byte, 8)
	if _, err := rand.Read(rb); err != nil {
		for i := 0; i < 8; i++ {
			salt[i] = cryptBase64[(i*37+13)&0x3f]
		}
	} else {
		for i := 0; i < 8; i++ {
			salt[i] = cryptBase64[int(rb[i])&0x3f]
		}
	}

	a := md5.New()
	a.Write(password)
	a.Write([]byte(magic))
	a.Write(salt)

	alt := md5.New()
	alt.Write(password)
	alt.Write(salt)
	alt.Write(password)
	altSum := alt.Sum(nil)

	pwLen := len(password)
	for n := pwLen; n > 0; n -= 16 {
		if n > 16 {
			a.Write(altSum)
		} else {
			a.Write(altSum[:n])
		}
	}

	for n := pwLen; n > 0; n >>= 1 {
		if (n & 1) == 1 {
			a.Write([]byte{0})
		} else if pwLen > 0 {
			a.Write(password[:1])
		} else {
			a.Write([]byte{0})
		}
	}

	final := a.Sum(nil)

	for i := 0; i < 1000; i++ {
		ri := md5.New()
		if (i & 1) == 1 {
			ri.Write(password)
		} else {
			ri.Write(final)
		}
		if i%3 != 0 {
			ri.Write(salt)
		}
		if i%7 != 0 {
			ri.Write(password)
		}
		if (i & 1) == 1 {
			ri.Write(final)
		} else {
			ri.Write(password)
		}
		final = ri.Sum(nil)
	}

	out := make([]byte, 0, 3+1+8+1+22)
	out = append(out, magic...)
	out = append(out, salt...)
	out = append(out, '$')

	var v uint32

	v = uint32(final[0])<<16 | uint32(final[6])<<8 | uint32(final[12])
	for j := 0; j < 4; j++ {
		out = append(out, cryptBase64[v&0x3f])
		v >>= 6
	}

	v = uint32(final[1])<<16 | uint32(final[7])<<8 | uint32(final[13])
	for j := 0; j < 4; j++ {
		out = append(out, cryptBase64[v&0x3f])
		v >>= 6
	}

	v = uint32(final[2])<<16 | uint32(final[8])<<8 | uint32(final[14])
	for j := 0; j < 4; j++ {
		out = append(out, cryptBase64[v&0x3f])
		v >>= 6
	}

	v = uint32(final[3])<<16 | uint32(final[9])<<8 | uint32(final[15])
	for j := 0; j < 4; j++ {
		out = append(out, cryptBase64[v&0x3f])
		v >>= 6
	}

	v = uint32(final[4])<<16 | uint32(final[10])<<8 | uint32(final[5])
	for j := 0; j < 4; j++ {
		out = append(out, cryptBase64[v&0x3f])
		v >>= 6
	}

	v = uint32(0)<<16 | uint32(0)<<8 | uint32(final[11])
	for j := 0; j < 2; j++ {
		out = append(out, cryptBase64[v&0x3f])
		v >>= 6
	}

	return string(out)
}

// sha256crypt - linux shadow $5$[rounds=R$]<salt>$<hash>
func sha256crypt(password []byte) string {
	const magic = "$5$"
	rounds := 5000
	salt := make([]byte, 16)
	rb := make([]byte, 16)
	if _, err := rand.Read(rb); err != nil {
		for i := 0; i < 16; i++ {
			salt[i] = cryptBase64[(i*37+13)&0x3f]
		}
	} else {
		for i := 0; i < 16; i++ {
			salt[i] = cryptBase64[int(rb[i])&0x3f]
		}
	}

	a := sha256.New()
	a.Write(password)
	a.Write(salt)

	alt := sha256.New()
	alt.Write(password)
	alt.Write(salt)
	alt.Write(password)
	altSum := alt.Sum(nil)

	pwLen := len(password)
	for n := pwLen; n > 0; n -= 32 {
		if n > 32 {
			a.Write(altSum)
		} else {
			a.Write(altSum[:n])
		}
	}

	for n := pwLen; n > 0; n >>= 1 {
		if (n & 1) == 1 {
			a.Write(altSum)
		} else {
			a.Write(password)
		}
	}
	adigest := a.Sum(nil)

	dp := sha256.New()
	for i := 0; i < pwLen; i++ {
		dp.Write(password)
	}
	dpSum := dp.Sum(nil)
	P := make([]byte, pwLen)
	for i := 0; i < pwLen; i += 32 {
		end := i + 32
		if end > pwLen {
			end = pwLen
		}
		copy(P[i:end], dpSum[:end-i])
	}

	ds := sha256.New()
	for i := 0; i < 16+int(adigest[0]); i++ {
		ds.Write(salt)
	}
	dsSum := ds.Sum(nil)
	S := make([]byte, len(salt))
	copy(S, dsSum[:len(salt)])

	digest := adigest
	for i := 0; i < rounds; i++ {
		c := sha256.New()
		if (i & 1) == 1 {
			c.Write(P)
		} else {
			c.Write(digest)
		}
		if i%3 != 0 {
			c.Write(S)
		}
		if i%7 != 0 {
			c.Write(P)
		}
		if (i & 1) == 1 {
			c.Write(digest)
		} else {
			c.Write(P)
		}
		digest = c.Sum(nil)
	}

	out := make([]byte, 0, len(magic)+len(salt)+1+43)
	out = append(out, magic...)
	out = append(out, salt...)
	out = append(out, '$')

	enc := func(b2, b1, b0 byte, n int) {
		v := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
		for j := 0; j < n; j++ {
			out = append(out, cryptBase64[v&0x3f])
			v >>= 6
		}
	}

	enc(digest[0], digest[10], digest[20], 4)
	enc(digest[21], digest[1], digest[11], 4)
	enc(digest[12], digest[22], digest[2], 4)
	enc(digest[3], digest[13], digest[23], 4)
	enc(digest[24], digest[4], digest[14], 4)
	enc(digest[15], digest[25], digest[5], 4)
	enc(digest[6], digest[16], digest[26], 4)
	enc(digest[27], digest[7], digest[17], 4)
	enc(digest[18], digest[28], digest[8], 4)
	enc(digest[9], digest[19], digest[29], 4)
	enc(0, digest[31], digest[30], 3)

	return string(out)
}

// sha512crypt - linux shadow ($6$)
func sha512crypt(password []byte) string {
	const magic = "$6$"
	const rounds = 5000
	salt := make([]byte, 16)
	{
		var rb [16]byte
		if _, err := rand.Read(rb[:]); err != nil {
			return ""
		}
		for i := 0; i < 16; i++ {
			salt[i] = cryptBase64[rb[i]&0x3f]
		}
	}

	saltBytes := salt
	keyLen := len(password)
	saltLen := len(saltBytes)

	a := sha512.New()
	a.Write(password)
	a.Write(saltBytes)

	alt := sha512.New()
	alt.Write(password)
	alt.Write(saltBytes)
	alt.Write(password)
	altSum := alt.Sum(nil)

	if keyLen > 0 {
		n := keyLen / 64
		for i := 0; i < n; i++ {
			a.Write(altSum)
		}
		a.Write(altSum[:keyLen%64])
	}

	for cnt := keyLen; cnt > 0; cnt >>= 1 {
		if (cnt & 1) != 0 {
			a.Write(altSum)
		} else {
			a.Write(password)
		}
	}
	final := a.Sum(nil)

	dp := sha512.New()
	for i := 0; i < keyLen; i++ {
		dp.Write(password)
	}
	dpSum := dp.Sum(nil)
	P := make([]byte, keyLen)
	for i := 0; i+64 <= keyLen; i += 64 {
		copy(P[i:i+64], dpSum)
	}
	copy(P[(keyLen/64)*64:], dpSum[:keyLen%64])

	ds := sha512.New()
	reps := 16 + int(final[0])
	for i := 0; i < reps; i++ {
		ds.Write(saltBytes)
	}
	dsSum := ds.Sum(nil)
	S := make([]byte, saltLen)
	for i := 0; i+64 <= saltLen; i += 64 {
		copy(S[i:i+64], dsSum)
	}
	copy(S[(saltLen/64)*64:], dsSum[:saltLen%64])

	for i := 0; i < rounds; i++ {
		c := sha512.New()
		if (i & 1) != 0 {
			c.Write(P)
		} else {
			c.Write(final)
		}
		if i%3 != 0 {
			c.Write(S)
		}
		if i%7 != 0 {
			c.Write(P)
		}
		if (i & 1) != 0 {
			c.Write(final)
		} else {
			c.Write(P)
		}
		final = c.Sum(nil)
	}

	enc := func(dst *[]byte, b2, b1, b0 byte, n int) {
		w := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
		for i := 0; i < n; i++ {
			*dst = append(*dst, cryptBase64[w&0x3f])
			w >>= 6
		}
	}

	buf := make([]byte, 0, len(magic)+saltLen+1+86)
	buf = append(buf, magic...)
	buf = append(buf, saltBytes...)
	buf = append(buf, '$')

	enc(&buf, final[0], final[21], final[42], 4)
	enc(&buf, final[22], final[43], final[1], 4)
	enc(&buf, final[44], final[2], final[23], 4)
	enc(&buf, final[3], final[24], final[45], 4)
	enc(&buf, final[25], final[46], final[4], 4)
	enc(&buf, final[47], final[5], final[26], 4)
	enc(&buf, final[6], final[27], final[48], 4)
	enc(&buf, final[28], final[49], final[7], 4)
	enc(&buf, final[50], final[8], final[29], 4)
	enc(&buf, final[9], final[30], final[51], 4)
	enc(&buf, final[31], final[52], final[10], 4)
	enc(&buf, final[53], final[11], final[32], 4)
	enc(&buf, final[12], final[33], final[54], 4)
	enc(&buf, final[34], final[55], final[13], 4)
	enc(&buf, final[56], final[14], final[35], 4)
	enc(&buf, final[15], final[36], final[57], 4)
	enc(&buf, final[37], final[58], final[16], 4)
	enc(&buf, final[59], final[17], final[38], 4)
	enc(&buf, final[18], final[39], final[60], 4)
	enc(&buf, final[40], final[61], final[19], 4)
	enc(&buf, final[62], final[20], final[41], 4)
	enc(&buf, 0, 0, final[63], 2)

	return string(buf)
}

// WordPress bcrypt: $wp$2y$10$<22-salt><31-hash>
// bcrypt(base64(HMAC-SHA384(key="wp-sha384",$password)))
func wpbcrypt(password []byte, cost int) string {
	const (
		wpPrefix     = "$wp$"
		bcryptPrefix = "$2y$"
	)

	mac := hmac.New(sha512.New384, []byte("wp-sha384"))
	mac.Write(password)
	tag := mac.Sum(nil)

	b64 := make([]byte, base64.StdEncoding.EncodedLen(len(tag)))
	base64.StdEncoding.Encode(b64, tag)

	bh, err := bcrypt.GenerateFromPassword(b64, cost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "wpbcrypt error:", err)
		return ""
	}
	s := string(bh)

	if len(s) < 4 || s[0] != '$' {
		fmt.Fprintln(os.Stderr, "wpbcrypt: unexpected bcrypt format")
		return ""
	}
	s = bcryptPrefix + s[4:]

	return wpPrefix + s[1:]
}

// yescrypt, using debian/libxcrypt defaults
func yescryptHash(pass []byte) string {
	// debian/libxcrypt defaults: N=4096, r=32, p=1, keyLen=32, 128-bit salt
	const N = 4096
	const r = 32
	const p = 1
	const keyLen = 32
	const saltLen = 16

	// salt
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		fmt.Fprintln(os.Stderr, "yescrypt: salt error:", err)
		return ""
	}

	// derive
	key, err := yescrypt.Key(pass, salt, N, r, p, keyLen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "yescrypt:", err)
		return ""
	}

	// crypt-base64 encoder (./0-9A-Za-z)
	encode64 := func(src []byte) string {
		var dst []byte
		var v uint32
		bitsAcc := 0
		for i := 0; i < len(src); i++ {
			v |= uint32(src[i]) << bitsAcc
			bitsAcc += 8
			for bitsAcc >= 6 {
				dst = append(dst, cryptBase64[v&0x3f])
				v >>= 6
				bitsAcc -= 6
			}
		}
		if bitsAcc > 0 {
			dst = append(dst, cryptBase64[v&0x3f])
		}
		return string(dst)
	}

	// params field:
	// flags 'j' (YESCRYPT_DEFAULTS), then log2(N) and r, both encoded 1-based in crypt-base64
	ln := bits.TrailingZeros(uint(N)) // N must be power of two
	if 1<<ln != N || r <= 0 {
		fmt.Fprintln(os.Stderr, "yescrypt: invalid N/r")
		return ""
	}
	params := []byte{'j', cryptBase64[(ln-1)&0x3f], cryptBase64[(r-1)&0x3f]}

	// assemble
	return "$y$" + string(params) + "$" + encode64(salt) + "$" + encode64(key)
}

// supported hash algos / modes
func hashBytes(hashFunc string, data []byte, cost int) string {
	// random salt gen
	// TODO move to helper func and optmize
	makeSaltHex := func() ([]byte, bool) {
		saltRaw := make([]byte, 8)
		if _, err := rand.Read(saltRaw); err != nil {
			fmt.Fprintln(os.Stderr, "salt generation error:", err)
			return nil, false
		}
		saltHex := make([]byte, hex.EncodedLen(len(saltRaw)))
		hex.Encode(saltHex, saltRaw)
		return saltHex, true
	}

	switch hashFunc {

	// Plaintext & Encoding
	// plaintext, dehex, -m 99999
	case "plaintext", "dehex", "99999":
		// passthrough & run checkForHex
		return string(data)

	// $HEX[]
	case "hex":
		buf := make([]byte, 5+hex.EncodedLen(len(data))+1) // "$HEX[" + hex + "]"
		copy(buf, "$HEX[")
		hex.Encode(buf[5:], data)
		buf[len(buf)-1] = ']'
		return string(buf)

	// base64 encode
	case "base64encode", "base64e":
		return base64.StdEncoding.EncodeToString(data)

	// base64 decode
	case "base64decode", "base64d":
		trimmedData := bytes.TrimSpace(data)
		decodedBytes := make([]byte, base64.StdEncoding.DecodedLen(len(trimmedData)))
		n, err := base64.StdEncoding.Decode(decodedBytes, trimmedData)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid Base64 string")
			return ""
		}
		return string(decodedBytes[:n])

	// base58 encode
	case "base58encode", "base58e":
		return base58.StdEncoding.EncodeToString(data)

	// base58 decode
	case "base58decode", "base58d":
		trimmedData := bytes.TrimSpace(data)
		decodedBytes := make([]byte, len(trimmedData))
		n, err := base58.StdEncoding.Decode(decodedBytes, trimmedData)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid Base58 string:", err)
			return ""
		}
		return string(decodedBytes[:n])

	// base32 encode
	case "base32encode", "base32e":
		return base32.StdEncoding.EncodeToString(data)

	// base32 decode
	case "base32decode", "base32d":
		trimmedData := bytes.TrimSpace(data)
		decodedBytes := make([]byte, base32.StdEncoding.DecodedLen(len(trimmedData)))
		n, err := base32.StdEncoding.Decode(decodedBytes, trimmedData)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid Base32 string")
			return ""
		}
		return string(decodedBytes[:n])

	// morsecode
	case "morsecode", "morse":
		return string(encodeToMorseBytes(data))

	// morsecode decode
	case "morsedecode", "morsed":
		return string(decodeMorseBytes(data))

	// Checksums

	// crc32 (standard, non-hashcat compatible)
	case "crc32":
		h := crc32.ChecksumIEEE(data)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, h)
		return hex.EncodeToString(b)

	// crc32 -m 11500
	case "11500": // hashcat compatible crc32 mode
		const hcCRCPad = ":00000000"
		h := crc32.ChecksumIEEE(data)
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, h)
		hashString := hex.EncodeToString(b)
		return hashString + hcCRCPad

	// crc64
	case "crc64":
		table := crc64.MakeTable(crc64.ECMA)
		h := crc64.Checksum(data, table)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, h)
		return hex.EncodeToString(b)

	// MDx

	// md4 -m 900
	case "md4", "900":
		h := md4.New()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))

	// md5 -m 0
	case "md5", "0":
		h := md5.Sum(data)
		return hex.EncodeToString(h[:])

	// -m 10 md5(pass.salt), -m 20 md5(salt.pass)
	case "10", "md5passsalt", "20", "md5saltpass":
		salt, ok := makeSaltHex()
		if !ok {
			return ""
		}
		h := md5.New()
		if hashFunc == "20" || hashFunc == "md5saltpass" {
			h.Write(salt) // salt first
			h.Write(data) // then pass
		} else {
			h.Write(data) // pass first
			h.Write(salt) // then salt
		}
		sum := h.Sum(nil)
		sumHexLen := hex.EncodedLen(len(sum))
		out := make([]byte, sumHexLen+1+len(salt)) // hex(sum) + ":" + saltHex
		hex.Encode(out[:sumHexLen], sum)
		out[sumHexLen] = ':'
		copy(out[sumHexLen+1:], salt)
		return string(out)

	// -m 2600 md5(md5($pass))
	case "md5md5", "2600":
		inner := md5.Sum(data)
		var innerHex [32]byte
		hex.Encode(innerHex[:], inner[:])
		outer := md5.Sum(innerHex[:])
		return hex.EncodeToString(outer[:])

	// SHA1

	// sha1 -m 100
	case "sha1", "100":
		h := sha1.Sum(data)
		return hex.EncodeToString(h[:])

	// -m 110 sha1(pass.salt), -m 120 sha1(salt.pass)
	case "110", "sha1passsalt", "120", "sha1saltpass":
		salt, ok := makeSaltHex()
		if !ok {
			return ""
		}
		h := sha1.New()
		if hashFunc == "120" || hashFunc == "sha1saltpass" {
			h.Write(salt) // salt first
			h.Write(data) // then pass
		} else {
			h.Write(data) // pass first
			h.Write(salt) // then salt
		}
		sum := h.Sum(nil)
		// 20-byte SHA1 -> 40 hex chars
		out := make([]byte, 40+1+len(salt)) // hex(sum) + ":" + saltHex
		hex.Encode(out[:40], sum)
		out[40] = ':'
		copy(out[41:], salt)
		return string(out)

	// -m 4500 sha1(sha1($pass))
	case "sha1sha1", "4500":
		inner := sha1.Sum(data)
		var innerHex [40]byte
		hex.Encode(innerHex[:], inner[:])
		outer := sha1.Sum(innerHex[:])
		return hex.EncodeToString(outer[:])

	// SHA2

	// sha2-224 -m 1300
	case "sha2-224", "sha224", "1300":
		h := sha256.New224()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))

	// -m 1310 sha224(pass.salt), -m 1320 sha224(salt.pass)
	case "1310", "sha224passsalt", "1320", "sha224saltpass":
		salt, ok := makeSaltHex() // returns ASCII-hex salt
		if !ok {
			return ""
		}
		h := sha256.New224()
		if hashFunc == "1320" || hashFunc == "sha224saltpass" {
			h.Write(salt) // salt first
			h.Write(data) // then pass
		} else {
			h.Write(data) // pass first
			h.Write(salt) // then salt
		}
		sum := h.Sum(nil)
		// SHA-224 = 28 bytes -> 56 hex chars
		out := make([]byte, 56+1+len(salt)) // hex(sum) + ":" + saltHex
		hex.Encode(out[:56], sum)
		out[56] = ':'
		copy(out[57:], salt)
		return string(out)

	// sha2-256 -m 1400
	case "sha2-256", "sha256", "1400":
		h := sha256.Sum256(data)
		return hex.EncodeToString(h[:])

	// -m 1410 sha256(pass.salt), -m 1420 sha256(salt.pass)
	case "1410", "sha256passsalt", "1420", "sha256saltpass":
		salt, ok := makeSaltHex() // reuse your helper that returns ASCII-hex salt
		if !ok {
			return ""
		}
		h := sha256.New()
		if hashFunc == "1420" || hashFunc == "sha256saltpass" {
			h.Write(salt) // salt first
			h.Write(data) // then pass
		} else {
			h.Write(data) // pass first
			h.Write(salt) // then salt
		}
		sum := h.Sum(nil)
		// 32-byte SHA-256 -> 64 hex chars
		out := make([]byte, 64+1+len(salt)) // hex(sum) + ":" + saltHex
		hex.Encode(out[:64], sum)
		out[64] = ':'
		copy(out[65:], salt)
		return string(out)

	// sha2-384 -m 10800
	case "sha2-384", "sha384", "10800":
		h := sha512.New384()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))

	// -m 10810 sha384(pass.salt), -m 10820 sha384(salt.pass)
	case "10810", "sha384passsalt", "10820", "sha384saltpass":
		salt, ok := makeSaltHex() // ASCII-hex salt
		if !ok {
			return ""
		}
		h := sha512.New384()
		if hashFunc == "10820" || hashFunc == "sha384saltpass" {
			h.Write(salt) // salt first
			h.Write(data) // then pass
		} else {
			h.Write(data) // pass first
			h.Write(salt) // then salt
		}
		sum := h.Sum(nil)

		// SHA-384 = 48 bytes -> 96 hex chars
		out := make([]byte, 96+1+len(salt)) // hex(sum) + ":" + saltHex
		hex.Encode(out[:96], sum)
		out[96] = ':'
		copy(out[97:], salt)
		return string(out)

	// sha2-512 -m 1700
	case "sha2-512", "sha512", "1700":
		h := sha512.Sum512(data)
		return hex.EncodeToString(h[:])

	// -m 1710 sha512(pass.salt), -m 1720 sha512(salt.pass)
	case "1710", "sha512passsalt", "1720", "sha512saltpass":
		salt, ok := makeSaltHex() // ASCII-hex salt
		if !ok {
			return ""
		}
		h := sha512.New()
		if hashFunc == "1720" || hashFunc == "sha512saltpass" {
			h.Write(salt) // salt first
			h.Write(data) // then pass
		} else {
			h.Write(data) // pass first
			h.Write(salt) // then salt
		}
		sum := h.Sum(nil)

		// 64-byte SHA-512 -> 128 hex chars
		out := make([]byte, 128+1+len(salt)) // hex(sum) + ":" + saltHex
		hex.Encode(out[:128], sum)
		out[128] = ':'
		copy(out[129:], salt)
		return string(out)

	// sha2-512-224
	case "sha2-512-224", "sha512-224", "sha512224":
		h := sha512.New512_224()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))

	// sha2-512-256
	case "sha2-512-256", "sha512-256", "sha512256":
		h := sha512.New512_256()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))

	// SHA3

	// sha3-224 -m 17300
	case "sha3-224", "sha3224", "17300":
		h := sha3.New224()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))

	// sha3-256 om 17400
	case "sha3-256", "sha3256", "17400":
		h := sha3.New256()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))

	// sha3-384 om 17500
	case "sha3-384", "sha3384", "17500":
		h := sha3.New384()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))

	// sha3-512 om 17600
	case "sha3-512", "sha3512", "17600":
		h := sha3.New512()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))

	// Keccak

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

	// BLAKE2

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

	// hashcat mode -m 600 BLAKE2b-512, $BLAKE2$<hex>
	case "600":
		h := blake2b.Sum512(data)
		const pB = "$BLAKE2$"
		buf := make([]byte, len(pB)+hex.EncodedLen(len(h)))
		copy(buf, pB)
		hex.Encode(buf[len(pB):], h[:])
		return string(buf)

	// blake2s-256 (raw hex)
	case "blake2s-256", "blake2s256":
		h := blake2s.Sum256(data)
		return hex.EncodeToString(h[:])

	// hashcat mode -m 31000 BLAKE2s-256, $BLAKE2$<hex>
	case "31000":
		h := blake2s.Sum256(data)
		const pS = "$BLAKE2$"
		buf := make([]byte, len(pS)+hex.EncodedLen(len(h)))
		copy(buf, pS)
		hex.Encode(buf[len(pS):], h[:])
		return string(buf)

	// Other Hashes

	// ripemd-160 -m 6000
	case "ripemd-160", "ripemd160", "6000":
		h := ripemd160.New()
		h.Write(data)
		return hex.EncodeToString(h.Sum(nil))

		// mysql5 -m 300
	case "mysql4", "mysql5", "300":
		first := sha1.Sum(data)
		second := sha1.Sum(first[:])
		buf := make([]byte, 1+hex.EncodedLen(len(second)))
		buf[0] = '*'
		hex.Encode(buf[1:], second[:])
		for i := 1; i < len(buf); i++ {
			if buf[i] >= 'a' && buf[i] <= 'f' {
				buf[i] -= 32
			}
		}
		return string(buf)

	// ntlm -m 1000 (strict: skip invalid UTF-8 / UTF-16)
	case "ntlm", "1000":
		var rs []rune
		for i := 0; i < len(data); {
			r, sz := utf8.DecodeRune(data[i:])
			if r == utf8.RuneError && sz == 1 {
				return ""
			}
			if r >= 0xD800 && r <= 0xDFFF {
				return ""
			}
			rs = append(rs, r)
			i += sz
		}
		u16 := utf16.Encode(rs)
		h := md4.New()
		_ = binary.Write(h, binary.LittleEndian, u16)
		return hex.EncodeToString(h.Sum(nil))

	// Crypt / KDF

	// argon2id
	case "argon2id", "34000":
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

	// wordpress bcrypt
	case "wpbcrypt":
		return wpbcrypt(data, cost)

	// md5crypt -m 500
	case "md5crypt", "500":
		return md5crypt(data)

	// sha256crypt ($5$) -m 7400
	case "sha256crypt", "7400":
		return sha256crypt(data)

	// sha512crypt ($6$) -m 1800
	case "sha512crypt", "1800":
		return sha512crypt(data)

	// phpass -m 400
	case "phpass", "phpbb3", "400": // phpass = $P$, phpbb3 = $H$
		return phpassMD5(data, hashFunc, 11, nil)

	// yescrypt
	case "yescrypt":
		return yescryptHash(data)

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
		lineBytes := scanner.Bytes()
		decodedBytes, hexContent, hexErrCount := checkForHex(lineBytes)
		hash := hashBytes(hashFunc, decodedBytes, cost)
		if hash == "" {
			continue
		} // skip empty lines
		writer.WriteString(hash)
		if hashPlainOutput {
			_ = writer.WriteByte(':')
			_, _ = writer.Write(hexContent)
		}
		_ = writer.WriteByte('\n')
		atomic.AddInt64(count, 1)                          // line count
		atomic.AddInt64(hexErrorCount, int64(hexErrCount)) // hex error count
	}
	_ = writer.Flush()
}

// process logic
func startProc(hashFunc string, inputFile string, outputPath string, hashPlainOutput bool, numGoroutines int, cost int) {
	//var readBufferSize = 1024 * 1024 // read buffer
	var readBufferSize = numGoroutines + 16*32*1024 // variable read buffer

	// lower read buffer for slow(ish) algos
	{
		bufFixed := map[string]bool{
			"phpass": true, "phpbb3": true, "400": true,
			"md5crypt": true, "500": true,
			"sha256crypt": true, "7400": true,
			"sha512crypt": true, "1800": true,
		}
		if bufFixed[hashFunc] {
			readBufferSize = numGoroutines + 16*32
		}
	}

	// lower read buffer for bcrypt-family (scale by cost)
	{
		bufBcrypt := map[string]bool{
			"bcrypt": true, "3200": true,
			"wpbcrypt": true,
		}
		if bufBcrypt[hashFunc] {
			readBufferSize = numGoroutines/cost + 32*2
		}
	}

	// lower read buffer for argon2id, yescrypt
	{
		bufSlow := map[string]bool{
			"argon2id": true, "34000": true,
			"yescrypt": true,
		}
		if bufSlow[hashFunc] {
			readBufferSize = numGoroutines + 8*2
		}
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
	costFlag := flag.Int("cost", 10, "Bcrypt cost (4-31)")
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
	costProvided := *costFlag != 10
	if costProvided && *hashFunc != "bcrypt" && *hashFunc != "3200" && *hashFunc != "wpbcrypt" {
		log.Fatalf("Error: -cost flag is only allowed for bcrypt modes")
	}
	if *hashFunc == "bcrypt" || *hashFunc == "3200" || *hashFunc == "wpbcrypt" {
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

	// start main logic (startProc)
	startProc(*hashFunc, *inputFile, *outputFile, *hashPlainOutput, numThreads, *costFlag)
}

// end code
