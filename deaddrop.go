package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

func promptForPlaintext(message string) string {
	input := bufio.NewReader(os.Stdin)
	var (
		raw string
		e   error
	)

	fmt.Printf("%s> ", message)
	for needInput := true; needInput; {
		if raw, e = input.ReadString('\n'); e != nil {
			fmt.Println("Error reading input string!", e)
		} else {
			needInput = false
		}
	}

	return strings.TrimSpace(raw)
}

func promptForHexString(message string) []byte {
	return parseHex(promptForPlaintext(message))
}

func parseHex(input string) []byte {
	key, e := hex.DecodeString(input)
	if e != nil {
		panic(fmt.Sprintln("Error parsing input! Please provide a string of even length with only hexadecimal characters."))
	}

	return key
}

func randomKey() []byte {
	key := make([]byte, 32) //Using a 32-byte key causes Go to use AES-256
	_, e := rand.Read(key)
	if e != nil {
		panic(fmt.Sprintln("Error generating AES key!", e))
	}
	fmt.Println("Generated random encryption key.")

	return key
}

func randomNonce() []byte {
	nonce := make([]byte, 12) //12 is Go's gcmStandardNonceSize
	_, e := rand.Read(nonce)
	if e != nil {
		panic(fmt.Sprintln("Error generating MAC key!", e))
	}

	fmt.Printf("Using random nonce: %x\n", nonce)
	return nonce
}

func Encrypt(plaintext, key, nonce []byte) []byte {
	aesCipher, e := aes.NewCipher(key)
	if e != nil {
		panic(fmt.Sprintln("Error creating AES cipher!", e))
	}

	aesgcm, e := cipher.NewGCM(aesCipher)
	if e != nil {
		panic(fmt.Sprintln("Error creating GCM cipher!", e))
	}

	fmt.Print("Encrypting...")
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	fmt.Println(" done.")

	return ciphertext
}

func Decrypt(ciphertext, key, nonce []byte) []byte {
	aesCipher, e := aes.NewCipher(key)
	if e != nil {
		panic(fmt.Sprintln("Error creating AES cipher!", e))
	}

	aesgcm, e := cipher.NewGCM(aesCipher)
	if e != nil {
		panic(fmt.Sprintln("Error creating GCM cipher!", e))
	}

	fmt.Print("Decrypting ...")
	plaintext, e := aesgcm.Open(nil, nonce, ciphertext, nil)
	if e != nil {
		panic(fmt.Sprintln("Error decrypting!", e))
	}
	fmt.Println(" done.")

	return plaintext
}

func errRecover() {
	if r := recover(); r != nil {
		fmt.Println(r)
	}
}

func main() {
	defer errRecover()

	var (
		key, input, nonce []byte
		eFlag, dFlag      bool
		kFlag, nFlag      string
	)

	flag.BoolVar(&eFlag, "e", false, "Encryption mode")
	flag.BoolVar(&dFlag, "d", false, "Decryption mode")
	flag.StringVar(&kFlag, "k", "", "Use this option to provide your own encryption key as a hexadecimal string. Otherwise a key will be generated for you.")
	flag.StringVar(&nFlag, "n", "", "Use this option to provide your own nonce for the encryption/decryption. This number must be 12 bytes long and unique for all time for a given key.")
	flag.Parse()

	if eFlag && dFlag {
		fmt.Println("You may supply only one of -e and -d!")
		fmt.Println("It's not very helpful to simultaneously encrypt and decrypt, now is it?")
		return
	}

	if kFlag != "" {
		key = parseHex(kFlag)
	} else {
		key = randomKey()
	}

	if nFlag != "" {
		nonce = parseHex(nFlag)
	} else if !dFlag {
		nonce = randomNonce()
	} else {
		nonce = promptForHexString("Enter the nonce to use")
	}

	args := flag.Args()
	if len(args) > 0 {
		input = []byte(args[0])
	} else if !dFlag {
		input = []byte(promptForPlaintext("Enter a string to encrypt"))
	} else {
		input = []byte(promptForPlaintext("Enter a string to decrypt"))
	}

	if dFlag {
		output := Decrypt(input, key, nonce)
		fmt.Println("Decrypted value:")
		fmt.Printf("%x\n", output)
	} else {
		output := Encrypt(input, key, nonce)
		fmt.Println("Encrypted value:")
		fmt.Printf("%x\n", output)
	}
}
