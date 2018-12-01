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

func promptForPlaintext() []byte {
	input := bufio.NewReader(os.Stdin)
	var (
		raw string
		e   error
	)

	fmt.Print("Enter a string to encrypt> ")
	for needInput := true; needInput; {
		if raw, e = input.ReadString('\n'); e != nil {
			fmt.Println("Error reading input string!", e)
		} else {
			needInput = false
		}
	}

	return []byte(strings.TrimSpace(raw))
}

func parseKey(input string) []byte {
	key, e := hex.DecodeString(input)
	if e != nil {
		panic(fmt.Sprintln("Error parsing your encryption key! Please provide a string of even length with only hexadecimal characters."))
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

	var plaintext, key []byte

	kFlag := flag.String("k", "", "Use this option to provide your own encryption key as a hexadecimal string. Otherwise a key will be generated for you.")
	flag.Parse()

	if *kFlag != "" {
		key = parseKey(*kFlag)
	} else {
		key = randomKey()
	}

	if args := flag.Args(); len(args) > 0 {
		plaintext = []byte(args[0])
	} else {
		plaintext = promptForPlaintext()
	}

	ciphertext := Encrypt(plaintext, key, randomNonce())

	fmt.Println("Encrypted value:")
	fmt.Printf("%x\n", ciphertext)
}
