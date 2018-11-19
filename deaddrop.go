package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

func main() {
	input := bufio.NewReader(os.Stdin)

	fmt.Print("Enter a string to encrypt> ")
	raw, e := input.ReadString('\n')
	if e != nil {
		fmt.Println("Error reading input:", e)
		return
	}

	plaintext := []byte(strings.TrimSpace(raw))
	fmt.Println("Your string's bytes:")
	fmt.Printf("%x\n", plaintext)

	fmt.Print("Generating new key pair for this encryption...")
	privateKey, e := rsa.GenerateKey(rand.Reader, 4096)
	if e != nil {
		fmt.Println("Error generating key pair:", e)
		return
	}
	fmt.Println(" done.")

	fmt.Print("Encrypting your string using RSA-OAEP...")
	ciphertext, e := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&privateKey.PublicKey,
		plaintext,
		[]byte("practicedeaddrop"))
	if e != nil {
		fmt.Println("Error encypting your string:", e)
		return
	}

	fmt.Println(" done.")

	fmt.Println("Your string's bytes, but encrypted:")
	fmt.Printf("%x\n", ciphertext)
}
