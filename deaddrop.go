package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func errCheck(e error) {
	if e != nil {
		panic(fmt.Sprintln("Encountered an error:", e))
	}
}

func errRecover() {
	if r := recover(); r != nil {
		fmt.Println(r)
	}
}

func checkMAC(message, messageMAC, key []byte) bool {
	calcMAC := hmac.New(sha256.New, key)
	calcMAC.Write(message)
	expectedMAC := calcMAC.Sum(nil)

	return hmac.Equal(messageMAC, expectedMAC)
}

// Got some hints from https://golang.org/pkg/crypto/cipher/#NewCFBEncrypter

func main() {
	defer errRecover()

	input := bufio.NewReader(os.Stdin)

	fmt.Print("Enter a string to encrypt> ")
	raw, e := input.ReadString('\n')
	errCheck(e)

	plaintext := []byte(strings.TrimSpace(raw))
	fmt.Println("Your string's bytes:")
	fmt.Printf("%x\n\n", plaintext)

	key, e := hex.DecodeString("42ba23df786863eaccd3a8ab34673245")
	errCheck(e)
	macKey, e := hex.DecodeString("ac82e7e4f9e2ab7483cc76dc37abfe29")
	errCheck(e)

	aesCipher, e := aes.NewCipher(key)
	errCheck(e)
	fmt.Printf("Using AES key: %x\n     HMAC key: %x\n\n", key, macKey)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, e = io.ReadFull(rand.Reader, iv)
	errCheck(e)

	fmt.Print("Encrypting your string...")
	eStream := cipher.NewCFBEncrypter(aesCipher, iv)
	eStream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	fmt.Println(" done.")
	fmt.Println("Your string's bytes, but encrypted:")
	fmt.Printf("%x\n\n", ciphertext)

	fmt.Print("Computing MAC on the ciphertext...")
	mac := hmac.New(sha256.New, macKey)
	mac.Write(ciphertext)
	macBytes := mac.Sum(nil)
	fmt.Println(" done.")
	fmt.Println("The MAC for this ciphertext is:")
	fmt.Printf("%x\n\n", macBytes)

	fmt.Print("Verifying the ciphertext's MAC...")
	str := " NOT verified!"
	if checkMAC(ciphertext, macBytes, macKey) {
		str = " verified."
	}
	fmt.Println(str)

	newPlaintext := make([]byte, len(ciphertext)-aes.BlockSize)
	fmt.Print("Decrypting with the same key...")
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext is too short!")
	}
	dStream := cipher.NewCFBDecrypter(aesCipher, ciphertext[:aes.BlockSize])
	dStream.XORKeyStream(newPlaintext, ciphertext[aes.BlockSize:])
	fmt.Println(" done.")
	fmt.Println("The string's bytes, de-encrypted:")
	fmt.Printf("%x\n", newPlaintext)
	fmt.Println("As a string:", string(newPlaintext))
}
