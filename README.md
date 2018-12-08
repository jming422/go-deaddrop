# go-deaddrop
Project for learning and experimenting with cryptography in go

Got some hints from https://golang.org/pkg/crypto/cipher/#NewGCM and other Go documentation examples.

As per Go's implementation of AES: The key may be either 16, 24, or 32
bytes, to select AES-128, AES-192, or AES-256 respectively. When a key
is not manually specified, a securely random 32 byte key is generated.
