package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

func main() {
	c1()
	c2()
}

func c1() {

	fmt.Println("\n-- Challenge 1 - Convert hex to base 64 --")

	plaintextHex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	plaintextBytes, err := hex.DecodeString(plaintextHex)
	handleError(err)

	plaintextB64 := base64.StdEncoding.EncodeToString(plaintextBytes)

	fmt.Println("Hex Plaintext:", plaintextHex)
	fmt.Println("Bytes Plaintext:", string(plaintextBytes))
	fmt.Println("Base 64 plaintext:", plaintextB64)
}

func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("Length of Byte slices not equal!")
	}

	// Create a new byte slice to store the result
	result := make([]byte, len(a))

	// Iterate through each pair of bytes and apply XOR
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}

	return result, nil
}

func c2() {

	fmt.Println("\n-- Challenge 2 - Fixed XOR --")

	ciphertextHex := "1c0111001f010100061a024b53535009181c"
	keyHex := "686974207468652062756c6c277320657965"

	ciphertext, err := hex.DecodeString(ciphertextHex)
	handleError(err)
	key, err := hex.DecodeString(keyHex)

	plaintext, err := xorBytes(ciphertext, key)
	handleError(err)

	fmt.Println("Ciphertext:", string(ciphertext))
	fmt.Println("Key:", string(key))
	fmt.Println("Plaintext:", string(plaintext))

}

func handleError(err error) {
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
}
