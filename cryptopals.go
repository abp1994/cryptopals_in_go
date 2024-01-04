package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"

	"github.com/abp1994/cryptopals_in_go/pkg/utils"
)

func main() {
	c1()
	c2()
	c3()
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

func c2() {

	fmt.Println("\n-- Challenge 2 - Fixed XOR --")

	ciphertextHex := "1c0111001f010100061a024b53535009181c"
	keyHex := "686974207468652062756c6c277320657965"

	ciphertext, err := hex.DecodeString(ciphertextHex)
	handleError(err)
	key, err := hex.DecodeString(keyHex)

	plaintext, err := utils.XorBytes(ciphertext, key)
	handleError(err)

	plaintextHex := hex.EncodeToString(plaintext)

	fmt.Println("Hex ciphertext:", ciphertextHex)
	fmt.Println("Key:", string(key))
	fmt.Println("Plaintext:", string(plaintext))
	fmt.Println("Hex encoded plaintext:", plaintextHex)

}

func c3() {

	fmt.Println("\n-- Challenge 3 - Single-byte XOR cipher --")

	ciphertextHex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	ciphertext, err := hex.DecodeString(ciphertextHex)
	handleError(err)

	plaintext := make([]byte, len(ciphertext))
	var lowestScore float32 = math.MaxFloat32
	var lowestScoreKey byte = 'A'
	lowestScoringPlaintext := ciphertext
	for i := 0; i <= 255; i++ {
		plaintext = utils.SingleByteXOR(byte(i), ciphertext)
		newScore := utils.EnglishTextScorer(plaintext)
		if newScore < lowestScore {
			lowestScore = newScore
			lowestScoreKey = byte(i)
			lowestScoringPlaintext = plaintext
		}
	}

	fmt.Println("Ciphertext: ", string(ciphertext))
	fmt.Printf("Lowest Chi-Square score: %f\n", lowestScore)
	fmt.Println("Corresponding Key: ", string(lowestScoreKey))
	fmt.Println("Lowest scoring plaintext: ", string(lowestScoringPlaintext))

}

func handleError(err error) {
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
}
