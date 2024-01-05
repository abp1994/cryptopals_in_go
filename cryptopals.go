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
	c4()
	c5()
	c6()
}

func c1() {
	fmt.Println("\n-- Challenge 1 - Convert hex to base 64 --")

	plaintextHex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	plaintextBytes, err := hex.DecodeString(plaintextHex)
	handleError(err)
	plaintextB64 := base64.StdEncoding.EncodeToString(plaintextBytes)

	fmt.Println("Hex Plaintext     :", plaintextHex)
	fmt.Println("Bytes Plaintext   :", string(plaintextBytes))
	fmt.Println("Base 64 plaintext :", plaintextB64)
}

func c2() {
	fmt.Println("\n-- Challenge 2 - Fixed XOR --")

	ciphertextHex := "1c0111001f010100061a024b53535009181c"
	keyHex := "686974207468652062756c6c277320657965"

	ciphertext, err := hex.DecodeString(ciphertextHex)
	handleError(err)

	key, err := hex.DecodeString(keyHex)
	handleError(err)

	plaintext, err := utils.XorBytes(ciphertext, key)
	handleError(err)

	plaintextHex := hex.EncodeToString(plaintext)

	fmt.Println("Hex ciphertext        :", ciphertextHex)
	fmt.Println("Key                   :", string(key))
	fmt.Println("Plaintext             :", string(plaintext))
	fmt.Println("Hex encoded plaintext :", plaintextHex)

}

func c3() {
	fmt.Println("\n-- Challenge 3 - Single-byte XOR cipher --")

	ciphertextHex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	ciphertext, err := hex.DecodeString(ciphertextHex)
	handleError(err)
	plaintext, key, score := utils.CrackSingleByteXor(ciphertext)

	fmt.Println("Ciphertext              :", string(ciphertext))
	fmt.Printf("Lowest Chi-Square score : %f\n", score)
	fmt.Println("Corresponding Key       :", string(key))
	fmt.Println("Corresponding plaintext :", string(plaintext))
}

func c4() {
	fmt.Println("\n-- Challenge 4 - Detect single-char XOR --")
	dataHex := utils.ImportTxtLines("res/data_S1C4.txt")

	var lowestScore float32 = math.MaxFloat32
	var lowestScoreKey byte = 'A'
	lowestScoringPlaintext := make([]byte, hex.DecodedLen(len(dataHex[0])))
	var lowestScoringLine int = 0

	// Crack lines of text.
	for i, ciphertextHex := range dataHex {
		// Create a byte slice to store the decoded data.
		ciphertext := make([]byte, hex.DecodedLen(len(ciphertextHex)))

		// Decode the hex-encoded data into the decoded byte slice.
		n, err := hex.Decode(ciphertext, ciphertextHex)
		if err != nil {
			fmt.Println("Error decoding base64:", err)
		}

		// Trim any extra capacity in the decoded byte slice.
		ciphertext = ciphertext[:n]

		//Crack single byte XOR and record key and score.
		plaintext, key, score := utils.CrackSingleByteXor(ciphertext)
		if score < lowestScore {
			lowestScore = score
			lowestScoreKey = key
			lowestScoringPlaintext = plaintext
			lowestScoringLine = i
		}
	}
	fmt.Printf("Lowest Chi-Square score : %f\n", lowestScore)
	fmt.Println("Corresponding line      :", lowestScoringLine)
	fmt.Println("Corresponding Key       :", string(lowestScoreKey))
	fmt.Println("Corresponding plaintext :", string(lowestScoringPlaintext))
}

func c5() {
	fmt.Println("\n-- Challenge 5 - Implement repeating-key XOR --")

	plaintext := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")
	ciphertext := utils.RepeatingKeyXor(key, plaintext)

	fmt.Println("Plaintext:", string(plaintext))
	fmt.Println("Key:", string(key))
	fmt.Println("Ciphertext hex:", hex.EncodeToString(ciphertext))
}
func c6() {
	fmt.Println("\n-- Challenge 6 - Break repeating-key XOR --")
	x, err := utils.FindHammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	handleError(err)
	fmt.Println(x)
}

func handleError(err error) {
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
}
