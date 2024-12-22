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
	var lowestScoreKey byte
	lowestScoringPlaintext := make([]byte, hex.DecodedLen(len(dataHex[0])))
	lowestScoringLine := 0

	// Crack lines of text.
	for i, ciphertextHex := range dataHex {
		// Create a byte slice to store the decoded data.
		ciphertext := make([]byte, hex.DecodedLen(len(ciphertextHex)))

		// Decode the hex-encoded data into the decoded byte slice.
		n, err := hex.Decode(ciphertext, ciphertextHex)
		if err != nil {
			fmt.Println("error decoding hex:", err)
		}

		// Trim any extra capacity in the decoded byte slice.
		ciphertext = ciphertext[:n]

		//Crack single byte XOR and record key and score.
		plaintext, key, score := utils.CrackSingleByteXor(ciphertext)
		if score < lowestScore {
			lowestScore = score
			lowestScoreKey = key
			copy(lowestScoringPlaintext, plaintext)
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

	fmt.Println("Plaintext      :", string(plaintext))
	fmt.Println("Key            :", string(key))
	fmt.Println("Ciphertext hex :", hex.EncodeToString(ciphertext))
}

func c6() {
	fmt.Println("\n-- Challenge 6 - Break repeating-key XOR --")
	text1 := []byte("this is a test")
	text2 := []byte("wokka wokka!!!")

	testDistance, err := utils.FindHammingDistance(text1, text2)
	handleError(err)

	fmt.Println("-- Part 1 --")
	fmt.Println("String 1         :", string(text1))
	fmt.Println("String 2         :", string(text2))
	fmt.Println("Hamming distance :", testDistance)
	fmt.Println("-- Part 2 --")

	ciphertextLinesB64 := utils.ImportTxtLines("res/data_S1C6.txt")

	// Concatenate slices using a loop
	var ciphertextB64 []byte
	for _, slice := range ciphertextLinesB64 {
		ciphertextB64 = append(ciphertextB64, slice...)
	}

	// Create a byte slice to store the decoded data.
	ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertextB64)))

	// Decode the base64-encoded data into the decoded byte slice.
	n, err := base64.StdEncoding.Decode(ciphertext, ciphertextB64)
	if err != nil {
		fmt.Println("error decoding hex:", err)
	}

	// Trim any extra capacity in the decoded byte slice.
	ciphertext = ciphertext[:n]

	//Find Best Keylength.
	likelyKeySizes := utils.FindBestKeySizes(ciphertext, 40, 10)[0:3]

	// Define a struct to hold the key, score, and secret
	type Record struct {
		Key    []byte
		Score  float32
		Secret []byte
	}

	table := []Record{}

	// Find highest scoring key for top 3 keysizes.
	for _, entry := range likelyKeySizes[:3] { // Iterate over the first 3 elements.
		Keylength := entry.IntValue
		key := utils.FindKey(Keylength, ciphertext)
		secret := utils.RepeatingKeyXor(key, ciphertext)
		score := utils.EnglishTextScorer(secret)

		table = append(table, Record{Key: key, Score: score, Secret: secret})
	}

	// Find the record with the lowest Score
	lowest := table[0] // Start with the first record as the lowest
	for _, record := range table[1:] {
		if record.Score < lowest.Score {
			lowest = record
		}
	}

	fmt.Println("Most likely key sizes and scores :", likelyKeySizes)
	fmt.Println("Lowest score         : ", lowest.Score)
	fmt.Println("Corresponding Key     : ", string(lowest.Key))
	fmt.Println("Secret                : \n", string(lowest.Secret))

}

func handleError(err error) {
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
}
