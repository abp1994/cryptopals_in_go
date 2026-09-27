package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/abp1994/cryptopals_in_go/pkg/utils"
)

func main() {
	start := time.Now()
	c1()
	c2()
	c3()
	c4()
	c5()
	c6()
	c7()
	c8()

	fmt.Println("\nTotal runtime:", time.Since(start))
}

// Challenge 1 - Convert hex to base 64
func c1() string {

	plaintextHex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	plaintextBytes, err := hex.DecodeString(plaintextHex)
	handleError(err)
	return base64.StdEncoding.EncodeToString(plaintextBytes)

}

// Challenge 2 - Fixed XOR
func c2() string {

	ciphertextHex := "1c0111001f010100061a024b53535009181c"
	keyHex := "686974207468652062756c6c277320657965"

	ciphertext, err := hex.DecodeString(ciphertextHex)
	handleError(err)

	key, err := hex.DecodeString(keyHex)
	handleError(err)

	plaintext, err := utils.XorBytes(ciphertext, key)
	handleError(err)

	return hex.EncodeToString(plaintext)

}

// Challenge 3 - Single-byte XOR cipher
func c3() string {

	ciphertextHex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	ciphertext, err := hex.DecodeString(ciphertextHex)
	handleError(err)
	plaintext, _, _ := utils.CrackSingleByteXor(ciphertext)
	return string(plaintext)
}

// Challenge 4 - Detect single-char XOR
func c4() string {
	dataHex := utils.ImportTxtLines("res/data_S1C4.txt")

	var lowestScore float32 = math.MaxFloat32
	lowestScoringPlaintext := make([]byte, hex.DecodedLen(len(dataHex[0])))

	// Crack lines of text.
	for _, ciphertextHex := range dataHex {
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
		plaintext, _, score := utils.CrackSingleByteXor(ciphertext)
		if score < lowestScore {
			lowestScore = score
			copy(lowestScoringPlaintext, plaintext)
		}
	}
	return string(lowestScoringPlaintext)
}

// Challenge 5 - Implement repeating-key XOR
func c5() string {

	plaintext := []byte(
		"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
	)
	key := []byte("ICE")
	ciphertext := utils.RepeatingKeyXor(key, plaintext)

	return hex.EncodeToString(ciphertext)
}

// Challenge 6 - Break repeating-key XOR
func c6() string {

	ciphertext, _ := utils.ImportB64Data("data_S1C6.txt")

	//Find Best Keylength.
	likelyKeySizes := utils.FindBestKeySizes(ciphertext, 40, 10)[0:3]

	// Define a struct to hold the key, score, and secret.
	type record struct {
		key, secret []byte
		score       float32
	}

	table := make([]record, 0, len(likelyKeySizes))

	// Find the record with the lowest Score for top 3 keysizes.
	for _, entry := range likelyKeySizes { // Iterate over the first 3 elements.
		Keylength := entry.KeySize
		key := utils.FindKey(Keylength, ciphertext)
		secret := utils.RepeatingKeyXor(key, ciphertext)
		score := utils.EnglishTextScorer(secret)
		table = append(table, record{key: key, score: score, secret: secret})
	}

	// Find lowest score.
	sort.Slice(table, func(i, j int) bool {
		return table[i].score < table[j].score
	})
	lowest := table[0]

	return string(lowest.secret)
}

// Challenge 7 - AES in ECB mode
func c7() string {

	key := []byte("YELLOW SUBMARINE")
	ciphertext, _ := utils.ImportB64Data("data_S1C7.txt")

	plaintext, _ := utils.AESECBDecrypt(key, ciphertext)

	return string(plaintext)
}

func c8() {
	fmt.Println("\n-- Challenge 8 - Detect AES in ECB mode --")
}

func handleError(err error) {
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
	}
}
