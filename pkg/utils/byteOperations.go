package utils

import (
	"errors"
	"fmt"
	"regexp"
)

func XorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("Length of Byte slices not equal!")
	}

	result := make([]byte, len(a))

	// Iterate through each pair of bytes and apply XOR.
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}

	return result, nil
}

func SingleByteXOR(singleByte byte, byteSlice []byte) []byte {

	result := make([]byte, len(byteSlice))

	for i, currentByte := range byteSlice {
		result[i] = singleByte ^ currentByte
	}
	return result
}

func CrackSingleByteXor(ciphertext []byte) ([]byte, byte, error) {
	fmt.Print(ciphertext)
	return ciphertext, ciphertext[0], nil

}

var nonAlphabeticCharPattern = regexp.MustCompile(`[^a-zA-Z]+`)
var desirableCharPattern = regexp.MustCompile(`[\w\s,.'!-"\(\)\&%-]`)

func EnglishTextScorer(text []byte) float32 {

	textLength := float32(len(text))

	// Pre screen
	// Reject low letter proportion.
	alphaOnlyText := nonAlphabeticCharPattern.ReplaceAll(text, []byte(""))
	alphabeticCharProportion := textLength / float32(len(alphaOnlyText))

	if alphabeticCharProportion < 0.8 {
		return 0
	}

	// Reject high undesirable character proportion.
	undesirableCharOnlyText := desirableCharPattern.ReplaceAll(text, []byte(""))
	undesirableCharProportion := textLength / float32(len(undesirableCharOnlyText))

	if 0.2 < undesirableCharProportion {
		return 0
	}

	// Score alphabet only text using chi-squared frequency analysis.

	return 1
}
