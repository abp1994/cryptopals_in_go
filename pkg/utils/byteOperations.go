package utils

import (
	"bytes"
	"fmt"
	"math"
	"math/bits"
	"regexp"
	"sort"
)

func XorBytes(a, b []byte) ([]byte, error) {

	if len(a) != len(b) {
		return nil, fmt.Errorf("xor: slice lengths differ: %d vs %d", len(a), len(b))
	}

	result := make([]byte, len(a))

	// Iterate through each pair of bytes and apply XOR.
	for i := range a {
		result[i] = a[i] ^ b[i]
	}

	return result, nil
}

func SingleByteXOR(key byte, data []byte) []byte {

	result := make([]byte, len(data))

	for i := range data {
		result[i] = key ^ data[i]
	}
	return result
}

func SingleByteXORInto(key byte, data, result []byte) {
	for i := range data {
		result[i] = key ^ data[i]
	}
}

func CrackSingleByteXor(ciphertext []byte) ([]byte, byte, float32) {
	var lowestScore float32 = math.MaxFloat32
	var lowestScoreKey byte = '*'
	var lowestScoringPlaintext = make([]byte, len(ciphertext))
	candidate := make([]byte, len(ciphertext))

	for i := 0; i <= 255; i++ {

		key := byte(i)

		SingleByteXORInto(key, ciphertext, candidate)
		newScore := EnglishTextScorer(candidate)

		if newScore < lowestScore {
			lowestScore = newScore
			lowestScoreKey = key
			copy(lowestScoringPlaintext, candidate)
		}
	}
	return lowestScoringPlaintext, lowestScoreKey, lowestScore
}

func RepeatingKeyXor(key, data []byte) []byte {

	if len(key) == 0 {
		return nil
	}

	result := make([]byte, len(data))

	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

func FindHammingDistance(a, b []byte) (int, error) {
	// Check if the input slices have equal length
	if len(a) != len(b) {
		return 0, fmt.Errorf("input slices must have equal length")
	}

	// XOR bytes and add any ones to count
	distance := 0
	for i := range a {
		distance += bits.OnesCount8(a[i] ^ b[i])
	}

	return distance, nil
}

func FindNormalisedHammingDistance(a, b []byte) (float32, error) {
	distance, _ := FindHammingDistance(a, b)
	normalisedDistance := float32(distance) / float32(len(a))
	return normalisedDistance, nil
}

type KeySizeScore struct {
	KeySize int
	Score   float32
}

func FindBestKeySizes(ciphertext []byte, maxKeySize, samplesPerKeysize int) []KeySizeScore {

	scoredKeySizes := make([]KeySizeScore, maxKeySize)

	for keySize := 1; keySize <= maxKeySize; keySize++ {
		//Calculate average normalised Hamming distance.
		var totalNormalHammingDistance float32
		for pairIndex := range samplesPerKeysize {
			// Take adjacent keysize size blocks.
			blockStart := 2 * pairIndex * keySize

			block1 := ciphertext[blockStart : blockStart+keySize]
			block2 := ciphertext[blockStart+keySize : blockStart+2*keySize]

			// Find normalised Hamming distance.
			distance, _ := FindNormalisedHammingDistance(block1, block2)
			totalNormalHammingDistance += distance
		}

		avgNormalHammingDistance := totalNormalHammingDistance / float32(samplesPerKeysize)

		//Save score for key size.
		scoredKeySizes[keySize-1] = KeySizeScore{
			KeySize: keySize,
			Score:   avgNormalHammingDistance}
	}
	// Sort keysizes in ascending order by relative score.
	sort.Slice(scoredKeySizes, func(i, j int) bool {
		return scoredKeySizes[i].Score < scoredKeySizes[j].Score
	})

	return scoredKeySizes
}

// Transpose transposes a 2D byte slice.
func Transpose(matrix [][]byte) [][]byte {
	if len(matrix) == 0 {
		return nil
	}

	rows := len(matrix)
	cols := len(matrix[0])

	transposed := make([][]byte, cols)
	for i := range transposed {
		transposed[i] = make([]byte, rows)
	}

	for i := range matrix {
		for j := range matrix[i] {
			transposed[j][i] = matrix[i][j]
		}
	}

	return transposed
}

func FillMatrixFromList(data []byte, colCount int) [][]byte {

	//Calculate the number of complete rows.
	rowCount := len(data) / colCount

	//Create a matrix of rowCount x colCount size and populate.
	matrix := make([][]byte, rowCount)
	for row := range matrix {
		matrix[row] = make([]byte, colCount)
		copy(matrix[row], data[row*colCount:(row+1)*colCount])
	}

	return matrix
}

func FindKey(keySize int, data []byte) []byte {

	matrix := FillMatrixFromList(data, keySize)
	matrixTransposed := Transpose(matrix)

	// Process each transposed row and find the most promising key.
	key := make([]byte, keySize)

	for i, row := range matrixTransposed {
		_, keyByte, _ := CrackSingleByteXor(row)
		key[i] = keyByte
	}

	return key

}

var nonAlphabeticCharPattern = regexp.MustCompile(`[^a-zA-Z]+`)
var undesirableTextCharPattern = regexp.MustCompile(`[^\w\s,.'!-"\(\)\&%@#~-]`)

const rejectionValue = float32(math.MaxFloat32)

// Normalised ascii character frequencies.
var englishCharFreq = [26]float32{
	0.08167, // A
	0.01492, // B
	0.02782, // C
	0.04253, // D
	0.12702, // E
	0.02228, // F
	0.02015, // G
	0.06094, // H
	0.06966, // I
	0.00153, // J
	0.00772, // K
	0.04025, // L
	0.02406, // M
	0.06749, // N
	0.07507, // O
	0.01929, // P
	0.00095, // Q
	0.05987, // R
	0.06327, // S
	0.09056, // T
	0.02758, // U
	0.00978, // V
	0.02360, // W
	0.00150, // X
	0.01974, // Y
	0.00074, // Z
}

// Returns normalised frequencies.
func createLetterFrequency(data []byte) [26]float32 {

	totalBytes := len(data)
	singleByteContribution := 1 / float32(totalBytes)

	var frequency [26]float32

	// Count normalised contribution of each Ascii byte instance.
	for _, value := range data {
		frequency[value-'A'] += singleByteContribution
	}

	return frequency
}

func EnglishTextScorer(text []byte) float32 {
	textLength := float32(len(text))

	// Prescreen
	// Reject texts containing undesirable characters.
	if undesirableTextCharPattern.Match(text) {
		return rejectionValue
	}

	// Reject text with low letter proportion.
	alphaOnlyText := nonAlphabeticCharPattern.ReplaceAll(text, []byte(""))
	alphabeticCharProportion := float32(len(alphaOnlyText)) / textLength
	if alphabeticCharProportion < 0.6 {
		return rejectionValue
	}

	// Score alphabet only text using chi-squared frequency analysis.
	alphaTextCharFreq := createLetterFrequency(bytes.ToUpper(alphaOnlyText))
	score := calculateChiSquared(alphaTextCharFreq, englishCharFreq)
	return score
}

// Compares two maps using chi-squared analysis and returns a float32 score.
// A lower score indicates a better fit.
func calculateChiSquared(observedFreq, expectedFreq [26]float32) float32 {
	var score float32

	for i, observed := range observedFreq {
		expected := expectedFreq[i]
		// Chi-squared formula: sum((observed - expected)^2 / expected)
		score += (observed - expected) * (observed - expected) / expected
	}
	return score
}
