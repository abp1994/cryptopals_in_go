package utils

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
)

func XorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("error - Length of Byte slices not equal")
	}

	result := make([]byte, len(a))

	// Iterate through each pair of bytes and apply XOR.
	for i := range a {
		result[i] = a[i] ^ b[i]
	}

	return result, nil
}

func SingleByteXOR(key byte, byteSlice []byte) []byte {

	result := make([]byte, len(byteSlice))

	for i, currentByte := range byteSlice {
		result[i] = key ^ currentByte
	}
	return result
}

func CrackSingleByteXor(ciphertext []byte) ([]byte, byte, float32) {
	var plaintext = make([]byte, len(ciphertext))
	var lowestScore float32 = math.MaxFloat32
	var lowestScoreKey byte = '*'
	var lowestScoringPlaintext = make([]byte, len(ciphertext))

	for i := 0; i <= 255; i++ {
		plaintext = SingleByteXOR(byte(i), ciphertext)
		newScore := EnglishTextScorer(plaintext)
		if newScore < lowestScore {
			lowestScore = newScore
			lowestScoreKey = byte(i)
			copy(lowestScoringPlaintext, plaintext)
		}
	}
	return lowestScoringPlaintext, lowestScoreKey, lowestScore
}

func RepeatingKeyXor(key []byte, byteslice []byte) []byte {

	targetLength := len(byteslice)
	repeatedKey := bytes.Repeat(key, (targetLength+len(key)-1)/len(key))

	result, _ := XorBytes(repeatedKey[:targetLength], byteslice)
	return result
}

func FindHammingDistance(bytes1, bytes2 []byte) (int, error) {
	// Check if the input slices have equal length
	if len(bytes1) != len(bytes2) {
		return 0, fmt.Errorf("input slices must have equal length")
	}

	// XOR the two slices to find differing bits
	xorResult, err := XorBytes(bytes1, bytes2)
	if err != nil {
		return 0, err
	}

	// Count the set bits in the XOR result
	distance := 0
	for _, b := range xorResult {
		for b != 0 {
			distance++
			b &= b - 1
		}
	}

	return distance, nil
}

func FindNormalisedHammingDistance(bytes1, bytes2 []byte) (float32, error) {
	distance, _ := FindHammingDistance(bytes1, bytes2)
	normalisedDistance := float32(distance) / float32(len(bytes1))
	return normalisedDistance, nil
}

type IntFloatPair struct {
	IntValue   int
	FloatValue float32
}

func FindBestKeySizes(ciphertext []byte, maxKeySize int, samplesPerKeysize int) []IntFloatPair {

	scoredKeySizes := make([]IntFloatPair, maxKeySize)

	for keysize := 1; keysize <= maxKeySize; keysize++ {
		normalHammingDistances := make([]float32, samplesPerKeysize)
		for pairIndex := range samplesPerKeysize {
			// Take adjacent keysize size blocks.
			startIndex := (2 * pairIndex) * keysize
			middleIndex := (2*pairIndex + 1) * keysize
			endIndex := (2*pairIndex + 2) * keysize

			block1 := ciphertext[startIndex:middleIndex]
			block2 := ciphertext[middleIndex:endIndex]

			// Find normalised Hamming distance.
			normalHammingDistances[pairIndex], _ = FindNormalisedHammingDistance(block1, block2)
		}

		//Calculate average normalised Hamming distance.
		totalNormalHammingDistance := float32(0)
		for _, number := range normalHammingDistances {
			totalNormalHammingDistance += number
		}
		avgNormalHammingDistance := totalNormalHammingDistance / float32(samplesPerKeysize)

		//Save score for key size.
		scoredKeySizes[keysize-1] = IntFloatPair{keysize, avgNormalHammingDistance}
	}
	// Sort keysizes in ascending order by relative score.
	sort.Slice(scoredKeySizes, func(i, j int) bool {
		return scoredKeySizes[i].FloatValue < scoredKeySizes[j].FloatValue
	})

	return scoredKeySizes
}

// Transpose transposes a 2D byte slice.
func Transpose(matrix [][]byte) [][]byte {
	if len(matrix) == 0 {
		return nil
	}

	rowCount := len(matrix)
	colCount := len(matrix[0])

	transposed := make([][]byte, colCount)
	for i := range transposed {
		transposed[i] = make([]byte, rowCount)
	}

	for i := range matrix {
		for j := range matrix[0] {
			transposed[j][i] = matrix[i][j]
		}
	}

	return transposed
}

func FillMatrixFromList(data []byte, colCount int) [][]byte {

	//Find max number of rows by using floor division.
	rowCount := len(data) / colCount

	//Create a matrix of rowCount x colCount size.
	matrix := make([][]byte, rowCount)
	for row := range matrix {
		matrix[row] = make([]byte, colCount)
	}

	// Populate the matrix using range.
	for rowIndex := range matrix {
		for colIndex := range matrix[rowIndex] {
			matrix[rowIndex][colIndex] = data[rowIndex*colCount+colIndex]
		}
	}
	return matrix
}

func FindKey(keysize int, data []byte) []byte {

	matrix := FillMatrixFromList(data, keysize)
	matrixTransposed := Transpose(matrix)

	// Process each transposed row and find the most promising key.
	var outputList [][]byte
	for _, row := range matrixTransposed {
		_, keyByte, _ := CrackSingleByteXor(row)
		//fmt.Println(string(secret))
		outputList = append(outputList, []byte{keyByte})
	}

	// Return most promising key of keySize size.
	return bytes.Join(outputList, nil)

}

var nonAlphabeticCharPattern = regexp.MustCompile(`[^a-zA-Z]+`)
var desirableTextCharPattern = regexp.MustCompile(`[\w\s,.'!-"\(\)\&%@#~-]`)

// Normalised ascii character frequencies.
var englishCharFreq = map[byte]float32{
	'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
	'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
	'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
	'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
	'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
	'Z': 0.00074,
}

// Returns normalised frequencies.
func createByteFrequencyMap(data []byte) map[byte]float32 {

	totalBtyes := len(data)
	singleByteContribution := 1 / float32(totalBtyes)
	frequencyMap := make(map[byte]float32, 256)

	// Set initial frequency of 0 for each byte (0 to 255)
	for i := range frequencyMap {
		frequencyMap[i] = 0
	}

	// Count normalised contribution of each Ascii byte instance.
	for _, value := range data {
		frequencyMap[value] += singleByteContribution
	}

	return frequencyMap
}

func EnglishTextScorer(text []byte) float32 {
	textLength := float32(len(text))
	rejectionValue := float32(math.MaxFloat32)

	// Prescreen
	// Reject texts containing undesirable characters.
	undesirableCharOnlyText := desirableTextCharPattern.ReplaceAll(text, []byte(""))
	if 0 < len(undesirableCharOnlyText) {
		return rejectionValue
	}

	// Reject text with low letter proportion.
	alphaOnlyText := nonAlphabeticCharPattern.ReplaceAll(text, []byte(""))
	alphabeticCharProportion := float32(len(alphaOnlyText)) / textLength
	if alphabeticCharProportion < 0.6 {
		return rejectionValue
	}

	// Score alphabet only text using chi-squared frequency analysis.
	alphaTextCharFreq := createByteFrequencyMap(bytes.ToUpper(alphaOnlyText))
	score := calculateChiSquared(alphaTextCharFreq, englishCharFreq)
	return score
}

// Compares two maps using chi-squared analysis and returns a float32 score.
// A lower score indicates a better fit.
func calculateChiSquared(observedFreq, expectedFreq map[byte]float32) float32 {
	var score float32
	for key := range observedFreq {
		observed := observedFreq[key]
		expected := expectedFreq[key]
		// Chi-squared formula: sum((observed - expected)^2 / expected)
		score += (observed - expected) * (observed - expected) / expected
	}
	return score
}
