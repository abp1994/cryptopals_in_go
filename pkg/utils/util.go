package utils

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"slices"
)

func ImportTxtLines(filepath string) [][]byte {
	// open file
	f, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	// remember to close the file at the end of the program
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Printf("warning: error closing file %s: %v", filepath, cerr)
		}
	}()
	// read the file line by line using scanner
	scanner := bufio.NewScanner(f)
	var result [][]byte

	for scanner.Scan() {
		// convert the line to bytes and append to the result
		result = append(result, []byte(scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return result
}

func ImportB64Data(filepath string) []byte {

	ciphertextLinesB64 := ImportTxtLines("res/" + filepath)

	// Concatenate slices
	ciphertextB64 := slices.Concat(ciphertextLinesB64...)

	// Create a byte slice to store the decoded data.
	ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(ciphertextB64)))

	// Decode the base64-encoded data into the decoded byte slice.
	n, err := base64.StdEncoding.Decode(ciphertext, ciphertextB64)
	if err != nil {
		fmt.Println("error decoding hex:", err)
	}

	// Trim any extra capacity in the decoded byte slice.
	ciphertext = ciphertext[:n]

	return ciphertext
}
