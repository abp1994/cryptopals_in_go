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

func ImportB64Data(filepath string) ([]byte, error) {

	linesB64 := ImportTxtLines("res/" + filepath)
	if len(linesB64) == 0 {
		return nil, fmt.Errorf("no data to decode in %q", filepath)
	}

	// Concatenate slices
	dataB64 := slices.Concat(linesB64...)

	// Decode the base64-encoded data into a decoded byte slice.
	decoded, err := base64.StdEncoding.DecodeString(string(dataB64))
	if err != nil {
		fmt.Println("base 64 decode failes: %w", err)
	}

	return decoded, nil
}
