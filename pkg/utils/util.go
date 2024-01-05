package utils

import (
	"bufio"
	"log"
	"os"
)

func ImportTxtLines(filepath string) [][]byte {
	// open file
	f, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	// remember to close the file at the end of the program
	defer f.Close()

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
