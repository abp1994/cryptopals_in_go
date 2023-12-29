package utils

import "errors"

func XorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("Length of Byte slices not equal!")
	}

	// Create a new byte slice to store the result
	result := make([]byte, len(a))

	// Iterate through each pair of bytes and apply XOR
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}

	return result, nil
}
