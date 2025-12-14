package utils

import (
	"crypto/aes"
	"fmt"
)

func AESECBEncrypt(plaintext, key []byte) ([]byte, error) {
	//loop over blocksize sections of the plaintext and encrypt with aes.
	//append answer to the ciphertext
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("plaintext not a multiple of block size")
	}
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], plaintext[i:i+blockSize])
	}

	return ciphertext, nil
}

func AESECBDecrypt(key, ciphertext []byte) ([]byte, error) {
	//loop over blocksize sections of the plaintext and encrypt with aes.
	//append answer to the ciphertext
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext not a multiple of block size")
	}
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(plaintext); i += blockSize {
		block.Decrypt(plaintext[i:i+blockSize], ciphertext[i:i+blockSize])
	}

	return plaintext, nil
}
