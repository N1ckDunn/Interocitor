// Interocitor
// Application for HTTP data bouncing
//
// Nick Dunn 2023-2024

// Main Package - decryption functionality
// These functions are used to decrypt exfiltrated data from a file,
// or directly from the data structures extracted from DNS JSON output.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base32"
	"errors"
	"fmt"
	"io/ioutil"
)

// Input is a file of encrypted data (usually extracted form the DNS server's JSON file)
// Return an unencrypted output file (name provided by calling function, default is outut.bin)
func DecryptFile(filePath string, outputFile string, key []byte) {

	// Check if the file path is provided
	if filePath == "" {
		fmt.Println("Please provide a file path.")
		return
	}

	// Read the content of the specified binary file
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading encrypted file:", err)
		return
	}

	// Define a key for encryption (16, 24, or 32 bytes for AES-128, AES-192, or AES-256)

	// Decrypt the data
	DecryptByteArray(fileContent, outputFile, key)

}

// Input is a byte array of encrypted data (usually extracted form the DNS server's JSON file)
// Return an unencrypted output file (name provided by calling function, default is outut.bin)
func DecryptByteArray(byteArray []byte, outputFile string, key []byte) {

	// Define a key for encryption (16, 24, or 32 bytes for AES-128, AES-192, or AES-256)

	// Decrypt the data
	decryptedData, err := decryptAES(byteArray, key)
	if err != nil {
		fmt.Println("Error decrypting data:", err)
		return
	}

	// Write decrypted data to binary file
	err = ioutil.WriteFile(outputFile, decryptedData, 0644)
	if err != nil {
		fmt.Println("Error writing decrypted data to file:", err)

	} else {
		fmt.Println("Decrypted data written to file successfully!")
	}

}

// decryptAES decrypts data encrypted using AES-GCM encryption
func decryptAES(encryptedData, key []byte) ([]byte, error) {

	// Pad the data to restore any trimmed = signs
	paddedData := padBase32(encryptedData)

	// Decode the Base32-encoded data
	decodedData := make([]byte, base32.StdEncoding.DecodedLen(len(paddedData)))
	numbytes, err := base32.StdEncoding.Decode(decodedData, bytes.ToUpper(paddedData))
	if err != nil {
		return nil, err
	}
	decodedData = decodedData[:numbytes]

	// Create a new AES block cipher with the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a new AES-GCM cipher with the block cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract the nonce from the decoded data
	nonceSize := aesGCM.NonceSize()
	if len(decodedData) < nonceSize {
		return nil, errors.New("nonce size is too short")
	}
	nonce, ciphertext := decodedData[:nonceSize], decodedData[nonceSize:]
	fmt.Println("Nonce:	", nonce)

	// Decrypt the data using AES-GCM
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Pad any missing "=" signs to end of Base32 input
func padBase32(encodedData []byte) []byte {

	// Get length of encoded data
	encodedLength := len(encodedData)

	// Calculate number of padding characters needed to make length a multiple of 8
	missingPadding := (8 - (encodedLength % 8)) % 8

	// Calculate the number of missing padding characters
	//missingPadding := 8 - len(encodedData)%8

	// Append missing padding characters to byte array
	for i := 0; i < missingPadding; i++ {
		encodedData = append(encodedData, '=')
	}

	return encodedData
}
