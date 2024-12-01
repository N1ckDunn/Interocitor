// Interocitor
// Application for HTTP data bouncing
//
// Nick Dunn 2023-2024

// Main Package - DNS file parsing functionality
// These functions are used to extract exfiltrated data from DNS JSON output.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
)

// Entry point and main loop for parsing JSON data to encrypted file
func ParseJSONData(filePath string, streamID string) ([]string, error) {

	// Check if the file path is provided
	if filePath == "" {
		fmt.Println("Please provide a JSON file path using the -c or --encrypted-file flag.")
		return nil, NewError("No JSON file path provided.")
	}

	// Read the JSON file
	jsonData, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading JSON file:", err)
		return nil, err
	}

	// Parse the JSON data
	var data map[string]interface{}
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return nil, err
	}

	var fullIDs []string

	// Check whether required JSON data is held within outer JSON (as for interactsh)

	// Search for the "data" key within the "app" object as for interactsh output
	appval := getValueForKey(data, "app")

	if appval != "" {

		// If we have data from interactsh, convert content of "app" to JSON
		appJson, err := readJSONFromString(appval)
		if err != nil {
			fmt.Println("Error extracting 'app' data:	", err)
		}

		// Extract all instances of "full-id" and add them to an array of strings
		extractFullIDs(appJson, &fullIDs)

	} else {
		// Extract all instances of "full-id" and add them to an array of strings
		extractFullIDs(data, &fullIDs)
	}

	// Split the output into individual strings, add encrypted data to output array
	// Populate struct with all parts of the payload
	var payloads []string

	// Keep a count of assigned chunks so that we know if any are missing at the end
	chunkcount := 0
	arraySize := 0

	// Process each individual payload from the array
	for _, fullID := range fullIDs {

		// Split payload to extract data - we should have FileExfilStructParts number of chunks
		chunks := strings.SplitN(fullID, ".", FileExfilStructParts)

		// Check if the number of chunks is at least the amount in our definied data chunk
		if len(chunks) < FileExfilStructParts {
			fmt.Printf("Error: 'full-id' payload string does not have %d chunks.\n", FileExfilStructParts)
			if GeneralSettings.Verbose {
				fmt.Println("Payload string:	", fullID)
			}
		} else {

			// Check we have valid content for our stream ID
			if chunks[1] != streamID {
				continue
			}

			// Populate the struct with the chunks
			dataChunk := DataFragment{
				FileHash:     chunks[0],
				StreamID:     chunks[1],
				ChunkID:      chunks[2],
				TotalChunks:  chunks[3],
				DataFragment: chunks[4],
				OobServer:    chunks[5],
			}

			// Print details if required
			if GeneralSettings.Verbose {
				// Print the populated struct
				fmt.Printf("FileHash: %s\n", dataChunk.FileHash)
				fmt.Printf("StreamID: %s\n", dataChunk.StreamID)
				fmt.Printf("ChunkID: %s\n", dataChunk.ChunkID)
				fmt.Printf("TotalChunks: %s\n", dataChunk.TotalChunks)
				fmt.Printf("DataFragment: %s\n", dataChunk.DataFragment)
				fmt.Printf("OobServer: %s\n", dataChunk.OobServer)
			} // End if verbose

			// ToDo: Separate files on basis of file hash

			// Use data from payload to create array of correct size on first pass
			if len(payloads) == 0 {
				arraySize, err = strconv.Atoi(dataChunk.TotalChunks)
				if err != nil {
					continue
				}
				payloads = make([]string, arraySize)
			} // End if len(payloads)

			// Get array position from payload and assign data to correct position
			index, err := strconv.Atoi(dataChunk.ChunkID)
			if err != nil {
				fmt.Println("Error converting chunkid to int.", err)

			} else if payloads[index] == "" {
				// Need to keep track of assigned payloads
				// This will be used to detect whether any are missing at the end
				// and to break out of the loop if all payoads are assigned (this will save time if numtimes is set to high value)
				payloads[index] = dataChunk.DataFragment
				chunkcount += 1

				// Notify user of status if required
				if GeneralSettings.Verbose {
					fmt.Printf("Chunk Count:	%d\n", chunkcount)
					fmt.Printf("Payload[%d]:	%s\n", index, dataChunk.DataFragment)
				}
				if chunkcount == arraySize {
					break
				}
			} else {
				// If this payload already assigned because numtimes > 1 then do nothing
				continue
			}
		} // End if len(chunks) < FileExfilStructParts
	} // End for

	// Check if there are any missing chunks
	if chunkcount < arraySize {
		fmt.Println("Error! Missing chunks in retrieved data.")
		fmt.Printf("Number of payloads expected:	%d\n", arraySize)
		fmt.Printf("Number of payloads received:	%d\n", chunkcount)
	}

	// Write encrypted array of strings to file as single block of data

	// Return encrypted array of strings
	return payloads, nil

}

// Write the extracted data to a new file in its entirety
func WriteDataToFile(targetStrings *[]string, outputFile string, newlines bool) {

	// The separator allows calling functions to determine whether each string is written to a new line in the file
	separator := ""
	if newlines {
		separator = "\n"
	}

	// Join array into single continuous string
	content := strings.Join(*targetStrings, separator)

	// Write the string to a file named "output.txt"
	err := ioutil.WriteFile(outputFile, []byte(content), 0644)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return
	}
}

// Read provided JSON data and return string value for the named tag
func getValueForKey(jsonData map[string]interface{}, tag string) string {

	// If no data is found an empty string is returned
	retval := ""

	// Check if the tag exists in the JSON data
	if value, ok := jsonData[tag]; ok {
		// Check if value is string and obtain data for return value
		if strValue, ok := value.(string); ok {
			retval = strValue
		}
	}

	// Return the data for named tag
	return retval
}

// Covert string into JSON data
func readJSONFromString(jsonStr string) (map[string]interface{}, error) {

	// Define a map to unmarshal the JSON data
	var jsonData map[string]interface{}

	// Unmarshal the JSON data from the string
	err := json.Unmarshal([]byte(jsonStr), &jsonData)
	if err != nil {
		return nil, err
	}

	if GeneralSettings.Verbose {
		fmt.Printf("Data Len:	%d\n", len(jsonData))
	}

	return jsonData, nil
}

// Recursively search for "full-id" elements in the JSON data
func extractFullIDs(data map[string]interface{}, fullIDs *[]string) {

	for key, value := range data {
		switch v := value.(type) {
		case string:
			if key == "full-id" {
				*fullIDs = append(*fullIDs, v)
			}
		case map[string]interface{}:
			extractFullIDs(v, fullIDs)
		case []interface{}:
			for _, item := range v {
				if nestedData, ok := item.(map[string]interface{}); ok {
					extractFullIDs(nestedData, fullIDs)
				}
			}
		}
	}
}

// Take JSON file from DNS lookups and extract usable hosts
// This function should be executed after a bounce check
func ExtractBounceableHosts(filePath string) ([]string, error) {

	// Check if the file path is provided
	if filePath == "" {
		fmt.Println("Please provide a JSON file path using the -j or --json-file flag.")
		return nil, NewError("No JSON file path provided.")
	}

	// Read the JSON file
	jsonData, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading JSON file:", err)
		return nil, err
	}

	// Parse the JSON data
	var data map[string]interface{}
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return nil, err
	}

	var fullIDs []string

	// Check whether required JSON data is held within outer JSON (as for interactsh)

	// Search for the "data" key within the "app" object as for interactsh output
	appval := getValueForKey(data, "app")

	if appval != "" {

		// If we have data from interactsh, convert content of "app" to JSON
		appJson, err := readJSONFromString(appval)
		if err != nil {
			fmt.Println("Error extracting 'app' data:	", err)
		}

		// Extract all instances of "full-id" and add them to an array of strings
		extractFullIDs(appJson, &fullIDs)

	} else {
		// Extract all instances of "full-id" and add them to an array of strings
		extractFullIDs(data, &fullIDs)
	}

	// Extract the initial bouncable host from the app value
	// This will be the entirety of the first part of string other than the final ".oobserver"

	// Create an empty return value
	var bouncableHosts []string
	bouncableHost := ""

	// Iterate through the full-ids and extract hosts
	for _, fullID := range fullIDs {

		// Locate the dot in the hostname
		lastDotIndex := strings.LastIndex(fullID, ".")

		// Check for valid hostname/dot position
		if lastDotIndex != -1 {
			// Extract substring before the last dot
			bouncableHost = fullID[:lastDotIndex]
			numParts := strings.Count(bouncableHost, ".")
			if numParts >= 2 {
				bouncableHosts = append(bouncableHosts, bouncableHost)
			}
		} // End if lastDotIndex
	} // End for _, fullID

	return bouncableHosts, nil
}
