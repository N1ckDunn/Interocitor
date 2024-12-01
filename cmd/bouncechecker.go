// Interocitor
// Application for HTTP data bouncing
//
// Nick Dunn 2023-2024

// Main Package - bounce check functionality
// These functions are used to ingest a file containing potential bounce URLs,
// any that work will be written to the output file.

package main

import (
	"fmt"
	"maps"
	"net/http"
	"os"
	"strings"
	"time"
)

func DomainBounceCheck() {

	// Define a command-line flag for the file path
	filePath := GeneralSettings.TargetsFile
	oobServer := OOBSettings.Server

	// Check if the file path is provided
	if filePath == "" {
		fmt.Println("Error. No file path provided for bounce targets.")
		os.Exit(NoTargetsFile)
	}

	// Check if the server IP/address is provided
	if oobServer == "" {
		fmt.Println("Error. No OOB domain provided.")
		os.Exit(NoOOBDomain)
	}

	// Read file to obtain targets
	domains, err := ReadArrayFromFile(filePath)
	if err != nil {
		fmt.Println("Error reading bounce targets from file:", err)
		os.Exit(FileReadError)
	}

	// Get total number of domains in order to calculate percentages for display during execution
	count := len(domains)

	// Iterate through targets
	for index, domain := range domains {

		// Add "http://" prefix to the domain
		//url := "http://" + domain

		// Send the provided URL to be submitted with appropriate headers
		processDomain(domain, index, count, oobServer)
	}

	// Check response

	// Add to output

}

// Check each domain for bounce-ability, using system the necessary headers
func processDomain(domain string, currentHostNumber int, domainCount int, oobDomain string) {

	// Check that the file line doesn't contain blank line or whitespace
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return
	}

	currentHostNumber++

	percentageComplete := 0.0
	if domainCount > 0 {
		percentageComplete = float64(currentHostNumber) / float64(domainCount) * 100
	}

	// Add a prefix - at some point allow user-selected prefix
	origin := "https://" + domain
	suffix := domain + "." + oobDomain

	// Standard headers for all requests
	headers := map[string]string{"User-Agent": OOBSettings.UserAgent, "Host": "host." + suffix,
		"Origin": origin, "Connection": "close"}

	originHeaders := map[string]string{"X-Forwarded-For": "xff.", "CF-Connecting_IP": "cfcon.", "Contact": "root@contact.",
		"X-Real-IP": "rip.", "True-Client-IP": "trip.", "X-Client-IP": "xclip.", "Forwarded": "for=ff.",
		"X-Originating-IP": "origip.", "Client-IP": "clip.", "Referer": "ref.", "From": "root@from."}

	for key, value := range originHeaders {
		originHeaders[key] = value + suffix
	}

	wapHeaders := map[string]string{"X-Wap-Profile": "http://wafp." + suffix + "/wap.xml"}

	// Merge all header maps together
	maps.Copy(headers, originHeaders)
	maps.Copy(headers, wapHeaders)

	// Create new HTTP request
	request, err := http.NewRequest(OOBSettings.HTTPVerb, origin+"/", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Add headers to request
	for key, value := range headers {
		request.Header.Add(key, value)
	}

	// Log the request being sent - this message will be be displayed to the user if verbose mode is on
	// The message will also be written to log file if logging is enabled
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logMessage := fmt.Sprintf("%s::Request sent to %s::%d of %d::%.2f%% complete\n", timestamp, domain, currentHostNumber, domainCount, percentageComplete)

	if GeneralSettings.Verbose {
		fmt.Println(logMessage)
	}

	// Write to log if required
	if GeneralSettings.LogEnabled {
		log, err := os.OpenFile(GeneralSettings.LogFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			fmt.Println("Error opening log file:", GeneralSettings.LogFile, err)
			return
		}
		defer log.Close()

		if _, err := log.WriteString(logMessage + "\n"); err != nil {
			fmt.Println("Error writing to log file:", err)
		}
	}

	// Send the request
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}

	// Check the response and output the details as required
	// If there's no response then this target isn't bounceable
	if response != nil {
		// Only close response body if a response was received
		defer response.Body.Close()

		// Print details for user
		if GeneralSettings.Verbose {
			responseMessage := fmt.Sprintf("Request Number:	%d\nStatus Code:	%d\nDomain Name:	%s\n", currentHostNumber, response.StatusCode, domain)
			fmt.Println("Response received.")
			fmt.Print(responseMessage)
		}

		// Valid response - write usable domain name to output file
		//bouncefile, err := os.OpenFile(GeneralSettings.BouncersFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		//if err != nil {
		//fmt.Println("Error opening output file:", GeneralSettings.BouncersFile, err)
		//return
		//}
		//if _, err := bouncefile.WriteString(domain + "\n"); err != nil {
		//fmt.Println("Error writing to output file:", err)
		//}
		//defer bouncefile.Close()
	}

}
