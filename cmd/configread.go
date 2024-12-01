// Interocitor
// Application for HTTP data bouncing
//
// Nick Dunn 2023-2024

// Main Package - config file functionality
// These functions are used to get settings from the config file,
// and to convert some of the file strings into the equivalent Interocitor settings.

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/ini.v1"
)

// Main entry point - use this function to read all config elements
func ConfigRead(inidata string) {

	alldata, err := ini.Load(inidata)
	if err != nil {
		fmt.Printf("Error reading config file (config.ini): %v", err)
		os.Exit(FileReadError)
	}

	// Read each config section and apply to current running instance
	ReadGeneral(alldata)
	ReadOOB(alldata)
	ReadCrypto(alldata)
	ReadMode(alldata)
	ReadExfil(alldata)
	ReadFileMode(alldata)
	ReadCmdMode(alldata)
	ReadTimingMode(alldata)
	ReadTriggerMode(alldata)
	ReadUploadTimingMode((alldata))
}

// Read the General settings section
func ReadGeneral(inidata *ini.File) {

	// Used to hold details of conversion failures, etc.
	var err error

	// Main application settings held in 'General'
	section := inidata.Section("General")
	GeneralSettings.Verbose = ConvertTextToBool(section.Key("Verbose").String())

	// Number of times to repeat each payload
	GeneralSettings.NumTimes, err = strconv.Atoi(section.Key("NumTimes").String())
	if err != nil {
		GeneralSettings.NumTimes = 1
	}

	Exfiltrator.UUID = section.Key("UUID").String()

	GeneralSettings.AppendURL = ConvertTextToBool(section.Key("AppendURL").String())
	GeneralSettings.URLSuffixFile = section.Key("URLSuffixFile").String()
}

// Read the Mode settings section
func ReadMode(inidata *ini.File) {

	// Mode settings held in 'Mode'
	section := inidata.Section("Mode")
	StringToMode(section.Key("OpsMode").String())
	StringToTask(section.Key("Task").String())
}

// Read the OOBServer settings section
func ReadOOB(inidata *ini.File) {

	// OOB server settings held in 'OOBServer'
	section := inidata.Section("OOBServer")
	OOBSettings.Server = section.Key("Server").String()
	OOBSettings.Port = section.Key("Port").String()
}

// Read the crypto setting section
func ReadCrypto(inidata *ini.File) {

	//Crypto settings in 'Encryption'
	section := inidata.Section("Encryption")
	GeneralSettings.Encrypted = ConvertTextToBool(section.Key("Encrypted").String())
	CryptoSettings.Key = section.Key("Key").String()
	CryptoSettings.Algorithm = ConvertTextToEncAlg(section.Key("Algorithm").String())
}

// Read the Proxy settings section

// Read the Obfuscation settings section

// Read the DNS settings section

// Read the ExfilDomains settings section
func ReadExfil(inidata *ini.File) {

	// Exfil server settings held in 'ExfilDomains'
	section := inidata.Section("ExfilDomains")
	GeneralSettings.TargetsFile = section.Key("TargetListFile").String()
	GeneralSettings.BouncersFile = section.Key("BouncerFile").String()
}

// Read the File Exfiltration Mode settings
func ReadFileMode(inidata *ini.File) {

	// File Mode settings held in 'FileMode'
	section := inidata.Section("FileMode")

	Exfiltrator.InputFile = section.Key("InputFile").String()
	Exfiltrator.OutputFile = section.Key("OutputFile").String()
	OOBSettings.JSONFile = section.Key("JSONFile").String()
	Exfiltrator.CryptFile = section.Key("EncryptedOutputFile").String()

}

// Read the Command Mode settings
func ReadCmdMode(inidata *ini.File) {

	// Command Mode settings held in 'CommandMode' section
	section := inidata.Section("CommandMode")

	// The command(s) to be executed
	CmdSettings.Command = section.Key("Cmd").String()
	CmdSettings.ShellInputFile = section.Key("CmdFile").String()

	// Take any commandline pramas as a string and split them according to the user-defined separator
	paramSplitter := section.Key("ParamSeparator").String()
	params := section.Key("Params").String()
	CmdSettings.Params = strings.Split(params, paramSplitter)

	// Provide an option to cancel if command does not finish after a specified time
	cancel := section.Key("CancelTiming").String()
	if cancel != "" {
		StringToCancel(cancel)
	}

}

// Timing Mode settings are used to determine when to carry out an action or exfiltration
func ReadTimingMode(inidata *ini.File) {

	var err error

	// Command Mode settings held in 'CommandMode' section
	section := inidata.Section("CommandTiming")

	// Run once or multiple executions
	StringToCmdTimer(section.Key("OpMode").String())

	// Only apply settings if a timer needs to be used
	if CmdSettings.OpMode == RunOnce {
		return
	}

	CmdSettings.OpTimingMode = StringToTimerMode(section.Key("TimingUnits").String())
	CmdSettings.OpTiming, err = section.Key("Timing").Int()
	if err != nil || CmdSettings.OpTiming < 1 {
		fmt.Println("Error converting TimingUnits value to valid integer. Using default value of 1 instead.")
		err = nil
		CmdSettings.OpTiming = 1
	}

	// Set the minimum and maximum for random values
	CmdSettings.RandOpMin, err = section.Key("RandomMin").Int()
	if err != nil || CmdSettings.RandOpMin < 1 {
		fmt.Println("Error converting RandomMin value to valid integer. Using default value of 1 instead.")
		err = nil
		CmdSettings.RandOpMin = 1
	}
	CmdSettings.RandOpMax, err = section.Key("RandomMax").Int()
	if err != nil || CmdSettings.RandOpMax < 2 {
		fmt.Println("Error converting RandomMax value to valid integer. Using default value of 2 instead.")
		err = nil
		CmdSettings.RandOpMax = 2
	}
}

// Trigger Mode settings are used to determine whether to carry out an action
func ReadTriggerMode(inidata *ini.File) {

	var err error

	// Only apply settings if a timer needs to be used
	if CmdSettings.OpMode == RunOnce {
		return
	}

	// Command Mode settings held in 'CommandMode' section
	section := inidata.Section("CommandTrigger")

	// Determine the type of trigger and comparison cmd, file or dir, and not equal, less than, or greater than
	StringToTriggerMode(section.Key("TriggerMode").String())
	StringToTriggerType(section.Key("TriggerType").String())

	target := section.Key("TriggerTarget").String()
	if TriggerSettings.TriggerMode == FileSize || TriggerSettings.TriggerMode == DirectoryListing {
		// If measuring a file or directory just need to assign the specified target
		TriggerSettings.TargetPath = target
	} else {
		// If running a command, split into command and params
		parts := strings.Split(target, " ")
		TriggerSettings.ShellCommand = parts[0]
		TriggerSettings.ShellParams = parts[1:]
	}

	// Set the amount and units for the timer
	TriggerSettings.TriggerTimerMode = StringToTimerMode(section.Key("TimingUnits").String())
	TriggerSettings.TriggerTiming, err = section.Key("Timing").Int()
	if err != nil || TriggerSettings.TriggerTiming < 1 {
		fmt.Println("Error converting Timing value to valid integer. Using default value of 1 instead.")
		err = nil
		TriggerSettings.TriggerTiming = 1
	}
}

// Upload Timing Mode settings are used to exfiltrate on a delayed or repated and regular basis
func ReadUploadTimingMode(inidata *ini.File) {

	var err error

	// Only apply settings if a timer needs to be used
	if CmdSettings.OpMode == RunOnce {
		return
	}

	// Command Mode settings held in 'CommandMode' section
	section := inidata.Section("ReportTiming")

	// Run once or multiple executions
	StringToUploadTimer(section.Key("UploadMode").String())

	// Set the amount and units
	CmdSettings.ResponseTimingMode = StringToTimerMode(section.Key("TimingUnits").String())
	CmdSettings.ResponseTiming, err = section.Key("Timing").Int()
	if err != nil || CmdSettings.ResponseTiming < 1 {
		fmt.Println("Error converting Timing value to valid integer. Using default value of 1 instead.")
		err = nil
		CmdSettings.ResponseTiming = 1
	}

	// Set the minimum and maximum for random values
	CmdSettings.RandRespMin, err = section.Key("RandomMin").Int()
	if err != nil || CmdSettings.RandRespMin < 1 {
		fmt.Println("Error converting RandomMin value to valid integer. Using default value of 1 instead.")
		err = nil
		CmdSettings.RandRespMin = 1
	}
	CmdSettings.RandRespMax, err = section.Key("RandomMax").Int()
	if err != nil || CmdSettings.RandRespMax < 2 {
		fmt.Println("Error converting RandomMax value to valid integer. Using default value of 2 instead.")
		err = nil
		CmdSettings.RandRespMax = 2
	}

}

// Check possible text version for true/false and return appropriate value
func ConvertTextToBool(inputStr string) bool {

	// Check lower case string for possible interprations of true, on ,etc.
	switch strings.ToLower(inputStr) {
	case "1", "true", "y", "yes", "on":
		return true
	default:
		return false
	}
}

// Check possible text version for available encryption algorithm and return appropriate value
func ConvertTextToEncAlg(inputStr string) int {

	// Check lower case string for possible interprations of AES-128, AES-192, or AES-256, etc.
	switch strings.ToLower(inputStr) {
	case "2", "AES-192", "AES192", "192":
		return AES192
	case "3", "AES-256", "AES256", "256":
		return AES256
	default:
		return AES128
	}
}
