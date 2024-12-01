// Interocitor
// Application for HTTP data bouncing
//
// Nick Dunn 2023-2024

// Main Package - app settings functionality
// These structs are used to hold application data, enums are easier use of settings and modes,
// functions are provided to populate defaults and easily apply settings.

package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Enum for operational modes
const (
	FileMode = iota
	TargetMode
	CmdMode
	PollMode
	DNSMode
)

// Enum for individual File Exfil and Cmd tasks
const (
	BounceCheck = iota
	HostExtract
	FileExfiltrate
	DNSExtract
	DNSExtractDecrypt
	FileDecrypt
	SingleCommand
	CommandFromFile
)

// Enum for cmd trigger types
const (
	ShellOutput = iota
	ShellOutputNumeric
	FileSize
	DirectoryListing
)

// Enum for changes to individual trigger
// Note that the only trigger types are NotEqual, GreaterThan, LessThan
// (but we have an Equal value for the other possible comparison return value)
const (
	Equal = iota
	NotEqual
	LessThan
	GreaterThan
)

// Enum for encryption algorithms
const (
	AES128 = iota
	AES192
	AES256
)

// Enum for the format of randomly generated folder names
const (
	AlphaNum = iota
	Alpha
	Num
	AppendAlphaNum
	AppendAlpha
	AppendNum
)

// General settings for main application
type General struct {
	Verbose   bool // Verbose commandline output (off by default)
	Mode      int  // Operational mode (see enum above) (FileMode is default setting)
	Encrypted bool // Encrypt exfiltrated data (on by default)
	NumTimes  int  // Number of times each payload packet will be sent
	Task      int  // Required task to be exeuted

	NumThreads int // Number of threads to be used when building and exfiltrating payloads (default=10)

	LogEnabled bool   // Enable/disable logging
	LogFile    string // Application logfile

	AppendURL           bool     // Add random path to OOB URL to limit patern matching
	RandomFolderNames   bool     // Create random strings for URLs instead of using names from file
	RandomURLFileSample bool     // Take a random selection of URL folder names from file if true
	URLSuffixFile       string   // File containing the suffixes to be appended to URLs
	URLSuffixes         []string // Slice of randomly generate suffixes to be added to end of fake host URLs
	NumSuffixes         int      // Number of folder names to be appended to the URL
	RandURLFormat       int      // The format to use for randomly generated folder names [AlphaNum = 0]
	URLPrefix           string   // Allow user to specify a prefix that the random URL may be appended onto

	TargetsFile  string // List of target URLs to be tested for 'bounce-ability'
	BouncersFile string // List of usable URLs resulting from bounce test
}

// The OOB DNS server settings
type Bouncer struct {
	Server    string // The OOB DNS bouncer (DNS name or IP address)
	Port      string // Leave blank for 80, 443, etc. defined by prefix
	Prefix    string // Default to http, but allow user to select other
	HTTPVerb  string // Used to allow use of GET, POST, HEAD, etc.
	HasProxy  bool   // Default to false - true will use whatever proxy settings set in ini file or on cmd line
	UserAgent string // Deafult user aent in place - user can change/customize in ini file or with cmd line flag
	JSONFile  string // The file from DNS server holding JSON data for lookups
}

// Encryption settings for application payloads
type Encryption struct {
	Key       string
	KeyFile   string
	Algorithm int
}

// DataFragment struct to hold the individual exfil payload chunks
type DataFragment struct {
	FileHash     string
	StreamID     string
	ChunkID      string
	TotalChunks  string
	DataFragment string
	OobServer    string
}

// Settings for file exfil mode
type FileExfil struct {
	FileID     string // Hash of the file to be exfiltrated
	UUID       string // An identifier to separate and collate individual exfiltrated files
	InputFile  string // Target file to be exfiltrated
	OutputFile string // Filename to hold exfiltrated decrypted data
	CryptFile  string // Filename to hold encrypted data if required by user
	WriteCrypt bool   // Write decrypted data to this file
}

// The struct to hold HTTP data - potentially remove this as all settings held elsewhere??
type HTTPClient struct {
	Client     *http.Client // Use built-in HTTP functionality
	Target     string       // Target IP or URL
	Port       string       // Target port
	Protocol   string       // Default to HTTP, but allow HTTPS, FTP, etc.
	FullTarget string       // Build full target from individual URL elements
	UserAgent  string
	// Proxy details
	// Headers

}

// Multiple operational timing modes for CmdMode
const (
	RunOnce = iota
	RepeatFixed
	RepeatRandom
	RepeatOnTrigger
)

// Options for return of shell output
const (
	Immediate = iota
	Fixed
	Randomized
	ReportOnTrigger
)

// Options for how frequently the "trigger chaecks" are made, and reports are uploaded
const (
	Daily = iota
	Weekly
	Monthly
	EveryXSeconds
	EveryXMinutes
	EveryXHours
	EveryXDays
	EveryXWeeks
)

// Settings for shell command mode
type CmdOutput struct {
	OpMode       int // Frequency for running commands (once|fixed|random|trigger)
	OpTimingMode int // Setting for units used by the timer below (hourly, daily, number of hours, etc.)
	OpTiming     int // Set timing for shell commands
	RandOpMin    int // Min value for random units
	RandOpMax    int // Max value for random units

	Command string   // Command to be executed
	Params  []string // Params for command
	OSShell string   // The shell to use - user can select alternative to the OS default

	ToFile          bool   // Write output to file or return output immediately
	ShellInputFile  string // The filename to hold shell commands (default = shellin.txt)
	ShellOutputFile string // The filename to hold shell output (default = shellout.txt)
	IncludeDateTime bool   // Include the date and time that command was executed in the output file
	IncludeCommand  bool   // Include the command that was executed in the output file
	IncrementUUID   bool   // Increase UUID for each commandf output

	ResponseMode       int // Frequency for uploading commands (immediate|fixed|random|trigger)
	ResponseTimingMode int // Setting for when response upload will take place (hourly, daily, number of hours, etc.)
	ResponseTiming     int // Set timing for response exfiltration
	RandRespMin        int // Min value for random units
	RandRespMax        int // Max value for random units

	HasPipeInput  bool     // Set requirement to pipe input from other command
	HasPipeOutput bool     // Set requirement to pipe output to other command
	PipeInput     []string // Collection of commands to pipe into the command
	PipeOutput    []string // Collection of commands to pipe the command output into

	CancelTiming int // Number of seconds for a command to run before sending cancel (0 = do not cancel)
}

// Settings for trigger that will determine whether or not a shell command will be exectuted and exfiltrated
type CmdTrigger struct {
	TriggerMode int // Using the enum, this will be shell output (alpha or num), change to file or change to dir listing
	TriggerType int // Using the enum this will be not equal, less than or greater than

	ShellCommand     string        // The shell command that will be run for comaparison with previous output
	ShellParams      []string      // The params for the above command
	TargetPath       string        // File or directory to be checked on trigger timing
	PreviousOutput   string        // Result of previous trigger
	PreviousDirFiles []os.FileInfo // Previous directory content

	TriggerTimerMode int // Setting for when trigger will be checked (hourly, daily, number of hours, etc.)
	TriggerTiming    int // Number of days/hours/etc. for above setting
}

//====================
//	Constructors
//--------------------

// Create new instance of General settings, populated with default values
func NewGeneralDefault() *General {

	// Get date as filename=safe string for logfilename
	datetime := time.Now()
	dateStr := datetime.String()
	tempstr := strings.Replace(dateStr, " ", "", -1)
	safeDate := strings.Replace(tempstr, ":", "-", -1)

	return &General{
		Verbose:             false,
		Mode:                FileMode,
		Encrypted:           true,
		NumTimes:            1,
		Task:                FileExfiltrate,
		NumThreads:          5,
		LogEnabled:          false,
		LogFile:             "script_log_" + safeDate + ".log",
		TargetsFile:         "targets.txt",
		BouncersFile:        "domains.txt",
		RandomFolderNames:   false,
		RandomURLFileSample: false,
		NumSuffixes:         1,
		AppendURL:           false,
		URLSuffixFile:       "urlpaths_short.txt",
		RandURLFormat:       AppendAlphaNum,
	}
}

// Create new instance of General settings, populated with user-specified values
func NewGeneral(verbose bool, opmode int, encrypted bool, numTimes int, task int, logEnable bool, logFile string, targetsFile string, appendURL bool, suffixFile string) *General {
	return &General{
		Verbose:       verbose,
		Mode:          opmode,
		Encrypted:     encrypted,
		NumTimes:      numTimes,
		Task:          task,
		LogEnabled:    logEnable,
		LogFile:       logFile,
		TargetsFile:   targetsFile,
		AppendURL:     appendURL,
		URLSuffixFile: suffixFile,
	}
}

// Create new Bouncer instance with default settings
func NewBouncerDefault() *Bouncer {
	return &Bouncer{
		Server:    "127.0.0.1",
		Port:      "", // Port will only be added into the URL if a string has been provided
		Prefix:    "http://",
		HTTPVerb:  "GET",
		HasProxy:  false,
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Safari/605.1.15",
		JSONFile:  "",
	}
}

// Create new Bouncer instance with default settings
func NewEncryptionDefault() *Encryption {
	return &Encryption{
		Key:       "ChangeThisValue!",
		KeyFile:   "key.bin",
		Algorithm: AES128,
	}
}

// Constant for the number of components in a file exfil URL fragment
var FileExfilStructParts int

// Create new FileExfil instance with default settings
func NewFileExfilDefault() *FileExfil {
	return &FileExfil{
		FileID:     "",
		UUID:       "0001",
		InputFile:  "",
		OutputFile: "",
		CryptFile:  "",
		WriteCrypt: false,
	}
}

// Create new CmdOutput instance with default settings
func NewCmdModeDefault() *CmdOutput {
	return &CmdOutput{
		OpMode:          RunOnce,
		OpTiming:        1,
		Command:         "",
		OSShell:         "",
		ToFile:          false,
		ShellInputFile:  "shellin.txt",
		ShellOutputFile: "shellout.txt",
		IncrementUUID:   false,
		ResponseTiming:  1,
		HasPipeInput:    false,
		HasPipeOutput:   false,
		CancelTiming:    0,
	}
}

// Create new CmdOutput instance with default settings
func NewCmdTriggerDefault() *CmdTrigger {
	return &CmdTrigger{
		TriggerMode:      ShellOutput,
		TriggerType:      NotEqual,
		TriggerTimerMode: Daily,
		TriggerTiming:    1,
	}
}

// Set the operational mode for Interocitor
func StringToMode(mode string) {

	// Check mode string and convert into setting
	switch strings.ToLower(mode) {
	case "t", "tgt", "targetmode", "target":
		GeneralSettings.Mode = TargetMode
	case "c", "cmd", "cmdmode", "command":
		GeneralSettings.Mode = CmdMode
	case "p", "poll", "pollmode":
		GeneralSettings.Mode = PollMode
	case "d", "dns", "dnsmode":
		GeneralSettings.Mode = DNSMode
	default:
		GeneralSettings.Mode = FileMode
	}

	if GeneralSettings.Verbose {
		fmt.Println("Running Interocitor in ", ModeToString(GeneralSettings.Mode))
	}
}

// Provide a text representation for operational mode
// (helpful for console output, etc.)
func ModeToString(mode int) string {

	// Check mode setting and convert into string
	switch mode {
	case TargetMode:
		return "Target Mode"
	case FileMode:
		return "File Mode"
	case CmdMode:
		return "Cmd Mode"
	case PollMode:
		return "Poll Mode"
	case DNSMode:
		return "DNS Mode"
	default:
		// This should be impossible
		return "[Error: No mode set]"
	}
}

// Set the task to be executed (partially dependent on operational mode)
func StringToTask(task string) {

	// Check task string and convert into setting
	switch strings.ToLower(task) {
	case "b", "bouncechk", "bounce_chk", "bouncecheck", "bounce_check":
		// Target mode - bounce check
		GeneralSettings.Task = BounceCheck
	case "j", "json", "jsonextract", "extract", "json_extract":
		// Target mnode and file mode - extract data from DNS
		GeneralSettings.Task = HostExtract
	case "ed", "extractdecrypt", "extract_decrypt", "extract-decrypt":
		// Target mnode and file mode - extract data from DNS and decrypt it
		GeneralSettings.Task = DNSExtractDecrypt
	case "f", "decrypt", "filedecrypt", "file_decrypt":
		// Decrypt the file provided (this would usually be output fromn the extract task)
		GeneralSettings.Task = FileDecrypt
	case "c", "cmd", "s", "once", "single", "singlecmd", "single_cmd", "singlecommand":
		// Execute single command
		GeneralSettings.Task = SingleCommand
	case "cf", "filecmd", "file_cmd", "cmdfile", "cmd_file":
		// Execute file containing list of commands
		GeneralSettings.Task = CommandFromFile
	case "file":
		// Dependent upon mode, this may indicate file exfiltration, or executing a list of commands in a file
		if GeneralSettings.Mode == CmdMode {
			GeneralSettings.Task = CommandFromFile
		} else {
			GeneralSettings.Task = FileExfiltrate
		}
	default:
		GeneralSettings.Task = FileExfiltrate
	}

	if GeneralSettings.Verbose {
		fmt.Println("Task Mode: ", TaskToString(GeneralSettings.Task))
	}
}

// Provide a text representation for operational mode
// (helpful for console output, etc.)
func TaskToString(task int) string {

	// Check task setting and convert into string
	switch task {
	case BounceCheck:
		return "Bounce Check"
	case HostExtract:
		return "Extract Hosts from DNS File"
	case DNSExtractDecrypt:
		return "Extract and Decrypt Data from DNS File"
	case FileDecrypt:
		return "Decrypt Data File"
	case FileExfiltrate:
		return "Exfiltrate File"
	case SingleCommand:
		return "Execute Single Command, Exfiltrate Output"
	case CommandFromFile:
		return "Execute Commands from File, Exfiltrate Output"
	default:
		// This should be impossible
		return "[Error: No mode set]"
	}
}

// Translate words from command line or ini file into the program's internal enum representation for time units
func StringToTimerMode(timeUnit string) int {

	// Default val is hours - using this variable to avoid the ugliness of returns inside each case
	retval := EveryXHours

	// Check command line input and get the time unit
	switch strings.ToLower(timeUnit) {
	case "s", "sec", "secs", "second", "seconds":
		retval = EveryXSeconds
	case "m", "min", "mins", "minute", "minutes":
		retval = EveryXMinutes
	case "h", "hr", "hrs", "hour", "hours":
		retval = EveryXHours
	case "d", "day", "days":
		retval = EveryXDays
	case "w", "wk", "wks", "week", "weeks":
		retval = EveryXWeeks
	}

	return retval
}

// Translate words from command line or ini file into the program's internal enum representation for timing modes
func StringToCmdTimer(cmdFrequency string) {

	// Set shell commands to run once or at specified times
	switch strings.ToLower(cmdFrequency) {
	case "o", "once", "1":
		CmdSettings.OpMode = RunOnce
	case "f", "fixed":
		CmdSettings.OpMode = RepeatFixed
	case "r", "rand", "random":
		CmdSettings.OpMode = RepeatRandom
	case "t", "trigger", "ontrigger":
		CmdSettings.OpMode = RepeatOnTrigger
	default:
		CmdSettings.OpMode = RunOnce
	}
}

// Translate words from command line or ini file into the program's internal enum representation for timing modes
func StringToUploadTimer(cmdFrequency string) {

	// Set shell commands to run once or at specified times
	switch strings.ToLower(cmdFrequency) {
	case "i", "immediate", "1":
		CmdSettings.ResponseTimingMode = RunOnce
	case "f", "fixed":
		CmdSettings.ResponseTimingMode = RepeatFixed
	case "r", "rand", "random":
		CmdSettings.ResponseTimingMode = RepeatRandom
	case "t", "trigger", "ontrigger":
		CmdSettings.ResponseTimingMode = RepeatOnTrigger
	default:
		CmdSettings.ResponseTimingMode = RunOnce
	}
}

// Translate words from command line or ini file into the program's internal enum representation for trigger modes
func StringToTriggerMode(trigger string) {

	// Set the mode of trigger that will be checked for command execution/exfiltration
	// This can be command output (alpha or num), file changes, or directory changes
	switch strings.ToLower(trigger) {
	case "f", "file", "filechange", "file_change", "filesize", "file_size":
		TriggerSettings.TriggerMode = FileSize
	case "d", "dir", "directory", "dirchange", "dir_change", "dirlisting", "dir_listing":
		TriggerSettings.TriggerMode = DirectoryListing
	case "cn", "cmdnum", "cmd_num", "shn", "shellnum", "shell_num":
		TriggerSettings.TriggerMode = ShellOutputNumeric
	default:
		TriggerSettings.TriggerMode = ShellOutput
	}
}

// Translate words from command line or ini file into the program's internal enum representation for trigger types
func StringToTriggerType(trigger string) {

	// Set the type of trigger that will be checked for command execution/exfiltration
	// It can be less than previous, greater than previous, or not equal to previous
	switch strings.ToLower(trigger) {
	case "<", "l", "lt", "lessthan", "less_than":
		TriggerSettings.TriggerType = LessThan
	case ">", "g", "gt", "greaterthan", "greater_than":
		TriggerSettings.TriggerType = GreaterThan
	default:
		TriggerSettings.TriggerType = NotEqual
	}
}

// Take a string (from user input) and convert to number of seconds to wait before sending Cancel to a shell command
func StringToCancel(settings string) {

	seconds, err := strconv.Atoi(settings)

	if err != nil || seconds < 0 {
		fmt.Println("Error converting Cancel Timing value to valid integer. Using default value of 0 (No Cancel Signal) instead.")
		CmdSettings.CancelTiming = 0
	} else {
		CmdSettings.CancelTiming = seconds
	}
}
