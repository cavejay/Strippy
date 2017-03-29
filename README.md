# Strippy
Use this Powershell Script to sanitise your logs of configured patterns before handing them off to someone else (like your support team)

It’s written in powershell and so will run natively on every company laptop with windows which means all you have to do is download the script and give it input files. 



## Usage

**This is a Powershell script. It will not execute natively in Window's command prompt**

Run `powershell -executionpolicy Unrestricted` to enter a Powershell prompt capable of running custom scripts.

Sanitise a file: `C:\PS> .\strippy.ps1 .\logs\server.1.log`

Sanitise files as part of a time based automation task: `C:\PS> .\strippy.ps1 "C:\Program Files\Dynatrace\CAS\Server\logs" -Recurse -Silent -out "C:\sanitised-$(get-date -UFormat %s)"`

## Other Info
- The script will take input from files and folders but will only process .log and .txt files (for now)
- It requires a config file called “strippyConfig.json” in the script’s directory to run. In this config file are the regex rules that determine which parts of the log files to sanitise and what generic name to replace them with. The -MakeConfig flag will create a default config file for you or you can use the one I attached to this email.
- The first group in a regex pattern is what will be replaced with the generic name. Using more than one group in a non-hierarchical manner is not yet tested/supported 
- Regex is usually disgusting to write in java, javascript and json due to the number of escaping backslashes that are necessary. I’ve implemented a somewhat intelligent method of getting around this so ignore json’s conventions and write normal regex in the config file
    - Eg. Write \\\\([\w\-.]*?)\\ not \\\\\\\\([\\w\\-.]*?\\\\
    - I expect this is a weak point in the application however, so try to break it
- There’s a fair amount of commenting and explanation throughout the script, but it’s fairly long so don’t feel like you need to read it. I’ve written a help section that’s readable by powershell’s get-help commandlet so running get-help .\strippy.ps1 or just running the script with no input will give you an explanation of some things
