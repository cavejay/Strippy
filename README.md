# Strippy
Use this Powershell Script to sanitise your logs using specific patterns before handing them off to someone else (like your support team)

It’s written in powershell and so will run natively on every company laptop with windows which means all you have to do is download the script and give it input files. 


## Usage

**This is a Powershell script. It will not execute natively in Window's command prompt**

Download the latest version from: https://github.com/cavejay/Strippy/releases/latest

Run `powershell -executionpolicy Unrestricted` to enter a Powershell prompt capable of running custom scripts.

Sanitise a file: `C:\PS> .\strippy.ps1 .\logs\server.1.log`

Sanitise files as part of a time based automation task: `C:\PS> .\strippy.ps1 "C:\Program Files\Dynatrace\CAS\Server\logs" -Recurse -Silent -out "C:\sanitised-$(get-date -UFormat %s)"`

## Other Info
- The script will take input from files and folders but will only process .log and .txt files (for now)
- It requires a config file called “strippy.conf” in the script’s directory to run. In this config file are the regex rules that determine which parts of the log files to sanitise and what generic name to replace them with. The -MakeConfig flag will create a default config file for you or you can use the one I've added beneath the 'config' heading.
- The first group in a regex pattern is what will be replaced with the generic name. Using more than one group in a non-hierarchical manner is not yet tested/supported
- There’s a fair amount of commenting and explanation throughout the script, but it’s quite long so don’t feel like you need to read it. I’ve written a help section that’s readable by powershell’s get-help commandlet so running get-help .\strippy.ps1, .\strippy.ps1 -help or just running the script with no input will give you an explanation of some things

## Config

Below is an example of a config file that should handle most, if not all of the sanitisation for the log files from a Dynatrace Data Center Real User Monitoring (DCRUM) 12.4.15 installation. It is being kept as current, being updated when I encounter more cases are not already covered. It is very possible that new log messages that need to be sanitised are added in newer versions, but I would need exposure to a live environment of that version to develop the determine the new rules.

```ini
; Strippy Config file
; Developed for a 12.4.15 release of DCRUM
;Recurse=true
;InPlace=false
;Silent=false
;MaxThreads=5

[ Config ]
IgnoredStrings="/0:0:0:0:0:0:0:0", "0.0.0.0", "127.0.0.1", "name", "applications", ""

; These settings can use braces to include dynamic formatting: 
; {0} = Date/Time at processing
; #notimplemented {1} = Depends on context. Name of specific file being processed where relevant otherwise it's the name of the Folder/File provided to Strippy 
SanitisedFileFirstLine="This file was Sanitised at {0}.`r`n==`r`n`r`n"
KeyListFirstLine="This keylist was created at {0}."
;KeyFileName="Keylist.txt"
;AlternateKeyListOutput=".\keylist.txt"
;AlternateOutputFolder=".\SanitisedOutput"

[ Rules ]
;"Some Regex String here"="Replacement here"
"((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))[^\d]"="Address"
"addr=(.*?)[,&]"="Address"
"\d\sUser (\w+?) "="Username"
"Machine : (.*?); "="Hostname"
"Key User Report : section (.*?) - "="Username"
"Key User Report : section .*? - (.*?) - IP: "="Hostname"
"Key User Report : section .*? - .*? - IP: (.*?)"="Address"
"Received update event \(member (.*?),"="Address"
"user:(.*?)$"="Username"
"Using CSS at address (.*)\."="Address"
"CSSAuthManager - connecting to CSS server ... connection with (.*?):\d\d+ established"="Hostname"
"Request .*?@(.*):\d\d+ hasn't been used since"="Hostname"
"\\\\([\w\-.]*?)\\"="Hostname"
"on CSS located at \[(.*?):\d+\]"="Address"
"User (.*?) logged in from"="User"
"User: (.*?) / .*"="User"
" user: \[?(.*?)\]?,"="User"
"User: .* / (.*)"="User"
"originatingHostname: (.*?),"="Hostname"
"hostname=(.*?),"="Hostname"
"sqlserver:(.*?);\]"="Database"
"URL '(.*?)',"="LDAP"
"LDAP server: (.*?);"="LDAP"
"\[ldap:(.*?)\]"="LDAP"
"Found DN \[(.+?)\] for Service Account"="LDAP"
"FQDN and IP address found via JDK \[(.*?)\] \[.*\]"="FQDN"
"FQDN and IP address found via JDK \[.*?\] \[(.*?)\]"="Address"
"FQDN, NBT, and IP addresses used \{\[(.*?)\]\[.*?\]\} \{\} \{\[.*?\]\}"="FQDN"
"FQDN, NBT, and IP addresses used \{\[.*?\]\[(.*?)\]\} \{\} \{\[.*?\]\}"="NBT"
"FQDN, NBT, and IP addresses used \{\[.*?\]\[.*?\]\} \{\} \{\[(.*?)\]\}"="Address"
"Verified CSS \[\[.*?\]\[(.*?)\]\] in Federation"="FQDN"
"Verified CSS \[\[(.*?)\]\[.*?\]\] in Federation"="FQDN"
"jdbc:(.*?);"="JDBC_URL"
"sqlserver:(.*?);\]"="Database"
"Software service (.*) is (alive|dead)"="SoftwareService"
"Cannot get user (.*?) data from CSS"="User"
"Unable to find user \[(.*)\]"="User"
"<(.+)>: Recipient address rejected: Access denied"="User"
"Collected data for report "(.+) : section .+" from .+ in "="DMIReport"
"Collected data for report ".+ : section (.+)" from .+ in "="DMISection"
"^..CSS .+; user: (.+) "="User"
"User (.+) \(\[.+\]\) on .+ has logged (on\.|OUT)"="User"
"User .+ \(\[(.+)\]\) on .+ has logged (on\.|OUT)"="UserPermissions"


; Rules with the Replacement text of '\delete' processed first and deleted entirely
"^.*resolved to.*$"=\delete
```
