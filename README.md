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

## Config

Below is an example of a config file that should handle most, if not all of the sanitisation for the log files from a Dynatrace Data Center Real User Monitoring (DCRUM) installation. It is being kept as current as possible so that as I encounter more cases that require sanitisation this example will updated.

```
{
    "_Comment": "This file contains rules to sanitise most log files created by DCRUM.",
    "UseMe": true,
    "IgnoredStrings": ["/0:0:0:0:0:0:0:0", "0.0.0.0", "127.0.0.1", "name", "applications"],
    "SanitisedFileFirstLine": "eval:This file was Sanitised at `$( `$(Get-Date).toString() ).`n==`n`n",
    "KeyListFirstline": "eval:This keylist was created at `$( `$(Get-Date).toString() ).`n",

    "KeyFile": "",
    "indicators": [
        ["Some Regex String here", "Replacement here"],
        ["((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))[^\d]", "Address"],
        ["addr=(.*?)[,&]", "Address"],
        ["\d\sUser (\w+?) ", "Username"],
        ["Machine : (.*?); ", "Hostname"],
        ["Key User Report : section (.*?) - ", "Username"],
        ["Key User Report : section .*? - (.*?) - IP: ", "Hostname"],
        ["Key User Report : section .*? - .*? - IP: (.*?)", "Address"],
        ["user:(.*?)$", "Username"],
        ["Using CSS at address (.*)\.", "Address"],
        ["CSSAuthManager - connecting to CSS server ... connection with (.*?):\d\d+ established", "Hostname"],
        ["Request .*?@(.*):\d\d+ hasn't been used since", "Hostname"],
        ["\\\\([\w\-.]*?)\\", "Hostname"],
        ["on CSS located at \[(.*?):\d+\]", "Address"],
        ["User (.*?) logged in from", "User"],
        ["User: (.*?) / .*", "User"],
        [" user: \[?(.*?)\]?,", "User"],
        ["User: .* / (.*)", "User"],
        ["originatingHostname: (.*?),","Hostname"],
        ["hostname=(.*?),", "Hostname"],
        ["sqlserver:(.*?);\]", "Database"],
        ["URL '(.*?)',", "LDAP"],
        ["LDAP server: (.*?);", "LDAP"],
        ["\[ldap:(.*?)\]", "LDAP"],
        ["Found DN \[(.+?)\] for Service Account", "LDAP"],
        ["FQDN and IP address found via JDK \[(.*?)\] \[.*\]","FQDN"],
        ["FQDN and IP address found via JDK \[.*?\] \[(.*?)\]","Address"],
        ["FQDN, NBT, and IP addresses used \{\[(.*?)\]\[.*?\]\} \{\} \{\[.*?\]\}","FQDN"],
        ["FQDN, NBT, and IP addresses used \{\[.*?\]\[(.*?)\]\} \{\} \{\[.*?\]\}","NBT"],
        ["FQDN, NBT, and IP addresses used \{\[.*?\]\[.*?\]\} \{\} \{\[(.*?)\]\}","Address"],
        ["Verified CSS \[\[.*?\]\[(.*?)\]\] in Federation", "FQDN"],
        ["Verified CSS \[\[(.*?)\]\[.*?\]\] in Federation", "FQDN"]
    ]
}
```