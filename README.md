# Strippy

Use this Powershell Script to sanitise your logs using specific patterns before handing them off to someone else (like your support team)

It’s written in powershell and so will run natively on every company laptop with windows which means all you have to do is download the script and give it input files. 

## Usage

**This is a Powershell script. It will not execute natively in Window's command prompt**

Download the latest version from: https://github.com/cavejay/Strippy/releases/latest

Run `powershell -executionpolicy Unrestricted` to enter a Powershell prompt capable of running custom scripts.

Sanitise a file: `C:\PS> .\strippy.ps1 .\logs\server.1.log`

Sanitise files as part of a time based automation task: `PS> .\strippy.ps1 "C:\Program Files\Dynatrace\CAS\Server\logs" -Recurse -Silent -out "C:\sanitised-$(get-date -UFormat %s)"`

## Other Info

- The script will take input from files and folders but will only process .log and .txt files (for now)
- It requires a config file called “strippy.conf” in the script’s directory to run. In this config file are the regex rules that determine which parts of the log files to sanitise and what generic name to replace them with. The -MakeConfig flag will create a default config file for you or you can use the one I've added beneath the 'config' heading.
- The first group in a regex pattern is what will be replaced with the generic name. Using more than one group in a non-hierarchical manner is not yet tested/supported
- There’s a fair amount of commenting and explanation throughout the script, but it’s quite long so don’t feel like you need to read it. I’ve written a help section that’s readable by powershell’s get-help commandlet so running get-help .\strippy.ps1, .\strippy.ps1 -help or just running the script with no input will give you an explanation of some things

## Config

Below is an example of a config file that should handle most, if not all of the sanitisation for the log files from a Dynatrace Data Center Real User Monitoring (DCRUM) 12.4.15 installation. 
It is being kept as current, being updated when I encounter more cases are not already covered. 
It is very possible that new log messages that need to be sanitised are added in newer versions, but I would need exposure to a live environment of that version to develop the determine the new rules.

The configFiles directory of this repo contains work-in-progress config files for particular applications. These are maintained by me on an as needed basis and that can be infrequent.

* [Dynatrace Network Application Monitoring](configFiles/nam.conf)
* [Dynatrace Managed/SaaS](configFiles/dt.conf)
