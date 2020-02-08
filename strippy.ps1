#Requires -Version 5

<#
.SYNOPSIS
    Tool for sanitising utf8 encoded files based on configured "indicators"

.DESCRIPTION
    Use this tool to automate the replacement of sensitive data in text files with generic strings.
    While intended for use with log files this tool should work with all text files.

    In order to use this tool effectively you will need to be proficient with regex. 
    Regex is used to filter out sensitive pieces of data from log files and replace it with a place holder.

    All rules (apart from basic unc and ip rules) must be added to a configuration file (named strippy.conf by default).
    Sanitisation rules added to the .conf file should look like this: 
        "<regex>"="<alias>" where:
            <regex> is a (not escaped) regex query and;
            <alias> is the text that will replace the first group inside the regex query.
        
        A complete example is:  "hostname=(.*?),"="Hostname"
        This example would transform 'hostname=SecretHostname,' into 'hostname=Hostname1,'
    
    Make use of the tool by reading the examples from: get-help .\strippy.ps1 -examples

    To start creating your own 'sensitive data indicators' you will need to create a .conf file that follows the ini style of formatting. An example config file can be generated using the -MakeConfig flag.
    Where a config file is not explicitly provided via the -configFile arg Strippy will check both the localdirectory of the script for a 'strippy.conf'
    
    If you haven't already then you'll need to change your execution policy to run this tool. 
    You can do this temporarily by using the following:
        powershell [-noexit] -executionpolicy Unrestricted -File .\strippy.ps1 <args>
    Or permanently by opening Powershell and running the following:
        Set-ExecutionPolicy Unrestricted https://ss64.com/ps/set-executionpolicy.html

.EXAMPLE
    C:\PS> .\strippy.ps1 .\logs

    This will sanitise only the files directly in .\logs using a default config file.
    Output files will be in the .\logs.sanitised folder and the keylist created for this run will be found in the directory you ran the script.

.EXAMPLE
    C:\PS> .\strippy.ps1 .\logs\server.1.log

    In this case only one file has been specified for sanitisation.
    The output in this case would be to .\logs\server.1.sanitised.log file and a keylist file .\KeyList.txt

.EXAMPLE
    C:\PS> .\strippy.ps1 ..\otherlogs\servers\oldlog.log -KeyFile .\KeyList.txt

    This would process the oldlog.log file like any other file, but will load in the keys already found from a key list file. 
    This means you can process files at different times but still have their keys matchup. Once done, this usecase will output a new keylist that contains all the keys from KeyList.txt and any new keys found in the oldlog.log file.

.EXAMPLE
    C:\PS> .\strippy.ps1 .\logs -Recurse

    If you need to sanitise an entire file tree, then use the -Recurse flag to iterate through each file in a folder and it's subfolders.
    This will output sanitised files to .\logs.sanitised

.EXAMPLE
    C:\PS> .\strippy.ps1 "C:\Program Files\Dynatrace\CAS\Server\logs" -Recurse -Silent -alternateOutputFolder "C:\sanitised-$(get-date -UFormat %s)"

    This example shows how you might integrate strippy in an automation scheme. The -Silent flag stops output to stdout, preventing the need for a stdout redirect. 
    The -alternateOutputFolder flag allows redirection of the sanitised files to a custom folder.

.NOTES
    Author: Michael Ball
    Version: 2.1.6 - 20200208
    Compatability: Powershell 5+

.LINK
    https://github.com/cavejay/Strippy
#>

# Todo
# combine AlternateKeyListOutput and keylistfile config settings. 
# Dealing with selections of files a la "server.*.log" or similar
# Use PS-InlineProgress or check and then use it if we're in the exe version
# Switch to add strippy to your ps profile for quick running
# Have option for diagnotics file or similar that shows how many times each rule was hit
# Publish to dxs wiki
# Support .zips as well.
# Have a blacklist of regexs.
# More intelligent capitalisation resolution.
# Move from jobs to runspaces?
# Switch used to create a single file strippy. ie, edit the script's code with the config rules etc.

<# Maintenance Todo list
    - Time global sanitise against running all the rules against each and every line in the files.    
    - use powershell options for directory and file edits
#>

[CmdletBinding(DefaultParameterSetName = 'input')]
param (
    <#              Help flags that return help information for -h -help types              #>
    # Help flags that return help information for -h types
    [Parameter(Position = 0, ParameterSetName = "help")][Switch] $h,
    [Parameter(ParameterSetName = "help")][Switch] $help,


    <#              Config things               #>
    # Creates a barebones strippy.conf file for the user to fill edit
    [Parameter(Position = 0, ParameterSetName = "makeconfig", Mandatory = $false)][Switch] $makeConfig,


    <#              Input Settings              #>
    # The File or Folder you wish to sanitise
    [Parameter(Position = 0, ParameterSetName = "input")][String] $File,
    # Specifies a previously generated keylist file to import keys from for this sanitisation
    [Parameter(Position = 1, ParameterSetName = "input")][String] $KeyFile, 
    # Specifies a config file to use rather than the default local file or no file at all
    [Parameter(Position = 2, ParameterSetName = "input")][String] $ConfigFile,
    # Looks for log files throughout a directory tree rather than only in the first level
    [Parameter(ParameterSetName = "input")][Switch] $Recurse = $false,
    # Destructively sanitises the file. There is no warning for this switch. If you use it, it's happened
    [Parameter(ParameterSetName = "input")][Switch] $InPlace = $false,
    # Do not include the sanitisation meta data in output
    [Parameter(ParameterSetName = "input")][switch] $noHeaderInOutput = $false,
    # A shortcut for -AlternateKeylistOutput 
    [Parameter(ParameterSetName = "input")][String] $ko,
    # Specifies an alternate name and path for the keylist file
    [Parameter(ParameterSetName = "input")][String] $AlternateKeyListOutput = $ko,
    # A shortcut for -AlternateOutputFolder 
    [Parameter(ParameterSetName = "input")][String] $o, 
    # Specifies an alternate path or file for the sanitised file
    [Parameter(ParameterSetName = "input")][String] $AlternateOutputFolder = $o, 
    # The tool will run silently, without printing to the terminal and exit with an error if it needed user input
    [Parameter(ParameterSetName = "input")][Switch] $Silent = $false,
    # How threaded can this process become?
    [Parameter(ParameterSetName = "input")][int] $MaxThreads = 5,
    

    <#              Logging Settings                #>
    # Perform logging for this execution
    [Switch] $log = $false,
    # The specific log file to log to. This is useless unless the log switch is used
    [String] $logfile = ".\strippy.log",
    # Show absolutely all log messages. This will create much larger logs
    [Switch] $showDebug = $false,
    # How big can a log file get before it's shuffled
    [int] $MaxLogFileSize = 10MB,
    # Max number of log files created by the script
    [int] $LogHistory = 5
)

$_startTime = get-date

## Setup Log functions
function shuffle-logs ($MaxSize, $LogFile = $script:logfile, $MaxFiles = $script:LogHistory) {
    if (!(Test-Path $LogFile)) {
        return # if the log file doesn't exist then we don't need to do anything
    }
    elseif ((Get-Item $logfile).Length -le $MaxSize) {
        return # the log file is still too small
    }

    # Get the name of the file
    $n = ((Split-Path -Leaf -Resolve $logFile) -split '\.')[-2]

    # Find all the files that fit that name
    $logfiles = Get-ChildItem (split-path $LogFile) -Filter "$n.*log"
    
    # When moving files make sure nothing else is accessing them. This is a bit of overkill but could be necessary.
    if ($mtx.WaitOne(500)) {
        # Shuffle the file numbers up
        ($MaxFiles - 1)..1 | ForEach-Object {
            move-item "$n.$_.log" "$n.$($_+1).log" -Force -ErrorAction SilentlyContinue
        }
        $timestamp = Get-Date -format "yy-MM-dd HH:mm:ss.fff"
        $logMessage = ("LOG SHUFFLE " + $timestamp + "   Continued in next log file")
        $logMessage | Out-File -FilePath $LogFile -Force -Append
        move-item $logFile "$n.1.log" 
    
        # Start a new file
        new-item -ItemType file -Path $LogFile | Out-Null;

        [void]$mtx.ReleaseMutex()
    }
}

# Create a mutex for the rest of the execution
$mtx = New-Object System.Threading.Mutex($false, "LoggerMutex")

# Enum to show what type of log it should be
Enum LEnum {
    Trace
    Warning
    Debug
    Error
    Question # Use this to show a prompt for user input
    Message # This is the log type that's printed and coloured
}

<#
    logfunction. Default params will log to file with date 
    https://www.sapien.com/blog/2015/01/05/enumerators-in-windows-powershell-5-0/
#>
function log ([String] $Stage, [LEnum] $Type = [LEnum]::Trace, [String] $String, [System.ConsoleColor] $Colour, [String] $Logfile = $script:logfile) {
    # Return instantly if this isn't output and we're not logging
    if (!$script:log -and @([LEnum]::Message, [LEnum]::Question, [LEnum]::Warning, [LEnum]::Error) -notcontains $type) {return}
    # Return instantly if this is a debug message and we're not showing debug
    if (!$script:showDebug -and $type -eq [Lenum]::Debug) {return}
 
    shuffle-logs $script:MaxLogFileSize $Logfile

    # Deal with the colouring and metadata
    switch ($Type) {
        "Message" {  
            $1 = 'I'
            $display = $true
            $Colour = ($null, $Colour, 'WHITE' -ne $null)[0]
            break
        }
        "Question" {
            $1 = 'Q'
            $display = $true
            $Colour = ($null, $Colour, 'CYAN' -ne $null)[0]
            break
        }
        "Debug" {  
            $1 = 'D'
            break
        }
        "Error" {  
            $1 = 'E'
            $Colour = ($null, $Colour, 'RED' -ne $null)[0]
            $display = $true
            $String = "ERROR: $string"
            break
        }
        "Warning" {  
            $1 = 'W'
            $Colour = ($null, $Colour, 'YELLOW' -ne $null)[0]
            $display = $true
            $String = "Warning: $string"
            break
        }
        Default {
            # Trace enums are default. 
            $1 = 'T'
        }
    }

    # If we need to display the message check that we're not meant to be silent
    if ($display -and -not $silent) {
        # Error messages require a black background to stand out and mirror powershell's native errors
        if ($type -eq [LEnum]::Error) {
            write-host $String -foregroundcolor $Colour -BackgroundColor 'Black'
        }
        else {
            write-host $String -foregroundcolor $Colour
        }
    }
    
    # Check whether we're meant to log to file
    if (!$script:log) {
        return
    }
    else {    
        # assemble log message!
        $stageSection = $(0..5 | % {$s = ''} {$s += @(' ', $Stage[$_])[[bool]$Stage[$_]]} {$s})
        $timestamp = Get-Date -format "yy-MM-dd HH:mm:ss.fff"
        $logMessage = ($1 + " " + $stageSection.toUpper() + " " + $timestamp + "   " + $String)
        try {
            # This try is to deal specifically when we've destroyed the mutex.
            if ($mtx.WaitOne()) {
                # use Powershell native code. .NET functions don't offer enough improvement here.
                $logMessage | Out-File -Filepath $Logfile -Append
                [void]$mtx.ReleaseMutex()
            } 
            # consider doing something here like: 
            # if waiting x ms then continue but build a buffer. Check each time the buffer is added to until a max is reached and wait to add that
            # Sometimes the mutex might have been destroyed already (like when we're finishing up) so work with what we've got
        }
        catch [ObjectDisposedException] {
            "$logMessage - NoMutex" | Out-File -FilePath $logFile -Append
        }
    }
}

function replace-null ($valIfNull, [Parameter(ValueFromPipeline = $true)]$TestVal) {
    return ($null, $TestVal, $valIfNull -ne $null)[0]
}

function show-path ($path) {
    $path = if ($path -eq '' -or $null -eq $path) {
        "Unset"
    }
    else {
        try {
            (Resolve-Path $path -ErrorAction Stop).path
        }
        catch {
            "$path (unresolveable)"
        }
    }
    return $path
}

# Help flag checks
if ($h -or $help) {
    log params trace "Strippy was started help flags. Showing the get-help output for the script and exiting"
    Get-Help $(join-path $(Get-Location) $MyInvocation.MyCommand.Name) -Detailed
    exit 0
}

# Usage todo need to make this usable without the reliance on get-help or powershell in general. 
if ( $File -eq "" -and -not $makeConfig ) {
    log params trace "Strippy was started with no file. Showing the get-help output for the script and exiting"
    Get-Help $(join-path $(Get-Location) $MyInvocation.MyCommand.Name) -Detailed
    exit 0
}

log init Trace "`r`n`r`n"
log init Trace "-=H||||||||    Starting Strippy Execution    |||||||||H=-"
log init Trace "   ||    Author:     michael.ball@dynatrace.com     ||"
log init Trace "   ||    Version:    2.1.6                         ||"
log params Trace "Strippy was started with the parameters:"
log params Trace "Sanitisation Target:              $(show-path $file)" # try to resolve the file here. Show nothing if it fails
log params Trace "Key file:                         $(@('Unset',(show-path $KeyFile))[$KeyFile -ne ''])"
log params Trace "Config file:                      $(@('Unset',(show-path $ConfigFile))[$ConfigFile -ne ''])"
log params Trace "Silent Mode:                      $Silent"
log params Trace "Recursive Searching:              $Recurse"
log params Trace "In-place sanitisation:            $InPlace"
log params Trace "No sanitisation header:           $noHeaderInOutput"
log params Trace "Creating a new Config file:       $MakeConfig"
log params Trace "Showing Debug logging:            $showDebug"
log params Trace "Alternate Keylist Output file:    $(@('Unset',(show-path $AlternateKeyListOutput))[$AlternateKeyListOutput -ne ''])"
log params Trace "Alternate Output folder files:    $(@('Unset',(show-path $AlternateOutputFolder))[$AlternateOutputFolder -ne ''])"
log params Trace "Maximum parrallel threads:        $MaxThreads"
log params Trace "Logging enabled:                  $log"
log params Trace "Destination Logfile:              $(show-path $logfile)" # try to resolve the file here. Show nothing if it fails
log params Trace "Max log file size:                $MaxLogFileSize"
log params Trace "Number of Log files kept:         $LogHistory"

# Special Variables: (Not overwritten by config files)
# If this script is self contained then all config is specified in the script itself and config files are not necessary or requested for. 
# This cuts down the amount of files necessary to move between computers and makes it easier to give to someone and say "run this"
# $SelfContained = $false # Not really implemented yet.

## Variables: (Over written by any config file and include all the command line variables)
# Priority of inputs: Default -> Configfile -> cmdline input
$Config = @{}
$Config.IgnoredStrings = @('/0:0:0:0:0:0:0:0', '0.0.0.0', '127.0.0.1', 'name', 'applications', "")
$Config.SanitisedFileFirstline = "This file was Sanitised at {0}.`r`n==`r`n`r`n"
$Config.KeyListFirstline = "This keylist was created at {0}."
$Config.KeyFileName = "KeyList.txt"
log params debug "Default Ignored Strings:          `"$($Config.IgnoredStrings -join '", "')`""
log params debug "Default Sanitised file header:    $($Config.SanitisedFileFirstLine)"
log params debug "Default Keylist/file header:      $($Config.KeyListFirstLine)"
log params debug "Default Keyfile name:             $($Config.KeyFileName)"

######################################################################
# Important Pre-script things like usage, setup and commands that change the flow of the tool

# General config 
$PWD = get-location
log params debug "Initial running location:         $PWD"
$_tp = 992313 # top Progress
log params debug "Special ID for top progress bar:  $_tp"
$_env = $script:log, $script:showDebug, $(resolve-path $script:logfile -ErrorAction 'SilentlyContinue').path, $script:MaxLogFileSize, $script:LogHistory
log params debug "Created `$_env variable to pass logging environment to jobs (log, showDebug, logfile, maxLogFileSize): $($_env -join ', ')"

# Flags
$Config.flags = New-Object System.Collections.ArrayList
# Added to every list of flags to cover IPs and UNC's
$defaultFlags = New-Object System.Collections.ArrayList
$defaultFlags.AddRange(@(
        [System.Tuple]::Create("((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))[^\d]", 'Address'),
        [System.Tuple]::Create("\\\\([\w\-.]*?)\\", "Hostname")
    ))
log params debug "Default flags/rules:              $defaultFlags"

#Check if we're _just_ creating a default config file
if ( $MakeConfig ) {
    log mkconf trace "Script launched with the -MakeConfig switch. Script will attempt to make a new, default config file before exiting."
    $confloc = Join-Path $( Get-Location ) 'strippy.conf'
    log mkconf trace "We're going to make the config file here: $confloc"
    # Apologies if you're trying to read this next string. 
    $defaultConfig = "; Strippy Config file`r`n;Recurse=true`r`n;InPlace=false`r`n;Silent=false`r`n;MaxThreads=5`r`n`r`n[ Config ]`r`nIgnoredStrings=""/0:0:0:0:0:0:0:0"", ""0.0.0.0"", ""127.0.0.1"", ""name"", ""applications"", """"`r`n`r`n; These settings can use braces to include dynamic formatting: `r`n; {0} = Date/Time at processing`r`n; #notimplemented {1} = Depends on context. Name of specific file being processed where relevant otherwise it`s the name of the Folder/File provided to Strippy `r`nSanitisedFileFirstLine=""This file was Sanitised at {0}.``r``n==``r``n``r``n""`r`nKeyListFirstLine=""This keylist was created at {0}.""`r`n;KeyFileName=""Keylist.txt""`r`n;AlternateOutputFolder="".\sanitisedoutput""`r`n`r`n[ Rules ]`r`n;""Some Regex String here""=""Replacement here""`r`n""((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))[^\d]""=""Address""`r`n""\\\\([\w\-.]*?)\\""=""Hostname""`r`n"
    log mkconf trace "We're going to give it this content:`r`n$defaultConfig"

    # Check to make sure we're not overwriting someone's config file
    if ( Test-Path $( $confloc ) ) {
        log mkconf debug "There is already a file at: $confloc. Polling user for action"
        log Mkconf question "A config file already exists. Would you like to overwrite it with the default?"
        $ans = Read-Host "y/n> (n) "
        log Mkconf trace "User answered with: '$ans'"
        if ( $ans -ne 'y' ) {
            log Mkconf message "Didn't overwrite the current config file. Exiting script"
            exit 0
        }
        else {
            log Mkconf message "You overwrote a config file that contained the following. Use this to recreate the file if you stuffed up:`r`n$([IO.file]::ReadAllText($confloc))"
        }
    }

    $defaultConfig | Out-File -Encoding ascii $confloc -ErrorAction Stop
    log Mkconf message "Generated config file: $confloc"
    exit 0
}

# Check we're dealing with an actual file
if ( -not (Test-Path $File) ) {
    log params error "$File does not exist. Exiting script"
    exit -1
}

log timing trace "[Start] Loading function definitions"
#########################################################################
# Function definitions

# This is a dupe of the same function in the JobFunctions Scriptblock
function eval-config-string ([string] $str) {
    log evlcfs trace "config string |$str| is getting eval'd"
    # Check if we actually need to do this?
    if ($str -notmatch "\{\d\}") {
        log evlcfs trace "Config string did not contain any eval-able components"
        return $str
    }

    # Lets make an array filled with the possible substitions. This is what will need to be updated for future versions
    $arrayOfFills = @($(get-date).ToString())

    $matches = [regex]::Matches($str, "\{\d\}")
    $out = $str
    foreach ($m in $matches.groups.value) {
        log evlcfs debug "Replacing $m with $($arrayOfFills[([int][string]$m[1])])"
        $out = $out -replace [regex]::Escape($m), $arrayOfFills[([int][string]$m[1])]
    }

    log evlcfs trace "Eval'd to: $out"
    return $out
}

# This is also a dupe of the function in the JobFunctions Scriptblock :( I can't figure out how to join the 2
function Get-PathTail ([string] $d1, [string] $d2) {
    if ($d1 -eq $d2) {return split-Path -Leaf $d1}
    #codemagicthing
    [String]::Join('', $($d2[$($d1.length)..$($d2.length - 1)], $d1[$($d2.length)..$($d1.length - 1)])[$d1 -gt $d2])
}

function output-keylist ($finalKeyList, $listOfSanitisedFiles, [switch]$quicksave) {
    log timing trace "[START] Saving Keylist to disk"
    $kf = join-path $PWD "KeyList.txt"
    # We have Keys?
    if ( $finalKeyList.Keys.Count -ne 0) {
        # Do we need to put them somewhere else?
        if ( $AlternateKeyListOutput ) {
            Set-Location $PWD # Should maybe not use PWD here todo
            New-Item -Force "$AlternateKeyListOutput" | Out-Null
            $kf = $( Get-Item "$AlternateKeyListOutput" ).FullName
        }
        
        if (!$quicksave) {log outkey message "`r`nExporting KeyList to $kf"}
        $KeyOutfile = (eval-config-string $script:config.KeyListFirstline) + "`r`n" + $( $finalKeyList.GetEnumerator() | sort -Property name | Out-String )
        $KeyOutfile += "List of files using this Key:`n$( $listOfSanitisedFiles | Out-String)"
        $KeyOutfile | Out-File -Encoding ascii $kf -Force
    }
    else {
        log outkey Warning "No Keys were found to show or output. There will be no key file"
    }
    log timing trace "[END] Saving Keylist to disk"
}

# This should be run before the script is closed
function Clean-Up {
    PARAM ([Switch] $NoExit = $false)

    log timing trace "[START] Script Cleanup"
    # output-keylist # This should no longer be needed.
    if ($NoExit) {log clnup debug "Cleanup function run with -NoExit arg. Will not exit after running"}

    ## Cleanup
    log clnup Debug "Returning preferences to original state"
    $VerbosePreference = $oldVerbosityPref
    $DebugPreference = $oldDebugPref
    $InformationPreference = $oldInfoPref

    log clnup debug "Return shell to original position"
    Set-Location $PWD

    log clnup trace "Destroying logging Mutex"
    $mtx.Dispose()
    
    log timing trace "[END] Script Cleanup"
    if (!$NoExit) {
        exit 0
    }
}

## Process Config file 
function proc-config-file ( $cf ) {
    log timing trace "[START] Processing of Config File"
    $stages = @('Switches', 'Config', 'Rules')
    $validLineKey = @('IgnoredStrings', 'SanitisedFileFirstLine', 'KeyListFirstLine', 'KeyFilename', 'AlternateKeyListOutput', 'AlternateOutputFolder')
    $stage = 0; $lineNum = 0

    $config = @{flags = @()}

    $lines = $cf -split "`r?`n"
    ForEach ( $line in $lines ) {
        $lineNum++
        # Do some checks about the line we're on
        if ( $line -match "^\s*;" ) {
            log prccnf trace "skipped comment: $line"
            continue
        }
        elseif ($line -eq '') {
            log prccnf trace "skipped empty line: $linenum"
            continue
        }

        # Check if this is a header
        if ( $line -match "^\s*\[ [\w\s]* \].*$" ) {
            # is it a valid header structure?
            $matches = [regex]::Matches($line, "^\s*\[ ([\w\s]*) \].*$")
            if ($matches.groups -and $matches.groups.length -gt 1) {} else {
                log prccnf trace "We found the '[]' for a header but something went wrong"
                log prccnf error "CONFIG: Error with Header on line $lineNum`: $line"
                exit -1
            }
            $headerVal = $matches.groups[1].value
            # bump the stage if we found a valid header
            if ( $stages[$stage + 1] -eq $headerVal ) {
                log prccnf trace "Moving to $($stages[$stage+1]) due to line $linenum`: $line"
                $stage++
            }
            elseif ( $stages -notcontains $headerVal ) {
                log prccnf trace "Tried to move to stage '$headval' at the wrong time on line $linenum`: $line"
                log prccnf error "Valid head '$headerval' in the wrong position on line $linenum`: $line"
                exit -1
            }
            else {
                log prccnf trace "Tried to move to unknown stage '$headval' on line $linenum`: $line"
                log prccnf error "Invalid header '$headerval' on line $linenum`: $line"
                exit -1
            }
            continue # if we're still here move to the next line
        }

        # Check if this is a valid config line
        if ( $line -match "^.*=.*$" ) {
            $matches = [regex]::Matches($line, "^(.*?)=(.*)$")
            if ( $matches.groups -and $matches.groups.length -ne 3 ) {
                log prccnf trace "Invalid config line. not enough values"
                log prccnf error "Invalid config line. Incorrect format/grouping on line $linenum`: $line"
                exit -1
            }
            $lineKey = $matches.groups[1].value
            $lineValue = $matches.groups[2].value
            # If we're not reading rules and we don't recognise the key, show a warning
            if ( $stages[$stage] -eq "Config" -and $validLineKey -notcontains $lineKey ) {
                log prccnf trace "We did not recognise the key '$lineKey' we won't exit but will generate a warning"
                log prccnf warning "Unrecognised config setting. '$lineKey' on line $linenum`: $line"
            }
        }
        else {
            # if we didn't match the above then we're broke so quit
            log prccnf trace "Could not parse line $linenum as a ini config line. Creating an error"
            log prccnf error "Unable to parse config on line $linenum`: $line"
            exit -1
        }

        # Action lines based on stage
        switch ( $stages[$stage] ) { 
            'Switches' {
                # \\todo this is super dodge and needs more validation :( please improve
                # Use a switch for easy adding if there's more
                switch ( $lineKey ) {
                    'MaxThreads' {
                        if ($lineValue -match "\d*") {
                            $config.MaxThreads = [convert]::ToInt32($lineValue, 10)
                        }
                        else {
                            log prccnf trace "MaxThreads value was not a valid numeric form. Will show a warning and continue with default"
                            log prccnf warning "Maxthreads value was not a valid number. Contining with default value: $script:MaxThreads"
                        }
                    }
                    'Silent' {$Config.Silent = $lineValue -eq "true"}
                    'Recurse' {$Config.Recurse = $lineValue -eq "true"}
                    'InPlace' {$Config.InPlace = $lineValue -eq "true"}
                    Default {
                        log prccnf warning "Unknown configuration setting '$lineKey' found on line $linenum`: $line"
                    }
                }
            }
            'Config' {
                # Binary Option
                if ($lineValue -eq "true" -or $lineValue -eq "false") {
                    $config[$lineKey] = $lineValue -match "true"

                    # Array option
                }
                elseif ( $line -match "^.*=(.*)(,.*)*$" ) {
                    $config[$lineKey] = ($lineValue[1..($lineValue.length - 2)] -join '') -split "`",\s*`"" -replace '\\"','"'

                    # String option
                }
                elseif ($lineValue[0] -eq '"' -and $lineValue[-1] -eq '"') {
                    $Config[$lineKey] = $lineValue[1..($lineValue.length - 2)] -join ''
                    log prccnf trace "Line $linenum stored: Setting: $lineKey, Value: $lineValue"
                }
                else {
                    log prccnf warning "Unrecognised config format on line $linenum`: $line. It Does not seem to be a string, bool or array and so will be ignored"
                }
            }
            'Rules' {
                # Need to validate keys and the like
                if ( $line -match '^".*"=".*"$' ) {
                    # re-find the key/value incase there are '=' in the key
                    $matches = [regex]::Matches($line, '^"(.*?)"="(.*)"$')
                    $lineKey = $matches.groups[1].value
                    $lineValue = $matches.groups[2].value

                    # Add the rule to the flags array
                    $config.flags += [System.Tuple]::Create($lineKey, $lineValue)
                }
                elseif ($line -match '^".*"=\\delete\s*$') {
                    $flagtoremoveentirely = $([regex]::Matches($line, '^"(.*?)"=\\delete$')).groups[1].value
                    if ($config.killerflag) {
                        $config.killerflag += "|$flagtoremoveentirely"
                    }
                    else {
                        $config.killerflag = "$flagtoremoveentirely"
                    }
                }
                else {
                    log prccnf warning "Invalid Rule found on line $linenum. It doesn't appear to be wrapped with '`"' and will not be processed.
                    Found as Key: |$lineKey| & Value: |$lineValue|"
                }
            }
            Default {
                log prccnf error "Something went wrong on line $($lineNum): $line"
                exit -1
            }
        }
    }

    log prccnf trace "config is here`n$($config | Out-String)`n`n"
    # todo log all keys here. Debugging is difficult if we can't see everything.
    # $config.origin = $ConfigFile # store where the config is from
    log timing trace "[END] Processing of Config File"
    return $config
}

# Process a KeyFile... This doen't really work at the moment. :S
function proc-keyfile ( [string] $kf ) {
    log timing trace "[START] Processing KeyFile"

    log prckyf warning "Sanitising files based on a pre-made keyfile is not currently supported. Many apologies if this affects a workflow"
    $importedKeylist = @{}
    $kfLines = [IO.file]::ReadAllLines($kf)

    # Find length of keylist
    $startOfFileList = $kfLines.IndexOf("List of files using this Key:") + 1
    $endOfKeyList = $startOfFileList - 4

    if ( $startOfFileList -eq 0 ) {
        log prckyf error "Invalid format for KeyFile ($KeyFile)`nCan't find list of output files"
        log timing trace "[END] Processing KeyFile"
        exit -1
    }

    $dataLines = $kfLines[4..$endOfKeyList]
    foreach ($d in $dataLines) {
        $d = $d -replace '\s+', ' ' -split "\s"
        if ( $d.Length -ne 3) {
            log prckyf error "Invalid format for KeyFile ($KeyFile)`nKey and Value lines are invalid"
            log timing trace "[END] Processing KeyFile"
            exit -1
        }

        log prckyf trace "Found Key: $($d[0]) & Value: $($d[1])"
        $k = $d[0]; $v = $d[1]

        if ( $k -eq "" -or $v -eq "") {
            log prckyf error "Invalid format for KeyFile ($KeyFile)`nKeys and Values cannot be empty"
            log timing trace "[END] Processing KeyFile"
            exit -1
        }

        $importedKeylist[$k] = $v
    }

    foreach ($d in $kfLines[$startOfFileList..$( $kfLines.Length - 2 )]) {
        $script:listOfSanitisedFiles += $d;
    }

    log timing trace "[END] Processing KeyFile"

    $importedKeylist = @{} # see function head for comment about this not super working
    return $importedKeylist
}

function Get-FileEncoding {
    # This function is only included here to preserve this as a single file.
    # Original Source: http://blog.vertigion.com/post/110022387292/powershell-get-fileencoding
    [CmdletBinding()]
    param (
        [Alias("PSPath")]
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]$Path,

        [Parameter(Mandatory = $False)]
        [System.Text.Encoding]$DefaultEncoding = [System.Text.Encoding]::ASCII
    )
    process {
        [Byte[]]$bom = Get-Content -Encoding Byte -ReadCount 4 -TotalCount 4 -Path $Path
        $encoding_found = $false
        foreach ($encoding in [System.Text.Encoding]::GetEncodings().GetEncoding()) {
            $preamble = $encoding.GetPreamble()
            if ($preamble -and $bom) {
                foreach ($i in 0..$preamble.Length) {
                    if ($preamble[$i] -ne $bom[$i]) {
                        break
                    }
                    elseif ($i -eq $preable.Length) {
                        $encoding_found = $encoding
                    }
                }
            }
        }
        if (!$encoding_found) {
            $encoding_found = $DefaultEncoding
        }
        $encoding_found
    }
}

function Get-MimeType() {
    # This function is only included here to preserve this as a single file.
    # From https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Function-to-6429566c#content
    param([parameter(Mandatory = $true, ValueFromPipeline = $true)][ValidateNotNullorEmpty()][System.IO.FileInfo]$CheckFile) 
    begin { 
        Add-Type -AssemblyName "System.Web"         
        [System.IO.FileInfo]$check_file = $CheckFile 
        [string]$mime_type = $null 
    } 
    process { 
        if (test-path $check_file) {  
            $mime_type = [System.Web.MimeMapping]::GetMimeMapping($check_file.FullName)  
        }
        else { 
            $mime_type = "false" 
        } 
    } 
    end { return $mime_type } 
}

# Group all the functions that we'll need to run in Jobs as a scriptblock
$JobFunctions = {
    # Enum to show what type of log it should be
    Enum LEnumJ {
        Trace
        Warning
        Debug
        Error
    }

    # mtx used to share logging file
    $mtx = [System.Threading.Mutex]::OpenExisting("LoggerMutex")

    function shuffle-logs ($MaxSize, $LogFile = $script:logfile, $MaxFiles = $script:LogHistory) {
        if (!(Test-Path $LogFile)) {
            return # if the log file doesn't exist then we don't need to do anything
        }
        elseif ((Get-Item $logfile).Length -le $MaxSize) {
            return # the log file is still too small
        }
    
        # Get the name of the file
        $n = ((Split-Path -Leaf -Resolve $logFile) -split '\.')[-2]
    
        # Find all the files that fit that name
        $logfiles = Get-ChildItem (split-path $LogFile) -Filter "$n.*log"
        
        # When moving files make sure nothing else is accessing them. This is a bit of overkill but could be necessary.
        if ($mtx.WaitOne(500)) {
    
            # Shuffle the file numbers up
            ($MaxFiles - 1)..1 | ForEach-Object {
                move-item "$n.$_.log" "$n.$($_+1).log" -Force -ErrorAction SilentlyContinue
            }
            $timestamp = Get-Date -format "yy-MM-dd HH:mm:ss.fff"
            $logMessage = ("LOG SHUFFLE " + $timestamp + "   Continued in next log file")
            $logMessage | Out-File -FilePath $LogFile -Force -Append
            move-item $logFile "$n.1.log" 
        
            # Start a new file
            new-item -ItemType file -Path $LogFile | Out-Null;
    
            [void]$mtx.ReleaseMutex()
        }
    }

    # Copy of $Script:Log function
    function log {
        [CmdletBinding()]
        PARAM (
            [Parameter (Mandatory)][String] $Stage,
            [Parameter (Mandatory)][LEnumJ] $Type = [LEnumJ]::Trace,
            [Parameter (Mandatory)][String] $String,
            [System.ConsoleColor] $Colour,
            [String] $Logfile = $script:logfile
        )

        # Return instantly if we're not logging
        if (!$script:log) {return}
        # Return instantly if this is a debug message and we're not showing debug
        if ($type -eq [LenumJ]::Debug -and !$script:showDebug) {return}

        shuffle-logs $script:MaxLogFileSize $Logfile

        # Deal with the colour
        switch ($Type) {
            "Debug" {  
                $1 = 'D'
                break
            }
            "Error" {  
                $1 = 'E'
                $Colour = ($null, $Colour, 'RED' -ne $null)[0]
                $String = "ERROR: $string"
                break
            }
            "Warning" {  
                $1 = 'W'
                $Colour = ($null, $Colour, 'YELLOW' -ne $null)[0]
                $String = "Warning: $string"
                break
            }
            Default {
                # Trace enums are default. 
                $1 = 'T'
            }
        }

        $stageSection = $(0..5 | % {$s = ''} {$s += @(' ', $Stage[$_])[[bool]$Stage[$_]]} {$s})
        $timestamp = Get-Date -format "yy-MM-dd HH:mm:ss.fff"
        $logMessage = ($1 + " " + $stageSection.toUpper() + " " + $timestamp + "   [JOB_$($script:JobId)]  " + $String)
        if ($mtx.WaitOne()) {
            $logMessage | Out-File -Filepath $logfile -Append
            [void]$mtx.ReleaseMutex()
        } 
        # consider doing something here like: 
        # if waiting x ms then continue but build a buffer. Check each time the buffer is added to until a max is reached and wait to add that
    }

    function log-job-start () {
        log jobenv trace "Job '$Script:JobName' started with Id: $Script:JobId"
        log jobenv trace "Logging enabled:          $($script:log)"
        log jobenv trace "Showing Debug messages:   $($script:showDebug)"
        log jobenv trace "Logfile:                  $($script:logfile)"
        log jobenv trace "Max log file size:        $($script:MaxLogFileSize)"
        log jobenv trace "Number of Historical Logs:$($script:LogHistory)"
    }

    function eval-config-string ([string] $str) {
        log evlcfs trace "config string |$str| is getting eval'd"
        # Check if we actually need to do this?
        if ($str -notmatch "\{\d\}") {
            log evlcfs trace "Config string did not contain any eval-able components"
            return $str
        }
    
        # Lets make an array filled with the possible substitions. This is what will need to be updated for future versions
        $arrayOfFills = @($(get-date).ToString())
    
        $matches = [regex]::Matches($str, "\{\d\}")
        $out = $str
        foreach ($m in $matches.groups.value) {
            log evlcfs debug "Replacing $m with $($arrayOfFills[([int][string]$m[1])])"
            $out = $out -replace [regex]::Escape($m), $arrayOfFills[([int][string]$m[1])]
        }
    
        log evlcfs trace "Eval'd to: $out"
        return $out
    }

    function Get-PathTail ([string] $d1, [string] $d2) {
        if ($d1 -eq $d2) {return split-Path -Leaf $d1}
        #codemagicthing
        [String]::Join('', $($d2[$($d1.length)..$($d2.length - 1)], $d1[$($d2.length)..$($d1.length - 1)])[$d1 -gt $d2])
    }

    function Save-File ( [string] $file, [string] $content, [string] $rootFolder, [string] $OutputFolder, [bool] $inPlace ) {
        log timing trace "[START] Saving sanitised file to disk"
        $filenameOUT = ''
        if ( -not $InPlace ) {
            # Create output file's name
            $name = Split-Path $file -Leaf -Resolve
            $filenameParts = $name -split '\.'
            $sanitisedName = $filenameParts[0..$( $filenameParts.Length - 2 )] -join '.'
            $sanitisedName += '.sanitised.' + $filenameParts[ $( $filenameParts.Length - 1 ) ]
            if ($rootFolder) {
                log svfile trace "Sanitising a folder, foldername is $rootFolder"
                $locality = Get-PathTail $(Split-Path $file) $rootFolder
                log svfile trace "File is $locality from the root folder"
                $filenameOUT = Join-Path $OutputFolder $locality 
                $filenameOUT = Join-Path $filenameOUT $sanitisedName
            }
            else {
                $filenameOUT = Join-Path $OutputFolder $sanitisedName
            }
        }
        else {
            log svfile trace "Overwriting original file at $file"
            $filenameOUT = $file
        }
    
        # Create the file if it doesn't already exist
        if (!(test-path $filenameOUT)) {
            New-Item -Force $filenameOUT | Out-Null
        }
        $content | Out-File -force -Encoding ascii $filenameOUT
        log svfile trace "Written out to $filenameOUT"
        
        log timing trace "[END] Saving sanitised file to disk"
        # Return name of sanitised file for use by the keylist
        return "$( $(Get-Date).toString() ) - $filenameOUT"
    }
    
    ## Sanitises a file and stores sanitised data in a key
    function Sanitise ( [string] $SanitisedFileFirstLine, $finalKeyList, [string] $content, [string] $filename) {
        log Snitis trace "Sanitising file: $filename"

        # Process file for items found using tokens in descending order of length. 
        # This will prevent smaller things ruining the text that longer keys would have replaced and leaving half sanitised tokens
        $count = 0
        foreach ( $key in $( $finalKeyList.GetEnumerator() | Sort-Object { $_.Value.Length } -Descending )) {
            log Snitis debug "   Substituting $($key.value) -> $($key.key)"
            Write-Progress -Activity "Sanitising $filename" -Status "Removing $($key.value)" -Completed -PercentComplete (($count++ / $finalKeyList.count) * 100)
            
            # Do multiple replaces with different types of the string to catch weird/annoying cases
            $content = $content.Replace($key.value, $key.key)
            $content = $content.Replace($key.value.toString().toUpper(), $key.key)
            $content = $content.Replace($key.value.toString().toLower(), $key.key)
        }
        Write-Progress -Activity "Sanitising $filename" -Completed -PercentComplete 100
    
        # Add first line to show sanitation //todo this doesn't really work :/
        $header = eval-config-string $SanitisedFileFirstLine
        $content = $header + $content
        return $content
    }
    
    ## Build the key table for all the files
    function Find-Keys ( [string] $fp, $flags, [System.Collections.Generic.HashSet[String]]$IgnoredStringsSet, [String] $killerFlags ) {
        log timing trace "[START] Finding Keys from $fp"

        # dictionary to populate with <key><kind> values
        $Keys = New-Object 'System.Collections.Generic.Dictionary[String,String]'

        # Remove entire lines that we don't want.
        if ($killerFlags) {
            log fndkys trace "Filtering out lines that match $killerFlags"
            $f = [IO.file]::ReadAllLines( $fp ) -notmatch $killerFlags -join "`r`n"
        }
        else {
            $f = [IO.file]::ReadAllLines( $fp ) -join "`r`n"
        }

        # Process file for tokens
        $count = 1
        foreach ( $token in $flags ) {
            Write-Progress -Activity "Scouting $fp" -Status "$($token.Item1)" -Completed -PercentComplete (($count++ / $flags.count) * 100)
            $pattern = $token.Item1
            $kind = $token.Item2
            log fndkys trace "Using '$pattern' to find matches"
            $matches = [regex]::matches($f, $pattern) #, [System.Text.RegularExpressions.RegexOptions]::Multiline)
            log fndkys trace "Finished using '$pattern' to find matches"

            # Grab the value for each match, if it doesn't have a key make one
            foreach ( $m in $matches ) {
                $mval = $m.groups[1].value
                log fndkys debug "Matched: $mval"
    
                # Do we have a key already?
                if ( $Keys.containsKey( $mval ) ) {
                    log fndkys debug "Recognised as: $($keys[$mval]) - $mval"
                
                } # Check the match against the list of ignored strings
                elseif ( $IgnoredStringsSet.contains( $mval ) ) {
                    log fndkys trace "Found ignored string: $mval"
    
                } # Save the key and it's associated kind
                else { 
                    $Keys.add($mval, $kind)
                    log fndkys trace "Made new key entry: $($keys[$mval]) - $mval"
                }
            }
        }
        # Set the bar to full for manage-job
        Write-Progress -Activity "Scouting $fp" -Completed -PercentComplete 100
    
        log fndkys trace "Keys: ${$keys | Format-Table}"
        log timing trace "[END] Finding Keys from $fp"
        return $keys
    }
}

# Takes a file and outputs it's the keys
function Scout-Stripper ($files, $flags, [string] $rootFolder, [String] $killerFlags, [int] $PCompleteStart, [int] $PCompleteEnd) {
    log timing trace "[START] Scouting file(s) with rules"
    $q = New-Object System.Collections.Queue

    ForEach ($file in $files) {
        $name = "Finding Keys in $(Get-PathTail $rootFolder $file)"
        $ScriptBlock = {
            PARAM($file, $flags, $IgnoredStringsSet, $killerFlags, $_env)
            $script:log, $script:showDebug, $script:logfile, $script:MaxLogFileSize, $script:LogHistory, $Script:JobName, $Script:JobId = $_env
            log-job-start

            Find-Keys $file $flags $IgnoredStringsSet $killerFlags
            log SctStr trace "Found all the keys in $file"
        }
        $ArgumentList = $file, $flags, $script:Config.IgnoredStringsSet, $killerFlags, $_env
        $q.Enqueue($($name, $JobFunctions, $ScriptBlock, $ArgumentList))
    }
    Manage-Job $q $MaxThreads $PCompleteStart $PCompleteEnd
    log SctStr trace "Key finding jobs are finished"

    # Collect the output from each of the jobs
    $jobs = Get-Job -State Completed
    $keylists = @()
    ForEach ($job in $jobs) {
        $kl = Receive-Job -Keep -Job $job
        $keylists += $kl
    }
    log SctStr debug "retrieved the following from completed jobs:`n$($keylists | Out-String)"
    
    # Clean up the jobs
    Get-Job | Remove-Job | Out-Null
    log SctStr trace "cleaned up scouting jobs"

    log timing trace "[END] Scouting file(s) with rules"
    return $keylists
}

function Sanitising-Stripper ( $finalKeyList, $files, [string] $OutputFolder, [string] $rootFolder, [String] $killerFlags, [bool] $inPlace, [int] $PCompleteStart, [int] $PCompleteEnd) {
    log timing trace "[START] Sanitising File(s)"
    $q = New-Object System.Collections.Queue

    # used to resolve https://github.com/cavejay/Strippy/issues/39
    # if the switch flagged then nothing will come through
    if ($script:noHeaderInOutput) {
        $script:config.SanitisedFileFirstLine = ''
    }

    # Sanitise each of the files with the final keylist and output them with Save-file
    ForEach ($file in $files) {
        $name = "Sanitising $(Get-PathTail $file $rootFolder)"
        $ScriptBlock = {
            PARAM($file, $finalKeyList, $firstline, $OutputFolder, $rootFolder, $killerFlags, $inPlace, $_env)
            $script:log, $script:showDebug, $script:logfile, $script:MaxLogFileSize, $script:LogHistory, $script:JobName, $script:JobId = $_env

            log-job-start

            if ($killerFlags) {
                log SanStr trace "Filtering out lines that match $killerFlags"
                $content = [IO.file]::ReadAllLines($file) -notmatch $killerFlags -join "`r`n"
            }
            else {
                $content = [IO.file]::ReadAllLines($file) -join "`r`n"
            }
            log SanStr trace "Loaded in content of $file"

            $sanitisedOutput = Sanitise $firstline $finalKeyList $content $file
            log SanStr trace "Sanitised content of $file"

            $exportedFileName = Save-File $file $sanitisedOutput $rootFolder $OutputFolder $inPlace
            log SanStr trace "Exported $file to $exportedFileName"

            $exportedFileName
        }
        $ArgumentList = $file, $finalKeyList, $script:Config.SanitisedFileFirstline, $OutputFolder, $(@($null, $rootFolder)[$files.Count -gt 1]), $killerFlags, $inPlace, $_env
        $q.Enqueue($($name, $JobFunctions, $ScriptBlock, $ArgumentList))
    }
    Manage-Job $q $MaxThreads $PCompleteStart $PCompleteEnd
    log SanStr trace "Sanitising jobs are finished. Files should be exported"

    # Collect the names of all the sanitised files
    $jobs = Get-Job -State Completed
    $sanitisedFilenames = @()
    ForEach ($job in $jobs) {
        $fn = Receive-Job -Keep -Job $job
        $sanitisedFilenames += $fn
    }
    log SanStr trace "Sanitised file names are:`n$sanitisedFilenames"

    # Clean up the jobs
    Get-Job | Remove-Job | Out-Null
    
    log timing trace "[END] Sanitising File(s)"
    return $sanitisedFilenames
}

function Merging-Stripper ([Array] $keylists, [int] $PCompleteStart, [int] $PCompleteEnd) {
    log timing trace "[START] Merging Keylists"

    # # If we only proc'd one file then return that
    # if ($keylists.Count -eq 1) {
    #     log mrgStr trace "Shortcutting for one file"
    #     log timing trace "[END] Merging Keylists"
    #     return $keylists[0]
    # }
    
    $keys = New-Object 'System.Collections.Generic.Dictionary[String,String]'
    $totalKeys = $keylists | ForEach-Object { $result = 0 } { $result += $_.Count } { $result }
    $keyIndex = 0
    
    # add everything to the set
    $keylistIndex = 0
    ForEach ($keylist in $keylists) {
        ForEach ($Key in $keylist.Keys) {
            Write-Progress -Activity "Gathering Keys" -PercentComplete (($keyIndex++ / $totalKeys) * 100) -ParentId $_tp
            
            # adding key to set will error on second add, so check first.
            if (!$keys.containsKey($key)) {
                $keys.add($key, $keylist[$key])
            }
        }
        $perc = (++$keylistIndex) / ($keylists.count)
        log mrgStr trace "Done $($perc*100)% of keylists"
        Write-Progress -Activity "Sanitising" -Id $_tp -PercentComplete $($perc * (($PCompleteEnd - $PCompleteStart) / 2) + $PCompleteStart)
    }
    Write-Progress -Activity "Gathering Keys" -PercentComplete 100 -ParentId $_tp -Completed

    $output = @{}
    $nameCounts = @{}
    $keyIndex = 0
    foreach ($key in $keys.Keys) {
        $possiblename = ''; $count = 0
        # log gnkynm debug $token.Item2
        log mrgStr debug "'$($keys.$key)' - '$key'"
        if ( !$nameCounts.ContainsKey($keys.$key) ) {
            # If we've not heard of this key before, make it
            $nameCounts[$keys.$key] = 0
        }
        
        $nameCounts[$keys.$key]++ # increment our count for this key 
        $newname = "$( $keys.$key )$( $nameCounts[$keys.$key] )"
        
        $output.$newname = $key

        # show progress
        $perc = (++$keyIndex) / ($keys.Keys.count)
        log mrgStr debug "Generated $($perc*100)% of key labels"
        Write-Progress -Activity "Generating Key labels" -PercentComplete (($keyIndex / $keys.Keys.count) * 100) -ParentId $_tp
        Write-Progress -Activity "Sanitising" -Id $_tp -PercentComplete $($perc * (($PCompleteEnd - $PCompleteStart) / 2) + $PCompleteStart + ($PCompleteEnd - $PCompleteStart) / 2)

    }
    Write-Progress -Activity "Generating Key labels" -PercentComplete 100 -ParentId $_tp -Completed

    log timing trace "[END] Merging Keylists"
    return $output
}

function Manage-Job ([System.Collections.Queue] $jobQ, [int] $MaxJobs, [int] $ProgressStart, [int] $ProgressEnd) {
    log timing trace "[START] Managing Job Execution"
    log manjob trace "Clearing all background jobs (again just in case)"
    Get-Job | Stop-Job
    Get-job | Remove-Job

    $totalJobs = $jobQ.count
    $ProgressInterval = ($ProgressEnd - $ProgressStart) / $totalJobs
    # While there are still jobs to deploy or there are jobs still running
    While ($jobQ.Count -gt 0 -or $(get-job -State "Running").count -gt 0) {
        $JobsRunning = $(Get-Job -State 'Running').count

        # For each job started and each child of those jobs
        ForEach ($Job in Get-Job) {
            ForEach ($Child in $Job.ChildJobs) {
                ## Get the latest progress object of the job
                $Progress = $Child.Progress[$Child.Progress.Count - 1]
                
                ## If there is a progress object returned write progress
                If ($Progress.Activity -ne $Null) {
                    Write-Progress -Activity $Job.Name -Status $Progress.StatusDescription -PercentComplete $Progress.PercentComplete -ID $Job.ID -ParentId $_tp
                    log manjob trace "Job '$($job.name)' is at $($Progress.PercentComplete)%"
                }
                
                ## If this child is complete then stop writing progress
                If ($Progress.PercentComplete -eq 100 -or $Progress.PercentComplete -eq -1) {
                    log manjob trace "Job '$($Job.name)' has finished"

                    #Update total progress
                    $perc = $ProgressStart + $ProgressInterval * ($totalJobs - $jobQ.count)
                    Write-Progress -Activity "Sanitising" -Id $_tp -PercentComplete $perc

                    Write-Progress -Activity $Job.Name -Status $Progress.StatusDescription  -PercentComplete $Progress.PercentComplete -ID $Job.ID -ParentId $_tp -Complete
                    ## Clear all progress entries so we don't process it again
                    $Child.Progress.Clear()
                }
            }
        }
        
        if ($JobsRunning -lt $MaxJobs -and $jobQ.Count -gt 0) {
            $NumJobstoRun = @(($MaxJobs - $JobsRunning), $jobQ.Count)[$jobQ.Count -lt ($MaxJobs - $JobsRunning)]
            log manjob trace "We've completed some jobs, we need to start $NumJobstoRun more"
            1..$NumJobstoRun | ForEach-Object {
                log manjob trace "iteration: $_ of $NumJobstoRun"
                if ($jobQ.Count -eq 0) {
                    log manjob trace "There are 0 jobs left. Skipping the loop"
                    return
                }
                $j = $jobQ.Dequeue()
                # Provide some context to the job's environment variable
                $JobDateId = "{0:x}" -f [int64]([datetime]::UtcNow - (get-date "1/1/1970")).TotalMilliseconds
                # Provide the name of the job and then the 'jobid' (which is just the date in hex and then shortened)
                $j[3][-1] += $j[0]; $j[3][-1] += ([char[]]$JobDateId[-6..-1] -join '')
                Start-Job -Name $j[0] -InitializationScript $j[1] -ScriptBlock $j[2] -ArgumentList $j[3] | Out-Null
                log manjob trace "Started Job named '$($j[0])'. There are $($jobQ.Count) jobs remaining"
            }
        }

        ## Setting for loop processing speed
        Start-Sleep -Milliseconds 500
    }

    # Ensure all progress bars are cleared
    ForEach ($Job in Get-Job) {
        Write-Progress -Activity $Job.Name -ID $Job.ID -ParentId $_tp -Complete
    }
    log timing trace "[END] Managing Job Execution"
}

function Head-Stripper ([array] $files, [String] $rootFolder, [String] $OutputFolder, $importedKeys) {
    log timing trace "[START] Sanitisation Manager"
    # There shouldn't be any other background jobs, but kill them anyway.
    Write-Progress -Activity "Sanitising" -Id $_tp -Status "Clearing background jobs" -PercentComplete 0
    log hdStrp debug "Current jobs running are: $(get-job *)"
    Get-Job | Stop-Job
    Get-job | Remove-Job
    log hdStrp debug "removed all background jobs"

    log hdStrp trace "Making a set from the list of ignored keys"
    $script:config.IgnoredStringsSet = New-Object System.Collections.Generic.HashSet[String]
    foreach ($s in $script:config.IgnoredStrings) {
        $script:config.IgnoredStringsSet.add($s) | Out-Null
    }
    log hdStrp trace "Finished making a set from the list of ignored keys"

    Write-Progress -Activity "Sanitising" -Id $_tp -Status "Discovering Keys" -PercentComplete 1
    # Use Scout stripper to start looking for the keys in each file
    log hdStrp message "Searching through input file(s) for sensitive data"
    $keylists = Scout-Stripper $files $script:Config.flags $rootFolder $script:Config.killerflag 1 35
    log hdStrp message "Finshed collecting sensitive data from file(s)"
    log hdStrp trace "finished finding keys"

    log tmp message ($keylists | out-string) -colour magenta
    
    Write-Progress -Activity "Sanitising" -Id $_tp -Status "Merging Keylists" -PercentComplete 35
    # Add potentially imported keys to the list of keys
    if ($importedKeys) { [array]$keylists += $importedKeys }

    # Merge all of the keylists into a single dictionary.
    log hdStrp message "Merging key lists to create a master version"
    $finalKeyList = Merging-Stripper $keylists 35 60
    log hdStrp trace "Finished merging keylists"

    # Export a keylist now incase we can't or don't later.
    log hdStrp trace "Exporting Partial keylist"
    output-keylist $finalKeyList $files -quicksave
    log hdStrp trace "Exported Partial Keylist"

    Write-Progress -Activity "Sanitising" -Id $_tp -Status "Sanitising separate files" -PercentComplete 60
    # Sanitise the files
    log hdStrp message "Sanitising file(s) with master keylist"
    $sanitisedFilenames = Sanitising-Stripper $finalKeyList $files $OutputFolder $rootFolder $script:Config.killerflag $InPlace 60 99
    log hdStrp trace "Finished sanitising and exporting files"

    log timing trace "[END] Sanitisation Manager"
    return $finalKeyList, $sanitisedFilenames
}

log timing trace "[End] Loading function definitions"

####################################################################################################
# Start Actual Execution

# Handle config loading
log timing trace "[Start] Config Checking/Loading"
$configUsed = $false
if ( $script:ConfigFile ) {
    log cfgchk trace "Attempting to load the provided config file: $Script:ConfigFile"
    try {
        $tmp = Get-Item $ConfigFile
        $configText = [IO.file]::ReadAllText($tmp.FullName)
        log cfgchk debug "Successfully loaded the data from $($tmp.FullName)"
    }
    catch {
        log cfgchk error "Could not load from Specified config file: $Config`r`nExiting Script"
        exit -1
    }
    log cfgchk trace "Processing specified Config file"
    $script:Config = proc-config-file $configText
    log cfgchk trace "Finished Processing Config file. Skipping further config checks"
    $configUsed = $true
}

# if there was not a config successfully loaded in the last step then check around the script directory for a 'default file'
if (!$configUsed) {
    log cfgchk warning "Config file was not successfully loaded or there was no config file provided."
    log cfgchk warning "Checking script's directory ($PSScriptRoot) for valid config file"
    $configText = ''
    try {
        $tmp_f = join-path $( $PSScriptRoot ) "strippy.conf"
        log cfgchk trace "Attempting to read data from $tmp_f"
        $configText = [IO.file]::ReadAllText($tmp_f)
        log cfgchk debug "Successfully loaded the data from $tmp_f"
    }
    catch {
        log cfgchk trace "Caught Exception with message: $($_.Exception.Message)"
        log cfgchk warning "Could not find or read $(join-path $PSScriptRoot "strippy.conf"). User will need to be prompted"
    }

    if ($configText) {
        log cfgchk trace "Found local default config file to use, attempting to import it's settings"
        $Script:Config = proc-config-file $configText
        log cfgchk trace "Finished Processing Config file. Skipping further config checks"
        $configUsed = $true
        log cfgchk message "Successfully found a script-local config file" -colour Green
    }
}

# If we still don't have a config then we need user input
if (!$configUsed) {
    log cfgchk trace "Failed to find config file at script's location. Will need to ask user for input"
    # If we were running silent mode then we should end specific error code There
    if ( $Silent ) {
        log cfgchk trace "Script is in Silent mode. Unable to prompt user and so will error and exit"
        log cfgchk error "Unable to locate config file. Please specify location using -ConfigFile flag or ensure strippy.conf exists in $(get-location)"
        throw "No config file"
    }

    log cfgchk question "Unable to find a strippy.conf file. This file contains the rules that are used to determine sensitive data.
    Continuing now will use the default configuration and only sanitise IP addresses and Windows UNC paths.
    Would you like to continue with only these?"
    $ans = Read-Host "y/n> (y) "
    log cfgchk trace "User answered with: '$ans'"
    if ( $ans -eq 'n' ) {
        # todo refactor makeconfig functionality into a function and call from here with additional question
        log cfgchk message "Use the -MakeConfig argument to create a strippy.conf file and start adding sensitive data rules. Script will now exit"
        exit
    }
    else {
        # Use default flags mentioned in the thingy
        log cfgchk trace "User has chosen to use the default flags to sanitise the file(s)"
        $script:config.flags = $defaultFlags
    }
}
log timing trace "[End] Config Checking/Loading"

# // todo this could/should be a function
log timing trace "[Start] KeyList Checking/Loading"
$importedKeys = $null
if ( $KeyFile ) {
    # Check the keyfile is legit before we start.
    log keychk trace "User provided key file. Checking it's legitimacy"
    if ( Test-Path $KeyFile ) {
        $kf = Get-Item $KeyFile
        log keychk trace "Key File exists and is: '$kf'"
    }
    else {
        log keychk error "$KeyFile could not be found. Test-Path failed to find '$Keyfile'"
        exit -1
    }

    if ( $kf.Mode -eq 'd-----' ) {
        log keychk error "$KeyFile cannot be a directory"
        log keychk trace "KeyFile had a mode of $($kf.Mode)"
        exit -1
    }
    elseif ( $kf.Extension -ne '.txt') {
        log keychk error "$KeyFile must be a .txt"
        log keychk trace "Key file had an extension of '$( $kf.Extension )'"
        exit -1
    }
    # Assume it's a valid format for now and check in the proc-keyfile function

    log keychk message "Importing Keys from $KeyFile"
    $importedKeys = proc-keyfile $kf.FullName # we need the fullname to load the file in
    log keychk message "Finished Importing Keys from keyfile:"
    if ($Silent) {
        $importedKeys
        log keychk trace "Contents of Imported Keylist: `r`n$importKeys"
    }
}
else {
    log keychk trace "There was no keylist provided by config or user"
}
log timing trace "[End] KeyList Checking/Loading"

log strppy message "Attempting to Santise $File"
$File = $(Get-Item $File).FullName
log strppy debug "Resolved input file/folder to $File"

log timing trace "[Start] Input/Output Discovery Process"
## Build the list of files to work on
$filesToProcess = @()
$OutputFolder = $File | Split-Path # Default output folder for a file is its parent dir
log ioproc trace "Default output folder is: $OutputFolder"

# is it a directory?
$isDir = Test-Path -LiteralPath $file -PathType Container
if ( $isDir ) {
    log ioproc trace "$File is a folder"

    # Get all the files
    if ($Recurse) {
        log ioproc trace "Recursive mode means we get all the files"
        $files = Get-ChildItem $File -Recurse -File
        log ioproc debug "$($files.Length) Files Found: `"$($files -join ', ')`""
    }
    else {
        log ioproc trace "Normal mode means we only get the files at the top directory"
        log ioproc debug "$($files.Length) Files Found: `"$($files -join ', ')`""
        $files = Get-ChildItem $File -File
    }

    # Filter out files that have been marked as sanitised or look suspiscious based on the get-filencoding or get-mimetype functions
    log ioproc trace "Filter out files that aren't sanitisable"
    $files = $files | Where-Object {
        $val = ( @('us-ascii', 'utf-8') -contains ( Get-FileEncoding $_.FullName ).BodyName ) -and -not
        ( $(Get-MimeType -CheckFile $_.FullName) -match "image") -and -not
        ( $_.name -like '*.sanitised.*')

        if (!$val) {
            log ioproc trace "$($_.FullName) will not be sanitised"
        }
        $val
    } | ForEach-Object {$_.FullName}
    log ioproc debug "$($files.Length) Files left after filtering: `"$($files -join ', ')`""

    # If we didn't find any files clean up and exit
    log ioproc trace "Checking number of files after filtering"
    if ( $files.Length -eq 0 ) {
        log ioproc trace "0 files left after filtering. Script will now exit"
        log ioproc error "Could not find any appropriate files to sanitise in $File"
        Clean-Up
    }

    # Declare which files we'd like to process
    $filesToProcess = $files

    # Calc the output folder
    $f = join-path $(Get-Item $File).Parent.FullName "$($(Get-Item $File).Name).sanitised"
    if ($AlternateOutputFolder) {} else {
        New-Item -ItemType directory -Path $f -Force | Out-Null
        $OutputFolder = $(Get-Item "$f").FullName
    } # Make the new dir

    # Support Paths with wildcards at somepoint
}
elseif ( $File -contains '*' ) {
    # Resolve the wildcard used in the thingy.
    # Check that there's actually files.
    # Check that they fit normal file criteria?
    # We process them where they are
    log ioproc trace "User attempted to use a wild-card path rather than a literal one. This is currently unsupported."
    log ioproc error "Paths with wildcards are not yet supported"
    Clean-Up

    # We also want to support archives by treating them as folders we just have to unpack first
}
elseif ( $( get-item $File ).Extension -eq '.zip') {
    log ioproc trace "User attempted to sanitise a .zip file. This will hopefully be supported in the future. Just unpack it for now."
    log ioproc error "Archives are not yet supported"
    # unpack
    # run something similar to the folder code above
    # add files that we want to process to $filestoprocess
    # set a flag or similar to handle the repacking of the files into a .zip

    # It's not a folder, so go for it
}
else {
    log ioproc trace "$File is a file. Adding only it to the list of files to process"
    
    # Add the file to process to the list
    $filesToProcess += $(get-item $File).FullName
}

# Redirect the output folder if necessary
if ($AlternateOutputFolder) {
    log ioproc trace "User has specified an alternate output folder: '$AlternateOutputFolder'. This will need to be made."
    try {
        New-Item -ItemType directory -Path $AlternateOutputFolder -Force -ErrorAction stop | Out-Null # Make the new dir
    }
    catch {
        log ioproc error "Failed to create the alternate output folder: '$AlternateOutputFolder'. Error was $($_.Exception.Message)"
        log ioproc error "Script will need to exit now"
        Clean-Up
    }
    log ioproc trace "Made alternate output folder."
    $OutputFolder = $(Get-item $AlternateOutputFolder).FullName
    log ioproc message "Using Alternate Folder for output: $OutputFolder"
}
log timing trace "[End] Input/Output Discovery Process"

# give the head stripper all the information we've just gathered about the task
log timing trace "[Start] File Processing/Sanitising"
$finalKeyList, $listOfSanitisedFiles = Head-Stripper $filesToProcess $File $OutputFolder $importedKeys
log timing trace "[End] File Processing/Sanitising"

log timing trace "[Start] Wrap up"
Write-Progress -Activity "Sanitising" -Id $_tp -Status "Outputting Keylist" -PercentComplete 99
# Found the Keys, lets output the keylist
output-keylist $finalKeyList $listOfSanitisedFiles

log strppy message "`n==========================================================================`nProcessed Keys:"
log strppy message "$($finalKeyList | sort -Property value | Out-String)"

Write-Progress -Activity "Sanitising" -Id $_tp -Status "Finished" -PercentComplete 100
Start-Sleep 1
Write-Progress -Activity "Sanitising" -Id $_tp -Completed

$_delta = (New-timespan -start $_startTime -end $(get-date)).totalSeconds
log timing message "Script completed in $_delta seconds"

Clean-Up -NoExit
log timing trace "[End] Wrap up"

