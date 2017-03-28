<#
.SYNOPSIS
    Tool for sanitising log files based on configured "indicators"

.DESCRIPTION
    Use this tool to automate the replacement of sensitive data in text files with generic strings.
    While intended for use with log files this tool will work with text filesa as a whole.

    In order to use this tool effectively you will need to be proficient with regex. 
    Regex is used to filter out sensitive pieces of data from log files and replace it with a place holder.

    To start creating your own sensitive data indicators you will need to use a config file that can be generated by using the -MakeConfig flag.
    Add regex strings to it, ensuring that the part of the string you want to replace is the first group in the regex. 
    That group will then be replaced with a generic string of your choice.
    An example for IP addresses is included in the generated config file.

    Make use of the tool by reading the examples from: get-help .\strippy.ps1 -examples
    
    If you haven't alerady then you'll need to change your execution policy to run this tool. 
    You can do this temporarily by using the following:
        powershell [-noexit] -executionpolicy Unrestricted -File .\strippy.ps1 <args>
    Or permanently by opening Powershell and running the following:
        Set-ExecutionPolicy Unrestricted https://ss64.com/ps/set-executionpolicy.html

    # Todo
    # Get logs from support site
    # write up doco for examples
    # Publish to dxs wiki
    # allow more than just .log and .txt files. think xml and the like as well.
    # Support .zips as well.
    # folder structure replication for folders
    # Recursive folder support
    # Have a blacklist of regexs. 
    # seriously consider using xml instead of json. 
    # Dealing with selections of files a la "server.*.log" or similar
    write tests. lol

.EXAMPLE
    # todo 
    C:\PS> 
    todo
    <Description of example>

.NOTES
    Author: Michael Ball
    Version: 170308
    Compatability: Powershell 3+

.LINK
    https://github.com/cavejay/Strippy
#>

# Logs we cover: 
#   CAS

[CmdletBinding()]
param (
    # The File or Folder you wish to sanitise
    [string] $File, 
     # The tool will run silently, without printing to the terminal and exit with an error if it needed user input
    [switch] $Silent,
    # Looks for log files throughout a directory tree rather than only in the first level
    [Switch] $Recusive = $false, 
    # Destructively sanitises the file. There is no warning for this switch. If you use it, it's happened.
    [switch] $InPlace, 
    # Creates a barebones strippyConfig.json file for the user to fill edit
    [switch] $MakeConfig, 
    # A shortcut for -AlternateKeyListOutput
    [string] $keyout, 
    # Specifies an alternate name and path for the keylist file
    [string] $AlternateKeyListOutput = $keyout,
    # A shortcut for -AlternateOutputFolder 
    [String] $out, 
    # Specifies an alternate path or file for the sanitised file
    [String] $AlternateOutputFolder = $out, 
    # Specifies a previously generated keylist file to import keys from for this sanitisation
    [String] $KeyFile, 
    # Specifies a config file to use rather than the default local file or no file at all.
    [String] $Config
)

# Special Variables: (Not overwritten by config files)
# If this script is self contained then all config is specified in the script itself and config files are not necessary or requested for. 
# This cuts down the amount of files necessary to move between computers and makes it easier to give to someone and say "run this"
$SelfContained = $false

## Variables: (Over written by any config file)
$IgnoredStrings = @('/0:0:0:0:0:0:0:0','0.0.0.0','127.0.0.1','name','applications')
$SanitisedFileFirstline = "This file was Sanitised at $( $(Get-Date).toString() ).`n==`n`n"
$KeyListFirstline = "This keylist was created at $( $(Get-Date).toString() ).`n"

######################################################################
# Important Pre-script things like usage, setup and commands that change the flow of the tool

# General config 
$PWD = Get-Location

# The list of keys we find
$key = @{}

# List to export with Keys
$listOfSanitisedFiles = @()

# Flags
# usernames, hostnames, ip addresses ## DSN is different!
$flags = New-Object System.Collections.ArrayList
$defaultFlags = New-Object System.Collections.ArrayList
$defaultFlags.AddRange(@(
    [System.Tuple]::Create("[^\d_:](\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)[^\d]", 'Address'),
    [System.Tuple]::Create("\\\\([\w\-.]*?)\\", "Hostname")

        # Format: (regex, Label to Replace)
        # 'db users' JDBC_USER: <user>
    ))

# Output Settings
$oldInfoPref = $InformationPreference
if ($Silent) { $InformationPreference = "ContinueSilently" } else { $InformationPreference = "Continue" }

if ( $Verbose -and -not $Silent) {
    $oldVerbosityPref = $VerbosePreference
    $VerbosePreference = "Continue"
    $DebugPreference = "Continue"
}

# Check if we're _just_ creating a default config file
if ( $MakeConfig ) {
    $confloc = "$( Get-Location )\strippyConfig.json"
    $defaultConfig = '{
    "_Comment": "These are the defaults. You should alter them. Please go do",
    "_version": 0.1,
    "UseMe": %useme%,
    "IgnoredStrings": [%ignoredstrings%],
    "SanitisedFileFirstLine": "%logfirstline%",
    "KeyListFirstline": "%keyfirstline%",

    "KeyFile": "",
    "indicators": [
        %indicators%
    ]
}
'
    if ( $SelfContained ) {
        Write-Verbose "In single file mode. Exporting most of the config from file"
        # In here we export all the variables we've set above and such.
        $defaultConfig = $defaultConfig -replace '%useme%', "false"
        $defaultConfig = $defaultConfig -replace '%ignoredstrings%', "`"$($IgnoredStrings -join '", "')`""
        $defaultConfig = $defaultConfig -replace '%logfirstline%', ""
        $defaultConfig = $defaultConfig -replace '%keyfirstline%', ""
        $t_ = $flags | Foreach-Object {"[`"$($_.Item1)`", `"$($_.Item2)`"]"}
        $defaultConfig = $defaultConfig -replace '%indicators%', $($t_ -join ', ')
    }

    # Fill areas of the default config
    $defaultConfig = $defaultConfig -replace '%useme%', "true"
    $defaultConfig = $defaultConfig -replace '%ignoredstrings%', "`"/0:0:0:0:0:0:0:0`", `"0.0.0.0`", `"127.0.0.1`", `"name`", `"applications`""
    $defaultConfig = $defaultConfig -replace '%logfirstline%', "This file was Sanitised at %date%``n==``n``n"
    $defaultConfig = $defaultConfig -replace '%keyfirstline%', "This keylist was created at %date%.``n"
    $defaultConfig = $defaultConfig -replace '%indicators%', "[`"Some Regex String here`", `"Replacement here`"], 
    [`"((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))[^\d]`", `"Address`"]"

    # Check to make sure we're not overwriting someone's config file
    if ( Test-Path $( $confloc ) ) {
        Write-Information "A config file already exists. Would you like to overwrite it with the default?"
        $ans = Read-Host "y/n> (n) "
        if ( $ans -ne 'y' ) {
            Write-Information "Didn't overwrite the current config file"
            exit 0
        } else {
            Write-Information "You overwrote a config file that contained the following. Use this to recreate the file if you stuffed up:"
            Write-Information "$([IO.file]::ReadAllText($confloc))"
        }
    }

    $defaultConfig | Out-File -Encoding ascii $confloc
    Write-Information "Generated config file: $confloc"
    exit 0
}

# Usage
if ( $File -eq "" ) {
    Get-Help "$( Get-Location )\$( $MyInvocation.MyCommand.Name )"
    exit 0
}

# Check we're dealing with an actual file
if ( -not (Test-Path $File) ) {
    Write-Error "$File does not exist"
    exit -1
}

#######################################################################################33
# Function definitions

# This should be run before the script is closed
function Clean-Up () {
    $kf = "$PWD\KeyList.txt"
    
    # We have Keys?
    if ( $key.Keys.Count -ne 0) {
        # Do we need to put them somewhere else?
        if ( $AlternateKeyListOutput ) {
            Set-Location $PWD
            New-Item -Force "$AlternateKeyListOutput" | Out-Null
            $kf = $( Get-Item "$AlternateKeyListOutput" ).FullName
        }

        Write-Information "`nExporting KeyList to $kf"
        $KeyOutfile = $KeyListFirstline + $( $key | Out-String )
        $KeyOutfile += "List of files using this Key:`n$( $listOfSanitisedFiles | Out-String)"
        $KeyOutfile | Out-File -Encoding ascii $kf
    }

    ## Cleanup
    $VerbosePreference = $oldVerbosityPref
    $InformationPreference = $oldInfoPref
    Set-Location $PWD
    exit
}

# Print only when not printing verbose comments
function write-when-normal {
    [cmdletbinding()]
    param([Switch] $NoNewline, [String] $str)

    if ($VerbosePreference -ne "Continue" -and -not $Silent) {
        if ($NoNewline) {
            Write-Host -NoNewline $str
        } else {
            Write-Host $str
        }
    } 
}

## Process Config file 
function proc-config-file ( $cf ) {
    Write-Verbose "Added '\'s where necessary"
    # add another backslash whereever necessary
    $cf = $cf -replace '\\', '\\'

    Write-Verbose "Swapping out date aliases"
    $cf = $cf -replace '%date%', $( $(Get-Date).ToString() )

    Write-Verbose "Attemping JSON -> PSObject transform"
    # turn into PS object
    try {
        $c = ConvertFrom-Json $cf -ErrorAction Stop
    } catch {
        Write-Error "Config file error:`n$_"
        exit 0
    }

    Write-Verbose "Applying Config to script"
    # Split up and assign all the pieces to their variables
    $KeyListFirstline = $c.KeyListFirstLine
    $KeyFile = $c.KeyFile
    $SanitisedFileFirstline = $c.SanitisedFileFirstline
    $IgnoredStrings = $c.IgnoredStrings
    foreach ($indicator in $c.indicators) {
        $flags.Add(
            [System.Tuple]::Create($indicator[0], $indicator[1])
        ) | Out-Null
    }
}

## Process a KeyFile
function proc-keyfile ( $kf ) {
    $kfLines = [IO.file]::ReadAllLines($kf)

    # Find length of keylist
    $startOfFileList = $kfLines.IndexOf("List of files using this Key:")+1
    $endOfKeyList = $startOfFileList - 4

    if ( $startOfFileList -eq 0 ) {
        write-when-normal '' 
        Write-Error "Invalid format for KeyFile ($KeyFile)`nCan't find list of output files"
        exit -1
    }

    $dataLines = $kfLines[4..$endOfKeyList]
    foreach ($d in $dataLines) {
        $d = $d -replace '\s+', ' ' -split "\s"
        if ( $d.Length -ne 3) {
            write-when-normal '' 
            Write-Error "Invalid format for KeyFile ($KeyFile)`nKey and Value lines are invalid"
            exit -1
        }

        write-when-normal -NoNewline '.'
        Write-Verbose "Found Key: $($d[0]) & Value: $($d[1])"
        $k = $d[0]; $v = $d[1]

        if ( $k -eq "" -or $v -eq "") {
            write-when-normal '' 
            Write-Error "Invalid format for KeyFile ($KeyFile)`nKeys and Values cannot be empty"
            exit -1
        }

        $key[$k] = $v
    }
    write-when-normal '.'

    foreach ($d in $kfLines[$startOfFileList..$( $kfLines.Length - 2 )]) {
        $script:listOfSanitisedFiles += $d;
    }
}

# Generates a keyname without doubles
$nameCounts = @{}
function Gen-Key-Name ( $token ) {
    $possiblename = ''
    do {
        Write-Debug $token.Item2
        if ( -not $nameCounts.ContainsKey($token.Item2) ) {
            $nameCounts[$token.Item2] = 0
        }

        $nameCounts[$token.Item2]++
        $possiblename = "$( $token.Item2 )$( $nameCounts[$token.Item2] )"
        Write-Verbose "PossibleName is $possiblename does it exist? :: '$( $key[$possiblename] )'"
    } while ( $key[$possiblename] -ne $null )
    return $possiblename
}

## Sanitises a file and stores sanitised data in a key
function Sanitise ( [string] $content, [string] $filenameIN, [string] $filenameOUT) {
    # Process file for items found using tokens
    Write-Information "Sanitising file: $filenameIN"
    foreach ( $k in $( $key.GetEnumerator() | Sort-Object { $_.Value.Length } -Descending )) {
        Write-Debug "   Substituting $($k.value) -> $($k.key)"
        write-when-normal -NoNewline '.'
        $content = $content -replace $k.value, $k.key
    }
    write-when-normal ''

    # Add first line to show sanitation
    $content = $SanitisedFileFirstline + $content

    if ( -not $InPlace ) {
        # Create output file's name
        $filenameParts = $filenameOUT -split '\.'
        $filenameOUT = $filenameParts[0..$( $filenameParts.Length-2 )] -join '.' 
        $filenameOUT += '.sanitised.' + $filenameParts[ $( $filenameParts.Length-1 ) ]
    }

    # Add file to $listOfSanitisedFiles
    $Script:listOfSanitisedFiles += "$( $(Get-Date).toString() ) - $filenameOUT";

    # Save file as .santised.extension
    if (test-path $filenameOUT) {} else {
        New-Item -Force $filenameOUT | Out-Null
    }
    $content | Out-File -force -Encoding ASCII $filenameOUT
}

## Build the key table for all the files
function Find-Keys ( [string] $fp ) {
    Write-Verbose "Finding Keys in $fp"

    # Open file
    $f = [IO.file]::ReadAllText( $fp )
    
    # Process file for tokens
    foreach ( $token in $flags ) {
        $pattern = $token.Item1
        Write-Verbose "Using '$pattern' to find matches"
        $matches = [regex]::matches($f, $pattern)
        
        # Grab the value for each match, if it doesn't have a key make one
        $c1 = $c2 = 0; $o = ' '; $t = $c = '.'
        foreach ( $m in $matches ) {
            # Pretty print for normal output
            $c1++
            if ($c1 % 10 -eq 0) {
                $c2++
                write-when-normal -NoNewline $t
                if ($c2 % 40*5 -eq 0) {
                    if ($t -eq $o) {$t = $c} else {$t = $o}
                    write-when-normal -NoNewline "`r$t"
                }
            }

            $mval = $m.groups[1].value
            Write-Verbose "Matched: $mval"

            # Do we have a key already?
            if ( $key.ContainsValue( $mval ) ) {
                $k =  $key.GetEnumerator() | Where-Object { $_.Value -eq $mval }
                Write-Verbose "Recognised as: $($k.key)"
            
            # Check the $IgnoredStrings list
            } elseif ( $IgnoredStrings.Contains($mval) ) {
                Write-Verbose "Found ignored string: $mval"

            # Create a key and assign it to the match
            } else { 
                Write-Verbose "Found new token! $( $mval )"
                $newkey = gen-key-name $token
                $key[$newkey] = $mval
                Write-Verbose "Made new alias: $newkey"
                Write-Information "`rMade new key entry: $( $mval ) -> $newkey"
            }
        }
    }
    if (-not $Silent) {Write-Host "`r"}
    # //todo intelligently build out keylist further using similar patterns? 
    return $f
}



####################################################################################################
# Start Actual Execution

# Handle config loading
$configUsed = $false
if ( $Config ) {
    try {
        $tmp = Get-Item $Config
        $configText = [IO.file]::ReadAllText($tmp.FullName)
    } catch {
        Write-Error "Error: Could not load from Specified config file: $Config"
        exit -1
    }
    Write-Verbose "Processing specified Config file"
    proc-config-file $configText
    $configUsed = $true
    Write-Verbose "Finished Processing Config file"
}

# If we didn't get told what config to use check locally for a 'UseMe' config file
if (-not $configUsed -and -not $SelfContained) {
    try {
        $tmp_f = "$( Get-location )\strippyConfig.json"
        $configText = [IO.file]::ReadAllText($tmp_f)
        $tmp_r = $true

        # Check it has the UseMe field set to true before continuing
        if ( $tmp_r -and $configText -match '"UseMe"\s*?:\s*?true\s*?,') { # should probs test this
            Write-Verbose "Found local default config file to use, importing it's settings"
            proc-config-file $configText
            $configUsed = $true
        } else {
            Write-Verbose "Ignored local config file due to false or missing UseMe value."
        }

    } catch {
        write-verbose "Could not find a local config file"
    }

}

# If we still don't have a config then we need user input
if (-not $configUsed -and -not $SelfContained) {
    # If we were running silent mode then we should end specific error code There
    if ( $Silent ) {
        Write-Error "Unable to find config file"
        exit -9
    }

    $ans = Read-Host "Unable to find Config file to extend the list of indicators used to find sensitive data.
Continuing now will only sanitise IP addresses and Windows UNC paths
Would you like to continue with only these? 
y/n> (y) "
    if ( $ans -eq 'n' ) {
        Write-Information "Use the -MakeConfig argument to create a strippyConfig.json file and start added indicators"
        exit 0;
    } else {
        # Use default flags mentioned in the thingy
        $script:flags = $defaultFlags
    }
}

if ( $KeyFile ) {
    # Check the keyfile is legit before we start.
    Write-Verbose "Checking the KeyFile"
    if ( Test-Path $KeyFile ) {
        $kf = Get-Item $KeyFile
        write-verbose "Key File exists and is: '$kf'"
    } else {
        Write-Error "Error: $KeyFile could not be found"
        exit -1
    }

    if ( $kf.Mode -eq 'd-----' ) {
        Write-Error "Error: $KeyFile cannot be a directory"
        Write-Verbose $kf.Mode
        exit -1
    } elseif ( $kf.Extension -ne '.txt') {
        Write-Error "Error: $KeyFile must be a .txt"
        Write-Verbose "Key file was a '$( $kf.Extension )'"
        exit -1
    }
    # Assume it's a valid format for now and check in the proc-keyfile function

    Write-Information "Importing Keys from $KeyFile"
    proc-keyfile $kf.FullName # we need the fullname to load the file in
    Write-Information "Finished Importing Keys from keyfile:"
    if (-not $Silent) {$key}
}

Write-Verbose "Attempting to Santise $File."
$File = $(Get-Item $File).FullName

## Detect files
# is it a directory?
$isDir = $( get-item $File ).Mode -eq 'd-----'
if ( $isDir ) {
    Write-Verbose "$File is a folder"

    # Get all the files
    if ($Recusive) {
        $files = Get-ChildItem $File -Recurse -File
    } else {
        $files = Get-ChildItem $File
    }

    # Filter for only the .txt and .log files and the absolute directory of each file
    $files = $files | Where-Object { 
        ( $_.Extension -eq '.txt' -or $_.Extension -eq '.log' ) -and -not
        ( $_.name -like '*.sanitised.*')
    } | ForEach-Object {$_.FullName}

    # Check if there's anything there to proc'
    if ( $files.Length -eq 0 ) {
        Write-Verbose "There were no files to Sanitise in $File"
        Clean-Up
    }

    # Build key list
    foreach ( $f in $files ) {
        $pre = $key.count
        Write-Information "Gathering Keys from $f"
        Find-Keys $f | Out-Null
        Write-Verbose "Got $($key.count - $pre) keys from $f"
    }

    # Create and set output folders if needed
    $OutputFolder = ''
    if ($AlternateOutputFolder) {
        md $AlternateOutputFolder -Force | Out-Null # Make the new dir        
        $OutputFolder = $(Get-item $AlternateOutputFolder).FullName
        Write-Information "Using Alternate Folder for output: $OutputFolder"
    } else {
        Write-Information "Made output folder: $File.sanitised\"
        $File = $File[0..$($File.length-2)] -join ""
        mkdir "$File.sanitised" -Force | Out-Null
        $OutputFolder = $(Get-Item "$File.sanitised").FullName
    }

    # Sanitise using key list
    foreach ($f in $files ) {
        $relativePath = ($f -split ($File -replace '\\','\\'))[1]
        $FilenameOUT = "$OutputFolder$relativePath"

        Sanitise $([IO.file]::ReadAllText( $f )) $f $filenameOUT
    }

# We also want to support archives by treating them as folders we just have to unpack first
} elseif ( $( get-item $File ).Extension -eq '.zip') {
    Write-Information "Archives are not supported yet"

# It's not a folder, so go for it
} else {
    Write-Verbose "$File is a file"
    Write-Information "Gathering Keys from $File"
    $file_content = Find-Keys $(get-item $File).FullName

    Sanitise $file_content $File $(Get-Item $File).FullName
}

Write-Information "`n==========================================================================`nProcessed Keys:"
if (-not $Silent) {$key}

Clean-Up