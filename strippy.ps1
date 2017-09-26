<#
.SYNOPSIS
    Tool for sanitising utf8 encoded files based on configured "indicators"

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
    
    If you haven't already then you'll need to change your execution policy to run this tool. 
    You can do this temporarily by using the following:
        powershell [-noexit] -executionpolicy Unrestricted -File .\strippy.ps1 <args>
    Or permanently by opening Powershell and running the following:
        Set-ExecutionPolicy Unrestricted https://ss64.com/ps/set-executionpolicy.html

.EXAMPLE
    C:\PS> .\strippy.ps1 .\logs

    This is the typical usecase and will sanitise only the files directly in .\logs using a default config file.
    Output files will be in the .\logs.sanitised folder and the keylist created for the logs will be found directory you the script.

.EXAMPLE
    C:\PS> .\strippy.ps1 .\logs\server.1.log

    In this case only one file has been specified for sanitisation. The output in this case would be to .\logs\server.1.sanitised.log file and a keylist file .\KeyList.txt

.EXAMPLE
    C:\PS> .\strippy.ps1 ..\otherlogs\servers\oldlog.log -KeyFile .\KeyList.txt

    This would process the oldlog.log file like any other file, but will load in the keys already found from a key list file. This means you can process files at different times but still have their keys matchup. Once done, this usecase will output a keylist that contains all the keys from KeyList.txt and any new keys found in the oldlog.log file.

.EXAMPLE
    C:\PS> .\strippy.ps1 .\logs -Recurse

    If you need to sanitise an entire file tree, then use the -Recurse flag to iterate through each file in a folder and it's subfolders.

.EXAMPLE
    C:\PS> .\strippy.ps1 "C:\Program Files\Dynatrace\CAS\Server\logs" -Recurse -Silent -out "C:\sanitised-$(get-date -UFormat %s)"

    This example shows how you might integrate strippy in an automation scheme. The -Silent flag stops output to stdout, preventing the need for a stdout redirect. The -out flag allows redirection of the sanitised files to a custom folder.

.NOTES
    Author: Michael Ball
    Version: 2.170926
    Compatability: Powershell 5+

.LINK
    https://github.com/cavejay/Strippy
#>

# Todo
# Dealing with selections of files a la "server.*.log" or similar
# Make -Silent print output to a file?
# Have option for diagnotics file or similar that shows how many times each rule was hit
# Print/Sanitising sometimes breaks?
# Publish to dxs wiki
# Support .zips as well.
# Have a blacklist of regexs.
# Switch used to create a single file strippy. ie, edit the script's code with the config rules etc.
# More intellient capitalisation resolution.
# Move from jobs to runspaces?
# Add support/warning for ps 4

<# Maintenance Todo list
    - Time global sanitise against running all the rules against each and every line in the files.    
    - use powershell options for directory and file edits
#>

[CmdletBinding()]
param (
    # A shortcut for -File
    [String] $f,
    # The File or Folder you wish to sanitise
    [String] $File = $f,
    # A shortcut for -Silent
    [Switch] $si = $false,
    # The tool will run silently, without printing to the terminal and exit with an error if it needed user input
    [Switch] $Silent = $si,
    # A shortcut for -Recurse
    [Switch] $r = $false,
    # Looks for log files throughout a directory tree rather than only in the first level
    [Switch] $Recurse = $r,
    # A shortcut for -InPlace
    [Switch] $i = $false,
    # Destructively sanitises the file. There is no warning for this switch. If you use it, it's happened.
    [Switch] $InPlace = $i,
    # Creates a barebones strippy.conf file for the user to fill edit
    [Switch] $MakeConfig, 
    # A shortcut for -AlternateKeylistOutput 
    [String] $ko,
    # Specifies an alternate name and path for the keylist file
    [String] $AlternateKeyListOutput = $ko,
    # A shortcut for -AlternateOutputFolder 
    [String] $o, 
    # Specifies an alternate path or file for the sanitised file
    [String] $AlternateOutputFolder = $o, 
    # A shortcut for -KeyFile
    [String] $k,
    # Specifies a previously generated keylist file to import keys from for this sanitisation
    [String] $KeyFile = $k, 
    # Archive the folder or file after sanitising it
    # [switch] $zip, 
    [String] $c,
    # Specifies a config file to use rather than the default local file or no file at all.
    [String] $ConfigFile = $c,
    # A shortcut for -MaxThreads
    [int] $m = 5,
    # How threaded can this process become?
    [int] $MaxThreads = $m
)

# Special Variables: (Not overwritten by config files)
# If this script is self contained then all config is specified in the script itself and config files are not necessary or requested for. 
# This cuts down the amount of files necessary to move between computers and makes it easier to give to someone and say "run this"
$SelfContained = $false

## Variables: (Over written by any config file)
$Config = @{"origin"="default"}
$Config.IgnoredStrings = @('/0:0:0:0:0:0:0:0','0.0.0.0','127.0.0.1','name','applications',"")
$Config.SanitisedFileFirstline = "This file was Sanitised at {0}.`n==`n`n"
$Config.KeyListFirstline = "This keylist was created at {0}.`n"
$Config.KeyFileName = "KeyList - $( $(Get-date).toString() ).txt"

######################################################################
# Important Pre-script things like usage, setup and commands that change the flow of the tool

# General config 
$PWD = Get-Location  # todo  - this should be replaced with the inbuilt thing that gets both where the script is and where it's being run

# Flags
$Config.flags = New-Object System.Collections.ArrayList
# Added to every list of flags to cover IPs and UNC's
$defaultFlags = New-Object System.Collections.ArrayList
$defaultFlags.AddRange(@(
    [System.Tuple]::Create("((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))[^\d]", 'Address'),
    [System.Tuple]::Create("\\\\([\w\-.]*?)\\", "Hostname")
))

# Output Settings
$oldInfoPref = $InformationPreference
if ($Silent) { $InformationPreference = "ContinueSilently" } else { $InformationPreference = "Continue" }

if ( $Verbose -and -not $Silent) {
    $oldVerbosityPref = $VerbosePreference
    $oldDebugPref = $DebugPreference
    $VerbosePreference = 'Continue'
    $DebugPreference = 'Continue'
}

# Usage
if ( $File -eq "" ) {
    Get-Help $(join-path $(Get-Location) $MyInvocation.MyCommand.Name)
    exit 0
}

# Check we're dealing with an actual file
if ( -not (Test-Path $File) ) {
    Write-Error "$File does not exist"
    exit -1
}

#######################################################################################33
# Function definitions

function output-keylist ($finalKeyList, $listOfSanitisedFiles) {
    . $JobFunctions # to gain access to eval-config-string
    $kf = join-path $PWD "KeyList.txt"
    
    # We have Keys?
    if ( $finalKeyList.Keys.Count -ne 0) {
        # Do we need to put them somewhere else?
        if ( $AlternateKeyListOutput ) {
            Set-Location $PWD
            New-Item -Force "$AlternateKeyListOutput" | Out-Null
            $kf = $( Get-Item "$AlternateKeyListOutput" ).FullName
        }

        Write-Information "`nExporting KeyList to $kf"
        $KeyOutfile = (eval-config-string $KeyListFirstline) + $( $finalKeyList | Out-String )
        $KeyOutfile += "List of files using this Key:`n$( $listOfSanitisedFiles | Out-String)"
        $KeyOutfile | Out-File -Encoding ascii $kf
    } else {
        Write-Information "No Keys were found to show or output. There will be no key file"
    }
}

# This should be run before the script is closed
function Clean-Up () {
    # output-keylist # This should no longer be needed.

    ## Cleanup
    $VerbosePreference = $oldVerbosityPref
    $DebugPreference = $oldDebugPref
    $InformationPreference = $oldInfoPref
    Set-Location $PWD
    exit 0
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
    $stages = @('UseMe', 'Config', 'Rules')
    $validLineKey = @('UseMe', 'IgnoredStrings', 'SanitisedFileFirstLine', 'KeyListFirstLine', 'KeyFilename')
    $stage = 0; $lineNum = 0

    $config = @{flags=@()}

    $lines = $cf -split "`r?`n"
    ForEach ( $line in $lines ) {
        $lineNum++

        # Do some checks about the line we're on
        if ( $line -match "^\s*;" ) {
            write-verbose "skipped comment: $line"
            continue
        } elseif ($line -eq '') {
            write-verbose "skipped empty line: $linenum"
            continue
        }

        # Check if this is a header
        if ( $line -match "^\s*\[ [\w\s]* \].*$" ) {
            # is it a valid header structure?
            $matches = [regex]::Matches($line, "^\s*\[ ([\w\s]*) \].*$")
            if ($matches.groups -and $matches.groups.length -gt 1) {} else {
                write-verbose "We found the '[]' for a header but something went wrong"
                write-error "CONFIG: Error with Header on line $lineNum`: $line"
                exit -1
            }
            $headerVal = $matches.groups[1].value
            # bump the stage if we found a valid header
            if ( $stages[$stage+1] -eq $headerVal ) {
                Write-Verbose "Moving to $($stages[$stage+1]) due to line $linenum`: $line"
                $stage++
            } elseif ( $stages -notcontains $headerVal ) {
                Write-Verbose "Tried to move to stage '$headval' at the wrong time on line $linenum`: $line"
                Write-Error "CONFIG: Valid head '$headerval' in the wrong position on line $linenum`: $line"
                exit -1
            } else {
                Write-Verbose "Tried to move to unknown stage '$headval' on line $linenum`: $line"
                Write-Error "CONFIG: Invalid header '$headerval' on line $linenum`: $line"
                exit -1
            }
            continue # if we're still here move to the next line
        }

        # Check if this is a valid config line
        if ( $line -match "^.*=.*$" ) {
            $matches = [regex]::Matches($line, "^(.*?)=(.*)$")
            if ( $matches.groups -and $matches.groups.length -ne 3 ) {
                Write-Verbose "Invalid config line. not enough values"
                Write-Error "CONFIG: Invalid config line. Incorrect format/grouping on line $linenum`: $line"
                exit -1
            }
            $lineKey = $matches.groups[1].value
            $lineValue = $matches.groups[2].value
            # If we're not reading rules and we don't recognise the key, show a warning
            if ( $stages[$stage] -ne "Rules" -and $validLineKey -notcontains $lineKey ) {
                Write-Verbose "We did not recognise the key '$lineKey' we won't exit but will generate a warning"
                Write-Warning "CONFIG: Unrecognised config setting. '$lineKey' on line $linenum`: $line"
            }
        }

        # Action lines based on stage
        switch ( $stages[$stage] ) {
            'UseMe' {
                # Use a switch for easy adding if there's more
                switch ( $lineKey ) {
                    'UseMe' {
                        $Config.UseMe = $lineValue -eq "true"
                    }
                    Default {
                        Write-Warning "Unknown configuration setting '$lineKey' found on line $linenum`: $line"
                    }
                }
            }
            'Config' {
                # Proc if its an array or bool
                $Config[$lineKey] = $lineValue
                Write-Verbose "Line $linenum stored: Setting: $lineKey, Value: $lineValue"
            }
            'Rules' {
                # Need to validate keys and the like
                if ( $line -match '^".*"=".*"$' ) {
                    # re-find the key/value incase there are '=' in the key
                    $matches = [regex]::Matches($line, '^"(.*?)"="(.*)"$')
                    $lineKey = $matches.groups[1].value
                    $lineValue = $matches.groups[2].value

                    # Add the rule to the flags array
                    $config.flags += [System.Tuple]::Create($lineKey,$lineValue)
                } else {
                    Write-Warning "Invalid Rule found on line $linenum. It doesn't appear to be wrapped with '`"' and will not be processed.
                    Found as Key: |$lineKey| & Value: |$lineValue|"
                }
            }
            Default {
                Write-Error "CONFIG: Something went wrong on line $($lineNum): $line"
                exit -1
            }
        }
    }

    Write-Verbose "config is here`n$($config | Out-String)`n`n"
    Write-host "Flags"
    $config.flags | % { Write-host "$($_.Item1)->$($_.Item2)" }
    $config.origin = $ConfigFile # store where the config is from
    return $config
}

# Process a KeyFile
function proc-keyfile ( [string] $kf ) {
    $importedKeylist = @{}
    $kfLines = [IO.file]::ReadAllLines($kf)

    # Find length of keylist
    $startOfFileList = $kfLines.IndexOf("List of files using this Key:")+1
    $endOfKeyList = $startOfFileList - 4

    if ( $startOfFileList -eq 0 ) {
        Write-Error "Invalid format for KeyFile ($KeyFile)`nCan't find list of output files"
        exit -1
    }

    $dataLines = $kfLines[4..$endOfKeyList]
    foreach ($d in $dataLines) {
        $d = $d -replace '\s+', ' ' -split "\s"
        if ( $d.Length -ne 3) {
            Write-Error "Invalid format for KeyFile ($KeyFile)`nKey and Value lines are invalid"
            exit -1
        }

        Write-Verbose "Found Key: $($d[0]) & Value: $($d[1])"
        $k = $d[0]; $v = $d[1]

        if ( $k -eq "" -or $v -eq "") {
            write-when-normal '' 
            Write-Error "Invalid format for KeyFile ($KeyFile)`nKeys and Values cannot be empty"
            exit -1
        }

        $importedKeylist[$k] = $v
    }

    foreach ($d in $kfLines[$startOfFileList..$( $kfLines.Length - 2 )]) {
        $script:listOfSanitisedFiles += $d;
    }

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
                    } elseif ($i -eq $preable.Length) {
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
    # From https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Function-to-6429566c#content
    param([parameter(Mandatory=$true, ValueFromPipeline=$true)][ValidateNotNullorEmpty()][System.IO.FileInfo]$CheckFile) 
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
    function eval-config-string ([string] $str) {
        $out = "$str"
        if (($str[0..4] -join '') -eq "eval:") {
            Write-Verbose "config string |$str| needs to be eval'd"
            $out = Invoke-Expression `"$(($str -split "eval:")[1] -f $(get-date).ToString())`"
            Write-Verbose "Eval'd to: $out"
        } else {
            Write-Verbose "Config string |$str| was not eval'd"
        }
        return $out
    }

    function Get-PathTail ([string] $d1, [string] $d2) {
        if ($d1 -eq $d2) {return split-Path -Leaf $d1}
        #codemagicthing
        [String]::Join('',$($d2[$($d1.length)..$($d2.length-1)],$d1[$($d2.length)..$($d1.length-1)])[$d1 -gt $d2])
    }

    # Generates a keyname without doubles
    $nameCounts = @{}
    function Gen-Key-Name ( $keys, $token ) {
        $possiblename = ''; $count = 0
        do {
            Write-Debug $token.Item2
            if ( -not $nameCounts.ContainsKey($token.Item2) ) {
                # If we've not heard of this key before, make it
                $nameCounts[$token.Item2] = 0
            }
    
            $nameCounts[$token.Item2]++ # increment our count for this key 
            $possiblename = "$( $token.Item2 )$( $nameCounts[$token.Item2] )"
        } while ( $keys[$possiblename] -ne $null )
        Write-Verbose "Had to loop $count times to find new name of '$possiblename'"
        return $possiblename
    }

    function Save-File ( [string] $file, [string] $content, [string] $rootFolder, [string] $OutputFolder, [bool] $inPlace ) { 
        $filenameOUT = ''
        if ( -not $InPlace ) {
            # Create output file's name
            $name = Split-Path $file -Leaf -Resolve
            $filenameParts = $name -split '\.'
            $sanitisedName = $filenameParts[0..$( $filenameParts.Length-2 )] -join '.'
            $sanitisedName += '.sanitised.' + $filenameParts[ $( $filenameParts.Length-1 ) ]
            if ($rootFolder) {
                Write-Verbose "Sanitising a folder, foldername is $rootFolder"
                $locality = Get-PathTail $(Split-Path $file) $rootFolder
                Write-Verbose "File is $locality from the root folder"
                $filenameOUT = Join-Path $OutputFolder $locality 
                $filenameOut = Join-Path $filenameOUT $sanitisedName
            } else {
                $filenameOUT = Join-Path $OutputFolder $sanitisedName
            }
        } else {
            Write-Verbose "Overwriting original file at $file"
            $filenameOUT = $file
        }
    
        # Save file as .santised.extension
        if (test-path $filenameOUT) {} else {
            New-Item -Force $filenameOUT | Out-Null
        }
        $content | Out-File -force -Encoding ascii $filenameOUT
        Write-Verbose "Written out to $filenameOUT"
        
        # Return name of sanitised file for use by the keylist
        return "$( $(Get-Date).toString() ) - $filenameOUT"
    }
    
    ## Sanitises a file and stores sanitised data in a key
    function Sanitise ( [string] $SanitisedFileFirstLine, $finalKeyList, [string] $content, [string] $filename) {
        Write-Verbose "Sanitising file: $filename"

        # Process file for items found using tokens in descending order of length. 
        # This will prevent smaller things ruining the text that longer keys would have replaced and leaving half sanitised tokens
        $count = 0
        foreach ( $key in $( $finalKeyList.GetEnumerator() | Sort-Object { $_.Value.Length } -Descending )) {
            Write-Debug "   Substituting $($key.value) -> $($key.key)"
            Write-Progress -Activity "Sanitising $filename" -Status "Removing $($key.value)" -Completed -PercentComplete (($count++/$finalKeyList.count)*100)
            $content = $content -replace [regex]::Escape($key.value), $key.key
        }
        Write-Progress -Activity "Sanitising $filename" -Completed -PercentComplete 100
    
        # Add first line to show sanitation //todo this doesn't really work :/
        $header = eval-config-string $SanitisedFileFirstLine
        $content = $header + $content
        return $content
    }
    
    ## Build the key table for all the files
    function Find-Keys ( [string] $fp, $flags, $IgnoredStrings ) {
        Write-Verbose "Finding Keys in $fp"
        # dictionary to populate
        $Keys = @{}
        # Open file
        $f = [IO.file]::ReadAllText( $fp )
        
        # Process file for tokens
        $count = 1
        foreach ( $token in $flags ) {
            Write-Progress -Activity "Scouting $fp" -Status "$($token.Item1)" -Completed -PercentComplete (($count++/$flags.count)*100)
            $pattern = $token.Item1
            Write-Verbose "Using '$pattern' to find matches"
            $matches = [regex]::matches($f, $pattern)
            
            # Grab the value for each match, if it doesn't have a key make one
            foreach ( $m in $matches ) {
                $mval = $m.groups[1].value
                Write-Verbose "Matched: $mval"
    
                # Do we have a key already?
                if ( $Keys.ContainsValue( $mval ) ) {
                    $k =  $Keys.GetEnumerator() | Where-Object { $_.Value -eq $mval }
                    Write-Verbose "Recognised as: $($k.key)"
                
                # Check the $IgnoredStrings list
                } elseif ( $IgnoredStrings.Contains($mval) ) {
                    Write-Verbose "Found ignored string: $mval"
    
                # Create a key and assign it to the match
                } else { 
                    Write-Verbose "Found new token! $( $mval )"
                    $newkey = gen-key-name $Keys $token
                    $Keys[$newkey] = $mval
                    Write-Verbose "Made new alias: $newkey"
                    Write-Verbose "Made new key entry: $( $mval ) -> $newkey"
                }
            }
        }
        # Set the bar to full for manage-job
        Write-Progress -Activity "Scouting $fp" -Completed -PercentComplete 100
    
        Write-Verbose "Keys: $keys"
        return $keys
    }
}

# Takes a file and outputs it's the keys
function Scout-Stripper ($files, $flags, $rootFolder) {
    Write-Verbose "Started scout stripper"
    $q = New-Object System.Collections.Queue
    . $JobFunctions # need for using Get-PathTail

    ForEach ($file in $files) {
        $name = "Finding Keys in $(Get-PathTail $rootFolder $file)"
        $ScriptBlock = {
            PARAM($file, $flags, $IgnoredStrings, $vPref)
            # $VerbosePreference = $vPref

            Find-Keys $file $flags $IgnoredStrings
            Write-Verbose "Found all the keys in $file"
        } 
        $ArgumentList = $file,$flags,$script:Config.IgnoredStrings,$VerbosePreference
        $q.Enqueue($($name,$JobFunctions,$ScriptBlock,$ArgumentList))
    }
    Manage-Job $q $MaxThreads 1 35
    Write-Verbose "Key finding jobs are finished"

    # Collect the output from each of the jobs
    $jobs = Get-Job -State Completed
    $keylists = @()
    ForEach ($job in $jobs) {
        $kl = Receive-Job -Keep -Job $job
        $keylists += $kl
    }
    Write-Debug "retrieved the following from completed jobs:`n$($keylists | Out-String)"
    
    # Clean up the jobs
    Get-Job | Remove-Job | Out-Null
    Write-Verbose "cleaned up scouting jobs"

    return $keylists
}

function Sanitising-Stripper ( $finalKeyList, $files, [string] $OutputFolder, [string] $rootFolder, [bool] $inPlace) {
    Write-Verbose "Started Sanitising Stripper"
    $q = New-Object System.Collections.Queue
    . $JobFunctions # need for using Get-PathTail

    # Sanitise each of the files with the final keylist and output them with Save-file
    ForEach ($file in $files) {
        $name = "Sanitising $(Get-PathTail $file $rootFolder)"
        $ScriptBlock = {
            PARAM($file, $finalKeyList, $firstline, $OutputFolder, $rootFolder, $inPlace, $vPref)
            # $VerbosePreference = $vPref
            # $DebugPreference = $vPref

            $content = [IO.file]::ReadAllText($file)
            Write-Verbose "Loaded in content of $file"

            $sanitisedOutput = Sanitise $firstline $finalKeyList $content $file
            Write-Verbose "Sanitised content of $file"

            $exportedFileName = Save-File $file $sanitisedOutput $rootFolder $OutputFolder $inPlace
            Write-Verbose "Exported $file to $exportedFileName"

            $exportedFileName
        }
        $ArgumentList = $file,$finalKeyList,$script:Config.SanitisedFileFirstline,$OutputFolder,$(@($null,$rootFolder)[$files.Count -gt 1]),$inPlace,$VerbosePreference
        $q.Enqueue($($name,$JobFunctions,$ScriptBlock,$ArgumentList))
    }
    Manage-Job $q $MaxThreads 60 99
    Write-Verbose "Sanitising jobs are finished. Files should be exported"

    # Collect the names of all the sanitised files
    $jobs = Get-Job -State Completed
    $sanitisedFilenames = @()
    ForEach ($job in $jobs) {
        $fn = Receive-Job -Keep -Job $job
        $sanitisedFilenames += $fn
    }
    Write-Verbose "Sanitised file names are:`n$sanitisedFilenames"

    # Clean up the jobs
    Get-Job | Remove-Job | Out-Null
    
    return $sanitisedFilenames
}

function Merging-Stripper ([Array] $keylists) {
    . $JobFunctions # Make the gen-key-name function available

    # If we only proc'd one file then return that
    if ($keylists.Count -eq 1) {
        Write-Verbose "Shortcutting for one file"
        return $keylists[0]
    }
    
    $output = @{}
    $totalKeys = $keylists | ForEach-Object { $result = 0 } { $result += $_.Count } { $result }
    $currentKey = 0
    ForEach ($keylist in $keylists) {
        ForEach ($Key in $keylist.Keys) {
            Write-Progress -Activity "Merging Keylists" -PercentComplete (($currentKey++/$totalKeys)*100) -ParentId 1

            # if new, merged keylist does not contain the key
            if ($output.values -notcontains $keylist.$Key) {
                # Generate a new name for the key and add it to the merged keylist (output)
                $newname = Gen-Key-Name $output $([System.Tuple]::Create("", $($key -split "\d*$")[0]))
                $output.$newname = $keylist.$key
            } else {
                Write-Verbose "Key $($keylist.$Key) already has name of $key"
            }
        }
        $perc = ($keylists.IndexOf($keylist)+1)/($keylists.count)
        write-verbose "Done $($perc*100)% of keylists"
        Write-Progress -Activity "Sanitising" -Id 1 -PercentComplete $($perc*(60-35)+35)
    }
    Write-Progress -Activity "Merging Keylists" -PercentComplete 100 -ParentId 1 -Completed

    return $output
}

function Manage-Job ([System.Collections.Queue] $jobQ, [int] $MaxJobs, [int] $ProgressStart, [int] $ProgressEnd) {
    Write-Verbose "Clearing all background jobs (again in-case)"
    Get-Job | Stop-Job
    Get-job | Remove-Job

    $totalJobs = $jobQ.count
    $ProgressInterval = ($ProgressEnd-$ProgressStart)/$totalJobs
    # While there are still jobs to deploy or there are jobs still running
    While ($jobQ.Count -gt 0 -or $(get-job -State "Running").count -gt 0) {
        $JobsRunning = $(Get-Job -State 'Running').count

        # For each job started and each child of those jobs
        ForEach ($Job in Get-Job) {
            ForEach ($Child in $Job.ChildJobs){
                ## Get the latest progress object of the job
                $Progress = $Child.Progress[$Child.Progress.Count - 1]
                
                ## If there is a progress object returned write progress
                If ($Progress.Activity -ne $Null){
                    Write-Progress -Activity $Job.Name -Status $Progress.StatusDescription -PercentComplete $Progress.PercentComplete -ID $Job.ID -ParentId 1
                    Write-Verbose "Job '$($job.name)' is at $($Progress.PercentComplete)%"
                }
                
                ## If this child is complete then stop writing progress
                If ($Progress.PercentComplete -eq 100 -or $Progress.PercentComplete -eq -1){
                    Write-Verbose "Job '$($Job.name)' has finished"

                    #Update total progress
                    $perc = $ProgressStart + $ProgressInterval*($totalJobs-$jobQ.count)
                    Write-Progress -Activity "Sanitising" -Id 1 -PercentComplete $perc

                    Write-Progress -Activity $Job.Name -Status $Progress.StatusDescription  -PercentComplete $Progress.PercentComplete -ID $Job.ID -ParentId 1 -Complete
                    ## Clear all progress entries so we don't process it again
                    $Child.Progress.Clear()
                }
            }
        }
        
        if ($JobsRunning -lt $MaxJobs -and $jobQ.Count -gt 0) {
            $NumJobstoRun = @(($MaxJobs-$JobsRunning),$jobQ.Count)[$jobQ.Count -lt ($MaxJobs-$JobsRunning)]
            Write-Verbose "We've completed some jobs, we need to start $NumJobstoRun more"
            1..$NumJobstoRun | ForEach-Object {
                Write-Verbose "iteration: $_ of $NumJobstoRun"
                if ($jobQ.Count -eq 0) {
                    Write-Verbose "There are 0 jobs left. Skipping the loop"
                    return
                }
                $j = $jobQ.Dequeue()
                Start-Job -Name $j[0] -InitializationScript $j[1] -ScriptBlock $j[2] -ArgumentList $j[3] | Out-Null
                Write-Verbose "Started Job named '$($j[0])'. There are $($jobQ.Count) jobs remaining"
            }
        }

        ## Setting for loop processing speed
        Start-Sleep -Milliseconds 1000
    }

    # Ensure all progress bars are cleared
    ForEach ($Job in Get-Job) {
        Write-Progress -Activity $Job.Name -ID $Job.ID -ParentId 1 -Complete
    }    
}

function Head-Stripper ([array] $files, [String] $rootFolder, [String] $OutputFolder, $importedKeys) {
    # There shouldn't be any other background jobs, but kill them anyway.
    Write-Progress -Activity "Sanitising" -Id 1 -Status "Clearing background jobs" -PercentComplete 0
    Write-Debug "Current jobs running are: $(get-job *)"
    Get-Job | Stop-Job
    Get-job | Remove-Job
    Write-Debug "removed all background jobs"
    
    Write-Progress -Activity "Sanitising" -Id 1 -Status "Discovering Keys" -PercentComplete 1
    # Use Scout stripper to start looking for the keys in each file
    $keylists = Scout-Stripper $files $script:Config.flags $rootFolder
    Write-Verbose "finished finding keys"
    
    Write-Progress -Activity "Sanitising" -Id 1 -Status "Merging Keylists" -PercentComplete 35
    # Add potentially imported keys to the list of keys
    if ($importedKeys) { [array]$keylists += $importedKeys }

    # Merge all of the keylists into a single dictionary.
    $finalKeyList = Merging-Stripper $keylists
    Write-Verbose "Finished merging keylists"

    Write-Progress -Activity "Sanitising" -Id 1 -Status "Sanitising separate files" -PercentComplete 60
    # Sanitise the files
    $sanitisedFilenames = Sanitising-Stripper $finalKeyList $files $OutputFolder $rootFolder $InPlace
    Write-Verbose "Finished sanitising and exporting files"

    return $finalKeyList, $sanitisedFilenames
}

####################################################################################################
# Start Actual Execution

# Handle config loading
$configUsed = $false
if ( $ConfigFile ) {
    try {
        $tmp = Get-Item $ConfigFile
        $configText = [IO.file]::ReadAllText($tmp.FullName)
    } catch {
        Write-Error "Error: Could not load from Specified config file: $Config"
        exit -1
    }
    Write-Verbose "Processing specified Config file"
    $script:Config = proc-config-file $configText
    Write-Verbose "Finished Processing Config file"
}

# If we didn't get told what config to use, check locally for a 'UseMe' config file
if (-not $configUsed -and -not $SelfContained) {
    $configText = ''
    try {
        $tmp_f = join-path $( Get-location ) "strippy.conf"
        $configText = [IO.file]::ReadAllText($tmp_f)
        
        # todo This will need to check all local .conf files to work properly this does nothing atm
        # # Check it has the UseMe field set to true before continuing
        # if ( $configText -match 'UseMe\s*=\s*true' ) { # should probs test this
            #     
            # } else {
                #     Write-Verbose "Ignored local config file due to false or missing UseMe value."
                # }   
    } catch {
        Write-Warning "SETUP: Could not find or read 'strippy.conf' in $(get-location)"
    }

    if ($configText) {
        Write-Verbose "Found local default config file to use, importing it's settings"
        $Script:Config = proc-config-file $configText
        $configUsed = $true
    }
}

# If we still don't have a config then we need user input
if (-not $configUsed -and -not $SelfContained) {
    # If we were running silent mode then we should end specific error code There
    if ( $Silent ) {
        Write-Error "SETUP: Unable to locate config file. Please specify location using -ConfigFile flag or ensure strippy.conf exists in $(get-location)"
        exit -9
    }

    $ans = Read-Host "Unable to find a strippy.conf file. This file contains the rules that are used to determine sensitive data.
    Continuing now will use the default configuration and only sanitise IP addresses and Windows UNC paths.
    Would you like to continue with only these? 
    y/n> (y) "
    if ( $ans -eq 'n' ) {
        # Could us another question here to ask if the user would like to make a config file
        Write-Information "Use the -MakeConfig argument to create a strippy.conf file and start adding sensitive data rules"
        exit 0;
    } else {
        # Use default flags mentioned in the thingy
        $script:config.flags = $defaultFlags
    }
}

# // todo this could/should be a function
$importedKeys = $null
if ( $KeyFile ) {
    # Check the keyfile is legit before we start.
    Write-Verbose "Checking the KeyFile"
    if ( Test-Path $KeyFile ) {
        $kf = Get-Item $KeyFile
        Write-Verbose "Key File exists and is: '$kf'"
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
    $importedKeys = proc-keyfile $kf.FullName # we need the fullname to load the file in
    Write-Information "Finished Importing Keys from keyfile:"
    if (-not $Silent) {$importedKeys}
}

Write-Verbose "Attempting to Santise $File"
$File = $(Get-Item $File).FullName

## Build the list of files to work on
$filesToProcess = @()
$OutputFolder = $File | Split-Path # Default output folder for a file is its parent dir

# is it a directory?
$isDir = Test-Path -LiteralPath $file -PathType Container
if ( $isDir ) {
    Write-Verbose "$File is a folder"

    # Get all the files
    if ($Recurse) {
        Write-Verbose "Recursive mode means we get all the files"
        $files = Get-ChildItem $File -Recurse -File
    } else {
        Write-Verbose "Normal mode means we only get the files at the top directory"
        $files = Get-ChildItem $File -File
    }

    # Filter out files that have been marked as sanitised or look suspiscious based on the get-filencoding or get-mimetype functions
    $files = $files | Where-Object { 
        # ( $_.Extension -eq '.txt' -or $_.Extension -eq '.log' ) -and 
        ( @('us-ascii', 'utf-8') -contains ( Get-FileEncoding $_.FullName ).BodyName ) -and -not
        ( $(Get-MimeType -CheckFile $_.FullName) -match "image") -and -not
        ( $_.name -like '*.sanitised.*')
    } | ForEach-Object {$_.FullName}

    # If we didn't find any files clean up and exit
    if ( $files.Length -eq 0 ) {
        Write-Error "SETUP: Could not find any appropriate files to sanitise in $File"
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
} elseif ( $File -contains '*' ) {
    # Resolve the wildcard used in the thingy.
    # Check that there's actually files.
    # Check that they fit normal file criteria?
    # We process them where they are
    Write-Error "SETUP: Paths with wildcards are not yet supported"
    Clean-Up
        
# We also want to support archives by treating them as folders we just have to unpack first
} elseif ( $( get-item $File ).Extension -eq '.zip') {
    Write-Error "SETUP: Archives are not yet supported"
    # unpack
    # run something similar to the folder code above
    # add files that we want to process to $filestoprocess
    # set a flag or similar to handle the repacking of the files into a .zip

# It's not a folder, so go for it
} else {
    Write-Verbose "$File is a file"
    
    # Add the file to process to the list
    $filesToProcess += $(get-item $File).FullName
}

# Redirect the output folder if necessary
if ($AlternateOutputFolder) {
    New-Item -ItemType directory -Path $AlternateOutputFolder -Force | Out-Null # Make the new dir
    $OutputFolder = $(Get-item $AlternateOutputFolder).FullName
    Write-Information "Using Alternate Folder for output: $OutputFolder"
}

# give the head stripper all the information we've just gathered about the task
$finalKeyList, $listOfSanitisedFiles = Head-Stripper $filesToProcess $File $OutputFolder $importedKeys

Write-Progress -Activity "Sanitising" -Id 1 -Status "Outputting Keylist" -PercentComplete 99
# Found the Keys, lets output the keylist
output-keylist $finalKeyList $listOfSanitisedFiles

Write-Information "`n==========================================================================`nProcessed Keys:"
if (-not $Silent) {$finalKeyList}

Write-Progress -Activity "Sanitising" -Id 1 -Status "Finished" -PercentComplete 100
Start-Sleep 1
Write-Progress -Activity "Sanitising" -Id 1 -Completed
Clean-Up