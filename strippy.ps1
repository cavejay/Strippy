#Requires -Version 5

<#
.SYNOPSIS
    Tool for bulk sanitising text-based files

.DESCRIPTION
    Use this tool to automate the replacement of sensitive data with generic strings in text-based files.

    Sensitive data is 'described' to Strippy using Regular Expressions (regex) that match the log patterns known to
    contain it. The rules are run across all input files, the matching strings are brought together, labelled, and
    then replaced with their generic label across all input files. The same piece of sensitive data receives the same
    label in every file, so sanitised logs remain readable and comparable.

    Step by step:
        1) Determine the file(s) that require sanitisation - a file, a folder, a wildcard or a .zip/.gz archive
        2) Create a config file describing the sensitive data. -MakeConfig creates a starting point (strippy.conf)
        3) Run strippy.ps1 against the target. Strippy looks for its config in this order:
                a. The file pointed to by -ConfigFile
                b. strippy.conf in the same folder as the target file/folder
                c. strippy.conf in the script's own directory
                d. Built-in rules (IP addresses and Windows UNC hostnames) after asking the user. Never when -Silent
        4) Sanitised output is written to <file>.sanitised.<ext>, <folder>.sanitised or -AlternateOutputFolder
        5) KeyList.txt is written to the directory the script was run from. It maps every generic label back to the
           original value. KEEP IT PRIVATE - it exists so you can answer questions about 'Address53'

    Config file format:
        ; comment
        Recurse=true                     <- switches (before any header). Recurse, InPlace, Silent, MaxThreads,
                                            UnpackZip, NoHeaderInOutput. The command line always wins.
        [ Config ]
        IgnoredStrings="null","unknown"  <- values that are never treated as sensitive (case-insensitive)
        SanitisedFileFirstLine="..."     <- {0} = date/time, {1} = newline, {2} = file name
        KeyListFirstLine="..."
        KeyFileName="KeyList.txt"
        AlternateKeyListOutput="..."
        AlternateOutputFolder="..."
        [ Rules ]
        "hostname=(.*?),"="Hostname"     <- first capture group is replaced with Hostname1, Hostname2, ...
        "servers: (.+)$"="Server",","    <- first capture group is a list that is split on the delimiter
        "^.*password.*$"=\delete         <- matching lines are removed from the output entirely

    Config files for specific tools live in: https://github.com/cavejay/Strippy/tree/master/configFiles

    If you haven't already then you'll need to change your execution policy to run this tool on Windows:
        powershell [-noexit] -executionpolicy Unrestricted -File .\strippy.ps1 <args>

.EXAMPLE
    C:\PS> .\strippy.ps1 .\logs

    Sanitises the files directly in .\logs. Output files are written to .\logs.sanitised and the keylist is written
    to the directory you ran the script from.

.EXAMPLE
    C:\PS> .\strippy.ps1 .\logs\server.1.log

    Sanitises a single file. The output is .\logs\server.1.sanitised.log and .\KeyList.txt

.EXAMPLE
    C:\PS> .\strippy.ps1 ..\otherlogs\servers\oldlog.log -KeyFile .\KeyList.txt

    Loads the keys from a previous run before sanitising, so files processed at different times share labels.
    The new keylist contains the imported keys plus any new keys found.

.EXAMPLE
    C:\PS> .\strippy.ps1 .\logs -Recurse

    Sanitises an entire file tree (maximum depth of 20 directories). Output is written to .\logs.sanitised

.EXAMPLE
    C:\PS> D:\strippy\strippy.ps1 "C:\Program Files\Dynatrace\CAS\Server\logs" -ConfigFile 'D:\strippy\batchjob.strippy.conf' -Recurse -Silent -AlternateOutputFolder "C:\sanitised-$(get-date -UFormat %s)"

    Automation usage. -Silent stops all console output and prompts. The exit code is 0 on success and 1 on failure.

.NOTES
    Author: Michael Ball
    Version: 3.0.0 - 20261113
    Compatability: Windows PowerShell 5.1 and PowerShell 7+ (Windows, Linux, macOS)

    Developer note: dot-sourcing this file with no arguments (. .\strippy.ps1) only loads its functions and does not
    run anything. This is what strippy.Tests.ps1 uses to unit test a single-file script.

.LINK
    https://github.com/cavejay/Strippy
#>

[CmdletBinding(DefaultParameterSetName = 'input')]
param (
    <#              Help flags              #>
    # Show help
    [Parameter(Position = 0, ParameterSetName = "help")][Switch] $h,
    # Show help
    [Parameter(ParameterSetName = "help")][Switch] $help,

    <#              Config things               #>
    # Creates a barebones strippy.conf file for the user to edit
    [Parameter(Position = 0, ParameterSetName = "makeconfig", Mandatory = $false)][Switch] $makeConfig,

    <#              Input Settings              #>
    # The File, Folder, wildcard or archive you wish to sanitise
    [Parameter(Position = 0, ParameterSetName = "input")][String] $File,
    # Specifies a previously generated keylist file to import keys from for this sanitisation
    [Parameter(Position = 1, ParameterSetName = "input")][String] $KeyFile,
    # Specifies a config file to use rather than a discovered strippy.conf
    [Parameter(Position = 2, ParameterSetName = "input")][String] $ConfigFile,
    # Looks for files throughout a directory tree rather than only in the first level
    [Parameter(ParameterSetName = "input")][Switch] $Recurse = $false,
    # Destructively sanitises the file. There is no warning for this switch. If you use it, it's happened
    [Parameter(ParameterSetName = "input")][Switch] $InPlace = $false,
    # Unpack .zip and .gz archives found in the target folder and sanitise their contents
    [Parameter(ParameterSetName = "input")][switch] $unpackZip,
    # Do not include the sanitisation header in output files
    [Parameter(ParameterSetName = "input")][switch] $noHeaderInOutput = $false,
    # A shortcut for -AlternateKeyListOutput
    [Parameter(ParameterSetName = "input")][String] $ko,
    # Specifies an alternate name and path for the keylist file
    [Parameter(ParameterSetName = "input")][String] $AlternateKeyListOutput,
    # A shortcut for -AlternateOutputFolder
    [Parameter(ParameterSetName = "input")][String] $o,
    # Specifies an alternate folder for the sanitised file(s)
    [Parameter(ParameterSetName = "input")][Alias('out')][String] $AlternateOutputFolder,
    # Run without printing to the terminal or prompting. Exits with an error if user input would have been needed
    [Parameter(ParameterSetName = "input")][Switch] $Silent = $false,
    # Maximum number of files processed in parallel
    [Parameter(ParameterSetName = "input")][int] $MaxThreads = 5,

    <#              Logging Settings                #>
    # Perform logging for this execution
    [Switch] $log = $false,
    # The specific log file to log to. This is useless unless the log switch is used
    [String] $logfile = (Join-Path '.' 'strippy.log'),
    # Show absolutely all log messages. This will create much larger logs
    [Switch] $showDebug = $false,
    # How big can a log file get before it's shuffled
    [int] $MaxLogFileSize = 10MB,
    # Max number of log files created by the script
    [int] $LogHistory = 5
)

###############################################################################################################
#region Logging
#   One writer, opened once, used only by the main thread. Worker threads never log - they return data.

function Get-StrippyLogState {
    if ($null -eq $script:StrippyLog) {
        $script:StrippyLog = @{ Enabled = $false; ShowDebug = $false; Silent = $false; Path = ''; Writer = $null; MaxSize = 10MB; History = 5; Written = 0 }
    }
    return $script:StrippyLog
}

function Open-StrippyLogWriter {
    $state = Get-StrippyLogState
    $dir = [System.IO.Path]::GetDirectoryName($state.Path)
    if ($dir) { [void][System.IO.Directory]::CreateDirectory($dir) }
    $state.Written = 0
    if ([System.IO.File]::Exists($state.Path)) { $state.Written = (New-Object System.IO.FileInfo $state.Path).Length }
    $state.Writer = [System.IO.StreamWriter]::new($state.Path, $true, [System.Text.UTF8Encoding]::new($false)
}

function Initialize-StrippyLog {
    param ([bool] $Enabled, [bool] $ShowDebug, [bool] $Silent, [string] $Path, [long] $MaxSize = 10MB, [int] $History = 5)

    Close-StrippyLog
    $state = Get-StrippyLogState
    $state.Enabled = $false
    $state.ShowDebug = $ShowDebug
    $state.Silent = $Silent
    $state.Path = $Path
    $state.MaxSize = $MaxSize
    $state.History = $History

    if ($Enabled -and $Path) {
        try {
            Open-StrippyLogWriter
            $state.Enabled = $true
            if ($state.Written -ge $state.MaxSize) { Invoke-StrippyLogRotation }
        }
        catch {
            $state.Writer = $null
            Write-StrippyLog logger Warning "Could not open log file '$Path' - continuing without a log file. $($_.Exception.Message)"
        }
    }
}

function Close-StrippyLog {
    $state = Get-StrippyLogState
    if ($state.Writer) {
        try { $state.Writer.Dispose() } catch { }
        $state.Writer = $null
    }
    $state.Enabled = $false
}

# strippy.log -> strippy.1.log -> strippy.2.log ... up to History files
function Invoke-StrippyLogRotation {
    $state = Get-StrippyLogState
    if (-not $state.Writer) { return }
    try {
        $state.Writer.WriteLine("LOG SHUFFLE " + (Get-Date).ToString('yy-MM-dd HH:mm:ss.fff') + "   Continued in next log file")
        $state.Writer.Dispose()
        $state.Writer = $null

        $dir = [System.IO.Path]::GetDirectoryName($state.Path)
        $base = [System.IO.Path]::GetFileNameWithoutExtension($state.Path)
        $ext = [System.IO.Path]::GetExtension($state.Path)
        for ($i = $state.History - 1; $i -ge 1; $i--) {
            $from = [System.IO.Path]::Combine($dir, "$base.$i$ext")
            $to = [System.IO.Path]::Combine($dir, "$base.$($i + 1)$ext")
            if ([System.IO.File]::Exists($from)) {
                if ([System.IO.File]::Exists($to)) { [System.IO.File]::Delete($to) }
                [System.IO.File]::Move($from, $to)
            }
        }
        if ($state.History -ge 1) {
            $first = [System.IO.Path]::Combine($dir, "$base.1$ext")
            if ([System.IO.File]::Exists($first)) { [System.IO.File]::Delete($first) }
            [System.IO.File]::Move($state.Path, $first)
        }
        else {
            [System.IO.File]::Delete($state.Path)
        }
        Open-StrippyLogWriter
    }
    catch {
        # Rotation is best effort. Try to keep logging to the same file, otherwise stop file logging.
        try { if (-not $state.Writer) { Open-StrippyLogWriter } } catch { $state.Writer = $null; $state.Enabled = $false }
        $state.Written = 0
    }
}

<#
    Types:  Trace, Debug        -> log file only (Debug requires -showDebug)
            Message, Question   -> console (unless silent) + log file
            Warning, Error      -> console (unless silent) + log file
    Log line format is unchanged from v1 so timecheck.ps1 continues to work.
#>
function Write-StrippyLog {
    param (
        [string] $Stage,
        [string] $Type = 'Trace',
        [string] $Message,
        [string] $Colour
    )

    $state = Get-StrippyLogState
    $code = 'T'
    $display = $false
    switch ($Type) {
        'Trace' { if (-not $state.Writer) { return } }
        'Debug' { if (-not $state.Writer -or -not $state.ShowDebug) { return }; $code = 'D' }
        'Message' { $code = 'I'; $display = $true; if (-not $Colour) { $Colour = 'White' } }
        'Question' { $code = 'Q'; $display = $true; if (-not $Colour) { $Colour = 'Cyan' } }
        'Warning' { $code = 'W'; $display = $true; if (-not $Colour) { $Colour = 'Yellow' }; $Message = "Warning: $Message" }
        'Error' { $code = 'E'; $display = $true; if (-not $Colour) { $Colour = 'Red' }; $Message = "ERROR: $Message" }
    }

    if ($display -and -not $state.Silent) {
        if ($code -eq 'E') { Write-Host $Message -ForegroundColor $Colour -BackgroundColor Black }
        else { Write-Host $Message -ForegroundColor $Colour }
    }

    if ($state.Writer) {
        $line = $code + ' ' + $Stage.PadRight(6).Substring(0, 6).ToUpper() + ' ' + (Get-Date).ToString('yy-MM-dd HH:mm:ss.fff') + '   ' + $Message
        try {
            $state.Writer.WriteLine($line)
            if ($display) { $state.Writer.Flush() }
            $state.Written += $line.Length + 2
            if ($state.Written -ge $state.MaxSize) { Invoke-StrippyLogRotation }
        }
        catch { }
    }
}

# Logs an error and throws. The entry point turns this into exit code 1.
function Stop-Strippy {
    param ([string] $Message)
    Write-StrippyLog fatal Error $Message
    $ex = New-Object System.InvalidOperationException -ArgumentList $Message
    $ex.Data['StrippyLogged'] = $true
    throw $ex
}

#endregion

###############################################################################################################
#region Paths

# Full path for something that may not exist yet, relative to PowerShell's location (not the process cwd)
function Resolve-StrippyPath {
    param ([string] $Path)
    if (-not $Path) { return '' }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

# Paths written in config files are usually Windows style. Make them work on Linux/macOS too.
function ConvertTo-StrippyNativePath {
    param ([string] $Path)
    if (-not $Path) { return '' }
    if ([System.IO.Path]::DirectorySeparatorChar -eq '/') { return $Path.Replace('\', '/') }
    return $Path
}

# 'sub/file.log' for a path beneath root. Just the file name when the path is not beneath root.
function Get-StrippyRelativePath {
    param ([string] $Path, [string] $Root)
    $r = $Root.TrimEnd('\', '/')
    if ($Path.Length -gt ($r.Length + 1) -and $Path.StartsWith($r, [System.StringComparison]::OrdinalIgnoreCase)) {
        $sep = [string]$Path[$r.Length]
        if ($sep -eq '\' -or $sep -eq '/') { return $Path.Substring($r.Length + 1) }
    }
    return [System.IO.Path]::GetFileName($Path)
}

# Where does the sanitised version of a file go?  name.ext -> <OutputFolder>/<path relative to root>/name.sanitised.ext
function Get-StrippyOutputPath {
    param ([string] $Source, [string] $Root, [string] $OutputFolder, [bool] $InPlace)
    if ($InPlace) { return $Source }
    $name = [System.IO.Path]::GetFileName($Source)
    $newName = [System.IO.Path]::GetFileNameWithoutExtension($name) + '.sanitised' + [System.IO.Path]::GetExtension($name)
    $relDir = [string][System.IO.Path]::GetDirectoryName((Get-StrippyRelativePath $Source $Root))
    if ($relDir) { return [System.IO.Path]::Combine($OutputFolder, $relDir, $newName) }
    return [System.IO.Path]::Combine($OutputFolder, $newName)
}

# Deepest directory that contains every one of the files
function Get-StrippyCommonRoot {
    param ([string[]] $Paths)
    $common = [System.IO.Path]::GetDirectoryName($Paths[0])
    foreach ($p in $Paths) {
        $dir = [System.IO.Path]::GetDirectoryName($p)
        while ($common) {
            $c = $common.TrimEnd('\', '/')
            if ($dir.Equals($c, [System.StringComparison]::OrdinalIgnoreCase)) { break }
            if ($dir.StartsWith($c + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) { break }
            $common = [System.IO.Path]::GetDirectoryName($common)
        }
        if (-not $common) { return [System.IO.Path]::GetPathRoot($Paths[0]) }
    }
    return $common
}

#endregion

###############################################################################################################
#region Config

function Get-StrippyDefaultConfig {
    return @{
        IgnoredStrings         = @('/0:0:0:0:0:0:0:0', '0.0.0.0', '127.0.0.1', 'name', 'applications', '', 'unknown', 'null', '.')
        SanitisedFileFirstLine = 'This file was Sanitised at {0}.{1}=={1}{1}'
        KeyListFirstLine       = 'This keylist was created at {0}.{1}'
        KeyFileName            = 'KeyList.txt'
        AlternateKeyListOutput = ''
        AlternateOutputFolder  = ''
        Switches               = @{ }
        Rules                  = @()
    }
}

# Used when there is no config file at all: IPv4 addresses and the host of Windows UNC paths
function Get-StrippyDefaultRules {
    return @(
        @{ Type = 'basic'; Pattern = '((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(?!\d)'; Alias = 'Address'; Delimiter = $null; Line = 0 },
        @{ Type = 'basic'; Pattern = '\\\\([\w\-.]*?)\\'; Alias = 'Hostname'; Delimiter = $null; Line = 0 }
    )
}

function Get-StrippyDefaultConfigText {
    return @'
; Strippy Config file
; Switches. Uncomment to change the default behaviour. Command line flags always win.
;Recurse=true
;InPlace=false
;Silent=false
;MaxThreads=5
;UnpackZip=false
;NoHeaderInOutput=false

[ Config ]
; Matches that are exactly one of these strings (case-insensitive) are never treated as sensitive
IgnoredStrings="/0:0:0:0:0:0:0:0","0.0.0.0","127.0.0.1","name","applications","","unknown","null","."

; These settings can use braces to include dynamic formatting:
; {0} = Date/Time at processing
; {1} = NewLine
; {2} = Name of the file being processed (file header) or the sanitisation target (keylist header)
SanitisedFileFirstLine="This file was Sanitised at {0}.{1}=={1}{1}"
KeyListFirstLine="This keylist was created at {0}."
;KeyFileName="KeyList.txt"
;AlternateKeyListOutput=".\keylist.txt"
;AlternateOutputFolder=".\sanitisedoutput"

[ Rules ]
; "<regex>"="<alias>"               The first capture group is replaced with <alias>1, <alias>2, ...
; "<regex>"="<alias>","<delimiter>" The first capture group is a list of values separated by <delimiter>
; "<regex>"=\delete                 Lines matching <regex> are removed from the output entirely
"((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(?!\d)"="Address"
"\\\\([\w\-.]*?)\\"="Hostname"
'@
}

<#
    Parses the text of a config file. Pure function: no logging, no side effects, throws on invalid input.
    Returns @{ Settings = @{}; Switches = @{}; Rules = @(...); Warnings = @(...) } containing only what the file set.
#>
function ConvertFrom-StrippyConfig {
    param ([AllowEmptyString()][string] $Text)

    $settings = @{ }
    $switches = @{ }
    $rules = New-Object 'System.Collections.Generic.List[object]'
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    $knownSections = 'Switches', 'Config', 'Rules'
    $knownSettings = 'IgnoredStrings', 'SanitisedFileFirstLine', 'KeyListFirstLine', 'KeyFileName', 'AlternateKeyListOutput', 'AlternateOutputFolder'
    $boolSwitches = 'Silent', 'Recurse', 'InPlace', 'UnpackZip', 'NoHeaderInOutput'
    $section = 'Switches'
    $lineNum = 0

    foreach ($rawLine in ($Text -split "\r?\n")) {
        $lineNum++
        $line = $rawLine.Trim().Trim([char]0xFEFF)
        if ($line.Length -eq 0 -or $line.StartsWith(';') -or $line.StartsWith('#')) { continue }

        # Section header: '[ Config ]' (v1) or '[Config]'
        if ($line -match '^\[\s*([\w\s]*?)\s*\]') {
            $name = $Matches[1]
            $canonical = $knownSections | Where-Object { $_ -eq $name }
            if (-not $canonical) { throw "Invalid header '$name' on line $lineNum`: $line" }
            $section = [string]$canonical
            continue
        }

        if ($section -eq 'Rules') {
            if ($line -match '^"(.+?)"="(.+)"\s*,\s*"(.+)"$') {
                $rules.Add(@{ Type = 'list'; Pattern = $Matches[1]; Alias = $Matches[2]; Delimiter = $Matches[3]; Line = $lineNum })
            }
            elseif ($line -match '^"(.*?)"="(.*)"$') {
                $rules.Add(@{ Type = 'basic'; Pattern = $Matches[1]; Alias = $Matches[2]; Delimiter = $null; Line = $lineNum })
            }
            elseif ($line -match '^"(.*)"=\\delete$') {
                $rules.Add(@{ Type = 'delete'; Pattern = $Matches[1]; Alias = $null; Delimiter = $null; Line = $lineNum })
            }
            else {
                throw "Invalid rule on line $lineNum. Expected `"<regex>`"=`"<alias>`", `"<regex>`"=`"<alias>`",`"<delimiter>`" or `"<regex>`"=\delete but found: $line"
            }
            continue
        }

        if ($line -match '^(.*?)=(.*)$') { $key = $Matches[1].Trim(); $value = $Matches[2].Trim() }
        else { throw "Unable to parse config on line $lineNum`: $line" }

        if ($section -eq 'Switches') {
            $canonical = $boolSwitches | Where-Object { $_ -eq $key }
            if ($canonical) {
                $switches[[string]$canonical] = ($value.Trim('"') -eq 'true')
            }
            elseif ($key -eq 'MaxThreads') {
                if ($value -match '^\d+$') { $switches['MaxThreads'] = [int]$value }
                else { $warnings.Add("MaxThreads value on line $lineNum is not a valid number and will be ignored: $line") }
            }
            else {
                $warnings.Add("Unknown switch '$key' on line $lineNum will be ignored: $line")
            }
            continue
        }

        # Config section. Values are "string", "list","of","strings" or true/false. \" is an escaped quote.
        $canonical = $knownSettings | Where-Object { $_ -eq $key }
        if (-not $canonical) {
            $warnings.Add("Unrecognised config setting '$key' on line $lineNum will be ignored: $line")
            continue
        }
        $quoted = ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"'))
        $inner = $value
        if ($quoted) { $inner = $value.Substring(1, $value.Length - 2) }
        if ($canonical -eq 'IgnoredStrings') {
            $settings['IgnoredStrings'] = @(($inner -split '",\s*"') | ForEach-Object { $_ -replace '\\"', '"' })
        }
        else {
            $settings[[string]$canonical] = ($inner -replace '\\"', '"')
        }
    }

    return @{ Settings = $settings; Switches = $switches; Rules = $rules.ToArray(); Warnings = $warnings.ToArray() }
}

# Defaults overlaid with whatever the config file set
function Merge-StrippyConfig {
    param ($Parsed)
    $config = Get-StrippyDefaultConfig
    foreach ($key in @($Parsed.Settings.Keys)) { $config[$key] = $Parsed.Settings[$key] }
    $config.Switches = $Parsed.Switches
    $config.Rules = $Parsed.Rules
    return $config
}

<#
    Compiles rule definitions once so every file (and every thread) reuses the same Regex objects.
    Throws if a rule's regex is invalid - a sanitiser must not quietly run with fewer rules than it was given.
    Returns { Capture = [rule objects]; DeletePattern = string or $null; Warnings = [string] }
#>
function New-StrippyRuleSet {
    param ([object[]] $Rules)

    $capture = New-Object 'System.Collections.Generic.List[object]'
    $delete = New-Object 'System.Collections.Generic.List[string]'
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    $options = [System.Text.RegularExpressions.RegexOptions]'Multiline, Compiled'

    foreach ($rule in $Rules) {
        $where = "rule on config line $($rule.Line)"
        if ($rule.Line -eq 0) { $where = 'built-in rule' }

        if ($rule.Type -eq 'delete') {
            try { [void][System.Text.RegularExpressions.Regex]::new($rule.Pattern) }
            catch { throw "Invalid regex in delete $where`: $($rule.Pattern) - $($_.Exception.Message)" }
            $delete.Add('(?:' + $rule.Pattern + ')')
            continue
        }

        try { $regex = [System.Text.RegularExpressions.Regex]::new($rule.Pattern, $options) }
        catch { throw "Invalid regex in $where`: $($rule.Pattern) - $($_.Exception.Message)" }

        if ($regex.GetGroupNumbers().Length -lt 2) {
            $warnings.Add("The $where has no capture group and will never match anything: $($rule.Pattern)")
            continue
        }

        $delimiter = $null
        if ($rule.Type -eq 'list') {
            try { $delimiter = [System.Text.RegularExpressions.Regex]::new($rule.Delimiter, [System.Text.RegularExpressions.RegexOptions]'IgnoreCase') }
            catch { throw "Invalid list delimiter in $where`: $($rule.Delimiter) - $($_.Exception.Message)" }
        }

        $capture.Add([pscustomobject]@{ Regex = $regex; Alias = [string]$rule.Alias; Delimiter = $delimiter; Pattern = $rule.Pattern; Line = $rule.Line })
    }

    $deletePattern = $null
    if ($delete.Count -gt 0) { $deletePattern = $delete -join '|' }

    return [pscustomobject]@{ Capture = $capture.ToArray(); DeletePattern = $deletePattern; Warnings = $warnings.ToArray() }
}

function New-StrippyIgnoredSet {
    param ([string[]] $IgnoredStrings)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($s in $IgnoredStrings) { if ($null -ne $s) { [void]$set.Add($s) } }
    return , $set
}

# {0} = date/time, {1} = newline, {2} = name. Any other {n} is removed.
function Expand-StrippyTemplate {
    param ([string] $Template, [string] $NewLine = [System.Environment]::NewLine, [string] $Name = '', [string] $Timestamp = '')
    if (-not $Template) { return '' }
    if (-not $Timestamp) { $Timestamp = (Get-Date).ToString() }
    $out = $Template -replace '\{[3-9]\}', ''
    return $out.Replace('{0}', $Timestamp).Replace('{1}', $NewLine).Replace('{2}', $Name)
}

function New-StrippyConfigFile {
    param ([string] $Path, [bool] $Silent)
    Write-StrippyLog mkconf Trace "Creating a default config file at $Path"
    if (Test-Path -LiteralPath $Path) {
        if ($Silent) { Stop-Strippy "A config file already exists at $Path and cannot be overwritten in silent mode" }
        Write-StrippyLog mkconf Question "A config file already exists at $Path. Would you like to overwrite it with the default?"
        $answer = Read-Host "y/n> (n) "
        if ($answer -ne 'y') {
            Write-StrippyLog mkconf Message "Didn't overwrite the current config file"
            return
        }
        Write-StrippyLog mkconf Message "You overwrote a config file that contained the following. Use this to recreate the file if you stuffed up:`n$([System.IO.File]::ReadAllText($Path))"
    }
    [System.IO.File]::WriteAllText($Path, (Get-StrippyDefaultConfigText) + [System.Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    Write-StrippyLog mkconf Message "Generated config file: $Path"
}

#endregion

###############################################################################################################
#region Core engine
#   These functions do the actual work. The ones listed in Get-StrippyWorkerFunctionNames also run inside worker
#   threads, so they must only depend on their parameters and on each other: no logging, no script variables.

function Get-StrippyWorkerFunctionNames {
    return 'Read-StrippyFile', 'Remove-StrippyLines', 'Expand-StrippyTemplate', 'Find-StrippyKeys', 'Protect-StrippyText', 'Protect-StrippyFile'
}

# Reads a whole file. BOMs are honoured, everything else is treated as UTF-8. The encoding is returned so the
# sanitised copy can be written the same way.
function Read-StrippyFile {
    param ([string] $Path)
    $reader = [System.IO.StreamReader]::new($Path, [System.Text.UTF8Encoding]::new($false), $true)
    try {
        $text = $reader.ReadToEnd()
        $encoding = $reader.CurrentEncoding
    }
    finally { $reader.Dispose() }
    return [pscustomobject]@{ Text = $text; Encoding = $encoding }
}

# Removes every line that matches the combined delete pattern (case-insensitive, as in v1)
function Remove-StrippyLines {
    param ([string] $Text, [string] $DeletePattern)
    if (-not $DeletePattern -or -not $Text) { return $Text }
    $newLine = "`n"
    if ($Text.Contains("`r`n")) { $newLine = "`r`n" }
    $lines = [regex]::Split($Text, "\r?\n")
    $kept = @($lines -notmatch $DeletePattern)
    if ($kept.Count -eq $lines.Length) { return $Text }
    return ($kept -join $newLine)
}

<#
    Scout pass: runs every rule over one file and returns the sensitive values found, in order of discovery.
    The first rule to find a value decides its alias. Values are unique ignoring case.
#>
function Find-StrippyKeys {
    param ([string] $Path, $RuleSet, $IgnoredSet)

    $values = New-Object 'System.Collections.Generic.List[string]'
    $types = New-Object 'System.Collections.Generic.List[string]'
    $ruleHits = New-Object 'int[]' $RuleSet.Capture.Length
    $failure = $null

    try {
        $text = Remove-StrippyLines (Read-StrippyFile $Path).Text $RuleSet.DeletePattern
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $index = -1

        foreach ($rule in $RuleSet.Capture) {
            $index++
            $hits = 0
            # Most log files repeat the same values thousands of times. Only look at each raw capture once.
            $raw = New-Object 'System.Collections.Generic.HashSet[string]'
            $m = $rule.Regex.Match($text)
            while ($m.Success) {
                $group = $m.Groups[1]
                if ($group.Success) {
                    $hits++
                    if ($raw.Add($group.Value)) {
                        if ($rule.Delimiter) { $candidates = $rule.Delimiter.Split($group.Value) }
                        else { $candidates = @($group.Value) }
                        foreach ($candidate in $candidates) {
                            $value = $candidate.Replace("`r", '').Replace("`n", '')
                            if ($rule.Delimiter) { $value = $value.Trim() }
                            if ($value.Trim().Length -eq 0) { continue }
                            if ($IgnoredSet.Contains($value)) { continue }
                            if ($seen.Add($value)) {
                                $values.Add($value)
                                $types.Add($rule.Alias)
                            }
                        }
                    }
                }
                $m = $m.NextMatch()
            }
            $ruleHits[$index] = $hits
        }
    }
    catch {
        $failure = $_.Exception.Message
    }

    return [pscustomobject]@{ Path = $Path; FoundValues = $values; FoundTypes = $types; RuleHits = $ruleHits; Error = $failure }
}

<#
    Replaces every key in the text in a single pass.
    KeyRegex is one alternation of every key (longest first), KeyMap maps a key to its alias ignoring case.
#>
function Protect-StrippyText {
    param ([string] $Text, $KeyRegex, $KeyMap)

    if ($null -eq $KeyRegex -or -not $Text) { return [pscustomobject]@{ Text = $Text; Count = 0 } }
    $m = $KeyRegex.Match($Text)
    if (-not $m.Success) { return [pscustomobject]@{ Text = $Text; Count = 0 } }

    $sb = New-Object System.Text.StringBuilder -ArgumentList $Text.Length
    $position = 0
    $count = 0
    while ($m.Success) {
        [void]$sb.Append($Text, $position, $m.Index - $position)
        $alias = $null
        if (-not $KeyMap.TryGetValue($m.Value, [ref]$alias)) {
            # The regex and the dictionary can disagree on exotic unicode case folding. Never leave the match in place.
            foreach ($key in $KeyMap.Keys) {
                if ([string]::Equals($key, $m.Value, [System.StringComparison]::InvariantCultureIgnoreCase)) { $alias = $KeyMap[$key]; break }
            }
            if ($null -eq $alias) { $alias = 'SANITISED' }
        }
        [void]$sb.Append([string]$alias)
        $position = $m.Index + $m.Length
        $count++
        $m = $m.NextMatch()
    }
    [void]$sb.Append($Text, $position, $Text.Length - $position)

    return [pscustomobject]@{ Text = $sb.ToString(); Count = $count }
}

# Sanitise pass for one file: read, drop deleted lines, replace keys, add the header, write to the destination
function Protect-StrippyFile {
    param ([string] $Source, [string] $Destination, [string] $DisplayName, $RuleSet, $KeyRegex, $KeyMap, [string] $HeaderTemplate, [string] $Timestamp)

    $count = 0
    $failure = $null
    try {
        $file = Read-StrippyFile $Source
        $text = Remove-StrippyLines $file.Text $RuleSet.DeletePattern
        $result = Protect-StrippyText $text $KeyRegex $KeyMap
        $count = $result.Count
        $output = $result.Text

        if ($HeaderTemplate) {
            $newLine = [System.Environment]::NewLine
            if ($output.Contains("`r`n")) { $newLine = "`r`n" }
            elseif ($output.Contains("`n")) { $newLine = "`n" }
            $output = (Expand-StrippyTemplate -Template $HeaderTemplate -NewLine $newLine -Name $DisplayName -Timestamp $Timestamp) + $output
        }

        $directory = [System.IO.Path]::GetDirectoryName($Destination)
        if ($directory) { [void][System.IO.Directory]::CreateDirectory($directory) }
        [System.IO.File]::WriteAllText($Destination, $output, $file.Encoding)
    }
    catch {
        $failure = $_.Exception.Message
    }

    return [pscustomobject]@{ Source = $Source; Destination = $Destination; Replacements = $count; Error = $failure }
}

<#
    Runs a worker function once per argument set and returns the results in input order.
    Uses a runspace pool (threads in this process) when there is more than one item and more than one thread allowed.
#>
function Invoke-StrippyParallel {
    param ([string] $FunctionName, [object[]] $ArgumentSets, [int] $MaxThreads = 1, [string] $Activity = 'Working', [bool] $ShowProgress = $false)

    $results = New-Object 'System.Collections.Generic.List[object]'
    $total = $ArgumentSets.Length
    $done = 0

    if ($MaxThreads -le 1 -or $total -le 1) {
        foreach ($arguments in $ArgumentSets) {
            $output = @(& $FunctionName @arguments)
            $results.Add($output[$output.Count - 1])
            $done++
            if ($ShowProgress) { Write-Progress -Activity $Activity -Status "$done of $total" -PercentComplete (100 * $done / $total) }
        }
    }
    else {
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        foreach ($name in (Get-StrippyWorkerFunctionNames)) {
            $definition = (Get-Command -Name $name -CommandType Function).Definition
            $sessionState.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $name, $definition))
        }
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, [Math]::Min($MaxThreads, $total), $sessionState, $Host)
        $pool.Open()
        try {
            $jobs = New-Object 'System.Collections.Generic.List[object]'
            foreach ($arguments in $ArgumentSets) {
                $ps = [System.Management.Automation.PowerShell]::Create()
                $ps.RunspacePool = $pool
                [void]$ps.AddCommand($FunctionName).AddParameters($arguments)
                $jobs.Add(@{ PowerShell = $ps; Handle = $ps.BeginInvoke(); Arguments = $arguments })
            }
            foreach ($job in $jobs) {
                try {
                    $output = $job.PowerShell.EndInvoke($job.Handle)
                    if ($output.Count -lt 1) { throw "The worker returned nothing" }
                    $results.Add($output[$output.Count - 1])
                }
                catch {
                    $a = $job.Arguments
                    $results.Add([pscustomobject]@{
                            Path = $a.Path; Source = $a.Source; Destination = $a.Destination; Replacements = 0
                            FoundValues = @(); FoundTypes = @(); RuleHits = @(); Error = "Worker failed: $($_.Exception.Message)"
                        })
                }
                finally {
                    $job.PowerShell.Dispose()
                }
                $done++
                if ($ShowProgress) { Write-Progress -Activity $Activity -Status "$done of $total" -PercentComplete (100 * $done / $total) }
            }
        }
        finally {
            $pool.Close()
            $pool.Dispose()
        }
    }

    if ($ShowProgress) { Write-Progress -Activity $Activity -Completed }
    return , $results.ToArray()
}

#endregion

###############################################################################################################
#region Keys

<#
    Reads a keylist written by a previous run (v1 or v2 format):
        <header>
        Alias01 - value
        ...
        List of files using this Key:
        <files>
#>
function Import-StrippyKeyList {
    param ([string] $Path)

    $lines = [System.IO.File]::ReadAllLines($Path)
    $marker = [Array]::IndexOf($lines, 'List of files using this Key:')
    if ($marker -lt 0) { throw "Invalid format for KeyFile ($Path). Can't find the 'List of files using this Key:' line" }

    $entries = New-Object 'System.Collections.Generic.List[object]'
    for ($i = 0; $i -lt $marker; $i++) {
        if ($lines[$i] -match '^(.+?\d) - (.+)$') {
            $entries.Add([pscustomobject]@{ Alias = $Matches[1]; Value = $Matches[2] })
        }
    }
    $files = @()
    if ($marker + 1 -lt $lines.Length) { $files = @($lines[($marker + 1)..($lines.Length - 1)] | Where-Object { $_.Trim() }) }

    return [pscustomobject]@{ Entries = $entries.ToArray(); Files = $files }
}

<#
    Merges the scout results (in order) with any imported keys and gives every value its alias.
    Aliases are numbered per type in order of discovery and zero padded: Address01 ... Address12.
    Imported keys keep the alias they already had.
    Returns { Map = Dictionary value -> alias (ignores case); Entries = [{ Alias, Value }] in order }
#>
function New-StrippyKeyMap {
    param ([object[]] $ScoutResults, [object[]] $ImportedEntries)

    $map = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $usedAliases = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $importedCount = @{ }

    foreach ($entry in $ImportedEntries) {
        if ($null -eq $entry -or -not $entry.Value -or $map.ContainsKey($entry.Value)) { continue }
        $map.Add($entry.Value, $entry.Alias)
        $entries.Add([pscustomobject]@{ Alias = $entry.Alias; Value = $entry.Value })
        [void]$usedAliases.Add($entry.Alias)
        $type = $entry.Alias -replace '\d+$', ''
        $importedCount[$type] = 1 + [int]$importedCount[$type]
    }

    # Collect what's new, keeping order, and count per type so the padding width is known up front
    $pendingValues = New-Object 'System.Collections.Generic.List[string]'
    $pendingTypes = New-Object 'System.Collections.Generic.List[string]'
    $pendingSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $newCount = @{ }
    foreach ($result in $ScoutResults) {
        if ($null -eq $result -or $null -eq $result.FoundValues) { continue }
        for ($i = 0; $i -lt $result.FoundValues.Count; $i++) {
            $value = $result.FoundValues[$i]
            if ($map.ContainsKey($value) -or -not $pendingSeen.Add($value)) { continue }
            $type = $result.FoundTypes[$i]
            $pendingValues.Add($value)
            $pendingTypes.Add($type)
            $newCount[$type] = 1 + [int]$newCount[$type]
        }
    }

    $next = @{ }
    for ($i = 0; $i -lt $pendingValues.Count; $i++) {
        $type = $pendingTypes[$i]
        $start = [int]$importedCount[$type]
        if (-not $next.ContainsKey($type)) { $next[$type] = $start + 1 }
        $format = 'D' + ([string]($start + [int]$newCount[$type])).Length
        do {
            $alias = $type + ([int]$next[$type]).ToString($format)
            $next[$type] = 1 + [int]$next[$type]
        } while (-not $usedAliases.Add($alias))
        $map.Add($pendingValues[$i], $alias)
        $entries.Add([pscustomobject]@{ Alias = $alias; Value = $pendingValues[$i] })
    }

    return [pscustomobject]@{ Map = $map; Entries = $entries.ToArray() }
}

# One regex that matches any key. Longest keys first so 'pineapple' wins over 'apple' at the same position.
function New-StrippyKeyRegex {
    param ($KeyMap)
    if ($null -eq $KeyMap -or $KeyMap.Count -eq 0) { return $null }

    $values = [string[]]@($KeyMap.Keys)
    $order = New-Object 'int[]' $values.Length
    for ($i = 0; $i -lt $values.Length; $i++) { $order[$i] = 0 - $values[$i].Length }
    [Array]::Sort($order, $values)

    $sb = New-Object System.Text.StringBuilder
    foreach ($value in $values) {
        if ($sb.Length -gt 0) { [void]$sb.Append('|') }
        [void]$sb.Append([regex]::Escape($value))
    }
    $options = [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'
    return [System.Text.RegularExpressions.Regex]::new($sb.ToString(), $options)
}

function Export-StrippyKeyList {
    param ([string] $Path, [object[]] $Entries, [string[]] $FileLines, [string] $HeaderTemplate, [string] $TargetName)

    $newLine = [System.Environment]::NewLine
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append((Expand-StrippyTemplate -Template $HeaderTemplate -NewLine $newLine -Name $TargetName)).Append($newLine)
    foreach ($entry in ($Entries | Sort-Object -Property Alias)) {
        [void]$sb.Append($entry.Alias).Append(' - ').Append($entry.Value).Append($newLine)
    }
    [void]$sb.Append('List of files using this Key:').Append($newLine)
    foreach ($line in $FileLines) { [void]$sb.Append($line).Append($newLine) }

    $directory = [System.IO.Path]::GetDirectoryName($Path)
    if ($directory) { [void][System.IO.Directory]::CreateDirectory($directory) }
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
}

#endregion

###############################################################################################################
#region Input discovery

function Test-StrippyArchive {
    param ([string] $Path)
    $ignoredArchives = 'plugins.zip', 'remote_plugins.zip'
    return ([System.IO.Path]::GetExtension($Path) -in '.zip', '.gz') -and ([System.IO.Path]::GetFileName($Path) -notin $ignoredArchives)
}

# Binary files contain NUL bytes, text files don't (UTF-16/32 text is identified by its BOM)
function Test-StrippyBinaryFile {
    param ([string] $Path)
    $buffer = New-Object 'byte[]' 8192
    $stream = [System.IO.File]::OpenRead($Path)
    try { $read = $stream.Read($buffer, 0, $buffer.Length) }
    finally { $stream.Dispose() }
    if ($read -ge 2) {
        if (($buffer[0] -eq 0xFF -and $buffer[1] -eq 0xFE) -or ($buffer[0] -eq 0xFE -and $buffer[1] -eq 0xFF)) { return $false }
    }
    return ([Array]::IndexOf($buffer, [byte]0, 0, $read) -ge 0)
}

# $null when the file should be sanitised, otherwise why it won't be
function Get-StrippySkipReason {
    param ([string] $Path)
    $ignoredExtensions = '.gif', '.jpeg', '.png', '.jpg', '.exe', '.tif', '.7z', '.py', '.bmp', '.ico', '.pdf', '.dll', '.tar', '.tgz', '.rar', '.jar'
    $name = [System.IO.Path]::GetFileName($Path)
    $extension = [System.IO.Path]::GetExtension($Path)
    if ($extension -in '.zip', '.gz') { return 'is zip/gz archive' }
    if ($extension -in $ignoredExtensions) { return 'is one of the ignored filetypes' }
    if ($name -like '*.sanitised.*' -or $name -like '*.sanitised') { return 'already sanitised file' }
    try { if (Test-StrippyBinaryFile $Path) { return 'has binary content' } }
    catch { return "could not be read: $($_.Exception.Message)" }
    return $null
}

# The folder an archive unpacks to: logs.zip -> logs-zip, server.log.gz -> server.log-gz (next to the archive)
function Get-StrippyArchiveFolder {
    param ([string] $ArchivePath)
    $leaf = [System.IO.Path]::GetFileNameWithoutExtension($ArchivePath) + '-' + [System.IO.Path]::GetExtension($ArchivePath).TrimStart('.')
    return [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($ArchivePath), $leaf.Replace(' ', '_'))
}

# Unpacks one .zip or .gz. An existing unpack folder is replaced. Returns the unpack folder.
function Expand-StrippyArchive {
    param ([string] $ArchivePath)

    $destination = Get-StrippyArchiveFolder $ArchivePath
    if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Recurse -Force }
    [void][System.IO.Directory]::CreateDirectory($destination)

    if ([System.IO.Path]::GetExtension($ArchivePath) -eq '.gz') {
        $target = [System.IO.Path]::Combine($destination, [System.IO.Path]::GetFileNameWithoutExtension($ArchivePath))
        $in = [System.IO.File]::OpenRead($ArchivePath)
        try {
            $gzip = New-Object System.IO.Compression.GZipStream -ArgumentList $in, ([System.IO.Compression.CompressionMode]::Decompress)
            try {
                $out = [System.IO.File]::Create($target)
                try { $gzip.CopyTo($out) } finally { $out.Dispose() }
            }
            finally { $gzip.Dispose() }
        }
        finally { $in.Dispose() }
    }
    else {
        try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch { }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath, $destination)
    }
    return $destination
}

# Unpacks archives, then the archives found inside those, up to MaxDepth levels. Returns the unpack folders.
function Expand-StrippyArchiveTree {
    param ([string[]] $Archives, [int] $MaxDepth = 1)

    $folders = New-Object 'System.Collections.Generic.List[string]'
    $queue = @($Archives | Where-Object { $_ -and (Test-StrippyArchive $_) })
    $depth = 0
    while ($queue.Count -gt 0 -and $depth -lt $MaxDepth) {
        $next = @()
        foreach ($archive in $queue) {
            try {
                $folder = Expand-StrippyArchive $archive
                $folders.Add($folder)
                Write-StrippyLog unzipr Trace "Unpacked $archive to $folder"
                $next += @(Get-ChildItem -LiteralPath $folder -Recurse -File | ForEach-Object { $_.FullName } | Where-Object { Test-StrippyArchive $_ })
            }
            catch {
                Write-StrippyLog unzipr Warning "Could not unpack '$archive' - it will be skipped. $($_.Exception.Message)"
            }
        }
        $queue = $next
        $depth++
    }
    return , $folders.ToArray()
}

<#
    Works out what -File points at and which files are candidates.
    Returns { Mode = folder|file|archive|wildcard; Root; Files = [full paths]; DefaultOutputFolder }
#>
function Resolve-StrippyInput {
    param ([string] $File, [bool] $Recurse, [bool] $UnpackZip)

    $maxDepth = 20
    $full = Resolve-StrippyPath $File

    if (Test-Path -LiteralPath $full -PathType Container) {
        $root = $full.TrimEnd('\', '/')
        if (-not $root) { $root = $full }
        if ($Recurse) { $files = @(Get-ChildItem -LiteralPath $root -File -Recurse -Depth $maxDepth | ForEach-Object { $_.FullName }) }
        else { $files = @(Get-ChildItem -LiteralPath $root -File | ForEach-Object { $_.FullName }) }

        if ($UnpackZip) {
            $depth = 1
            if ($Recurse) { $depth = $maxDepth }
            $folders = Expand-StrippyArchiveTree -Archives $files -MaxDepth $depth
            if ($Recurse) {
                $files = @(Get-ChildItem -LiteralPath $root -File -Recurse -Depth $maxDepth | ForEach-Object { $_.FullName })
            }
            else {
                # Without -Recurse only the top level is scanned, but an archive the user asked to unpack is read in full
                foreach ($folder in $folders) { $files += @(Get-ChildItem -LiteralPath $folder -File -Recurse | ForEach-Object { $_.FullName }) }
            }
        }
        return [pscustomobject]@{ Mode = 'folder'; Root = $root; Files = $files; DefaultOutputFolder = "$root.sanitised" }
    }

    if (Test-Path -LiteralPath $full -PathType Leaf) {
        if ([System.IO.Path]::GetExtension($full) -in '.zip', '.gz') {
            $root = Expand-StrippyArchive $full
            Write-StrippyLog ioproc Message "Unpacked archive to: $root"
            if ($Recurse) {
                $nested = @(Get-ChildItem -LiteralPath $root -Recurse -File | ForEach-Object { $_.FullName })
                [void](Expand-StrippyArchiveTree -Archives $nested -MaxDepth ($maxDepth - 1))
                $files = @(Get-ChildItem -LiteralPath $root -File -Recurse -Depth $maxDepth | ForEach-Object { $_.FullName })
            }
            else {
                $files = @(Get-ChildItem -LiteralPath $root -File -Depth 1 | ForEach-Object { $_.FullName })
            }
            return [pscustomobject]@{ Mode = 'archive'; Root = $root; Files = $files; DefaultOutputFolder = "$root.sanitised" }
        }
        $parent = [System.IO.Path]::GetDirectoryName($full)
        return [pscustomobject]@{ Mode = 'file'; Root = $parent; Files = @($full); DefaultOutputFolder = $parent }
    }

    if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($File)) {
        $files = @(Get-Item -Path $File -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.FullName })
        if ($files.Count -gt 0) {
            $root = Get-StrippyCommonRoot $files
            return [pscustomobject]@{ Mode = 'wildcard'; Root = $root; Files = $files; DefaultOutputFolder = $root }
        }
    }

    throw "$File does not exist"
}

#endregion

###############################################################################################################
#region Main flow

# Command line beats the config file, the config file beats the default
function Get-StrippyEffectiveSwitch {
    param ([hashtable] $Options, [hashtable] $ConfigSwitches, [string] $Name)
    if ($Options.Bound -contains $Name) { return $Options[$Name] }
    if ($ConfigSwitches -and $ConfigSwitches.ContainsKey($Name)) { return $ConfigSwitches[$Name] }
    return $Options[$Name]
}

<#
    Finds and loads the config. Returns the merged config hashtable with an extra 'Path' entry ('' for built-in rules).
#>
function Get-StrippyConfig {
    param ([hashtable] $Options, [string] $TargetPath)

    $path = ''
    if ($Options.ConfigFile) {
        $path = Resolve-StrippyPath $Options.ConfigFile
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Stop-Strippy "Could not find the specified config file: $($Options.ConfigFile)" }
    }
    else {
        $candidates = @()
        if ($TargetPath) {
            if (Test-Path -LiteralPath $TargetPath -PathType Container) { $candidates += [System.IO.Path]::Combine($TargetPath, 'strippy.conf') }
            elseif (Test-Path -LiteralPath $TargetPath -PathType Leaf) { $candidates += [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($TargetPath), 'strippy.conf') }
        }
        if ($Options.ScriptRoot) { $candidates += [System.IO.Path]::Combine($Options.ScriptRoot, 'strippy.conf') }
        foreach ($candidate in $candidates) {
            Write-StrippyLog cfgchk Trace "Looking for a config file at $candidate"
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $path = $candidate; break }
        }
    }

    if ($path) {
        Write-StrippyLog cfgchk Message "Using config file: $path"
        try { $parsed = ConvertFrom-StrippyConfig ([System.IO.File]::ReadAllText($path)) }
        catch { Stop-Strippy "CONFIG: $($_.Exception.Message)" }
        foreach ($warning in $parsed.Warnings) { Write-StrippyLog cfgchk Warning "CONFIG: $warning" }
        $config = Merge-StrippyConfig $parsed
        $config.Path = $path
        return $config
    }

    # No config anywhere. Built-in rules are better than nothing but the user has to agree to that.
    if ($Options.Silent) {
        Stop-Strippy "Unable to locate a config file. Specify one with -ConfigFile or place strippy.conf next to the target or in $($Options.ScriptRoot)"
    }
    Write-StrippyLog cfgchk Question "Unable to find a strippy.conf file. This file contains the rules that are used to determine sensitive data.
    Continuing now will use the default configuration and only sanitise IP addresses and Windows UNC paths.
    Would you like to continue with only these?"
    $answer = Read-Host "y/n> (y) "
    Write-StrippyLog cfgchk Trace "User answered with: '$answer'"
    if ($answer -eq 'n') {
        Stop-Strippy "Use the -MakeConfig argument to create a strippy.conf file and start adding sensitive data rules"
    }
    $config = Get-StrippyDefaultConfig
    $config.Rules = Get-StrippyDefaultRules
    $config.Path = ''
    return $config
}

function Invoke-StrippyMain {
    param ([hashtable] $Options)

    $started = Get-Date
    Write-StrippyLog init Trace "-=H||||||||    Starting Strippy Execution    |||||||||H=-"
    Write-StrippyLog init Trace "   ||    Version:    3.0.0                         ||"
    foreach ($key in ($Options.Keys | Sort-Object)) {
        if ($key -ne 'Bound') { Write-StrippyLog params Trace ("{0,-28}{1}" -f "$key`:", $Options[$key]) }
    }
    Write-StrippyLog params Trace "Explicitly set on command line: $($Options.Bound -join ', ')"

    if ($Options.MakeConfig) {
        New-StrippyConfigFile -Path (Resolve-StrippyPath 'strippy.conf') -Silent $Options.Silent
        return
    }

    ## Config
    Write-StrippyLog timing Trace "[START] Config Checking/Loading"
    $targetPath = Resolve-StrippyPath $Options.File
    $config = Get-StrippyConfig -Options $Options -TargetPath $targetPath

    $recurse = [bool](Get-StrippyEffectiveSwitch $Options $config.Switches 'Recurse')
    $inPlace = [bool](Get-StrippyEffectiveSwitch $Options $config.Switches 'InPlace')
    $unpackZip = [bool](Get-StrippyEffectiveSwitch $Options $config.Switches 'UnpackZip')
    $noHeader = [bool](Get-StrippyEffectiveSwitch $Options $config.Switches 'NoHeaderInOutput')
    $silent = [bool](Get-StrippyEffectiveSwitch $Options $config.Switches 'Silent')
    $maxThreads = [Math]::Max(1, [Math]::Min(64, [int](Get-StrippyEffectiveSwitch $Options $config.Switches 'MaxThreads')))
    (Get-StrippyLogState).Silent = $silent
    Write-StrippyLog params Trace "Effective switches: Recurse=$recurse InPlace=$inPlace UnpackZip=$unpackZip NoHeaderInOutput=$noHeader Silent=$silent MaxThreads=$maxThreads"

    try { $ruleSet = New-StrippyRuleSet $config.Rules }
    catch { Stop-Strippy "CONFIG: $($_.Exception.Message)" }
    foreach ($warning in $ruleSet.Warnings) { Write-StrippyLog cfgchk Warning "CONFIG: $warning" }
    if ($ruleSet.Capture.Length -eq 0) {
        Write-StrippyLog cfgchk Warning "The config contains no usable sanitisation rules. No sensitive data will be found."
    }
    $ignoredSet = New-StrippyIgnoredSet $config.IgnoredStrings
    Write-StrippyLog timing Trace "[END] Config Checking/Loading"

    ## Previously generated keys
    $importedEntries = @()
    $previousFiles = @()
    $keyFilePath = ''
    if ($Options.KeyFile) {
        Write-StrippyLog timing Trace "[START] Processing KeyFile"
        $keyFilePath = Resolve-StrippyPath $Options.KeyFile
        if (-not (Test-Path -LiteralPath $keyFilePath -PathType Leaf)) { Stop-Strippy "KeyFile '$($Options.KeyFile)' could not be found or is not a file" }
        try { $imported = Import-StrippyKeyList $keyFilePath }
        catch { Stop-Strippy $_.Exception.Message }
        $importedEntries = $imported.Entries
        $previousFiles = $imported.Files
        Write-StrippyLog keychk Message "Imported $($importedEntries.Length) key(s) from $keyFilePath"
        Write-StrippyLog timing Trace "[END] Processing KeyFile"
    }

    ## Input and output locations
    Write-StrippyLog timing Trace "[START] Input/Output Discovery Process"
    Write-StrippyLog strppy Message "Attempting to Sanitise $($Options.File)"
    try { $target = Resolve-StrippyInput -File $Options.File -Recurse $recurse -UnpackZip $unpackZip }
    catch { Stop-Strippy $_.Exception.Message }

    $outputFolder = $target.DefaultOutputFolder
    $alternateOutput = $Options.AlternateOutputFolder
    if (-not $alternateOutput) { $alternateOutput = ConvertTo-StrippyNativePath $config.AlternateOutputFolder }
    if ($alternateOutput -and -not $inPlace) {
        $outputFolder = (Resolve-StrippyPath $alternateOutput).TrimEnd('\', '/')
        Write-StrippyLog ioproc Message "Using Alternate Folder for output: $outputFolder"
    }

    $keyListPath = $Options.AlternateKeyListOutput
    if (-not $keyListPath) { $keyListPath = ConvertTo-StrippyNativePath $config.AlternateKeyListOutput }
    if (-not $keyListPath) { $keyListPath = ConvertTo-StrippyNativePath $config.KeyFileName }
    if (-not $keyListPath) { $keyListPath = 'KeyList.txt' }
    $keyListPath = Resolve-StrippyPath $keyListPath
    if (Test-Path -LiteralPath $keyListPath -PathType Container) { $keyListPath = [System.IO.Path]::Combine($keyListPath, 'KeyList.txt') }

    # Never sanitise our own files, or anything already in the output folder
    $excluded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($p in @($keyListPath, $keyFilePath, $config.Path, (Get-StrippyLogState).Path)) { if ($p) { [void]$excluded.Add($p) } }
    $outputPrefix = ''
    if (-not $inPlace -and $outputFolder.StartsWith($target.Root + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        $outputPrefix = $outputFolder + [System.IO.Path]::DirectorySeparatorChar
    }

    $plan = New-Object 'System.Collections.Generic.List[object]'
    $skipped = 0
    foreach ($source in ($target.Files | Sort-Object)) {
        $reason = $null
        if ($excluded.Contains($source)) { $reason = 'is a strippy config, keylist or log file' }
        elseif ($outputPrefix -and $source.StartsWith($outputPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { $reason = 'is inside the output folder' }
        else { $reason = Get-StrippySkipReason $source }
        if ($reason) {
            $skipped++
            Write-StrippyLog ioproc Trace "$source will not be sanitised - $reason"
            continue
        }
        $plan.Add([pscustomobject]@{
                Source      = $source
                Destination = Get-StrippyOutputPath -Source $source -Root $target.Root -OutputFolder $outputFolder -InPlace $inPlace
                DisplayName = Get-StrippyRelativePath $source $target.Root
            })
    }
    if ($skipped -gt 0) { Write-StrippyLog ioproc Message "Skipping $skipped file(s) that are binary, archives, ignored types or already sanitised" }
    if ($plan.Count -eq 0) { Stop-Strippy "Could not find any appropriate files to sanitise in $($Options.File)" }
    Write-StrippyLog ioproc Trace "$($plan.Count) file(s) to sanitise. Output folder: $outputFolder. Keylist: $keyListPath"
    Write-StrippyLog timing Trace "[END] Input/Output Discovery Process"

    ## Pass 1 - find the sensitive data in every file
    $failed = 0
    Write-StrippyLog timing Trace "[START] Scouting file(s) with rules"
    Write-StrippyLog hdstrp Message "Searching through $($plan.Count) input file(s) for sensitive data"
    $scoutArguments = @($plan | ForEach-Object { @{ Path = $_.Source; RuleSet = $ruleSet; IgnoredSet = $ignoredSet } })
    $scoutResults = Invoke-StrippyParallel -FunctionName 'Find-StrippyKeys' -ArgumentSets $scoutArguments -MaxThreads $maxThreads -Activity 'Strippy: finding sensitive data' -ShowProgress (-not $silent)

    $unreadable = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ruleTotals = New-Object 'long[]' $ruleSet.Capture.Length
    foreach ($result in $scoutResults) {
        if ($result.Error) {
            $failed++
            [void]$unreadable.Add($result.Path)
            Write-StrippyLog sctstr Error "Could not search $($result.Path) - it will not be sanitised. $($result.Error)"
            continue
        }
        for ($i = 0; $i -lt $result.RuleHits.Length; $i++) { $ruleTotals[$i] += $result.RuleHits[$i] }
        Write-StrippyLog sctstr Debug "$($result.FoundValues.Count) key(s) found in $($result.Path)"
    }
    for ($i = 0; $i -lt $ruleTotals.Length; $i++) {
        $rule = $ruleSet.Capture[$i]
        Write-StrippyLog sctstr Trace "Rule hits: $($ruleTotals[$i]) for '$($rule.Pattern)' -> $($rule.Alias)"
    }
    Write-StrippyLog timing Trace "[END] Scouting file(s) with rules"

    ## Merge into a single key list and label everything
    Write-StrippyLog timing Trace "[START] Merging Keylists"
    $keys = New-StrippyKeyMap -ScoutResults $scoutResults -ImportedEntries $importedEntries
    $keyRegex = New-StrippyKeyRegex $keys.Map
    Write-StrippyLog timing Trace "[END] Merging Keylists"

    $header = $config.SanitisedFileFirstLine
    if ($noHeader) { $header = '' }

    # Save the keylist before touching any output, in case the sanitise pass is interrupted
    if ($keys.Entries.Length -gt 0) {
        Export-StrippyKeyList -Path $keyListPath -Entries $keys.Entries -FileLines $previousFiles -HeaderTemplate $config.KeyListFirstLine -TargetName $Options.File
    }

    ## Pass 2 - replace the keys in every file
    Write-StrippyLog timing Trace "[START] Sanitising File(s)"
    Write-StrippyLog hdstrp Message "Sanitising file(s) with $($keys.Entries.Length) key(s)"
    $timestamp = (Get-Date).ToString()
    $sanitiseArguments = @($plan | Where-Object { -not $unreadable.Contains($_.Source) } | ForEach-Object {
            @{ Source = $_.Source; Destination = $_.Destination; DisplayName = $_.DisplayName; RuleSet = $ruleSet; KeyRegex = $keyRegex; KeyMap = $keys.Map; HeaderTemplate = $header; Timestamp = $timestamp }
        })
    $sanitiseResults = @()
    if ($sanitiseArguments.Count -gt 0) {
        $sanitiseResults = Invoke-StrippyParallel -FunctionName 'Protect-StrippyFile' -ArgumentSets $sanitiseArguments -MaxThreads $maxThreads -Activity 'Strippy: sanitising files' -ShowProgress (-not $silent)
    }

    $fileLines = New-Object 'System.Collections.Generic.List[string]'
    foreach ($line in $previousFiles) { $fileLines.Add($line) }
    $written = 0
    foreach ($result in $sanitiseResults) {
        if ($result.Error) {
            $failed++
            Write-StrippyLog sanstr Error "Could not sanitise $($result.Source): $($result.Error)"
            continue
        }
        $written++
        $fileLines.Add("$timestamp - $($result.Destination)")
        Write-StrippyLog sanstr Trace "$($result.Replacements) replacement(s): $($result.Source) -> $($result.Destination)"
    }
    Write-StrippyLog timing Trace "[END] Sanitising File(s)"

    ## Wrap up
    Write-StrippyLog timing Trace "[START] Saving Keylist to disk"
    if ($keys.Entries.Length -gt 0) {
        Export-StrippyKeyList -Path $keyListPath -Entries $keys.Entries -FileLines $fileLines.ToArray() -HeaderTemplate $config.KeyListFirstLine -TargetName $Options.File
        Write-StrippyLog outkey Message "Exported KeyList to $keyListPath"
        $summary = $keys.Entries | Group-Object -Property { $_.Alias -replace '\d+$', '' } | Sort-Object -Property Name | ForEach-Object { "$($_.Name): $($_.Count)" }
        Write-StrippyLog strppy Message "Keys: $($summary -join ', ')"
    }
    else {
        Write-StrippyLog outkey Warning "No Keys were found to show or output. There will be no key file"
    }
    Write-StrippyLog timing Trace "[END] Saving Keylist to disk"

    $where = $outputFolder
    if ($inPlace) { $where = 'in place' }
    Write-StrippyLog strppy Message "Sanitised $written file(s) -> $where"
    Write-StrippyLog timing Message "Script completed in $(((Get-Date) - $started).TotalSeconds) seconds"

    if ($failed -gt 0) { Stop-Strippy "$failed file(s) could not be processed. Check the messages above before sharing any output" }
}

#endregion

###############################################################################################################
# Entry point
#   Dot-sourcing with no arguments (or setting STRIPPY_IMPORT_ONLY) loads the functions above and stops here.
#   That is the hook the unit tests use.

if ($env:STRIPPY_IMPORT_ONLY -or ($MyInvocation.InvocationName -eq '.' -and $PSBoundParameters.Count -eq 0)) { return }

if ($h -or $help -or (-not $File -and -not $makeConfig)) {
    Get-Help $PSCommandPath -Detailed
    exit 0
}

$strippyOptions = @{
    File                   = $File
    KeyFile                = $KeyFile
    ConfigFile             = $ConfigFile
    Recurse                = [bool]$Recurse
    InPlace                = [bool]$InPlace
    UnpackZip              = [bool]$unpackZip
    NoHeaderInOutput       = [bool]$noHeaderInOutput
    Silent                 = [bool]$Silent
    MaxThreads             = $MaxThreads
    MakeConfig             = [bool]$makeConfig
    AlternateKeyListOutput = $AlternateKeyListOutput
    AlternateOutputFolder  = $AlternateOutputFolder
    ScriptRoot             = $PSScriptRoot
    Bound                  = @($PSBoundParameters.Keys)
}
if (-not $strippyOptions.AlternateKeyListOutput) { $strippyOptions.AlternateKeyListOutput = $ko }
if (-not $strippyOptions.AlternateOutputFolder) { $strippyOptions.AlternateOutputFolder = $o }

$strippyExitCode = 0
try {
    Initialize-StrippyLog -Enabled ([bool]$log) -ShowDebug ([bool]$showDebug) -Silent ([bool]$Silent) -Path (Resolve-StrippyPath $logfile) -MaxSize $MaxLogFileSize -History $LogHistory
    Invoke-StrippyMain -Options $strippyOptions | Out-Null
}
catch {
    $strippyExitCode = 1
    if (-not $_.Exception.Data['StrippyLogged']) {
        Write-StrippyLog fatal Error "Unexpected failure: $($_.Exception.Message)`n$($_.ScriptStackTrace)"
    }
}
finally {
    Close-StrippyLog
}
exit $strippyExitCode
