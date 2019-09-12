<#
    Small script to analyse logs made by Strippy
#>

[cmdletbinding()]
param (
    [string]$logfile = "strippy.log",
    [String]$section
)

function timeForSection ($section) {
    $startLine = "T TIMING.+\[START\] $([Regex]::Escape($section))"
    $endLine = "T TIMING.+\[END\] $([Regex]::Escape($section))"
    
    write-host "Calculating time taken to perform section: '$section'"
    
    # find the start and end lines
    
    $start = $log | Select-String -Pattern $startLine
    $end = $log | Select-String -Pattern $endLine
    
    $startTime = ($start -split '\s+')[3]
    $startDate = ($start -split '\s+')[2] -split '-'; [array]::Reverse($startDate); $startDate = $startDate -join '-'
    $endTime = ($end  -split '\s+')[3]
    $endDate = ($end -split '\s+')[2] -split '-'; [array]::Reverse($endDate); $endDate = $endDate -join '-'
    
    return New-TimeSpan -Start ("$startDate $starttime" | get-date) -end ("$enddate $endtime" | get-date)
}

$log = get-content -path $logfile

# find sections
$sectionPrefix = "T TIMING.+\[START\]"
$sectionList = (($log | Select-String -Pattern $sectionPrefix) | % {($_ -split "\[START\] ")[1]}) | Select-Object -Unique

# If only a specific section
if ($section -ne '' -and $sectionList -notcontains $section) {
    Write-Error "Invalid section. '$section' was not found in $logfile"
    return
} elseif ($section) {
    return timeForSection $section | Select-Object -Property "TotalSeconds"
}

$times = @()
foreach ($section in $sectionList) {
    $times += New-Object PSObject -Property @{
        'section'=$section;
        'time'=(timeForSection $section)
    }
}

return $times | sort -Property time -Descending

<#

Alt implementation

PARAM (
    $logfile = "strippy.log"
)

# find every TIMING line
$lines = Get-Content $logfile | Select-String -Pattern "^T TIMING "

# $lines
$sectionTimes = @{}
forEach ($l in $lines) {
    try {
        # If this was a job, ignore it >.<
        if ($l -match '\[Job_\w{6}\]') {
            continue
        }
        # if it's a starting line
        if ($l -match '\[START\]') {
            $components = $l -split '\[START\]\s+'
            $sectionTimes[$components[1]] = @{bTime = ''; eTime = ''; delta = ''}
            
            # Get the time
            $sectionTimes[$components[1]].bTime = get-date (($components[0] -split 'TIMING ')[1])
        }
        elseif ($l -match '\[END\]') {
            $components = $l -split '\[END\]\s+'
            $sectionTimes[$components[1]].eTime = get-date (($components[0] -split 'TIMING ')[1])
            $sectionTimes[$components[1]].delta = New-TimeSpan -Start $sectionTimes[$components[1]].bTime -End (get-date (($components[0] -split 'TIMING ')[1]))
        }
    }
    catch {
        Write-Warning "Could not process section '$l' very well"
    }
}

$data = @()
foreach ($s in $sectionTimes.Keys) {
    $_tmp = $sectionTimes.$s
    $_tmp.section = $s
    $_tmp.dSeconds = $sectionTimes.$s.delta.totalSeconds
    $data += New-Object -TypeName psobject -Property $_tmp
}

$data #| Sort-Object -Property dSeconds -Descending | Where-Object -Property Section -EQ 'Merging Keylists'

#>

