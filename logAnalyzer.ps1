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

$data | Sort-Object -Property dSeconds -Descending | Where-Object -Property Section -EQ 'Merging Keylists'