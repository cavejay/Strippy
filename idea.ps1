$jobs = @(0);

$goal = 100;

$export_functions = {
    function rc () {
        $vals = @();

        $goal = 100;
        $current = 0;

        while ($true) {
            $val = Get-Random -Minimum 0 -Maximum 100
            $vals += $val
            if ($val -gt 20) {
                $current++
            }

            Write-Progress -Id 1 -Activity "Doing Activity" -PercentComplete $current -Completed

            Start-Sleep -Milliseconds 10

            if ($current -eq $goal) {
                break;
            }
        }

        $input.word
    }
}

Get-Job | Stop-Job
Get-job | Remove-Job

$p = @{}
$p.word = "lolololololol"
$object = New-Object -TypeName PSObject -Prop $p

$j = Start-Job -InputObject $object -ScriptBlock { rc } -InitializationScript $export_functions

## While we are still launching threads or wait for them to close
While ($(Get-Job -State "Running").count -gt 0) {
    ## Main portion - Read all jobs
    ForEach ($Job in Get-Job) {
        ## Read all children of all jobs
        ForEach ($Child in $Job.ChildJobs){
            ## Get the latest progress object of the job
            $Progress = $Child.Progress[$Child.Progress.Count - 1]
            
            ## If there is a progress object returned write progress
            If ($Progress.Activity -ne $Null){
                Write-Progress  -Activity $Job.Name -Status $Progress.StatusDescription -PercentComplete $Progress.PercentComplete -ID $Job.ID
            }
            
            ## If this child is complete then stop writing progress
            If ($Progress.PercentComplete -eq 100){
                Write-Progress  -Activity $Job.Name -Status $Progress.StatusDescription  -PercentComplete $Progress.PercentComplete  -ID $Job.ID  -Complete
                ## Clear all progress entries so we don't process it again
                $Child.Progress.Clear()
            }
        }
    }
    
    Get-Job -State "Completed" | Receive-Job
    
    ## Setting for loop processing speed
    Start-Sleep -Milliseconds 1
}

Get-Job | Wait-Job | Out-Null
Get-Job | Receive-Job
Get-Job | Remove-Job