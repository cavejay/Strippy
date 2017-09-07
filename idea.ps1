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



## Write some code for the child threads to execute
$ThreadCode = {
    $x = 0
    $time = Get-Random -Maximum 200 -SetSeed $(Get-Date).Millisecond
    While ($x -lt 100){
        $x++

        Write-Progress -Activity "Testing" -Status "Testing" -PercentComplete $X -completed
        Start-Sleep -Milliseconds $time
    }
    Write-Progress -Activity "Testing" -Status "Testing" -PercentComplete 100 -Completed
    "Annnd we're done."
}

## Kill any current jobs in the sessions and get rid of them
Get-Job | Stop-Job
Get-Job | Remove-Job

## Loop control
$x = 0

## While we are still launching threads or wait for them to close
While (($x -lt 10) -or ($(Get-Job -State "Running").count -gt 0)){
    ## While there are less than three jobs running and less than 10 have started
    While (($(Get-Job -State "Running").count -lt 3) -and ($x -lt 10)){
        Start-Job -ScriptBlock $ThreadCode | Out-Null
        $x++
    }
    
    ## Main portion - Read all jobs
    ForEach ($Job in Get-Job) {
        ## Read all children of all jobs
        ForEach ($Child in $Job.ChildJobs){
            ## Get the latest progress object of the job
            $Progress = $Child.Progress[$Child.Progress.Count - 1]
            
            ## If there is a progress object returned write progress
            If ($Progress.Activity -ne $Null){
                Write-Progress  -Activity $Job.Name 
                                -Status $Progress.StatusDescription 
                                -PercentComplete $Progress.PercentComplete 
                                -ID $Job.ID
            }
            
            ## If this child is complete then stop writing progress
            If ($Progress.PercentComplete -eq 100){
                Write-Progress  -Activity $Job.Name 
                                -Status $Progress.StatusDescription 
                                -PercentComplete $Progress.PercentComplete 
                                -ID $Job.ID 
                                -Complete
                ## Clear all progress entries so we don't process it again
                $Child.Progress.Clear()
            }
        }
    }
    
    Get-Job -State "Completed" | Receive-Job
    
    ## Setting for loop processing speed
    Start-Sleep -Milliseconds 200
}

Get-Job | Wait-Job | Out-Null
Get-Job | Receive-Job