<#
    .synopsis
        Used to easily bump the version of the script on master + apply a tag       
#>

param (
    [Parameter(Position = 0, Mandatory = $true)][ValidateSet('minor', 'major', 'patch')][String] $semver,
    [Parameter(Position = 1, Mandatory = $true)][String] $message,
    [switch] $forceApply
)

# is git accessible
if ($null -eq (Get-Command 'git.exe' -ErrorAction 'SilentlyContinue')) {
    Write-Error "Could not find git exe on path"
    throw 2
}
Write-Host -ForegroundColor DarkGray 'Found Git in path'

# is git on master
$branch = ((git status)[0] -split ' ')[2]
if ($branch -ne 'master') {
    Write-Error "Tagging and script versioning should be done on master. Currently using branch $branch"
    throw 1
}
Write-host -ForegroundColor DarkGray 'Current branch is master'

# find v. from top comment 
$version = (select-string -Pattern 'Version: (\d+\.\d+\.\d+)' -Path ./strippy.ps1).Matches[0].Value -split ' ' | Select-Object -Index 1

write-host -ForegroundColor Magenta "Found current version as: $version"

# bump version
$splits = $version -split '\.'

switch ($semver) {
    major {
        $splits = ([int]$splits[0] + 1), 0, 0
    }
    minor {
        $splits = $splits[0], ([int]$splits[1] + 1), 0
    }
    patch {
        $splits[2] = [int]$splits[2] + 1 
    }
}

$bumpedVersion = $splits -join '.'

write-host -ForegroundColor Cyan "Version is being bumped to '$bumpedVersion' w/ message: '$message'"
write-host -ForegroundColor Cyan "Change will affect $((Select-String -Pattern ('v?'+[regex]::Escape($version)) -Path ./strippy.ps1 ).LineNumber.length) lines of ./strippy.ps1"

if (!$forceApply) {
    $ans = Read-Host "`tApply, tag and push? y/(n)"
    
    if ($ans -ne 'y') {
        write-host -ForegroundColor white "No changes will be made"
        exit
    }
} else {
    write-host -ForegroundColor Red "CHOO CHOO No brakes on this train"
}

# replace all instances of %%version%% with top comment version
(get-content -raw -Encoding UTF8 -Path './strippy.ps1') -replace ('v?'+[regex]::Escape($version)), $bumpedVersion | Out-File './strippy.ps1' -Encoding utf8

# checkin the changes

write-host -ForegroundColor Green "Checking in modified strippy.ps1 to master"
git add './strippy.ps1'
git commit -m "Bumped version from $version -> $bumpedVersion \
$message"

write-host -ForegroundColor Green "Tagging the branch with 'v$bumpedVersion'"
# tag the branch
git tag "v$bumpedVersion"

write-host -ForegroundColor Green "Pushing changes to Origin"
# update tags in origin
git push origin --tags
