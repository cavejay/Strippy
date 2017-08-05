<#
    Test that when there are no rules there is no sanitisation
#>

Set-Location $input.strippy_path

.\strippy -file .\tests\file.in -out 