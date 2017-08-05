<#
    This is the first test
#>
Set-Location $input.strippy_path
.\strippy.ps1 -config .\tests\test1\testConfig.test1.json -file .\tests\test1\test.log.test1.in -out .\tests\test1\output\test.sanitised.log.test1.out -keyout .\tests\test1output\KeyList.txt.test1.out
