<#
    This is the first test
#>
Set-Location $input.strippy_path
.\strippy.ps1 -config .\tests\Base.IPs\config.json -file .\tests\Base.IPs\file.in -out .\tests\test1\output\test.sanitised.log.test1.out -keyout .\tests\test1output\KeyList.txt.test1.out
