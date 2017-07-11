<#
.SYNOPSIS
    Checks inputs and outputs to create a testing framework for strippy

.DESCRIPTION
    Run a command and then do the thing and check the output

.EXAMPLE
    // todo

.NOTES
    Author: Michael Ball
    Version: 170310

.LINK
    https://github.com/cavejay/Strippy
#>

# 2 Check there's a tests dir

# 2 Make a tests/testoutput dir

# 1 run a *.test file (piping it's output to tests/testoutput/std.*.out) and compare their output in tests/testoutput with the *.out files that match what was created.
powershell .\test1.test > .\tests\testoutput\std.test1.out

# 1 Record as an error if there's a difference and a pass if there is none.

# 2 repeat for all .test files

# 2 optionally delete the tests dir