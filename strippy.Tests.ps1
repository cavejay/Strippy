<#
    Pester 5 tests for strippy.ps1

        Invoke-Pester ./strippy.Tests.ps1

    strippy.ps1 is a single file script, not a module. Dot-sourcing it with no arguments (or with the
    STRIPPY_IMPORT_ONLY environment variable set) only loads its functions, which is how the unit tests get at them.
    The end to end tests further down run the script exactly as a user would.
#>

BeforeAll {
    $script:StrippyScript = Join-Path $PSScriptRoot 'strippy.ps1'
    $script:TestData = Join-Path $PSScriptRoot 'tests'
    $script:ConfigFiles = Join-Path $PSScriptRoot 'configFiles'

    $env:STRIPPY_IMPORT_ONLY = '1'
    try { . $script:StrippyScript }
    finally { Remove-Item Env:STRIPPY_IMPORT_ONLY -ErrorAction SilentlyContinue }

    function New-TestFolder {
        param ([string] $Name)
        $path = Join-Path $TestDrive $Name
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        return $path
    }

    function New-TestRuleSet {
        param ([string] $RulesText)
        return New-StrippyRuleSet (ConvertFrom-StrippyConfig "[ Rules ]`n$RulesText").Rules
    }

    function Write-TestFile {
        param ([string] $Path, [string] $Text)
        [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($false))
    }

    $script:BasicConfig = @'
[ Config ]
IgnoredStrings="null","0.0.0.0"
SanitisedFileFirstLine="Sanitised {2}{1}"
KeyListFirstLine="Keys{1}"

[ Rules ]
"((?:\d{1,3}\.){3}\d{1,3})(?!\d)"="Address"
"\\\\([\w\-.]*?)\\"="Hostname"
'@
}

Describe 'ConvertFrom-StrippyConfig' {
    It 'parses the shipped v1 config <_> and every rule compiles' -ForEach 'nam.conf', 'dt-managed.conf' {
        $text = [System.IO.File]::ReadAllText((Join-Path $script:ConfigFiles $_))
        $parsed = ConvertFrom-StrippyConfig $text
        $parsed.Rules.Length | Should -BeGreaterThan 40
        $parsed.Settings.IgnoredStrings | Should -Contain '127.0.0.1'
        $parsed.Settings.IgnoredStrings | Should -Contain ''
        $parsed.Settings.SanitisedFileFirstLine | Should -Be 'This file was Sanitised at {0}.{1}{1}'
        { New-StrippyRuleSet $parsed.Rules } | Should -Not -Throw
    }

    It 'finds the delete rule in nam.conf' {
        $parsed = ConvertFrom-StrippyConfig ([System.IO.File]::ReadAllText((Join-Path $script:ConfigFiles 'nam.conf')))
        $delete = @($parsed.Rules | Where-Object { $_.Type -eq 'delete' })
        $delete.Count | Should -Be 1
        $delete[0].Pattern | Should -Be '^.*resolved to.*$'
    }

    It 'finds the five list rules in dt-managed.conf' {
        $parsed = ConvertFrom-StrippyConfig ([System.IO.File]::ReadAllText((Join-Path $script:ConfigFiles 'dt-managed.conf')))
        @($parsed.Rules | Where-Object { $_.Type -eq 'list' }).Count | Should -Be 5
    }

    It 'parses list rules whose regex contains quotes' {
        $parsed = ConvertFrom-StrippyConfig "[ Rules ]`n`"Buildings:`"(.+?)`"`"=`"Building`",`";`""
        $parsed.Rules.Length | Should -Be 1
        $parsed.Rules[0].Type | Should -Be 'list'
        $parsed.Rules[0].Pattern | Should -Be 'Buildings:"(.+?)"'
        $parsed.Rules[0].Alias | Should -Be 'Building'
        $parsed.Rules[0].Delimiter | Should -Be ';'
    }

    It 'keeps = characters that are part of a rule regex' {
        $parsed = ConvertFrom-StrippyConfig "[ Rules ]`n`"hostname=(.*?),`"=`"Hostname`""
        $parsed.Rules[0].Pattern | Should -Be 'hostname=(.*?),'
        $parsed.Rules[0].Alias | Should -Be 'Hostname'
    }

    It 'unescapes quotes in IgnoredStrings' {
        $text = [System.IO.File]::ReadAllText((Join-Path (Join-Path $script:TestData 'ignoreTests') 'strippy_weirdIgnores.conf'))
        $parsed = ConvertFrom-StrippyConfig $text
        $parsed.Settings.IgnoredStrings | Should -Contain 'null'
        $parsed.Settings.IgnoredStrings | Should -Contain '"pleaseignore"'
        $parsed.Settings.IgnoredStrings.Count | Should -Be 2
    }

    It 'reads switches placed before the first header' {
        $parsed = ConvertFrom-StrippyConfig "; comment`nRecurse=true`nInPlace=false`nMaxThreads=3`nUnpackZip=true`n[ Config ]`n[ Rules ]"
        $parsed.Switches.Recurse | Should -BeTrue
        $parsed.Switches.InPlace | Should -BeFalse
        $parsed.Switches.MaxThreads | Should -Be 3
        $parsed.Switches.UnpackZip | Should -BeTrue
        $parsed.Switches.ContainsKey('Silent') | Should -BeFalse
    }

    It 'accepts headers without the v1 padding and in any case' {
        $parsed = ConvertFrom-StrippyConfig "[config]`nKeyFileName=`"k.txt`"`n[RULES]`n`"a(b)`"=`"B`""
        $parsed.Settings.KeyFileName | Should -Be 'k.txt'
        $parsed.Rules.Length | Should -Be 1
    }

    It 'warns about unknown settings and switches instead of failing' {
        $parsed = ConvertFrom-StrippyConfig "Bogus=true`nMaxThreads=lots`n[ Config ]`nNotASetting=`"x`""
        $parsed.Warnings.Length | Should -Be 3
    }

    It 'throws on an unknown header' {
        { ConvertFrom-StrippyConfig "[ Nope ]" } | Should -Throw '*Invalid header*line 1*'
    }

    It 'throws on a rule that cannot be parsed, naming the line' {
        { ConvertFrom-StrippyConfig "[ Rules ]`n`"a(b)`"=`"B`"`nnot a rule" } | Should -Throw '*line 3*'
    }

    It 'merges parsed values over the defaults' {
        $config = Merge-StrippyConfig (ConvertFrom-StrippyConfig "[ Config ]`nKeyFileName=`"mine.txt`"")
        $config.KeyFileName | Should -Be 'mine.txt'
        $config.SanitisedFileFirstLine | Should -Be 'This file was Sanitised at {0}.{1}=={1}{1}'
        $config.IgnoredStrings | Should -Contain 'unknown'
    }

    It 'generates a default config that parses and compiles' {
        $parsed = ConvertFrom-StrippyConfig (Get-StrippyDefaultConfigText)
        $parsed.Warnings.Length | Should -Be 0
        $parsed.Rules.Length | Should -Be 2
        (New-StrippyRuleSet $parsed.Rules).Capture.Length | Should -Be 2
    }
}

Describe 'New-StrippyRuleSet' {
    It 'throws on an invalid regex rather than dropping the rule' {
        { New-TestRuleSet '"(unclosed"="Broken"' } | Should -Throw '*Invalid regex*'
    }

    It 'warns about rules without a capture group' {
        $ruleSet = New-TestRuleSet "`"no group here`"=`"Nothing`"`n`"x(y)`"=`"Y`""
        $ruleSet.Capture.Length | Should -Be 1
        $ruleSet.Warnings.Length | Should -Be 1
    }

    It 'combines delete rules into one pattern' {
        $ruleSet = New-TestRuleSet "`"^secret`"=\delete`n`"password`"=\delete"
        $ruleSet.Capture.Length | Should -Be 0
        'secret one' | Should -Match $ruleSet.DeletePattern
        'my password' | Should -Match $ruleSet.DeletePattern
        'not a secret' | Should -Not -Match $ruleSet.DeletePattern
    }
}

Describe 'Remove-StrippyLines' {
    It 'removes matching lines and keeps CRLF line endings' {
        Remove-StrippyLines "keep`r`nDROP me`r`nkeep too`r`n" 'drop' | Should -Be "keep`r`nkeep too`r`n"
    }

    It 'removes matching lines and keeps LF line endings' {
        Remove-StrippyLines "a`nb`nc" '^b$' | Should -Be "a`nc"
    }

    It 'returns the text untouched when there is no pattern or no match' {
        Remove-StrippyLines "a`nb" '' | Should -Be "a`nb"
        Remove-StrippyLines "a`nb" 'zzz' | Should -Be "a`nb"
    }
}

Describe 'Find-StrippyKeys' {
    BeforeAll {
        $script:FindFolder = New-TestFolder 'find'
    }

    It 'returns unique values in order of discovery, skipping ignored strings' {
        $path = Join-Path $script:FindFolder 'basic.log'
        Write-TestFile $path "host=alpha, host=beta, host=ALPHA, host=null, host=, host=gamma,`n"
        $result = Find-StrippyKeys -Path $path -RuleSet (New-TestRuleSet '"host=(.*?),"="Host"') -IgnoredSet (New-StrippyIgnoredSet 'NULL', '')
        $result.Error | Should -BeNullOrEmpty
        $result.FoundValues | Should -Be 'alpha', 'beta', 'gamma'
        $result.FoundTypes | Should -Be 'Host', 'Host', 'Host'
        $result.RuleHits[0] | Should -Be 6
    }

    It 'gives a value the alias of the first rule that finds it' {
        $path = Join-Path $script:FindFolder 'order.log'
        Write-TestFile $path "user=bob`nadmin=bob`nadmin=sue`n"
        $result = Find-StrippyKeys -Path $path -RuleSet (New-TestRuleSet "`"user=(\w+)`"=`"User`"`n`"admin=(\w+)`"=`"Admin`"") -IgnoredSet (New-StrippyIgnoredSet @())
        $result.FoundValues | Should -Be 'bob', 'sue'
        $result.FoundTypes | Should -Be 'User', 'Admin'
    }

    It 'splits list rules on the delimiter and trims the elements' {
        $path = Join-Path $script:FindFolder 'list.log'
        Write-TestFile $path "fruits: apple, pear,kiwi`r`n"
        $result = Find-StrippyKeys -Path $path -RuleSet (New-TestRuleSet '"fruits: (.+)$"="Fruit",","') -IgnoredSet (New-StrippyIgnoredSet @())
        $result.FoundValues | Should -Be 'apple', 'pear', 'kiwi'
    }

    It 'supports ^ and $ per line and never returns line endings' {
        $path = Join-Path $script:FindFolder 'anchors.log'
        Write-TestFile $path "name: one`r`nname: two`r`n"
        $result = Find-StrippyKeys -Path $path -RuleSet (New-TestRuleSet '"^name: (.+)$"="Name"') -IgnoredSet (New-StrippyIgnoredSet @())
        $result.FoundValues | Should -Be 'one', 'two'
    }

    It 'does not look inside lines removed by delete rules' {
        $path = Join-Path $script:FindFolder 'delete.log'
        Write-TestFile $path "host=alpha, noise`nhost=beta, keep`n"
        $result = Find-StrippyKeys -Path $path -RuleSet (New-TestRuleSet "`"host=(.*?),`"=`"Host`"`n`"noise`"=\delete") -IgnoredSet (New-StrippyIgnoredSet @())
        $result.FoundValues | Should -Be 'beta'
    }

    It 'reports an unreadable file as an error instead of throwing' {
        $result = Find-StrippyKeys -Path (Join-Path $script:FindFolder 'missing.log') -RuleSet (New-TestRuleSet '"a(b)"="B"') -IgnoredSet (New-StrippyIgnoredSet @())
        $result.Error | Should -Not -BeNullOrEmpty
        $result.FoundValues.Count | Should -Be 0
    }
}

Describe 'New-StrippyKeyMap' {
    It 'numbers aliases per type and zero pads them to the same width' {
        $values = 1..12 | ForEach-Object { "10.0.0.$_" }
        $scout = [pscustomobject]@{ FoundValues = @($values) + 'srv'; FoundTypes = @($values | ForEach-Object { 'Address' }) + 'Hostname' }
        $keys = New-StrippyKeyMap -ScoutResults @($scout) -ImportedEntries @()
        $keys.Map['10.0.0.1'] | Should -Be 'Address01'
        $keys.Map['10.0.0.12'] | Should -Be 'Address12'
        $keys.Map['srv'] | Should -Be 'Hostname1'
        $keys.Entries.Length | Should -Be 13
    }

    It 'merges files in order and treats values as case-insensitive' {
        $a = [pscustomobject]@{ FoundValues = @('ServerA', 'bob'); FoundTypes = @('Hostname', 'User') }
        $b = [pscustomobject]@{ FoundValues = @('SERVERA', 'ServerB'); FoundTypes = @('Other', 'Hostname') }
        $keys = New-StrippyKeyMap -ScoutResults @($a, $b) -ImportedEntries @()
        $keys.Map.Count | Should -Be 3
        $keys.Map['servera'] | Should -Be 'Hostname1'
        $keys.Map['ServerB'] | Should -Be 'Hostname2'
    }

    It 'keeps imported aliases and continues numbering after them' {
        $imported = @(
            [pscustomobject]@{ Alias = 'Address1'; Value = '10.0.0.1' },
            [pscustomobject]@{ Alias = 'Address2'; Value = '10.0.0.2' }
        )
        $scout = [pscustomobject]@{ FoundValues = @('10.0.0.2', '10.0.0.3'); FoundTypes = @('Address', 'Address') }
        $keys = New-StrippyKeyMap -ScoutResults @($scout) -ImportedEntries $imported
        $keys.Map['10.0.0.1'] | Should -Be 'Address1'
        $keys.Map['10.0.0.2'] | Should -Be 'Address2'
        $keys.Map['10.0.0.3'] | Should -Be 'Address3'
    }

    It 'never hands out an alias that is already in use' {
        $imported = @([pscustomobject]@{ Alias = 'Host2'; Value = 'old' })
        $scout = [pscustomobject]@{ FoundValues = @('new'); FoundTypes = @('Host') }
        $keys = New-StrippyKeyMap -ScoutResults @($scout) -ImportedEntries $imported
        $keys.Map['new'] | Should -Not -Be 'Host2'
        @($keys.Entries | ForEach-Object { $_.Alias } | Select-Object -Unique).Count | Should -Be 2
    }
}

Describe 'Protect-StrippyText' {
    BeforeAll {
        function Protect-TestText {
            param ([string] $Text, [hashtable] $Keys)
            $map = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($k in $Keys.Keys) { $map.Add($k, $Keys[$k]) }
            return Protect-StrippyText -Text $Text -KeyRegex (New-StrippyKeyRegex $map) -KeyMap $map
        }
    }

    It 'replaces every occurrence and counts them' {
        $result = Protect-TestText 'alpha beta alpha' @{ alpha = 'Host1' }
        $result.Text | Should -Be 'Host1 beta Host1'
        $result.Count | Should -Be 2
    }

    It 'prefers the longest key at a position' {
        (Protect-TestText 'apple pineapple applesauce' @{ apple = 'Fruit1'; pineapple = 'Fruit2' }).Text | Should -Be 'Fruit1 Fruit2 Fruit1sauce'
    }

    It 'matches regardless of case' {
        (Protect-TestText 'ServerA SERVERA servera' @{ ServerA = 'Host1' }).Text | Should -Be 'Host1 Host1 Host1'
    }

    It 'treats keys as literal text, not regex' {
        (Protect-TestText 'a.b axb (x)' @{ 'a.b' = 'K1'; '(x)' = 'K2' }).Text | Should -Be 'K1 axb K2'
    }

    It 'never re-sanitises an alias it has just written' {
        # v1 replaced keys one after another, so the key "1" would corrupt the freshly written "Address1"
        (Protect-TestText '1 and 10.0.0.1' @{ '10.0.0.1' = 'Address1'; '1' = 'Num1' }).Text | Should -Be 'Num1 and Address1'
    }

    It 'returns the text untouched when there are no keys' {
        $result = Protect-StrippyText -Text 'nothing to do' -KeyRegex $null -KeyMap $null
        $result.Text | Should -Be 'nothing to do'
        $result.Count | Should -Be 0
    }
}

Describe 'Paths and templates' {
    It 'adds .sanitised before the extension' {
        $root = Join-Path $TestDrive 'in'
        $out = Join-Path $TestDrive 'out'
        Get-StrippyOutputPath -Source (Join-Path $root 'server.1.log') -Root $root -OutputFolder $out -InPlace $false | Should -Be (Join-Path $out 'server.1.sanitised.log')
        Get-StrippyOutputPath -Source (Join-Path $root 'noextension') -Root $root -OutputFolder $out -InPlace $false | Should -Be (Join-Path $out 'noextension.sanitised')
    }

    It 'keeps the folder structure beneath the root' {
        $root = Join-Path $TestDrive 'in'
        $out = Join-Path $TestDrive 'out'
        $source = Join-Path (Join-Path (Join-Path $root 'a') 'b') 'x.log'
        Get-StrippyOutputPath -Source $source -Root $root -OutputFolder $out -InPlace $false | Should -Be (Join-Path (Join-Path (Join-Path $out 'a') 'b') 'x.sanitised.log')
    }

    It 'returns the source for in-place sanitisation' {
        $source = Join-Path $TestDrive 'x.log'
        Get-StrippyOutputPath -Source $source -Root $TestDrive -OutputFolder 'ignored' -InPlace $true | Should -Be $source
    }

    It 'finds the deepest folder shared by a set of files' {
        $root = Join-Path $TestDrive 'common'
        $files = (Join-Path (Join-Path $root 'a') '1.log'), (Join-Path (Join-Path (Join-Path $root 'a') 'deep') '2.log'), (Join-Path (Join-Path $root 'b') '3.log')
        Get-StrippyCommonRoot $files | Should -Be $root
    }

    It 'expands {0} {1} {2} and drops unknown placeholders' {
        Expand-StrippyTemplate -Template 'At {0}.{1}File {2}{5}' -NewLine '|' -Name 'a.log' -Timestamp 'NOW' | Should -Be 'At NOW.|File a.log'
        Expand-StrippyTemplate -Template '' | Should -Be ''
    }

    It 'identifies files that should not be sanitised' {
        $folder = New-TestFolder 'skip'
        $text = Join-Path $folder 'ok.log'; Write-TestFile $text 'plain text'
        $binary = Join-Path $folder 'data.bin'; [System.IO.File]::WriteAllBytes($binary, [byte[]](1, 2, 0, 3))
        $picture = Join-Path $folder 'p.PNG'; Write-TestFile $picture 'x'
        $done = Join-Path $folder 'ok.sanitised.log'; Write-TestFile $done 'x'
        Get-StrippySkipReason $text | Should -BeNullOrEmpty
        Get-StrippySkipReason $binary | Should -Match 'binary'
        Get-StrippySkipReason $picture | Should -Match 'ignored'
        Get-StrippySkipReason $done | Should -Match 'already'
        Get-StrippySkipReason (Join-Path $folder 'a.zip') | Should -Match 'archive'
    }
}

Describe 'Keylist files' {
    It 'round trips through export and import' {
        $path = Join-Path (New-TestFolder 'keylist') 'KeyList.txt'
        $entries = @(
            [pscustomobject]@{ Alias = 'Hostname1'; Value = 'server - with dash' },
            [pscustomobject]@{ Alias = 'Address02'; Value = '10.0.0.2' },
            [pscustomobject]@{ Alias = 'Address01'; Value = '10.0.0.1' }
        )
        Export-StrippyKeyList -Path $path -Entries $entries -FileLines @('today - /some/file.log') -HeaderTemplate 'This keylist was created at {0}.{1}' -TargetName 'x'
        $imported = Import-StrippyKeyList $path
        $imported.Entries.Length | Should -Be 3
        $imported.Entries[0].Alias | Should -Be 'Address01'
        ($imported.Entries | Where-Object { $_.Alias -eq 'Hostname1' }).Value | Should -Be 'server - with dash'
        $imported.Files | Should -Be 'today - /some/file.log'
    }

    It 'imports a keylist written by v1' {
        $path = Join-Path (New-TestFolder 'keylistv1') 'KeyList.txt'
        Write-TestFile $path "This keylist was created at 08/02/2020 11:04:00 PM.`r`n`r`nAddress1 - 12.123.55.31`r`nHostname1 - theserverofall`r`nList of files using this Key:`n08/02/2020 11:04:01 PM - C:\logs\simpletest.sanitised.log`r`n"
        $imported = Import-StrippyKeyList $path
        $imported.Entries.Length | Should -Be 2
        $imported.Entries[1].Value | Should -Be 'theserverofall'
    }

    It 'rejects a file that is not a keylist' {
        $path = Join-Path (New-TestFolder 'keylistbad') 'notes.txt'
        Write-TestFile $path "just some text`n"
        { Import-StrippyKeyList $path } | Should -Throw '*Invalid format*'
    }
}

Describe 'Invoke-StrippyParallel' {
    It 'returns the same results in the same order with one thread or many' {
        $folder = New-TestFolder 'parallel'
        $ruleSet = New-TestRuleSet '"id=(\w+)"="Id"'
        $ignored = New-StrippyIgnoredSet @()
        $arguments = @(1..6 | ForEach-Object {
                $path = Join-Path $folder "f$_.log"
                Write-TestFile $path "id=value$_ id=shared`n"
                @{ Path = $path; RuleSet = $ruleSet; IgnoredSet = $ignored }
            })
        $single = Invoke-StrippyParallel -FunctionName 'Find-StrippyKeys' -ArgumentSets $arguments -MaxThreads 1
        $multi = Invoke-StrippyParallel -FunctionName 'Find-StrippyKeys' -ArgumentSets $arguments -MaxThreads 4
        $multi.Length | Should -Be 6
        for ($i = 0; $i -lt 6; $i++) {
            $multi[$i].Error | Should -BeNullOrEmpty
            $multi[$i].Path | Should -Be $single[$i].Path
            ($multi[$i].FoundValues -join ',') | Should -Be "value$($i + 1),shared"
            ($multi[$i].FoundValues -join ',') | Should -Be ($single[$i].FoundValues -join ',')
        }
    }
}

Describe 'Logging' {
    AfterEach {
        Initialize-StrippyLog -Enabled $false -ShowDebug $false -Silent $true -Path ''
    }

    It 'writes the v1 line format that timecheck.ps1 parses' {
        $path = Join-Path (New-TestFolder 'log') 'strippy.log'
        Initialize-StrippyLog -Enabled $true -ShowDebug $false -Silent $true -Path $path
        Write-StrippyLog timing Trace '[START] A section'
        Write-StrippyLog whatever Debug 'hidden without -showDebug'
        Write-StrippyLog x Warning 'careful'
        Close-StrippyLog
        $lines = [System.IO.File]::ReadAllLines($path)
        $lines.Length | Should -Be 2
        $lines[0] | Should -Match '^T TIMING \d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}   \[START\] A section$'
        $lines[1] | Should -Match '^W X      .*Warning: careful$'
    }

    It 'rotates the log when it grows past the maximum size' {
        $folder = New-TestFolder 'logrotate'
        $path = Join-Path $folder 'strippy.log'
        Initialize-StrippyLog -Enabled $true -ShowDebug $false -Silent $true -Path $path -MaxSize 300 -History 2
        1..20 | ForEach-Object { Write-StrippyLog rotate Trace "line number $_ with some padding to fill the file" }
        Close-StrippyLog
        Test-Path -LiteralPath $path | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $folder 'strippy.1.log') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $folder 'strippy.2.log') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $folder 'strippy.3.log') | Should -BeFalse
    }
}

Describe 'End to end' {
    BeforeAll {
        function Invoke-Strippy {
            # Runs the real script. Returns its exit code.
            param ([hashtable] $Parameters)
            $global:LASTEXITCODE = 0
            & $script:StrippyScript @Parameters | Out-Null
            return $LASTEXITCODE
        }
    }

    It 'creates a config with -makeConfig, discovers it next to the target and sanitises a file' {
        $folder = New-TestFolder 'e2e-single'
        Copy-Item -LiteralPath (Join-Path $script:TestData 'simpletest.log') -Destination $folder
        Push-Location $folder
        try { Invoke-Strippy @{ makeConfig = $true } | Should -Be 0 }
        finally { Pop-Location }
        Test-Path -LiteralPath (Join-Path $folder 'strippy.conf') | Should -BeTrue

        $keyList = Join-Path $folder 'KeyList.txt'
        Invoke-Strippy @{ File = (Join-Path $folder 'simpletest.log'); Silent = $true; AlternateKeyListOutput = $keyList } | Should -Be 0

        $output = [System.IO.File]::ReadAllText((Join-Path $folder 'simpletest.sanitised.log'))
        $output | Should -Match '^This file was Sanitised at '
        $output | Should -Match 'Address1\r?\nAddress2\r?\n'
        $output | Should -Match ([regex]::Escape('\\Hostname1\the\stuff'))
        $output | Should -Not -Match '12\.123\.55\.31|123\.44\.221\.1|theserverofall'
        [System.IO.File]::ReadAllText((Join-Path $folder 'simpletest.log')) | Should -Match 'theserverofall'

        $keys = [System.IO.File]::ReadAllText($keyList)
        $keys | Should -Match 'Address1 - 12\.123\.55\.31'
        $keys | Should -Match 'Address2 - 123\.44\.221\.1'
        $keys | Should -Match 'Hostname1 - theserverofall'
        $keys | Should -Match 'simpletest\.sanitised\.log'
    }

    It 'accepts v1 positional arguments and the -o / -ko shortcuts' {
        $folder = New-TestFolder 'e2e-positional'
        $conf = Join-Path $folder 'my.conf'; Write-TestFile $conf $script:BasicConfig
        $log = Join-Path $folder 'a.log'; Write-TestFile $log "10.1.1.1 talks to 10.1.1.2`n"
        $out = Join-Path $folder 'out'
        $keyList = Join-Path $folder 'keys.txt'
        $global:LASTEXITCODE = 0
        & $script:StrippyScript $log -ConfigFile $conf -o $out -ko $keyList -Silent | Out-Null
        $LASTEXITCODE | Should -Be 0
        [System.IO.File]::ReadAllText((Join-Path $out 'a.sanitised.log')) | Should -Be "Sanitised a.log`nAddress1 talks to Address2`n"
        Test-Path -LiteralPath $keyList | Should -BeTrue
    }

    It 'only reads the top level of a folder without -Recurse' {
        $folder = New-TestFolder 'e2e-flat'
        $target = Join-Path $folder 'logs'
        Copy-Item -LiteralPath (Join-Path $script:TestData 'folderRecurse') -Destination $target -Recurse
        $conf = Join-Path $folder 'my.conf'; Write-TestFile $conf $script:BasicConfig
        Invoke-Strippy @{ File = $target; ConfigFile = $conf; Silent = $true; AlternateKeyListOutput = (Join-Path $folder 'k.txt') } | Should -Be 0
        $produced = @(Get-ChildItem -LiteralPath "$target.sanitised" -Recurse -File)
        $produced.Count | Should -Be 1
        $produced[0].Name | Should -Be 'simpletest.sanitised.log'
    }

    It 'walks the tree with -Recurse and gives the same value the same alias in every file' {
        $folder = New-TestFolder 'e2e-recurse'
        $target = Join-Path $folder 'logs'
        Copy-Item -LiteralPath (Join-Path $script:TestData 'folderRecurse') -Destination $target -Recurse
        $conf = Join-Path $folder 'my.conf'; Write-TestFile $conf $script:BasicConfig
        $keyList = Join-Path $folder 'k.txt'
        Invoke-Strippy @{ File = $target; ConfigFile = $conf; Silent = $true; Recurse = $true; AlternateKeyListOutput = $keyList } | Should -Be 0

        $out = "$target.sanitised"
        $deep = Join-Path (Join-Path (Join-Path $out 'OtherFolder') 'DeeperFolder') 'superdeeptest.sanitised.log'
        $different = Join-Path (Join-Path $out 'Folder1') 'differenttest.sanitised.log'
        Test-Path -LiteralPath $deep | Should -BeTrue
        Test-Path -LiteralPath $different | Should -BeTrue
        @(Get-ChildItem -LiteralPath $out -Recurse -File).Count | Should -Be 3

        $keyLine = [System.IO.File]::ReadAllLines($keyList) | Where-Object { $_ -match ' - 12\.123\.55\.31$' }
        @($keyLine).Count | Should -Be 1
        $alias = ($keyLine -split ' - ')[0]
        [System.IO.File]::ReadAllText($different) | Should -Match "(?m)^$alias\r?$"
        [System.IO.File]::ReadAllText((Join-Path $out 'simpletest.sanitised.log')) | Should -Match "(?m)^$alias\r?$"
        Get-ChildItem -LiteralPath $out -Recurse -File | ForEach-Object {
            [System.IO.File]::ReadAllText($_.FullName) | Should -Not -Match '12\.123\.55\.31|theserverofall'
        }
    }

    It 'applies switches from the config file and lets the command line override them' {
        $folder = New-TestFolder 'e2e-switches'
        $target = Join-Path $folder 'logs'
        Copy-Item -LiteralPath (Join-Path $script:TestData 'folderRecurse') -Destination $target -Recurse
        $conf = Join-Path $folder 'my.conf'; Write-TestFile $conf ("Recurse=true`nNoHeaderInOutput=true`n" + $script:BasicConfig)

        $out1 = Join-Path $folder 'out1'
        Invoke-Strippy @{ File = $target; ConfigFile = $conf; Silent = $true; AlternateOutputFolder = $out1; AlternateKeyListOutput = (Join-Path $folder 'k1.txt') } | Should -Be 0
        @(Get-ChildItem -LiteralPath $out1 -Recurse -File).Count | Should -Be 3
        [System.IO.File]::ReadAllText((Join-Path $out1 'simpletest.sanitised.log')) | Should -Not -Match '^Sanitised'

        $out2 = Join-Path $folder 'out2'
        Invoke-Strippy @{ File = $target; ConfigFile = $conf; Silent = $true; Recurse = $false; AlternateOutputFolder = $out2; AlternateKeyListOutput = (Join-Path $folder 'k2.txt') } | Should -Be 0
        @(Get-ChildItem -LiteralPath $out2 -Recurse -File).Count | Should -Be 1
    }

    It 'sanitises lists (tests/sensitiveLists)' {
        $folder = New-TestFolder 'e2e-lists'
        Copy-Item -Path (Join-Path (Join-Path $script:TestData 'sensitiveLists') '*') -Destination $folder
        Invoke-Strippy @{ File = (Join-Path $folder 'simpleLists.log'); ConfigFile = (Join-Path $folder 'list.conf'); Silent = $true; AlternateKeyListOutput = (Join-Path $folder 'k.txt') } | Should -Be 0
        $output = [System.IO.File]::ReadAllText((Join-Path $folder 'simpleLists.sanitised.log'))
        $output | Should -Not -Match 'apple|pear|orange|kiwi|house|apartment|shop|school|cafe|DEBUG'
        $output | Should -Match 'listOfFruits: Fruit\d,Fruit\d,Fruit\d,Fruit\d,Fruit\d'
        $output | Should -Match 'secondlistofBuildings:"Building\d;Building\d;Building\d;Building\d;Building\d;Building\d;Building\d"'
        $output | Should -Match '\[LogLevel1\]'
    }

    It 'honours ignored strings with escaped quotes (tests/ignoreTests)' {
        $folder = New-TestFolder 'e2e-ignore'
        Copy-Item -Path (Join-Path (Join-Path $script:TestData 'ignoreTests') '*') -Destination $folder
        Invoke-Strippy @{ File = (Join-Path $folder 'test-ignoreworks.log'); ConfigFile = (Join-Path $folder 'strippy_weirdIgnores.conf'); Silent = $true; AlternateKeyListOutput = (Join-Path $folder 'k.txt') } | Should -Be 0
        $output = [System.IO.File]::ReadAllText((Join-Path $folder 'test-ignoreworks.sanitised.log'))
        $output | Should -Not -Match 'doNotIgnoreThis|dumbtest'
        $output | Should -Match 'Sanitized: BAD_STRING!!!!!1 - '
        $output | Should -Match 'Sanitized: "pleaseignore" - '
        $output | Should -Match 'Sanitized: null - '
        $output | Should -Match 'Stupid Test - SanitisationSuccess1'
    }

    It 'removes lines for \delete rules and overwrites the source with -InPlace -noHeaderInOutput' {
        $folder = New-TestFolder 'e2e-inplace'
        $conf = Join-Path $folder 'my.conf'; Write-TestFile $conf ($script:BasicConfig + "`n`"^.*password.*$`"=\delete`n")
        $log = Join-Path $folder 'a.log'; Write-TestFile $log "from 10.1.1.1`r`nthe Password is hunter2`r`nto 10.1.1.1`r`n"
        Invoke-Strippy @{ File = $log; ConfigFile = $conf; Silent = $true; InPlace = $true; noHeaderInOutput = $true; AlternateKeyListOutput = (Join-Path $folder 'k.txt') } | Should -Be 0
        [System.IO.File]::ReadAllText($log) | Should -Be "from Address1`r`nto Address1`r`n"
        Test-Path -LiteralPath (Join-Path $folder 'a.sanitised.log') | Should -BeFalse
    }

    It 'reuses aliases from a previous run with -KeyFile' {
        $folder = New-TestFolder 'e2e-keyfile'
        $conf = Join-Path $folder 'my.conf'; Write-TestFile $conf $script:BasicConfig
        $first = Join-Path $folder 'first.log'; Copy-Item -LiteralPath (Join-Path $script:TestData 'simpletest.log') -Destination $first
        $second = Join-Path $folder 'second.log'; Copy-Item -LiteralPath (Join-Path (Join-Path (Join-Path $script:TestData 'folderRecurse') 'Folder1') 'differenttest.log') -Destination $second
        $keys1 = Join-Path $folder 'keys1.txt'
        $keys2 = Join-Path $folder 'keys2.txt'

        Invoke-Strippy @{ File = $first; ConfigFile = $conf; Silent = $true; AlternateKeyListOutput = $keys1 } | Should -Be 0
        Invoke-Strippy @{ File = $second; KeyFile = $keys1; ConfigFile = $conf; Silent = $true; AlternateKeyListOutput = $keys2 } | Should -Be 0

        $result = [System.IO.File]::ReadAllText($keys2)
        $result | Should -Match 'Address1 - 12\.123\.55\.31'
        $result | Should -Match 'Address2 - 123\.44\.221\.1\r?\n'
        $result | Should -Match 'Address3 - 123\.44\.221\.56'
        $result | Should -Match 'first\.sanitised\.log'
        $result | Should -Match 'second\.sanitised\.log'
        [System.IO.File]::ReadAllText((Join-Path $folder 'second.sanitised.log')) | Should -Match '(?m)^Address1\r?\nAddress3\r?$'
    }

    It 'produces identical output with one thread or several (tests/cTest with nam.conf)' {
        $folder = New-TestFolder 'e2e-threads'
        $target = Join-Path $folder 'cTest'
        Copy-Item -LiteralPath (Join-Path $script:TestData 'cTest') -Destination $target -Recurse
        $conf = Join-Path $script:ConfigFiles 'nam.conf'
        $results = foreach ($threads in 1, 4) {
            $out = Join-Path $folder "out$threads"
            $keyList = Join-Path $folder "keys$threads.txt"
            Invoke-Strippy @{ File = $target; ConfigFile = $conf; Silent = $true; MaxThreads = $threads; noHeaderInOutput = $true; AlternateOutputFolder = $out; AlternateKeyListOutput = $keyList } | Should -Be 0
            [pscustomobject]@{
                Hashes = (Get-ChildItem -LiteralPath $out -File | Sort-Object Name | ForEach-Object { $_.Name + '=' + (Get-FileHash -LiteralPath $_.FullName).Hash }) -join ';'
                Keys   = ([System.IO.File]::ReadAllLines($keyList) | Where-Object { $_ -match '^\S+\d - ' }) -join ';'
                Count  = @(Get-ChildItem -LiteralPath $out -File).Count
            }
        }
        $results[0].Count | Should -Be 3
        $results[0].Keys | Should -Not -BeNullOrEmpty
        $results[1].Keys | Should -Be $results[0].Keys
        $results[1].Hashes | Should -Be $results[0].Hashes
    }

    It 'unpacks a zip (and the zips inside it with -Recurse) and sanitises the contents' {
        $folder = New-TestFolder 'e2e-zip'
        $zip = Join-Path $folder 'zips.zip'
        Copy-Item -LiteralPath (Join-Path $script:TestData 'zips.zip') -Destination $zip
        Invoke-Strippy @{ File = $zip; ConfigFile = (Join-Path $script:ConfigFiles 'nam.conf'); Silent = $true; Recurse = $true; AlternateKeyListOutput = (Join-Path $folder 'k.txt') } | Should -Be 0
        $out = Join-Path $folder 'zips-zip.sanitised'
        Test-Path -LiteralPath (Join-Path (Join-Path $out 'zips') 'server.1.sanitised.log') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path (Join-Path (Join-Path $folder 'zips-zip') 'zips') 'logs-zip') | Should -BeTrue
        @(Get-ChildItem -LiteralPath $out -Recurse -File).Count | Should -BeGreaterThan 1
    }

    It 'sanitises wildcard targets next to their sources' {
        $folder = New-TestFolder 'e2e-wildcard'
        $conf = Join-Path $folder 'my.conf'; Write-TestFile $conf $script:BasicConfig
        Write-TestFile (Join-Path $folder 'server.1.log') "10.1.1.1`n"
        Write-TestFile (Join-Path $folder 'server.2.log') "10.1.1.1`n"
        Write-TestFile (Join-Path $folder 'other.log') "10.1.1.1`n"
        Invoke-Strippy @{ File = (Join-Path $folder 'server.*.log'); ConfigFile = $conf; Silent = $true; AlternateKeyListOutput = (Join-Path $folder 'k.txt') } | Should -Be 0
        Test-Path -LiteralPath (Join-Path $folder 'server.1.sanitised.log') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $folder 'server.2.sanitised.log') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $folder 'other.sanitised.log') | Should -BeFalse
    }

    It 'leaves pictures and already sanitised files alone (tests/UntouchedPictures)' {
        $folder = New-TestFolder 'e2e-pictures'
        $target = Join-Path $folder 'pics'
        Copy-Item -LiteralPath (Join-Path $script:TestData 'UntouchedPictures') -Destination $target -Recurse
        Invoke-Strippy @{ File = $target; ConfigFile = (Join-Path $script:ConfigFiles 'nam.conf'); Silent = $true; AlternateKeyListOutput = (Join-Path $folder 'k.txt') } | Should -Be 0
        $produced = @(Get-ChildItem -LiteralPath "$target.sanitised" -Recurse -File)
        $produced.Count | Should -Be 1
        $produced[0].Name | Should -Be 'server.12.sanitised.log'
    }

    It 'writes a log file when asked' {
        $folder = New-TestFolder 'e2e-log'
        $conf = Join-Path $folder 'my.conf'; Write-TestFile $conf $script:BasicConfig
        $log = Join-Path $folder 'a.log'; Write-TestFile $log "10.1.1.1`n"
        $logFile = Join-Path $folder 'run.log'
        Invoke-Strippy @{ File = $log; ConfigFile = $conf; Silent = $true; log = $true; logfile = $logFile; AlternateKeyListOutput = (Join-Path $folder 'k.txt') } | Should -Be 0
        $content = [System.IO.File]::ReadAllText($logFile)
        $content | Should -Match 'T TIMING .*\[START\] Sanitising File\(s\)'
        $content | Should -Match 'T TIMING .*\[END\] Sanitising File\(s\)'
        $content | Should -Match 'Rule hits: 1 for'
    }

    It 'exits 1 when the target does not exist' {
        $folder = New-TestFolder 'e2e-missing'
        $conf = Join-Path $folder 'my.conf'; Write-TestFile $conf $script:BasicConfig
        Invoke-Strippy @{ File = (Join-Path $folder 'nope.log'); ConfigFile = $conf; Silent = $true } | Should -Be 1
    }

    It 'exits 1 in silent mode when there is no config file to use' {
        $folder = New-TestFolder 'e2e-noconfig'
        $log = Join-Path $folder 'a.log'; Write-TestFile $log "10.1.1.1`n"
        Invoke-Strippy @{ File = $log; Silent = $true; AlternateKeyListOutput = (Join-Path $folder 'k.txt') } | Should -Be 1
        Test-Path -LiteralPath (Join-Path $folder 'a.sanitised.log') | Should -BeFalse
    }

    It 'exits 1 and writes nothing when the config contains an invalid regex' {
        $folder = New-TestFolder 'e2e-badregex'
        $conf = Join-Path $folder 'my.conf'; Write-TestFile $conf ($script:BasicConfig + "`n`"(unclosed`"=`"Broken`"`n")
        $log = Join-Path $folder 'a.log'; Write-TestFile $log "10.1.1.1`n"
        Invoke-Strippy @{ File = $log; ConfigFile = $conf; Silent = $true; AlternateKeyListOutput = (Join-Path $folder 'k.txt') } | Should -Be 1
        Test-Path -LiteralPath (Join-Path $folder 'a.sanitised.log') | Should -BeFalse
    }
}
