# Strippy

Use this PowerShell script to sanitise your logs using specific patterns before handing them off to someone else (like your support team).

It is a single PowerShell file with no dependencies. It runs on Windows PowerShell 5.1 (so natively on any Windows laptop) and on PowerShell 7+ on Windows, Linux and macOS.

## Usage

Download `strippy.ps1` from: https://github.com/cavejay/Strippy/releases/latest

On Windows, run `powershell -executionpolicy Unrestricted` to enter a PowerShell prompt capable of running downloaded scripts.

| Task | Command |
| --- | --- |
| Create a starter config (`strippy.conf`) in the current folder | `.\strippy.ps1 -makeConfig` |
| Sanitise a file | `.\strippy.ps1 .\logs\server.1.log` |
| Sanitise a folder | `.\strippy.ps1 .\logs` |
| Sanitise a folder tree | `.\strippy.ps1 .\logs -Recurse` |
| Sanitise a selection of files | `.\strippy.ps1 '.\logs\server.*.log'` |
| Sanitise the contents of an archive | `.\strippy.ps1 .\support-bundle.zip -Recurse` |
| Reuse the labels from an earlier run | `.\strippy.ps1 .\more-logs -KeyFile .\KeyList.txt` |
| Unattended | `.\strippy.ps1 "C:\app\logs" -Recurse -Silent -ConfigFile C:\strippy\app.conf -o "C:\sanitised"` |

`.\strippy.ps1 -help` shows the full help.

### What you get

- `server.1.log` becomes `server.1.sanitised.log` next to it. A folder `logs` becomes `logs.sanitised` with the same structure. Use `-o <folder>` to choose the output folder or `-InPlace` to overwrite the originals.
- `KeyList.txt` in the folder you ran the script from (`-ko <file>` to move it). It maps every label back to the original value, so you can answer questions about `Address53`. **This file is the sensitive data - do not send it with the logs.**
- Exit code `0` on success, `1` if anything failed.

The same value gets the same label in every file of a run, and matching ignores case (`ServerA` and `SERVERA` are one key).

### What is skipped

Archives (unless you point Strippy at one or use `-unpackZip`), pictures and other known binary types, any file containing NUL bytes, files already named `*.sanitised.*`, and Strippy's own config, keylist and log files.

## Config

Strippy needs to be told what sensitive data looks like. It looks for a config in this order:

1. `-ConfigFile <path>`
2. `strippy.conf` in the same folder as the target
3. `strippy.conf` in the same folder as `strippy.ps1`
4. Built-in rules for IPv4 addresses and Windows UNC hostnames, after asking. `-Silent` exits with an error instead.

```ini
; Switches go before the first header. Command line flags always win.
;Recurse=true
;InPlace=false
;Silent=false
;MaxThreads=5
;UnpackZip=false
;NoHeaderInOutput=false

[ Config ]
; Matches that are exactly one of these (ignoring case) are never treated as sensitive
IgnoredStrings="0.0.0.0","127.0.0.1","null","unknown",""
; {0} = date/time, {1} = newline, {2} = file name
SanitisedFileFirstLine="This file was Sanitised at {0}.{1}=={1}{1}"
KeyListFirstLine="This keylist was created at {0}."
;KeyFileName="KeyList.txt"
;AlternateKeyListOutput=".\keylist.txt"
;AlternateOutputFolder=".\sanitisedoutput"

[ Rules ]
; The first capture group is replaced with Hostname1, Hostname2, ...
"hostname=(.*?),"="Hostname"
; The first capture group is a list of values separated by the delimiter
"servers: (.+)$"="Server",","
; Lines matching the regex are removed entirely
"^.*password.*$"=\delete
```

Rules are .NET regular expressions and are case-sensitive. They are run over the whole file with `^` and `$` matching at line boundaries. Only the first capture group is used. A config with an invalid rule or regex stops the run before anything is written.

The `configFiles` directory contains work-in-progress configs for particular applications. They are maintained on an as needed basis.

* [Dynatrace Network Application Monitoring](configFiles/nam.conf)
* [Dynatrace Managed/SaaS](configFiles/dt-managed.conf)

## Logging and performance

- `-log` writes a log (`-logfile`, default `.\strippy.log`); `-showDebug` adds detail. The log includes how many times each rule matched. `timecheck.ps1` summarises where the time went.
- Files are processed in parallel (`-MaxThreads`, default 5). Each thread holds one whole file in memory, so reduce it for very large files.

## Upgrading from 2.x

Command line flags and config files are unchanged. Behaviour that is different on purpose:

- Config switches (`Recurse=`, `InPlace=`, `Silent=`, `MaxThreads=`) are now applied. 2.x parsed and ignored them.
- Settings missing from a config file fall back to the defaults instead of to nothing.
- Invalid rules and regexes are errors, not warnings.
- Output keeps the source's line endings and is UTF-8. 2.x wrote ASCII with CRLF.
- `IgnoredStrings` and keys ignore case.
- `-KeyFile` works.
- The key values are no longer printed to the console, only counts.
- Errors exit with `1` (was `-1`).

The reasoning for each is in [qanda.md](qanda.md).

## Development

`strippy.ps1` is deliberately one file. Dot-sourcing it with no arguments loads its functions without running anything, which is how the tests get at them:

```powershell
. ./strippy.ps1                       # functions only
Invoke-Pester ./strippy.Tests.ps1     # Pester 5
```

CI runs the tests on Linux (pwsh), Windows (pwsh) and Windows PowerShell 5.1.
