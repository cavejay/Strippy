# Strippy v2 rewrite - questions and answers

Questions that would normally have gone to the maintainer during the rewrite, answered here with the reasoning.
"v1" means `strippy.ps1` 2.4.0. "v2" means this rewrite, released as version 3.0.0.

## Scope and versioning

**Q1. The script already calls itself 2.4.0. What version is "v2"?**
3.0.0. It is the second generation of the code, but the behaviour changes listed under *Behaviour changes* are
enough to warrant a major bump under the semver scheme `version-bumper.ps1` already uses. The `Version: x.y.z`
line in the help block is kept in the same format so `version-bumper.ps1` still works.

**Q2. Replace `strippy.ps1` or add a new file beside it?**
Replace. The mandatory requirement is a single file, releases are "download the script", and v1 is still in git
history and the existing release tags.

**Q3. Which PowerShell versions?**
Windows PowerShell 5.1 and PowerShell 7+ on Windows/Linux/macOS. The stated preference is pwsh on both platforms,
but the README's pitch is "runs natively on every company laptop", which means 5.1. Supporting it only costs
avoiding 7-only syntax (`?:`, `??`, `ForEach-Object -Parallel`, 3-argument `Join-Path`). CI runs all three.

## Architecture

**Q4. How do you unit test a script that must stay a single file and is not a module?**
The jank: the last section of the script is the entry point, and it returns early when the script is dot-sourced
with no arguments (`. ./strippy.ps1`) or when `$env:STRIPPY_IMPORT_ONLY` is set. Everything above that line is
function definitions with no side effects. `strippy.Tests.ps1` dot-sources the script and calls the functions
directly; the end-to-end tests run the script file as a user would. The tests are a separate file - the *tool*
is still one file, and nobody deploying it needs the tests. Embedding Pester tests inside the script behind a
hidden flag was rejected: it bloats the deployed file and adds a flag for no user benefit.

**Q5. Jobs, runspaces, or `ForEach-Object -Parallel`?**
A runspace pool. `Start-Job` (v1) starts a new PowerShell process per file and v1 polled them on a 500 ms sleep.
`-Parallel` is 7-only. Runspaces are threads in the current process, work on 5.1 and 7, and can share the compiled
`Regex` objects and the key dictionary by reference. Worker functions are injected into the pool from the
definitions already in the script, which removes v1's duplicated `$JobFunctions` block. With one file or
`-MaxThreads 1` no pool is created at all.

**Q6. How should replacement work?**
v1 looped over every key and ran three full `String.Replace` passes (as-is, upper, lower) over the whole file, so
cost was keys x file size x 3, plus a `Write-Progress` call per key. v2 builds one case-insensitive regex that
matches any key, preferring the longest at each position, and walks the matches once per file.
This also fixes a v1 correctness bug: because v1 replaced sequentially, a short key (say `1`) corrupted aliases
already written by a longer key. On the repo's own `tests/cTest` + `nam.conf`, v1 emits `HostnameDMISection02`
where it means `Hostname1`. A single pass never re-reads its own output.

**Q6a. What shape should that regex be?**
A prefix tree, not `key1|key2|...`. The first draft used the flat alternation and it was the slowest part of the
script by far: the engine tries every alternative at every character, so 3,500 keys cost ~5.9 s per 1.5 MB file.
Folding the keys into a tree (`10\.0\.(?:0\.1(?:2)?|7\.3)`) took the same file to ~54 ms with byte-identical
output. `RegexOptions.Compiled` was measured and is slower for this shape, so it is not used. A Pester test checks
the tree against the naive longest-first alternation on 300 random overlapping keys.

**Q7. Stream files line by line to save memory?**
No. Rules are applied to the whole file with `RegexOptions.Multiline`, exactly like v1, because existing configs
use `^`/`$` and rules may legitimately span lines. Whole-file reads cost roughly 2x file size in memory per
worker thread, which is fine for log files. Lower `-MaxThreads` for very large files.

**Q8. Add-Type/C# for the hot path?**
No. It would be faster again, but compiling C# is blocked on locked-down machines (Constrained Language Mode,
AppLocker), and that is precisely where this tool gets used.

**Q9. Logging design?**
One `StreamWriter` opened once and written only by the main thread. Workers return data instead of logging, so the
named mutex and per-line `Out-File -Append` are gone. The line format (`T TIMING yy-MM-dd HH:mm:ss.fff   [START] x`)
is unchanged so `timecheck.ps1` still works. Rotation now writes `<name>.1.log` next to the log file; v1 wrote the
rotated files to the current directory.

## Backwards compatibility decisions

**Q10. Keep `-o` / `-ko` as real parameters or make them aliases?**
Kept as real parameters, exactly as v1 declared them, so abbreviation/ambiguity behaviour cannot change. Added the
alias `-out` for `-AlternateOutputFolder` because the v1 README documented `-out` and it never worked.

**Q11. Config switches (`Recurse=`, `InPlace=`, `Silent=`, `MaxThreads=`) were parsed but never applied in v1.
Apply them now?**
Yes. v1's own comment states the intended priority as default -> config file -> command line, so v2 implements
that. `UnpackZip=` and `NoHeaderInOutput=` are added. Risk: a config that has `Recurse=true` uncommented starts
recursing. Both shipped configs have these commented out.

**Q12. A v1 config file replaced the defaults wholesale, so a config without `IgnoredStrings` ignored nothing and
one without `SanitisedFileFirstLine` wrote no header. Keep that?**
No. Settings missing from the config now fall back to the defaults. To get no header use `-noHeaderInOutput`, or
`SanitisedFileFirstLine=""`.

**Q13. Invalid config lines and invalid regexes: warn or fail?**
Fail, with the line number, before anything is written. v1 warned on unparseable rule lines, and an invalid regex
threw inside a background job, which silently produced *no keys for that file* and then wrote it out
"sanitised". For a tool whose output gets sent to third parties, running with fewer rules than configured is the
worst outcome. Unknown settings/switches and rules with no capture group are still only warnings.

**Q14. Case sensitivity of keys and ignored strings?**
Keys are case-insensitive: `ServerA`, `SERVERA` and `servera` are one key with one alias. v1 gave them separate
aliases but then replaced upper/lower variants of each, so the result depended on ordering. Rule regexes remain
case-sensitive as in v1. `IgnoredStrings` is now case-insensitive too; otherwise `NULL` would become a key and,
with case-insensitive replacement, wipe out every `null` in the file - which is what v1 effectively did.

**Q15. Output encoding?**
v1 wrote everything as ASCII, turning every non-ASCII character into `?`, and rewrote all line endings as CRLF.
v2 preserves line endings, writes UTF-8 without BOM, and keeps the source encoding when the source has a BOM.
Files with no BOM are read as UTF-8 (same as v1); legacy ANSI files with high-bit characters will have those
characters replaced, which is no worse than v1.

**Q16. v1 printed every key and its original value to the console at the end. Keep?**
No. It is the sensitive data, it scrolls into terminal history and CI logs, and with thousands of keys it is
unreadable. v2 prints a count per alias type and the path of the keylist.

**Q17. `-KeyFile` was accepted but v1 threw the imported keys away. Implement it?**
Yes, it is documented in the help examples. Imported keys keep their alias, new keys continue the numbering, and
the previous run's file list is carried forward. v1-format keylists import. The `.txt`-only restriction is dropped.

**Q18. Where does the keylist go?**
`-AlternateKeyListOutput`/`-ko`, then config `AlternateKeyListOutput`, then config `KeyFileName`, then
`KeyList.txt` - relative paths resolve against the current directory as in v1. v1 ignored both config settings.

**Q19. Exit codes?**
0 on success, 1 on any failure including individual files that could not be processed. v1 used `exit -1` (255 on
Linux), a bare `throw` in one path, and exited 0 from `Clean-Up` after reporting errors. Anything testing for
non-zero still works.

**Q20. The built-in IP rule requires a non-digit *after* the address, so an address at the very end of a file was
missed. Fix?**
Yes: `[^\d]` became `(?!\d)` in the built-in rule and the `-makeConfig` template. Existing config files are not
touched and behave as before.

**Q21. v1 stripped `|` from captured values (the character class `[\r|\n]`). Keep?**
No, that was a typo for "CR or LF". v2 strips only CR and LF.

**Q22. List rules: trim whitespace around elements?**
Yes. With `a, b` and delimiter `,` v1 produced the key `" b"`, which only ever matched with its leading space.
The delimiter is still treated as a regex, as in v1.

## New behaviour

**Q23. Should Strippy look for `strippy.conf` next to the target?**
Yes. The v1 help listed it as "NOT IMPLEMENTED". Order: `-ConfigFile`, target folder, script folder, then the
built-in rules after a prompt (never in `-Silent`). The config, keylist, key file and log file are never sanitised
as input, nor is anything inside the output folder.

**Q24. Wildcards in `-File`?**
Implemented (`server.*.log`); it was a v1 TODO behind a check that could never be true. Output is written next to
each source file unless an output folder is given.

**Q25. How should binary files be handled?**
v1 relied on an extension list. v2 keeps the list and also skips anything with a NUL byte in its first 8 KB, since
v2 would otherwise rewrite a binary as UTF-8 text. UTF-16 files are recognised by their BOM and still processed.

**Q26. `-unpackZip` on a folder did nothing in v1 (it passed an undefined variable). What should it do?**
Unpack archives found in scope into `<name>-zip` / `<name>-gz` beside the archive, as v1 does for a top-level
archive, and sanitise the contents. Without `-Recurse` only top-level archives are unpacked, but their contents
are read in full. Nested archives are followed only with `-Recurse`, to v1's depth limit of 20.

**Q27. `{2}` in header templates was documented as "not implemented". Implement?**
Yes: the file's relative path in file headers, the target in the keylist header. `{1}` now matches the file's own
line ending instead of always CRLF.

**Q28. Add a CI workflow? Nobody asked for one.**
Yes. "Runs on Linux and Windows pwsh" is a claim that needs something to check it, and a test suite nobody runs
rots. `.github/workflows/tests.yml` runs Pester 5+ on Ubuntu pwsh, Windows pwsh and Windows PowerShell 5.1.

**Q29. A rule captures a 1 or 2 character value (nam.conf's `DMISection` rule captures section `0` and `1`), so
every `0` and `1` in every file is replaced, timestamps included. Skip short keys?**
No - replace them and warn. This is what v1 did too, and for a sanitiser leaving a captured value in the output is
worse than mangling it. But the output is unreadable and v1 gave no hint why, so v2 prints a warning naming the
aliases (not the values) and says to tighten the rule or add the values to `IgnoredStrings`. The shipped `nam.conf`
is left alone; adding `"0","1"` to its `IgnoredStrings` is the fix and is the config owner's call.

**Q30. `-h`, `-help` and no arguments printed blank lines under `pwsh -File ... | more`. Fix?**
Yes. The help object is rendered to text before it is written. v1 has the same problem on pwsh.

## Verification

Run on Linux, PowerShell 7.4.6, Pester 6.2.0, 4 cores. 68 tests pass.

| Workload | v1 (2.4.0) | v2 (3.0.0) |
| --- | --- | --- |
| `tests/cTest` + `nam.conf`: 3 files, 6 MB, 64 keys, ~400k replacements | 6.8 s | 3.5 s |
| Synthetic: 20 files, 30 MB, 3,500 keys, 600k replacements | 132 s | 7.7 s |

On both workloads v1 and v2 find the same set of keys. On the synthetic one the sanitised output is identical line
for line once alias numbers are normalised (numbering differs because v1's order depended on which job finished
first; v2's is deterministic). On `cTest` it differs only where v1 corrupted its own aliases (Q6).

Two bugs in the first draft were only found by running it: `StringBuilder.Append(string, int, int)` called from
PowerShell copies the whole string per call (a 2 MB file took minutes), and the flat alternation above (Q6a).

Not verified here: Windows PowerShell 5.1 and Windows pwsh. The code avoids 7-only syntax and CI runs both, but
nothing was executed on Windows in this session. Estimated odds the 5.1 job passes first time: 80%.
The .NET Framework regex engine in 5.1 is slower than .NET 8's; the prefix tree matters more there, not less.

## Not done

- No `-WhatIf`, no per-rule case-insensitivity flag, no named capture groups. None were asked for.
- `timecheck.ps1` and `version-bumper.ps1` are untouched.
- Rule regexes have no match timeout. A pathological regex in a config can still hang on a large file, as in v1.
