# File name: security-collect-endpoint-triage.ps1
# Version: 1.0.2
# Last updated: 2026-11-16
# Copyright (C) 2026 sultanovich
#
# Changelog:
#   1.0.2 - 2026-11-16 - Make every section state its result instead of
#                        printing an empty heading, and stop the collection
#                        noise from hiding the findings:
#                        * section 7 lists the extensions themselves - profile,
#                          id, name and version - instead of profile folder
#                          names, which returned no extension at all, and
#                          resolves localised names (__MSG_..__) from the
#                          extension locale files.
#                        * section 8 says so when npm or pip is not installed.
#                        * section 10 lists the credential directories in full
#                          and never truncates them, separately from AppData,
#                          so a day of application churn cannot push them off
#                          the list; antivirus and browser caches, Electron
#                          app-* trees, node_modules, VS Code CachedData and
#                          the Firefox profile - bar the files that carry
#                          evidence - are excluded.
#                        * section 11 says whether the history file was absent
#                          or simply had no match.
#                        Also avoid assigning the automatic variables $matches
#                        and $profile, and calling .Count on a possible scalar,
#                        which break under Set-StrictMode -Version Latest.
#   1.0.1 - 2026-11-16 - Fail with exit code 2 when the log cannot be written
#                        (it used to report success); drop the "paste into a
#                        console" usage, since the script exits the session.
#   1.0.0 - 2026-11-14 - Initial release.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

###############################################################################
# security-collect-endpoint-triage.ps1
#
# Description:
#   Collects read-only endpoint metadata for incident triage after a suspected
#   credential theft or endpoint compromise: installed editor extensions,
#   credential file metadata, running processes, network connections,
#   persistence mechanisms, browser extensions, recently modified files and
#   PowerShell history references to credentials.
#
#   The script never reads the contents of credential files, private keys or
#   secrets. It records only metadata: paths, timestamps, sizes and versions.
#   Output is additionally passed through a redaction filter that masks
#   anything resembling an access key or a private key block, so the resulting
#   log can be shared with a responder.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File security-collect-endpoint-triage.ps1
#
# Parameters:
#   -OutputDir DIR   Directory for the log file (default: Desktop, else profile)
#   -Ioc PATTERN[]   Extra patterns to search for in extensions and processes
#   -Quiet           Suppress progress output
#   -Version         Show version and exit
#
# Examples:
#   .\security-collect-endpoint-triage.ps1
#   .\security-collect-endpoint-triage.ps1 -OutputDir C:\Temp -Ioc 'some.extension'
#
# Supported systems:
#   - Windows 10 / 11 / Server 2016+ with PowerShell 5.1 or later
#
# The script does NOT require administrator rights and is safe to run as a
# normal user. Two sections behave differently without elevation:
#   - Section 12 (security event log) is skipped entirely.
#   - Section 4 may not resolve executable paths for other users' processes.
# Everything else is collected from the current user's own profile and from
# registry keys that are readable by standard users.
#
# Exit codes:
#   0 - collection completed
#   2 - output directory not writable
###############################################################################

[CmdletBinding()]
param(
    [string]   $OutputDir,
    [string[]] $Ioc = @(),
    [switch]   $Quiet,
    [switch]   $Version
)

Set-StrictMode -Version Latest
# Individual failures must not abort a collector run.
$ErrorActionPreference = 'SilentlyContinue'

$ScriptName    = 'security-collect-endpoint-triage.ps1'
$ScriptVersion = '1.0.2'

if ($Version) { Write-Output "$ScriptName $ScriptVersion"; exit 0 }

function Write-Progress-Msg { param([string]$Text, [string]$Color = 'Cyan')
    if (-not $Quiet) { Write-Host $Text -ForegroundColor $Color }
}

# Resolve output directory: explicit, else Desktop, else user profile.
if (-not $OutputDir) {
    $OutputDir = [Environment]::GetFolderPath('Desktop')
    if (-not (Test-Path $OutputDir)) { $OutputDir = $env:USERPROFILE }
}
if (-not (Test-Path $OutputDir)) {
    Write-Host "[ERROR] Output directory does not exist: $OutputDir" -ForegroundColor Red
    exit 2
}

$hostSafe = ($env:COMPUTERNAME -replace '[^A-Za-z0-9._-]', '')
$stamp    = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$logFile  = Join-Path $OutputDir "endpoint-triage_${hostSafe}_${stamp}.log"

# Fail early if the log cannot be written ($ErrorActionPreference hides cmdlet
# errors, so test with a .NET call that throws).
try {
    [System.IO.File]::WriteAllText($logFile, '')
} catch {
    Write-Host "[ERROR] Output directory not writable: $OutputDir" -ForegroundColor Red
    exit 2
}

$lines = New-Object System.Collections.Generic.List[string]

function Add-Line    { param([string]$Text = '') ; $lines.Add($Text) | Out-Null }
function Add-Section { param([string]$Title)
    Add-Line ''
    Add-Line ('=' * 78)
    Add-Line "== $Title"
    Add-Line ('=' * 78)
}
function Add-Table { param($Data)
    if ($null -eq $Data) { Add-Line '   (no data)'; return }
    ($Data | Format-Table -AutoSize | Out-String -Width 200) -split "`r?`n" |
        Where-Object { $_.Trim() } | ForEach-Object { Add-Line $_ }
}

# Defensive redaction: nothing here reads secret values, but any output that
# looks like an access key, a token or a private key block is masked.
function Protect-Secrets { param([string]$Text)
    $t = $Text
    $t = $t -replace '(AKIA|ASIA|AIDA|AROA)[A-Z0-9]{12,}', '$1<REDACTED>'
    $t = $t -replace '(?i)(aws_secret_access_key\s*=\s*).*', '$1<REDACTED>'
    $t = $t -replace '(?i)(password|passwd|secret|token|api[_-]?key)(\s*[:=]\s*).*', '$1$2<REDACTED>'
    $t = $t -replace '-----BEGIN [A-Z ]*PRIVATE KEY-----', '<REDACTED PRIVATE KEY BLOCK>'
    $t = $t -replace 'gh[pousr]_[A-Za-z0-9]{20,}', '<REDACTED GITHUB TOKEN>'
    return $t
}

Write-Progress-Msg '[*] Collecting endpoint triage data...'

Add-Line "$ScriptName $ScriptVersion"
Add-Line ("Collected: " + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
Add-Line ("Host: $env:COMPUTERNAME   User: $env:USERNAME")
Add-Line ''
Add-Line 'This report contains METADATA ONLY. No credential, key or secret'
Add-Line 'values are read or stored. Secret-like strings are redacted.'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Add-Section '1. SYSTEM'
$os = Get-CimInstance Win32_OperatingSystem
Add-Line ("   OS        : " + $os.Caption + ' ' + $os.Version)
Add-Line ("   Last boot : " + $os.LastBootUpTime)
Add-Line ("   PowerShell: " + $PSVersionTable.PSVersion)
Add-Line ("   Elevated  : $isAdmin")
if (-not $isAdmin) {
    Add-Line '   NOTE: not elevated. Section 12 (security event log) will be skipped'
    Add-Line '         and process paths for other users may be unavailable.'
}

Add-Section '2. EDITOR EXTENSIONS'
Add-Line 'Known supply-chain attacks ship through editor marketplaces. Review the'
Add-Line 'list below for anything the user did not install deliberately.'
Add-Line ''
foreach ($d in @("$env:USERPROFILE\.vscode\extensions", "$env:USERPROFILE\.vscode-insiders\extensions",
                 "$env:USERPROFILE\.cursor\extensions", "$env:USERPROFILE\.windsurf\extensions")) {
    if (Test-Path $d) {
        Add-Line "-- $d"
        Get-ChildItem $d -Directory | ForEach-Object { Add-Line ('   ' + $_.Name) }
    }
}
foreach ($b in @('code', 'code-insiders', 'cursor', 'windsurf')) {
    if (Get-Command $b -ErrorAction SilentlyContinue) {
        Add-Line "-- $b --list-extensions --show-versions"
        & $b --list-extensions --show-versions | ForEach-Object { Add-Line ('   ' + $_) }
    }
}
foreach ($p in $Ioc) {
    Add-Line "-- IOC search: $p"
    Get-ChildItem $env:USERPROFILE -Recurse -Depth 4 -Filter "*$p*" |
        Select-Object -First 20 | ForEach-Object { Add-Line ('   ' + $_.FullName) }
    Get-Process | Where-Object { $_.Name -like "*$p*" } |
        ForEach-Object { Add-Line ('   process: ' + $_.Name + ' (' + $_.Id + ')') }
}

Add-Section '3. CREDENTIAL FILES PRESENT (metadata only, contents never read)'
$files = @("$env:USERPROFILE\.aws\credentials", "$env:USERPROFILE\.aws\config",
           "$env:USERPROFILE\.npmrc", "$env:USERPROFILE\.docker\config.json",
           "$env:USERPROFILE\.kube\config", "$env:USERPROFILE\.gitconfig")
$files += (Get-ChildItem "$env:USERPROFILE\.ssh" -File | ForEach-Object { $_.FullName })
foreach ($f in $files) {
    if ($f -and (Test-Path $f)) {
        $i = Get-Item $f
        Add-Line ('   ' + $i.FullName + ' | modified ' + $i.LastWriteTime +
                  ' | accessed ' + $i.LastAccessTime + ' | ' + $i.Length + ' bytes')
    }
}

Add-Section '4. RUNNING PROCESSES (top 50 by memory)'
Add-Table (Get-Process | Sort-Object WS -Descending | Select-Object -First 50 Name, Id, Path)

Add-Section '5. ESTABLISHED NETWORK CONNECTIONS'
Add-Table (Get-NetTCPConnection -State Established |
           Select-Object LocalPort, RemoteAddress, RemotePort, OwningProcess |
           Sort-Object RemoteAddress | Select-Object -First 60)

Add-Section '6. PERSISTENCE'
Add-Line '-- scheduled tasks (non-Microsoft, enabled)'
Add-Table (Get-ScheduledTask |
           Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' } |
           Select-Object TaskName, TaskPath, State)
Add-Line '-- Run keys'
foreach ($k in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')) {
    if (Test-Path $k) {
        Add-Line "   $k"
        (Get-ItemProperty $k).PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' } |
            ForEach-Object { Add-Line ('     ' + $_.Name + ' = ' + $_.Value) }
    }
}

# Chromium extensions may declare a localised name as __MSG_<key>__, which is
# meaningless to a responder. Resolve it from the extension's own locale files.
function Resolve-ExtName {
    param([string]$Raw, [string]$VerDirPath, [string]$DefaultLocale)
    if ($Raw -notmatch '^__MSG_(.+)__$') { return $Raw }
    $key = $Matches[1]
    $locales = @()
    if ($DefaultLocale) { $locales += $DefaultLocale }
    $locales += @('en', 'en_US', 'en_GB', 'es', 'es_419')
    foreach ($loc in ($locales | Select-Object -Unique)) {
        $mp = Join-Path $VerDirPath ('_locales\' + $loc + '\messages.json')
        if (-not (Test-Path $mp)) { continue }
        try {
            $m = Get-Content $mp -Raw -ErrorAction Stop | ConvertFrom-Json
            $prop = $m.PSObject.Properties | Where-Object { $_.Name -ieq $key } | Select-Object -First 1
            if ($prop -and $prop.Value.PSObject.Properties['message']) {
                return [string]$prop.Value.PSObject.Properties['message'].Value
            }
        } catch { }
    }
    return $Raw
}

Add-Section '7. BROWSER EXTENSIONS'
Add-Line 'Format: <profile> | <extension id> | <name from manifest> | <version>'
Add-Line 'A name shown as __MSG_...__ is localised: look it up by its id.'
Add-Line ''
$browserFound = $false
foreach ($p in @("$env:LOCALAPPDATA\Google\Chrome\User Data",
                 "$env:LOCALAPPDATA\Microsoft\Edge\User Data",
                 "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data",
                 "$env:LOCALAPPDATA\Vivaldi\User Data",
                 "$env:LOCALAPPDATA\Chromium\User Data")) {
    if (-not (Test-Path $p)) { continue }
    $browserFound = $true
    Add-Line "-- $p"
    # The extension id directories live one level below Extensions; the
    # previous glob stopped at Extensions itself and listed nothing useful.
    $exts = Get-ChildItem "$p\*\Extensions\*" -Directory -ErrorAction SilentlyContinue |
            Select-Object -First 80
    if (-not $exts) { Add-Line '   (no extensions installed in any profile)'; continue }
    foreach ($ext in $exts) {
        # Chromium keeps a Temp staging folder next to the extension ids.
        if ($ext.Name -eq 'Temp') { continue }
        $profileName = $ext.Parent.Parent.Name
        $name = '<manifest unreadable>'
        $ver  = '?'
        $verDir = Get-ChildItem $ext.FullName -Directory -ErrorAction SilentlyContinue |
                  Sort-Object Name | Select-Object -Last 1
        if ($verDir) {
            $mf = Join-Path $verDir.FullName 'manifest.json'
            if (Test-Path $mf) {
                try {
                    $j = Get-Content $mf -Raw -ErrorAction Stop | ConvertFrom-Json
                    if ($j.PSObject.Properties['name'])    { $name = [string]$j.PSObject.Properties['name'].Value }
                    if ($j.PSObject.Properties['version']) { $ver  = [string]$j.PSObject.Properties['version'].Value }
                    $defLoc = ''
                    if ($j.PSObject.Properties['default_locale']) { $defLoc = [string]$j.PSObject.Properties['default_locale'].Value }
                    $name = Resolve-ExtName -Raw $name -VerDirPath $verDir.FullName -DefaultLocale $defLoc
                } catch { $name = '<manifest unparsable>' }
            }
        }
        Add-Line ('   ' + $profileName + ' | ' + $ext.Name + ' | ' + $name + ' | ' + $ver)
    }
}
if (-not $browserFound) { Add-Line '-- RESULT: no browser profile directory found' }

Add-Section '8. GLOBAL PACKAGES'
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Add-Line '-- npm -g'; npm ls -g --depth=0 | ForEach-Object { Add-Line ('   ' + $_) }
} else {
    Add-Line '-- RESULT: npm is not installed on this host'
}
if (Get-Command pip -ErrorAction SilentlyContinue) {
    # Note: invoking pip.exe can trigger an antivirus "unknown file" prompt
    # (Avast CyberCapture and similar). pip generates a per-installation,
    # unsigned launcher, so the binary is unique to this host. Expected noise.
    $pkgs = pip list 2>$null
    Add-Line ('-- pip (' + [Math]::Max(0, (@($pkgs).Count - 2)) + ' packages)')
    $pkgs | ForEach-Object { Add-Line ('   ' + $_) }
} else {
    Add-Line '-- RESULT: pip is not installed on this host'
}

Add-Section '9. SOFTWARE INSTALLED IN THE LAST 30 DAYS'
# Read the uninstall registry keys rather than Win32_Product: querying that WMI
# class triggers a consistency check on every installed MSI, which is slow and
# can make Windows Installer reconfigure packages.
$cut = (Get-Date).AddDays(-30).ToString('yyyyMMdd')
$uninstallKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Add-Table (Get-ItemProperty $uninstallKeys |
           Where-Object { $_.DisplayName -and $_.InstallDate -and $_.InstallDate -gt $cut } |
           Select-Object DisplayName, DisplayVersion, InstallDate |
           Sort-Object InstallDate -Descending)

Add-Section '10. FILES MODIFIED IN SENSITIVE PATHS (last 30 days)'
Add-Line 'Antivirus, browser and Electron caches are excluded: they are rewritten'
Add-Line 'constantly and would otherwise crowd out the real findings.'
Add-Line 'Most recently modified first, capped at 40 entries.'
Add-Line ''
# Firefox writes telemetry, IndexedDB, shader and session-store state into the
# profile on every page load, and uses different directory names than Chromium,
# so it needs its own patterns rather than the Chromium ones.
$cacheNoise = '\\node_modules\\|\\app-[0-9][^\\]*\\(modules|resources)\\|' +
              '\\(Cache|Cache_Data|CachedData|GPUCache|Code Cache|ShaderCache|GrShaderCache|CacheStorage|' +
              'Service Worker|Local Storage|Session Storage|IndexedDB|Crashpad|' +
              'CrashReports|Crash Reports|Dictionaries|blob_storage|INetCache|WebCache|Logs|' +
              'Recent|AutomaticDestinations|CustomDestinations|Spelling)\\|' +
              '\\Mozilla\\Firefox\\(Profiles|Background Tasks Profiles)\\[^\\]+\\' +
              '(?!(extensions|addons|extension-preferences|extension-settings)\.json$' +
              '|prefs\.js$|user\.js$)|' +
              '\\(Network Persistent State|TransportSecurity|Trust Tokens)$|' +
              '-journal$|-wal$|-shm$|\\LOG(\.old)?$|\\LOCK$|\\CURRENT$|\\MANIFEST-|' +
              '\.(ldb|sst|pma|etl|tmp)$'
$cutoff = (Get-Date).AddDays(-30)

# Credential directories are listed in full and never capped. Sorting them
# together with AppData lets a single day of application churn push them out,
# and they are the whole point of this section.
Add-Line '-- credential directories (complete, never truncated)'
$credHits = @()
foreach ($p in @("$env:USERPROFILE\.aws", "$env:USERPROFILE\.ssh",
                 "$env:USERPROFILE\.kube", "$env:USERPROFILE\.docker",
                 "$env:USERPROFILE\.gnupg", "$env:USERPROFILE\.config")) {
    if (-not (Test-Path $p)) { continue }
    $credHits += Get-ChildItem $p -Recurse -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -gt $cutoff -and $_.FullName -notmatch $cacheNoise }
}
if ($credHits) {
    $credHits | Sort-Object LastWriteTime -Descending |
        ForEach-Object { Add-Line ('   ' + $_.FullName + ' | ' + $_.LastWriteTime) }
} else {
    Add-Line '   RESULT: no credential file modified in the last 30 days.'
}

Add-Line '-- application data (40 most recently modified)'
$appHits = @()
if (Test-Path $env:APPDATA) {
    $appHits = Get-ChildItem $env:APPDATA -Recurse -File -ErrorAction SilentlyContinue |
               Where-Object { $_.LastWriteTime -gt $cutoff -and $_.FullName -notmatch $cacheNoise } |
               Sort-Object LastWriteTime -Descending | Select-Object -First 40
}
if ($appHits) {
    $appHits | ForEach-Object { Add-Line ('   ' + $_.FullName + ' | ' + $_.LastWriteTime) }
} else {
    Add-Line '   RESULT: no file modified in the last 30 days outside excluded caches.'
}

Add-Section '11. POWERSHELL HISTORY REFERENCING CREDENTIALS (redacted)'
$h = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $h) {
    $histHits = Select-String -Path $h -Pattern 'AKIA|aws_secret|AWS_SECRET|credentials' |
               Select-Object -Last 30
    if ($histHits) {
        $histHits | ForEach-Object { Add-Line ('   ' + $_.Line.Substring(0, [Math]::Min(200, $_.Line.Length))) }
    } else {
        Add-Line '   RESULT: history file present but no command references'
        Add-Line '   credentials. Empty BY RESULT, not because the check failed.'
        Add-Line ('   File: ' + $h)
    }
} else {
    Add-Line '   RESULT: no PSReadLine history file found at'
    Add-Line ('   ' + $h)
    Add-Line '   Either history is disabled or this user has not used PowerShell.'
}

Add-Section '12. RECENT LOGONS'
# The Security event log is readable by administrators only.
if ($isAdmin) {
    Add-Table (Get-WinEvent -FilterHashtable @{LogName = 'Security'; Id = 4624} -MaxEvents 25 |
               Select-Object TimeCreated, Id, @{N = 'Account'; E = {$_.Properties[5].Value}})
} else {
    Add-Line '   (skipped: reading the Security event log requires administrator rights)'
    Add-Line '   Re-run from an elevated PowerShell if this section is needed.'
}

Add-Section 'END OF COLLECTION'
Add-Line 'Send this file to your security team.'
Add-Line 'Do not uninstall, clean or reboot until instructed.'

try {
    (Protect-Secrets ($lines -join [Environment]::NewLine)) |
        Out-File -FilePath $logFile -Encoding UTF8 -ErrorAction Stop
} catch {
    Write-Host "[ERROR] Could not write the report to: $logFile" -ForegroundColor Red
    exit 2
}

Write-Progress-Msg '[OK] Report written to:' 'Green'
Write-Host "  $logFile"
Write-Host ''
Write-Host 'Send this file to your security team. Do not uninstall, clean or reboot yet.' -ForegroundColor Yellow
exit 0
