<#
.SYNOPSIS
Scan every disk share on a server into the filecat catalog.

.EXAMPLE
.\ScanServer.ps1 -ServerName nas-vm

.EXAMPLE
.\ScanServer.ps1 -ServerName 192.0.2.13 -Alias nas-main -User nas-main\admin
Connects to the NAS by IP as the admin account (prompting for its password),
so a mapping of \\nas-main under your own account is left alone, and records
the shares as \\nas-main\<share>.
#>
param(
    [string]$ServerName = "nas-vm",
    # Record the shares under \\$Alias instead of \\$ServerName (filecat scan --alias).
    [string]$Alias,
    # Connect to \\$ServerName as this account first (net use prompts for the password).
    [string]$User,
    [int]$Workers = 8
)

$ProjectRoot = $PSScriptRoot
Push-Location $ProjectRoot
try {
    $VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (Test-Path $VenvPython) {
        $Python = $VenvPython
    } else {
        $PythonCommand = Get-Command "python.exe" -ErrorAction SilentlyContinue
        if (-not $PythonCommand) {
            $PythonCommand = Get-Command "python" -ErrorAction SilentlyContinue
        }
        if (-not $PythonCommand) {
            throw "Neither the project virtual environment nor a system Python installation was found."
        }
        $Python = $PythonCommand.Source
    }

    if (-not (Test-Connection -ComputerName $ServerName -Count 1 -Quiet)) {
        throw "Unable to reach server $ServerName."
    }

    $ConfigOutput = & $Python -m filecat config show
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read the effective filecat configuration."
    }
    $Backend = $null
    foreach ($Line in $ConfigOutput) {
        if ($Line -match '^backend:\s*(\S+)\s*$') {
            $Backend = $Matches[1]
            break
        }
    }
    if (-not $Backend) {
        throw "The effective filecat backend was not reported by 'filecat config show'."
    }

    Write-Host "Testing filecat backend '$Backend'..." -ForegroundColor Cyan
    & $Python -m filecat config test $Backend
    if ($LASTEXITCODE -ne 0) {
        throw "The filecat backend '$Backend' failed its configuration test; no shares were scanned."
    }

    if ($User) {
        # One connection to IPC$ carries these credentials to every share on the server.
        & net.exe use "\\$ServerName\IPC$" /user:$User *
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to connect to \\$ServerName as $User."
        }
    }

    $ShareOutput = & net.exe view "\\$ServerName" /all
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to list shares on $ServerName."
    }
    $SharesToScan = @($ShareOutput | ForEach-Object {
        if ($_ -match '^(?<Name>.+?)\s+(?<Type>Disk|Print)\s*(?<Remark>.*)$') {
            [pscustomobject]@{
                Name   = $Matches.Name.Trim()
                Type   = $Matches.Type.Trim()
                Remark = $Matches.Remark.Trim()
            }
        }
    })
    Write-Host "Found $($SharesToScan.Count) total shares on $ServerName." -ForegroundColor Cyan
    $Roots = @($SharesToScan | Where-Object { $_.Type -eq 'Disk' -and $_.Name -ne 'Admin' } |
        ForEach-Object { "\\$ServerName\$($_.Name)" })
    if ($Roots.Count -eq 0) {
        throw "No disk shares to scan on $ServerName."
    }

    # One scan run takes every share: an unreachable one is recorded and skipped.
    $ScanArgs = @('-m', 'filecat', 'scan') + $Roots + @('--backend', $Backend, '--workers', $Workers)
    if ($Alias) {
        $ScanArgs += @('--alias', "\\$ServerName=\\$Alias")
        Write-Host "Recording $($Roots.Count) shares as \\$Alias\<share>." -ForegroundColor Cyan
    }
    & $Python @ScanArgs
    # Exit 1 means some files or shares carry errors (see 'filecat roots'); anything else is a failure.
    if ($LASTEXITCODE -eq 1) {
        Write-Warning "filecat scan finished with errors on some records; see 'filecat roots'."
    } elseif ($LASTEXITCODE -ne 0) {
        throw "filecat scan failed on $ServerName (exit $LASTEXITCODE)."
    }
} finally {
    Pop-Location
}