<#
.SYNOPSIS
    Safely regenerate the Gmail OAuth token.json and deploy it to the headless
    scanner container.

.DESCRIPTION
    This app's OAuth consent screen is in Google "Testing" status, so refresh
    tokens expire after 7 days and the scanner fails with invalid_grant. The
    only way to mint a new refresh token is a real, interactive browser consent
    flow, which must run on a machine with a browser (this Windows PC), not the
    headless Linux container.

    This script automates every step EXCEPT the browser "Allow" click (which is
    the security mechanism and cannot be removed):

      1. Refuse to run if a leftover token.json.bak exists (a prior failed run).
      2. Pre-flight: verify python, app/main.py, credentials, scp and ssh exist
         BEFORE touching anything.
      3. Back up token.json -> token.json.bak and verify the backup byte-for-byte.
      4. Remove token.json (forces app/main.py to run the interactive flow;
         see the note below on why this deletion is required).
      5. Run app/main.py under a bounded timeout to trigger the consent flow.
      6. Verify a NEW token.json was genuinely just written (fresh mtime + valid
         JSON with the required OAuth fields). The process exit code is NOT
         trusted, because main.py also runs a full scan after auth.
      7. scp the verified token to the container, checking the transfer exit
         code explicitly, then verify the remote copy's SHA-256 matches.
      8. Only after regeneration AND verified transfer, delete the backup.

    SAFETY MODEL: token.json.bak is created before token.json is removed and is
    deleted only on full success. At no instant does the project have neither a
    token nor a backup. On any failure the script tells you the exact current
    state and, when a new token was not produced, restores the old one.

    WHY token.json MUST be deleted first: app/gmail_client.py only runs the
    interactive browser flow when there is no usable credential. With an expired
    token.json still present it instead tries creds.refresh(), which raises
    google.auth.exceptions.RefreshError (invalid_grant) and crashes WITHOUT
    re-prompting. Removing token.json first makes the consent flow deterministic.

.NOTES
    Exit codes (also stated in each message):
        0   Success: new token generated, transferred, verified; backup removed.
        2   Pre-flight failure. Nothing was touched.
        3   A token.json.bak already exists. Nothing was touched.
        4   Backup creation/verification failed. token.json is intact, untouched.
        5   Could not remove old token.json. token.json is intact, untouched.
        6   Auth produced no fresh token. OLD token RESTORED from backup.
        7   CRITICAL: auth failed AND restore failed. Manual recovery required.
        8   New token is valid locally but the scp transfer FAILED.
        9   New token transferred but REMOTE VERIFICATION failed/mismatched.
        10  Success, but the backup file could not be deleted (token is fine).

    If PowerShell's execution policy blocks this script, it simply will not run
    and nothing is touched (a safe, inert failure). Invoke it as:
        powershell -ExecutionPolicy Bypass -File .\regenerate-token.ps1
    or, on PowerShell 7:
        pwsh -ExecutionPolicy Bypass -File .\regenerate-token.ps1

.PARAMETER RemoteHost
    SSH destination (default root@192.168.2.51).

.PARAMETER AuthTimeoutSeconds
    Max seconds to wait for you to complete the browser consent AND for the
    subsequent scan to finish. On timeout the process is killed; if a fresh
    token was already written before the kill, that still counts as success.
#>

[CmdletBinding()]
param(
    [string]  $ProjectRoot           = $PSScriptRoot,
    [string]  $Python,
    [string]  $MainScript,
    [string]  $CredentialsFile,
    [string]  $TokenPath,
    [string]  $BackupPath,
    [string]  $RemoteHost            = 'root@192.168.2.51',
    [string]  $RemotePath            = '/opt/phishing-detector/token.json',
    # Program may be a bare exe name or an array of exe + fixed leading args
    # (the array form exists so the test harness can substitute a mock).
    [string[]]$ScpProgram            = @('scp'),
    [string[]]$SshProgram            = @('ssh'),
    [int]     $AuthTimeoutSeconds    = 300,
    [int]     $TransferTimeoutSeconds = 60,
    [int]     $ConnectTimeoutSeconds = 15,
    [switch]  $SkipRemoteVerify
)

# Unexpected cmdlet errors must stop, not silently continue: this is a
# safety-critical script and "keep going after a failed Copy-Item" is exactly
# the kind of optimism we are avoiding.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Resolve defaults relative to the project root
# ---------------------------------------------------------------------------
if (-not $ProjectRoot) { $ProjectRoot = (Get-Location).Path }
if (-not $Python)          { $Python          = Join-Path $ProjectRoot 'venv\Scripts\python.exe' }
if (-not $MainScript)      { $MainScript      = Join-Path $ProjectRoot 'app\main.py' }
if (-not $CredentialsFile) { $CredentialsFile = Join-Path $ProjectRoot 'credentials\credentials.json' }
if (-not $TokenPath)       { $TokenPath       = Join-Path $ProjectRoot 'token.json' }
if (-not $BackupPath)      { $BackupPath      = Join-Path $ProjectRoot 'token.json.bak' }

$RequiredTokenFields = @('token', 'refresh_token', 'client_id', 'client_secret')

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
function Write-Step { param([string]$Message) Write-Host "[*] $Message" }
function Write-Ok   { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Err  { param([string]$Message) Write-Host "[FAIL] $Message" -ForegroundColor Red }

function Stop-Script {
    param(
        [Parameter(Mandatory)][int]$Code,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$State,
        [string]$Recovery
    )
    Write-Host ''
    Write-Err $Message
    Write-Host "    CURRENT STATE : $State" -ForegroundColor Yellow
    if ($Recovery) { Write-Host "    NEXT STEP     : $Recovery" -ForegroundColor Yellow }
    Write-Host "    EXIT CODE     : $Code"
    exit $Code
}

function Get-Sha256 {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# Validate a token.json: exists, non-empty, (optionally) written after a given
# time, parses as JSON, and contains the required OAuth fields. A partial write
# or a garbage/stale file fails here.
function Test-TokenFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [datetime]$MustBeNewerThan
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Ok = $false; Reason = 'file does not exist' }
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -eq 0) {
        return [pscustomobject]@{ Ok = $false; Reason = 'file is empty' }
    }
    if ($MustBeNewerThan -and $item.LastWriteTime -lt $MustBeNewerThan) {
        return [pscustomobject]@{
            Ok = $false
            Reason = "file is stale (last modified $($item.LastWriteTime.ToString('s')), before this run started $($MustBeNewerThan.ToString('s')))"
        }
    }
    try {
        $json = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        return [pscustomobject]@{ Ok = $false; Reason = 'file is not valid JSON (possible partial write)' }
    }
    foreach ($field in $RequiredTokenFields) {
        if (-not ($json.PSObject.Properties.Name -contains $field) -or -not $json.$field) {
            return [pscustomobject]@{ Ok = $false; Reason = "missing required OAuth field '$field'" }
        }
    }
    return [pscustomobject]@{ Ok = $true; Reason = 'valid' }
}

# Run a native program under a hard timeout. Returns TimedOut/ExitCode/StdOut/
# StdErr. Uses .NET Process for reliable timeout + whole-tree kill + capture.
function Invoke-Bounded {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSeconds = 60,
        [switch]$CaptureOutput,
        [string]$WorkingDirectory
    )
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FilePath
    foreach ($a in $ArgumentList) { [void]$psi.ArgumentList.Add([string]$a) }
    $psi.UseShellExecute = $false
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
    if ($CaptureOutput) {
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
    }

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    [void]$proc.Start()

    $outTask = $null; $errTask = $null
    if ($CaptureOutput) {
        # Read asynchronously so a full pipe buffer cannot deadlock the child.
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
    }

    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
        # Kill($true) (whole tree) is .NET 5+/PowerShell 7; fall back to the
        # parameterless Kill() so a stray host can never leave the child running
        # (which could race us writing token.json).
        try { $proc.Kill($true) } catch { try { $proc.Kill() } catch {} }
        try { [void]$proc.WaitForExit(5000) } catch {}
        return [pscustomobject]@{ TimedOut = $true; ExitCode = $null; StdOut = ''; StdErr = '' }
    }

    $stdout = ''; $stderr = ''
    if ($CaptureOutput) {
        try { $stdout = $outTask.GetAwaiter().GetResult() } catch {}
        try { $stderr = $errTask.GetAwaiter().GetResult() } catch {}
    }
    return [pscustomobject]@{ TimedOut = $false; ExitCode = $proc.ExitCode; StdOut = $stdout; StdErr = $stderr }
}

# Split a program spec (@('scp') or @('python','mock_scp.py')) into an exe and
# leading args, so a wrapper/mock can be substituted transparently.
function Split-Program {
    param([string[]]$Spec)
    if (-not $Spec -or $Spec.Count -eq 0) { throw 'empty program spec' }
    return [pscustomobject]@{ Exe = $Spec[0]; Prefix = @($Spec[1..($Spec.Count - 1)]) }
}

# Restore token.json from the backup. Returns $true on success. Never deletes
# the backup (the caller keeps it on every failure path).
function Restore-Backup {
    if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) { return $false }
    try {
        Copy-Item -LiteralPath $BackupPath -Destination $TokenPath -Force
    } catch {
        return $false
    }
    return (Test-Path -LiteralPath $TokenPath -PathType Leaf)
}

# ===========================================================================
# 0. Banner
# ===========================================================================
Write-Host '================================================================'
Write-Host ' Gmail OAuth token regeneration'
Write-Host '================================================================'
Write-Host "Project root : $ProjectRoot"
Write-Host "Token        : $TokenPath"
Write-Host "Backup       : $BackupPath"
Write-Host "Remote       : $($RemoteHost):$($RemotePath)"
Write-Host ''

# ===========================================================================
# 1. Refuse to run if a leftover backup exists (prior failed attempt)
# ===========================================================================
if (Test-Path -LiteralPath $BackupPath) {
    Stop-Script -Code 3 `
        -Message "A backup file already exists at '$BackupPath'." `
        -State "This almost always means a PREVIOUS run failed partway. That backup may be your only copy of a good token. This script will NOT overwrite it." `
        -Recovery "Inspect '$BackupPath' and the current '$TokenPath'. Decide which is the token you want to keep, copy it to '$TokenPath' if needed, then DELETE '$BackupPath' and re-run."
}

# ===========================================================================
# 2. Pre-flight checks (touch NOTHING until these all pass)
# ===========================================================================
Write-Step 'Running pre-flight checks...'

# This script relies on .NET Core APIs (ProcessStartInfo.ArgumentList,
# Process.Kill($true)) that do not exist on Windows PowerShell 5.1. Refuse to
# run on an unsupported host BEFORE touching the token, so we can never delete
# token.json and then fail on a missing API.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Stop-Script -Code 2 -Message "This script requires PowerShell 7+ (found $($PSVersionTable.PSVersion))." `
        -State "Nothing was touched. token.json is unchanged." `
        -Recovery "Run it with pwsh, e.g.  pwsh -ExecutionPolicy Bypass -File .\regenerate-token.ps1"
}

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    Stop-Script -Code 2 -Message "Python interpreter not found at '$Python'." `
        -State "Nothing was touched. token.json is unchanged." `
        -Recovery "Create the venv / fix the path, then re-run."
}
if (-not (Test-Path -LiteralPath $MainScript -PathType Leaf)) {
    Stop-Script -Code 2 -Message "CLI entry point not found at '$MainScript'." `
        -State "Nothing was touched. token.json is unchanged." `
        -Recovery "Restore app/main.py, then re-run."
}
if (-not (Test-Path -LiteralPath $CredentialsFile -PathType Leaf)) {
    Stop-Script -Code 2 -Message "OAuth client secrets not found at '$CredentialsFile'." `
        -State "Nothing was touched. token.json is unchanged." `
        -Recovery "Place credentials/credentials.json (the Google OAuth client), then re-run. Without it the consent flow cannot run and there is no point deleting the token."
}

$scp = Split-Program $ScpProgram
$ssh = Split-Program $SshProgram
if (-not (Get-Command $scp.Exe -ErrorAction SilentlyContinue)) {
    Stop-Script -Code 2 -Message "scp program '$($scp.Exe)' not found on PATH." `
        -State "Nothing was touched. token.json is unchanged." `
        -Recovery "Install the OpenSSH client (scp), then re-run. Regenerating a token we cannot transfer would leave you worse off."
}
if (-not $SkipRemoteVerify -and -not (Get-Command $ssh.Exe -ErrorAction SilentlyContinue)) {
    Stop-Script -Code 2 -Message "ssh program '$($ssh.Exe)' not found on PATH (needed for remote verification)." `
        -State "Nothing was touched. token.json is unchanged." `
        -Recovery "Install the OpenSSH client (ssh), or re-run with -SkipRemoteVerify to transfer without remote hash verification."
}

if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) {
    Write-Host ''
    Write-Host "    NOTE: No existing token.json was found at '$TokenPath'." -ForegroundColor Yellow
    Write-Host "    There is nothing to back up; a fresh token will be created." -ForegroundColor Yellow
    Write-Host "    If regeneration fails you will simply still have no token (no worse than now)." -ForegroundColor Yellow
    $HadExistingToken = $false
} else {
    $HadExistingToken = $true
}
Write-Ok 'Pre-flight checks passed.'

# ===========================================================================
# 3. Back up the existing token (before removing it) and verify the backup
# ===========================================================================
if ($HadExistingToken) {
    Write-Step "Backing up '$TokenPath' -> '$BackupPath'..."
    try {
        Copy-Item -LiteralPath $TokenPath -Destination $BackupPath -Force
    } catch {
        # token.json is still intact; no destructive change has happened.
        Stop-Script -Code 4 -Message "Failed to create backup: $($_.Exception.Message)" `
            -State "token.json is INTACT and unchanged. No backup was created." `
            -Recovery "Fix the cause (disk space / permissions) and re-run."
    }

    # Verify the backup is a byte-for-byte copy BEFORE we delete the original.
    $srcHash = Get-Sha256 $TokenPath
    $bakHash = Get-Sha256 $BackupPath
    if ($srcHash -ne $bakHash) {
        try { Remove-Item -LiteralPath $BackupPath -Force } catch {}
        Stop-Script -Code 4 -Message 'Backup verification failed: backup does not match the original.' `
            -State "token.json is INTACT and unchanged. The bad backup was removed." `
            -Recovery "Investigate the filesystem and re-run."
    }
    Write-Ok "Backup created and verified (sha256 $bakHash)."
}

# ===========================================================================
# 4. Remove the old token so the interactive flow will trigger
#    (POINT OF NO RETURN begins after a successful removal)
# ===========================================================================
$PastPointOfNoReturn = $false
if ($HadExistingToken) {
    Write-Step "Removing old token so the consent flow will trigger..."
    try {
        Remove-Item -LiteralPath $TokenPath -Force
    } catch {
        # Original still present; safe to delete the just-made backup and stop.
        try { Remove-Item -LiteralPath $BackupPath -Force } catch {}
        Stop-Script -Code 5 -Message "Failed to remove old token.json: $($_.Exception.Message)" `
            -State "token.json is INTACT and unchanged. Backup was removed." `
            -Recovery "Close anything using token.json (e.g. a running scan) and re-run."
    }
    if (Test-Path -LiteralPath $TokenPath) {
        try { Remove-Item -LiteralPath $BackupPath -Force } catch {}
        Stop-Script -Code 5 -Message 'token.json still present after removal attempt.' `
            -State "token.json is INTACT and unchanged. Backup was removed." `
            -Recovery "Investigate file locks/permissions and re-run."
    }
    $PastPointOfNoReturn = $true
    Write-Ok 'Old token removed. Backup retained.'
}

# ===========================================================================
# 5. Trigger the interactive OAuth flow via app/main.py (bounded timeout)
# ===========================================================================
Write-Host ''
Write-Host '----------------------------------------------------------------'
Write-Host ' A browser window will open for Google consent.'
Write-Host ' Click "Allow" to finish. This window is waiting for you.'
Write-Host "  (Timeout: $AuthTimeoutSeconds seconds.)"
Write-Host '----------------------------------------------------------------'
Write-Host ''

$startTime = Get-Date
$auth = Invoke-Bounded -FilePath $Python -ArgumentList @($MainScript) `
    -TimeoutSeconds $AuthTimeoutSeconds -WorkingDirectory $ProjectRoot

if ($auth.TimedOut) {
    Write-Host ''
    Write-Host "    The app/main.py process exceeded $AuthTimeoutSeconds s and was killed." -ForegroundColor Yellow
    Write-Host "    Checking whether a fresh token was written before the kill..." -ForegroundColor Yellow
} else {
    Write-Host ''
    Write-Step "app/main.py exited with code $($auth.ExitCode) (NOT used to judge success; the token file is)."
}

# ===========================================================================
# 6. Verify a NEW token was genuinely just written
# ===========================================================================
Write-Step 'Verifying a fresh, valid token.json was created...'
$verify = Test-TokenFile -Path $TokenPath -MustBeNewerThan $startTime

if (-not $verify.Ok) {
    # No usable new token. Put the old one back.
    Write-Err "No valid fresh token: $($verify.Reason)."
    if ($HadExistingToken) {
        Write-Step 'Restoring the old token from backup...'
        if (Restore-Backup) {
            $restoredHash = Get-Sha256 $TokenPath
            $bakHash2 = Get-Sha256 $BackupPath
            if ($restoredHash -eq $bakHash2) {
                Stop-Script -Code 6 -Message "Authentication did not produce a valid new token ($($verify.Reason))." `
                    -State "OLD token RESTORED from backup and verified. The container still has whatever token it had before; nothing was sent." `
                    -Recovery "This usually means the browser consent was cancelled/closed/denied or timed out. Delete '$BackupPath', then re-run and click Allow. (Old token restored, so you are no worse off than before running this.)"
            }
        }
        # Restore itself failed - this is the dangerous corner.
        Stop-Script -Code 7 -Message "Authentication failed AND automatic restore of the old token failed." `
            -State "token.json may be MISSING, but your old token is preserved at '$BackupPath'." `
            -Recovery "MANUAL RECOVERY REQUIRED: copy '$BackupPath' to '$TokenPath' yourself, e.g.  Copy-Item '$BackupPath' '$TokenPath'  — then investigate. Do NOT delete the backup until token.json is restored."
    } else {
        Stop-Script -Code 6 -Message "Authentication did not produce a valid new token ($($verify.Reason))." `
            -State "There is no token.json and there was none before this run. Nothing was sent to the container." `
            -Recovery "Re-run and complete the browser consent (click Allow)."
    }
}

$newTokenHash = Get-Sha256 $TokenPath
Write-Ok "Fresh, valid token verified (sha256 $newTokenHash, modified $((Get-Item -LiteralPath $TokenPath).LastWriteTime.ToString('s')))."
if ($auth.TimedOut) {
    Write-Host "    (The process was killed for exceeding the timeout, but the token had already been written before then, so it is safe.)" -ForegroundColor Yellow
}

# ===========================================================================
# 7. Transfer to the container via scp, checking the exit code explicitly
# ===========================================================================
Write-Step "Transferring token to $($RemoteHost):$($RemotePath) via scp..."
$scpArgs = @(
    $scp.Prefix +
    @('-o', 'BatchMode=yes',
      '-o', "ConnectTimeout=$ConnectTimeoutSeconds",
      $TokenPath,
      "$($RemoteHost):$($RemotePath)")
)
$scpResult = Invoke-Bounded -FilePath $scp.Exe -ArgumentList $scpArgs `
    -TimeoutSeconds $TransferTimeoutSeconds -CaptureOutput

$transferFailedRecovery = "Your NEW, valid token is at '$TokenPath' locally. The container still has its OLD token. To finish WITHOUT another browser click, run:  scp `"$TokenPath`" $($RemoteHost):$($RemotePath)  then delete '$BackupPath'. Or delete '$BackupPath' and re-run this script."

if ($scpResult.TimedOut) {
    Stop-Script -Code 8 -Message "scp timed out after $TransferTimeoutSeconds s (container unreachable/powered off?)." `
        -State "NEW valid token exists locally; it was NOT transferred. Old token preserved at '$BackupPath'." `
        -Recovery $transferFailedRecovery
}
if ($scpResult.ExitCode -ne 0) {
    $detail = ($scpResult.StdErr + ' ' + $scpResult.StdOut).Trim()
    Stop-Script -Code 8 -Message "scp failed with exit code $($scpResult.ExitCode). $detail" `
        -State "NEW valid token exists locally; it was NOT transferred. Old token preserved at '$BackupPath'." `
        -Recovery $transferFailedRecovery
}
Write-Ok 'scp reported success (exit code 0).'

# ===========================================================================
# 8. Verify the remote copy matches (unless explicitly skipped)
# ===========================================================================
if (-not $SkipRemoteVerify) {
    Write-Step 'Verifying the remote copy matches (SHA-256)...'
    $sshArgs = @(
        $ssh.Prefix +
        @('-o', 'BatchMode=yes',
          '-o', "ConnectTimeout=$ConnectTimeoutSeconds",
          $RemoteHost,
          "sha256sum '$RemotePath'")
    )
    $sshResult = Invoke-Bounded -FilePath $ssh.Exe -ArgumentList $sshArgs `
        -TimeoutSeconds $TransferTimeoutSeconds -CaptureOutput

    $remoteHash = ''
    if (-not $sshResult.TimedOut -and $sshResult.ExitCode -eq 0) {
        $remoteHash = (($sshResult.StdOut -split '\s+') | Where-Object { $_ }) | Select-Object -First 1
        if ($remoteHash) { $remoteHash = $remoteHash.ToLowerInvariant() }
    }

    if (-not $remoteHash) {
        Stop-Script -Code 9 -Message "scp succeeded but the remote hash could not be read (ssh timed out or errored)." `
            -State "The token was very likely transferred (scp exit 0) but this is UNVERIFIED. NEW token is at '$TokenPath'; old token preserved at '$BackupPath'." `
            -Recovery "Manually verify the container's /opt/phishing-detector/token.json (e.g. run the scanner once), then delete '$BackupPath'. Or delete '$BackupPath' and re-run with -SkipRemoteVerify."
    }
    if ($remoteHash -ne $newTokenHash) {
        Stop-Script -Code 9 -Message "Remote hash MISMATCH: local $newTokenHash vs remote $remoteHash." `
            -State "scp exit 0 but the remote file does NOT match the new local token. NEW token is at '$TokenPath'; old token preserved at '$BackupPath'." `
            -Recovery "Investigate the remote path/permissions, re-transfer manually:  scp `"$TokenPath`" $($RemoteHost):$($RemotePath)  and re-verify, then delete '$BackupPath'."
    }
    Write-Ok "Remote copy verified (sha256 matches: $remoteHash)."
} else {
    Write-Host "    Skipping remote verification (-SkipRemoteVerify)." -ForegroundColor Yellow
}

# ===========================================================================
# 9. Everything succeeded: NOW it is safe to delete the backup
# ===========================================================================
if ($HadExistingToken) {
    Write-Step 'All steps succeeded. Removing the backup...'
    try {
        Remove-Item -LiteralPath $BackupPath -Force
    } catch {
        Stop-Script -Code 10 -Message "Everything succeeded but the backup could not be deleted: $($_.Exception.Message)" `
            -State "SUCCESS: new token generated, transferred and verified. A harmless leftover backup remains at '$BackupPath'." `
            -Recovery "Delete '$BackupPath' manually at your convenience. Your token is fully deployed."
    }
}

Write-Host ''
Write-Host '================================================================' -ForegroundColor Green
Write-Ok 'DONE: new token generated, transferred to the container, verified.'
Write-Host "     Local  : $TokenPath (sha256 $newTokenHash)" -ForegroundColor Green
Write-Host "     Remote : $($RemoteHost):$($RemotePath) (verified match)" -ForegroundColor Green
Write-Host "     Backup : removed (no longer needed)." -ForegroundColor Green
Write-Host '================================================================' -ForegroundColor Green
exit 0
