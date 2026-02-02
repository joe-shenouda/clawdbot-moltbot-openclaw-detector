Write-Host "Starting Security Scan for OpenClaw / MoltBot / ClawdBot..." -ForegroundColor Cyan
Write-Host "--------------------------------------------------------"

$found = $false

$port = 18789
$networkConn = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue

if ($networkConn) {
    $found = $true
    Write-Host "[!] CRITICAL: Port $port is OPEN and LISTENING." -ForegroundColor Red
    Write-Host "    State: $($networkConn.State)"
    
    if ($networkConn.LocalAddress -eq "0.0.0.0" -or $networkConn.LocalAddress -eq "::") {
        Write-Host "    [!!!] DANGER: Service is bound to 0.0.0.0. It is potentially accessible from the internet." -ForegroundColor Magenta
    } else {
        Write-Host "    [i] Service is bound to $($networkConn.LocalAddress) (likely local only)." -ForegroundColor Yellow
    }
} else {
    Write-Host "[+] Port $port is not in use." -ForegroundColor Green
}

$targetNames = @("openclaw", "moltbot", "clawdbot")
$processes = Get-Process | Where-Object { 
    $pName = $_.ProcessName.ToLower()
    $pPath = try { $_.Path.ToLower() } catch { "" }
    
    ($targetNames -contains $pName) -or 
    ($pName -eq "node" -and ($targetNames | Where-Object { $pPath -match $_ }))
}

if ($processes) {
    $found = $true
    Write-Host "`n[!] FOUND RUNNING PROCESSES:" -ForegroundColor Red
    foreach ($proc in $processes) {
        Write-Host "    - ID: $($proc.Id) | Name: $($proc.ProcessName)"
    }
} else {
    Write-Host "[+] No active agent processes found." -ForegroundColor Green
}

$userProfile = $env:USERPROFILE
$pathsToCheck = @(
    "$userProfile\.openclaw",
    "$userProfile\.moltbot",
    "$userProfile\.clawdbot",
    "$userProfile\clawdbot",
    "$userProfile\moltbot"
)

$foundPaths = @()
foreach ($path in $pathsToCheck) {
    if (Test-Path $path) {
        $foundPaths += $path
    }
}

if ($foundPaths.Count -gt 0) {
    $found = $true
    Write-Host "`n[!] FOUND CONFIGURATION FOLDERS:" -ForegroundColor Yellow
    foreach ($p in $foundPaths) {
        Write-Host "    - $p"
    }
} else {
    Write-Host "[+] No configuration folders found in User Profile." -ForegroundColor Green
}

Write-Host "--------------------------------------------------------"
if ($found) {
    Write-Host "VERDICT: ARTIFACTS FOUND. PLEASE REVIEW ABOVE." -ForegroundColor Red
} else {
    Write-Host "VERDICT: CLEAN. No traces found." -ForegroundColor Green
}