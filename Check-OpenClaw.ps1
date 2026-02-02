<#
.SYNOPSIS
    OpenClaw / MoltBot / ClawdBot Security Detector
    Author: Joe Shenouda (shenouda.nl)
.DESCRIPTION
    A high-fidelity scanning tool to detect exposed ports, active processes, 
    and configuration artifacts related to vulnerable AI agents.
#>

# --- 1. HELPER FUNCTIONS & VISUALS ---

function Write-Typewriter {
    param([string]$Message, [ConsoleColor]$Color = "White", [int]$Speed = 20)
    $chars = $Message.ToCharArray()
    foreach ($char in $chars) {
        Write-Host $char -NoNewline -ForegroundColor $Color
        Start-Sleep -Milliseconds $Speed
    }
    Write-Host "" # New line
}

function Start-Spinner {
    param([string]$Message, [int]$DurationSeconds = 2)
    $sprites = @("-", "\", "|", "/")
    $endTime = (Get-Date).AddSeconds($DurationSeconds)
    
    Write-Host " [ ] $Message" -NoNewline -ForegroundColor Cyan
    
    # Save cursor position to overwrite the spinner character
    $cursorTop = $Host.UI.RawUI.CursorPosition.Y
    $cursorLeft = 1 
    
    while ((Get-Date) -lt $endTime) {
        foreach ($s in $sprites) {
            try {
                $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $cursorLeft, $cursorTop
                Write-Host $s -NoNewline -ForegroundColor Yellow
            } catch {
                # Fallback for some terminals that don't support cursor moves well
            }
            Start-Sleep -Milliseconds 100
        }
    }
    # Finish line
    try {
        $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $cursorLeft, $cursorTop
    } catch {}
    Write-Host "✔" -ForegroundColor Green
    Write-Host ""
}

function Show-Header {
    Clear-Host
    $cyan = "Cyan"
    Write-Host "================================================================" -ForegroundColor DarkGray
    Write-Host "   ___                   _____ _                 " -ForegroundColor $cyan
    Write-Host "  / _ \ _ __   ___ _ __ /  __ \ | __ ___      __ " -ForegroundColor $cyan
    Write-Host " | | | | '_ \ / _ \ '_ \| /  \/ |/ _` \ \ /\ / / " -ForegroundColor $cyan
    Write-Host " | |_| | |_) |  __/ | | | \__/\ | (_| |\ V  V /  " -ForegroundColor $cyan
    Write-Host "  \___/| .__/ \___|_| |_|\____/_|\__,_| \_/\_/   " -ForegroundColor $cyan
    Write-Host "       | |   SECURITY SCANNER v1.0               " -ForegroundColor $cyan
    Write-Host "       |_|   " -ForegroundColor $cyan -NoNewline
    Write-Host "By Joe Shenouda (shenouda.nl)" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor DarkGray
    Write-Host ""
}

# --- 2. CORE DETECTION FUNCTIONS ---

function Check-Port {
    param([int]$Port)
    $status = @{ Found = $false; Message = "" }
    
    $networkConn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    
    if ($networkConn) {
        $status.Found = $true
        # Check if bound to all interfaces
        if ($networkConn.LocalAddress -eq "0.0.0.0" -or $networkConn.LocalAddress -eq "::") {
             $status.Message = "   [!!!] CRITICAL: Port $Port is OPEN (0.0.0.0) -> PUBLICLY EXPOSED!"
        } else {
             $status.Message = "   [!] WARNING: Port $Port is OPEN (Bound to $($networkConn.LocalAddress))"
        }
    } else {
        $status.Message = "   [+] Port $Port is secure (Not listening)."
    }
    return $status
}

function Check-Processes {
    $targetNames = @("openclaw", "moltbot", "clawdbot")
    $suspicious = @()
    
    # Get all processes safely
    $allProcs = Get-Process -ErrorAction SilentlyContinue
    
    foreach ($proc in $allProcs) {
        $pName = $proc.ProcessName.ToLower()
        $pPath = try { $proc.Path.ToLower() } catch { "" }
        
        # Check 1: Direct name match
        if ($targetNames -contains $pName) {
            $suspicious += $proc
        }
        # Check 2: Node process running target script
        elseif ($pName -eq "node" -and $pPath) {
            foreach ($target in $targetNames) {
                if ($pPath -match $target) {
                    $suspicious += $proc
                    break
                }
            }
        }
    }
    return $suspicious
}

function Check-Files {
    $userProfile = $env:USERPROFILE
    $pathsToCheck = @(
        "$userProfile\.openclaw", "$userProfile\.moltbot", 
        "$userProfile\.clawdbot", "$userProfile\clawdbot", "$userProfile\moltbot"
    )
    $found = @()
    foreach ($path in $pathsToCheck) {
        if (Test-Path $path) { $found += $path }
    }
    return $found
}

# --- 3. MAIN EXECUTION FLOW ---

Show-Header
Start-Sleep -Seconds 1

Write-Typewriter "INITIALIZING SECURITY PROTOCOLS..." -Color Gray
Start-Spinner "Scanning Network Interfaces..." 

# -- Step 1: Port Check
$portResult = Check-Port -Port 18789
if ($portResult.Found) {
    Write-Host $portResult.Message -ForegroundColor Red
} else {
    Write-Host $portResult.Message -ForegroundColor Green
}

Start-Sleep -Milliseconds 500

# -- Step 2: Process Check
Start-Spinner "Analyzing Running Processes..."
$procResult = Check-Processes
if ($procResult) {
    Write-Host "   [!] ACTIVE AGENTS DETECTED:" -ForegroundColor Red
    foreach ($p in $procResult) {
        Write-Host "       -> PID: $($p.Id) | Name: $($p.ProcessName)" -ForegroundColor Magenta
    }
} else {
    Write-Host "   [+] No active malicious agents found in memory." -ForegroundColor Green
}

Start-Sleep -Milliseconds 500

# -- Step 3: File Check
Start-Spinner "Forensic File Scan (User Profile)..."
$fileResult = Check-Files
if ($fileResult.Count -gt 0) {
    Write-Host "   [!] CONFIGURATION ARTIFACTS FOUND:" -ForegroundColor Yellow
    foreach ($f in $fileResult) {
        Write-Host "       -> $f" -ForegroundColor DarkYellow
    }
} else {
    Write-Host "   [+] No configuration folders found." -ForegroundColor Green
}

# --- 4. FINAL VERDICT ---

Write-Host ""
Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray

if ($portResult.Found -or $procResult -or ($fileResult.Count -gt 0)) {
    Write-Host "  ⚠️  SECURITY ALERT: VULNERABILITIES DETECTED  ⚠️" -ForegroundColor White -BackgroundColor Red
    Write-Host ""
    Write-Host "  ACTION REQUIRED:" -ForegroundColor Red
    if ($portResult.Found) { Write-Host "  - Close Port 18789 immediately or update Docker config." }
    if ($procResult) { Write-Host "  - Kill the running processes identified above." }
    if ($fileResult) { Write-Host "  - Review config folders for plaintext API keys." }
} else {
    Write-Host "  ✅  SYSTEM SECURE: NO THREATS DETECTED  ✅" -ForegroundColor Black -BackgroundColor Green
    Write-Host ""
    Write-Host "  You are safe from the OpenClaw/MoltBot vulnerability." -ForegroundColor Green
}

Write-Host "----------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Tool provided by Joe Shenouda | shenouda.nl" -ForegroundColor DarkGray
Write-Host ""
Read-Host -Prompt "Press Enter to exit"
