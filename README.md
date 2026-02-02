# 🛡️ OpenClaw / MoltBot / ClawdBot Security Detector

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg?style=flat&logo=powershell)](https://github.com/joe-shenouda/clawdbot-moltbot-openclaw-detector)
[![Security](https://img.shields.io/badge/Security-Critical-red.svg?style=flat&logo=security)](https://github.com/joe-shenouda/clawdbot-moltbot-openclaw-detector)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Author](https://img.shields.io/badge/Author-Joe%20Shenouda-orange.svg)](https://shenouda.nl)

> **URGENT:** Over **16,000 instances** of OpenClaw (formerly MoltBot & ClawdBot) are currently exposed to the public internet. This tool helps you verify if you are one of them.

---

## 🚨 The Vulnerability
Popular self-hosted AI agents known as **OpenClaw**, **MoltBot**, or **ClawdBot** often bind their internal control port (`18789`) to `0.0.0.0` by default. 

**If this port is exposed, anyone on the internet can:**
* ❌ **Steal your API Keys** (OpenAI, Anthropic, etc.).
* ❌ **Read Private Logs** (WhatsApp, Discord, Telegram integrations).
* ❌ **Execute Remote Code** (RCE) on your host machine.

## ⚡ What This Tool Does
This PowerShell script performs a **deep forensic scan** of your Windows environment to detect traces of these vulnerable agents.

### 🕵️ 3-Point Inspection System:
1.  **Network Scan:** Checks if **TCP Port 18789** is listening and if it is bound to the public internet (`0.0.0.0`).
2.  **Process Analysis:** Scans memory for hidden `node.exe` processes running the bot's code.
3.  **File Forensics:** Searches user directories for leftover configuration artifacts (`.openclaw`, `.moltbot`) that may contain plaintext secrets.

---

## 🚀 Quick Start (Run in 10 Seconds)

You do not need to be a developer to run this.

### Option 1: Download & Run
1.  **[Download the Script Here](https://github.com/joe-shenouda/clawdbot-moltbot-openclaw-detector/archive/refs/heads/main.zip)**
2.  Extract the ZIP file.
3.  Right-click `Scan-OpenClaw.ps1` and select **"Run with PowerShell"**.

### Option 2: Terminal (For Pros)
Clone the repo and run directly:
```powershell
git clone [https://github.com/joe-shenouda/clawdbot-moltbot-openclaw-detector.git](https://github.com/joe-shenouda/clawdbot-moltbot-openclaw-detector.git)
cd clawdbot-moltbot-openclaw-detector
.\Scan-OpenClaw.ps1
