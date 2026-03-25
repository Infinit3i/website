---
title: "VirusTotal Watcher"
date: 2026-03-25 07:00:00 -0500
categories: [Project, GitHub]
tags: [linux, virustotal, malware, quarantine, bash, systemd, inotify, security-tools, threat-detection, file-scanning, dotfiles, arch-linux, defensive-security]
---

A lightweight, real-time download scanner that quarantines new files in `~/Downloads`, checks their SHA256 hash against VirusTotal, and only releases them once verified clean.

## Why

Every file you download is a potential threat. Browsers don't verify file reputation beyond basic Safe Browsing checks. VT Watcher adds a second layer — every file that lands in your Downloads folder is automatically hashed, checked against 70+ antivirus engines via VirusTotal, and held in quarantine until cleared.

## How It Works

```
New file arrives in ~/Downloads
        │
        ▼
  Strip execute permission
  Move to ~/Downloads/.quarantine/
        │
        ▼
  Compute SHA256 hash
  Log hash to ~/.local/share/vt-watcher-hashes.log
        │
        ▼
  Query VirusTotal API with hash
        │
        ├── CLEAN (0 detections)
        │     → Release back to ~/Downloads
        │     → Cache hash to skip future re-scans
        │
        ├── MALICIOUS / SUSPICIOUS
        │     → Keep quarantined
        │     → Desktop notification (critical)
        │
        └── UNKNOWN (not in VT database)
              → Keep quarantined
              → Desktop notification to review
```

## Requirements

- **OS**: Linux (tested on Arch Linux)
- **Dependencies**: `inotify-tools`, `curl`, `jq`, `libnotify` (`notify-send`)
- **VirusTotal API key**: Free tier at [virustotal.com](https://www.virustotal.com) (4 requests/min, 500/day)
- **GNU Stow**: For dotfiles deployment

On Arch:

```bash
sudo pacman -S inotify-tools curl jq libnotify
```

## Installation

### 1. Clone the dotfiles

The watcher lives in a stow-managed dotfiles repo with the following structure:

```
~/.dotfiles/
├── bin/.local/bin/
│   ├── vt-watcher.sh        # Main watcher daemon
│   └── vt-release.sh        # Manual quarantine release tool
├── systemd-user/.config/systemd/user/
│   └── vt-watcher.service   # Systemd user service
└── Makefile
```

### 2. Add your API key

```bash
mkdir -p ~/.config/vt-watcher
echo "YOUR_VT_API_KEY" > ~/.config/vt-watcher/api_key
```

### 3. Deploy

```bash
cd ~/.dotfiles
make security
```

This runs `stow bin` and `stow systemd-user`, reloads systemd, and enables the watcher service.

Or manually:

```bash
cd ~/.dotfiles
stow bin
stow systemd-user
systemctl --user daemon-reload
systemctl --user enable --now vt-watcher.service
```

## Usage

### Check service status

```bash
systemctl --user status vt-watcher.service
```

### View logs

```bash
# Activity log
tail -f ~/.local/share/vt-watcher.log

# Hash log
cat ~/.local/share/vt-watcher-hashes.log
```

### Manage quarantine

```bash
# List quarantined files
vt-release.sh --list

# Manually release a file after review
vt-release.sh suspicious-file.exe
```

## Example Log Output

```
[2026-03-25 08:13:35] NEW: Processing document.pdf
[2026-03-25 08:13:35] HASH: document.pdf -> fb5a425bd3b3cd6...
[2026-03-25 08:13:51] CLEAN: document.pdf (0:0:0:63) — releasing from quarantine
```

The detection stats format is `malicious:suspicious:harmless:undetected` — representing how many of VirusTotal's 70+ engines flagged the file.

## How It Handles Edge Cases

| Scenario | Behavior |
|---|---|
| Browser partial downloads (`.part`, `.crdownload`) | Skipped until renamed to final filename |
| File still being written | Waits for file size to stabilize before scanning |
| Same file re-downloaded | Cache hit — skips re-scan, no delay |
| VT rate limit exceeded | Waits 60 seconds and retries once |
| API key missing or invalid | Service exits with error and desktop notification |
| File not in VT database | Stays quarantined with notification to review manually |

## Limitations

- **Hash-only lookup**: VT only knows files that have been previously submitted. A brand-new, targeted payload will return "unknown" — not a guarantee of safety.
- **Free API tier**: 4 requests/minute, 500/day. Fine for normal download volume, but heavy downloading will hit the rate limit.
- **Not a sandbox**: This checks file reputation, not runtime behavior. For behavioral analysis, pair with ClamAV or a local sandbox.
- **No browser integration**: Files are caught after they land on disk. There is a brief window between write and quarantine.

## Pairing with ClamAV

VT Watcher complements a local ClamAV setup. VT checks cloud reputation across 70+ engines in real time, while ClamAV performs signature-based scanning locally on a schedule. Together they provide both immediate reputation checks and periodic deep scans:

```
~/.dotfiles/
├── bin/.local/bin/
│   ├── clamav-hourly.sh      # Local AV scan
│   ├── vt-watcher.sh         # Cloud reputation check
│   └── vt-release.sh         # Quarantine management
└── systemd-user/.config/systemd/user/
    ├── clamav-hourly.service
    ├── clamav-hourly.timer
    └── vt-watcher.service
```

## Source

### vt-watcher.sh

```bash
#!/bin/bash
WATCH_DIR="$HOME/Downloads"
QUARANTINE_DIR="$HOME/Downloads/.quarantine"
CONFIG_DIR="$HOME/.config/vt-watcher"
API_KEY_FILE="$CONFIG_DIR/api_key"
VT_API="https://www.virustotal.com/api/v3/files"
CLEAN_CACHE="$CONFIG_DIR/clean_cache"

# Watch for new files with inotifywait
# Quarantine immediately, hash, query VT, release or hold
inotifywait -m -r \
    -e close_write -e moved_to \
    --exclude '\.quarantine' \
    --format '%w%f' \
    "$WATCH_DIR" | while read -r file; do
        # compute sha256, check cache, quarantine, query VT
        # release if clean, hold if malicious/unknown
    done
```

### vt-release.sh

```bash
#!/bin/bash
# Usage: vt-release.sh <filename>    — release from quarantine
#        vt-release.sh --list        — list quarantined files
```
