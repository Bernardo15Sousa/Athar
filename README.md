<div align="center">
  <img src=".assets/Athar_logo_cropped.png" alt="Athar Logo" width="300"/>
</div>

<div align="center">

```
     ___            __
 /\   |  |__|  /\  |__)
/~~\  |  |  | /~~\ |  \
```

**v0.1.0 — by Bernardo Sousa**

*Every file leaves a trace. Athar finds it.*

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)

</div>

---

## What is Athar?

Athar is a cross-platform Python DFIR tool that ingests Windows forensic artefacts, correlates them temporally, and produces an analyst-ready timeline with findings, confidence scores, and a self-contained HTML report.

It does one thing — and does it well.

## Artefacts Supported

| Artefact | Description |
|---|---|
| **Prefetch** (`.pf`) | Windows execution traces — binary names, run counts, timestamps |
| **$MFT** | Master File Table — file creation, deletion, modification, timestomp detection |
| **$UsnJrnl:$J** | USN Change Journal — granular file system activity log |
| **Event Logs** (`.evtx`) | Security, System, PowerShell — logons, process creation, persistence events |

## What it Detects

- LOLBin executions (WMIC, Rundll32, PowerShell, CertUtil, etc.)
- Files created and executed within seconds
- Timestomping ($STANDARD\_INFORMATION vs $FILE\_NAME divergence)
- Log clearing events followed by suspicious activity
- Service installation with correlated binary drops
- Scheduled task creation
- Executable staging and execution chains

## Output Formats

- **JSON** — structured, machine-readable, with metadata header
- **CSV** — flat timeline compatible with Timeline Explorer (EZ Tools)
- **HTML** — self-contained forensic report, works fully offline

## Installation

```bash
git clone https://github.com/bernardosousa/athar
cd athar
pip install .
```

## Quick Usage

```bash
athar --prefetch C:\Windows\Prefetch\ \
      --mft path/to/$MFT \
      --usn path/to/$J \
      --evtx path/to/evtx/ \
      --output ./results \
      --format all
```

---

<div align="center">
  MIT License · Bernardo Sousa · 2024
</div>
