# Scabular
TLDR; Scanning child-parent process relationships.

**Scabular** was created while im working on becoming a blue teamer. Scabular is a lightweight and local cybersecurity tool for analyzing Windows process lists and detecting unusual parent-child relationships. It's designed mainly for blue team learners, malware analysts, and SOC trainees who want to explore process anomalies.
This is not meant to be used by professionals though, as SOC tools already scan for unusal parent-child relationships.

## What It Does

Scabular parses process data from exports (from task manager) and flags suspicious or uncommon parent-child process combinations.

## Installation

Dependencies is pandas, thats it ^.^

```bash
pip install -r requirements.txt
```

## How to Use

To analyze a CSV file:

```
python3 scabular.py analyze --file sample.csv
```

Or with British spelling :)

```
python3 scabular.py analyse --file sample.csv
```

Example output:

[!] Command used: analyze (American spelling)
[!] Initiating analysis on file: sample.csv
[+] Loaded 4 processes from file

[!] Scanning for suspicious process relationships...

[!] Suspicious relationships detected:

🚨 Parent: explorer.exe (PID: 1368)
   → Child: cmd.exe (PID: 1560)

## Detection Logic

Based on real-world ATT&CK techniques:

Examples: 
explorer.exe → cmd.exe        T1059.003
svchost.exe → powershell.exe  T1047





