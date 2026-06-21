# Investigator

Windows forensics tool. Answers: who logged in, when, what they did, and resource consumption over a period.

## Prerequisites

- Windows (collectors read Security Event Log)
- Python 3.10+

## Setup

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```powershell
python -m investigator --hours 48 --resource-duration 30
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--hours` | 24 | Hours of history to investigate |
| `--resource-duration` | 60 | Seconds to sample resource consumption |
| `--resource-interval` | 2 | Interval (s) between resource samples |
| `--output` | text | Output format: `text` or `json` |
| `--server` | (local) | Remote Windows event log server |

## Build

```powershell
pip install pyinstaller
pyinstaller --onefile src/investigator/__main__.py --name investigator
```

## Security

All user-facing inputs are validated (shell metacharacter filtering, bounds checking). No hardcoded credentials.

## Project

```
src/investigator/
├── __main__.py         # CLI entry point
├── models/models.py    # Data models
├── collectors/
│   ├── logins.py       # Security Event Log (4624/4634/4647)
│   ├── activity.py     # Process creation (4688)
│   └── resources.py    # psutil-based sampling
├── analysis/report.py  # Text report generation
└── utils/security.py   # Input validation
```
