# Scripting & Automation: Phase 1

Two command-line security tools built for Phase 1 of the Scripting & Automation
program: one in Bash and one in Python. Each tool bundles two related features
as modes of a single script.

| Tool | Language | Modes | Details |
|------|----------|-------|---------|
| [SecToolkit (Bash)](Bash-Tool/) | Bash | Log Analyzer, File Integrity Checker | [README](Bash-Tool/README.md) |
| [SecTool (Python)](Python-Tool/) | Python 3 | Password Generator, Security Report Generator | [README](Python-Tool/README.md) |

## Repository structure
```
Phase-1/
├── Bash-Tool/
│   ├── tool.sh
│   ├── README.md
│   └── screenshots/
└── Python-Tool/
    ├── tool.py
    ├── README.md
    └── screenshots/
```

## Quick start
```bash
# Bash tool
cd Bash-Tool
chmod +x tool.sh
./tool.sh --help

# Python tool
cd ../Python-Tool
python3 tool.py -h
```

## Author
KUYA PITER (kd3army)
