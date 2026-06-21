# Agent Guide — Investigator

Python forensics app for Windows client machines. Answers: who logged in, when, what they did, and resource consumption over a period.

## Setup

- **Python venv required** — always create and activate before working
- **Windows-only target** — final deliverable is a standalone `.exe` (use PyInstaller or similar)

## Commands (to be defined)

No package manager or build config exists yet. When adding one:

- Prefer standard Python project layout (pyproject.toml, src/ layout)
- Add `requirements.txt` or `pyproject.toml` as the source of truth for dependencies
- Define test, lint, and build scripts there

## Security

- "Cyber-proof" is a stated goal — avoid hardcoded creds, validate all inputs, use safe deserialization
- Since the app runs on Windows and inspects system state, be mindful of privilege escalation and data sanitization

## Context

The project's single source of truth for intent is `context.md` at repo root. Check it before making architectural decisions.
