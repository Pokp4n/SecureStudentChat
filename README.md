# SecureStudentChat

A simple local secure chat application for an Applied Cryptography university project.
It demonstrates confidentiality, integrity, authentication, and replay protection without any login or account management.

## Final project files
- server.py
- client.py
- requirements.txt
- README.md

## Features
- Local server + multiple client windows
- AES-256-CBC encryption for confidentiality
- HMAC-SHA256 for integrity and authentication
- Replay protection using UUID message IDs and timestamps
- Security analysis and attack demonstration window

## Quick start
1. python -m venv .venv
2. .\.venv\Scripts\Activate.ps1
3. pip install -r requirements.txt
4. python server.py
5. Open another terminal and run: python client.py
