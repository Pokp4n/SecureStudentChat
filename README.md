# SecureStudentChat

This project is a local secure messaging application developed for an Applied Cryptography university project. It demonstrates Confidentiality, Integrity, Authentication, and Replay Protection without login, registration, databases, or cloud services.

## Features
- Local server with multiple chat clients
- AES-256-CBC encryption for confidentiality
- HMAC-SHA256 for integrity and authentication
- Replay protection using UUID message IDs and timestamps
- Security Analysis window
- Attack Demonstration window
- Compatible with Wireshark for Packet Sniffing demonstrations

## Security Architecture

Message
→ AES-256-CBC Encryption
→ Ciphertext
→ HMAC-SHA256 Generation
→ Send Packet

Server:
- Verify HMAC
- Check Replay Protection
- Relay Valid Packets

Receiver:
- Receive Packet
- Verify Integrity
- Decrypt Message

## Security Attacks Demonstrated

1. Packet Sniffing Attack — demonstrated using Wireshark
2. Captured packets contain ciphertext instead of plaintext
3. Demonstrates Confidentiality
4. Message Tampering Attack — demonstrated through HMAC verification
5. Modified packets are rejected
6. Demonstrates Integrity
7. Replay Attack — demonstrated through UUID message ID validation
8. Duplicate packets are rejected
9. Demonstrates Authentication and Replay Protection

## Project Files
- server.py
- client.py
- requirements.txt
- README.md

## Quick Start

1. Create a virtual environment
2. Activate the virtual environment
3. Install requirements
4. Run server.py
5. Run one or more client.py instances

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python server.py
```

Open another terminal and run:

```powershell
python client.py
```

Additional client instances can be started in other terminals with the same command to demonstrate multi-client communication through the local secure chat server.

## Project Objective

The objective of this project is to demonstrate how cryptographic mechanisms can protect Confidentiality, Integrity, Authentication, and Replay Protection in a simple secure messaging system for presentation and academic review.
