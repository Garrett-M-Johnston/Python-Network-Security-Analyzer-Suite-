# Network Security Monitoring Tool

A Python-based desktop application for basic network monitoring and file security operations, providing URL analysis and encryption capabilities.

## Features

### Network Monitoring
- Port scanning capabilities (1-1024 ports)
- Network traffic visualization
- Multi-threaded scanning operations
- Queue-based result processing

### Security Analysis
- URL threat detection using pattern matching
- Suspicious TLD identification
- Phishing keyword detection
- Malicious URL pattern recognition
- IP address and URL shortener detection

### Encryption Tools
- Text encryption/decryption
- File encryption/decryption
- Password-based key derivation (PBKDF2)
- Fernet symmetric encryption

### User Interface
- Custom-styled Tkinter GUI
- Real-time data visualization
- Dark mode support
- Responsive layout design

## Requirements

- Python 3.8+
- Npcap (Windows)
- Required packages:
- 
## Installation

1. Clone the repository
2. Install required packages:
```bash
# Verify packages
pip install -r requirements.txt

# If any missing, install individually:
pip install scapy==2.5.0
pip install cryptography==41.0.0
pip install matplotlib==3.7.0
