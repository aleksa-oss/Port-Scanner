# Network Service Banner Grabber

A **beginner-level** multi-threaded network service scanner and banner grabber written in Python.  
This tool demonstrates how to use raw sockets and protocol-specific packets for network enumeration and reconnaissance.

---

## Features

- Scans common network services and attempts to gather banner and protocol information.
- Supports protocols like HTTP, HTTPS, FTP, SSH, Telnet, DNS, LDAP, SNMP, SMB, Kerberos, RDP, MSSQL, PostgreSQL, and more.
- Multi-threaded scanning for speed.
- Customizable ports and ranges.
- Built purely with Python standard libraries using sockets and SSL.

---

## Important Note

This script is intended as a **learning example** for those beginning network programming and security scanning.  
It does **not guarantee** 100% accuracy or reliability in real-world environments. Many services might not respond as expected, use encryption, or implement protections that limit banner grabbing.  
Use this tool to understand the basics of socket communication, protocol negotiation, and network enumeration, **not** as a production-grade scanner.

---

## Requirements

- Python 3.6+
- No external dependencies besides the Python standard library.

---

## Usage

```bash
python3 main.py <host> [options]

