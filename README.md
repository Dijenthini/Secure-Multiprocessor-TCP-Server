# 🔐 Secure Multiprocessor TCP Application Server

[![C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.linux.org/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-721412?style=for-the-badge&logo=openssl&logoColor=white)](https://www.openssl.org/)

A **multi-client TCP server** built in C with custom protocol framing, salted SHA256 authentication, session token management, and comprehensive security features.

---
## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [File Structure](#-file-structure)
- [Installation](#-installation)
- [Usage](#-usage)
- [Commands](#-commands)
- [Security Features](#-security-features)
- [Logging Format](#-logging-format)

---
## 🎯Features

| Feature | Description |
|---------|-------------|
| **TCP Server** | Concurrent multi-client handling using `fork()` |
| **Custom Protocol** | `LEN:<n> <payload>` explicit framing architecture |
| **Authentication** | REGISTER, LOGIN, LOGOUT commands |
| **Password Security** | Salted SHA256 hashing (passwords NEVER stored in plain text) |
| **Session Management** | 32-character hex tokens with 5-minute auto-expiry |
| **Rate Limiting** | 10 requests per minute per IP address |
| **Brute-Force Protection** | Account lockout after 3 consecutive failed attempts |
| **Audit Logging** | Comprehensive logging with timestamps, IP, PID, username |
| **Zombie Prevention** | SIGCHLD signal handler with `waitpid()` |
| **Colored Output** | ANSI escape codes for better readability |

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    SERVER (C Language)                      │
│                                                             │
│                    Port: 50158  SID: 1041                   │
│                                                             │
│          ┌─────────┐                                        │
│          │ Parent  │                                        │
│          │ Process │                                        │
│          │         │                                        │
│          │(accept) │──fork()──▶ Child 1 ───▶ Client 1      │
│          │         │                                        │
│          │         │──fork()──▶ Child 2 ───▶ Client 2      │
│          │         │                                        │
│          │         │──fork()──▶ Child N ───▶ Client N      │
│          └─────────┘                                        │
└─────────────────────────────────────────────────────────────┘

                              ▼

┌─────────────────────────────────────────────────────────────┐
│                      CLIENT (Python)                        │
│                                                             │
│  Commands:                                                  │
│  • REGISTER <username> <password>                           │
│  • LOGIN <username> <password>                              │
│  • LOGOUT                                                   │
│                                                             │
│  Protocol: LEN:<byte_count> <command>                       │
└─────────────────────────────────────────────────────────────┘
```
---

## Tech Stack

| Technology | Purpose |
|------------|---------|
| **C Language** | High-performance server implementation |
| **Python 3** | Client application with interactive menu |
| **TCP Sockets** | Reliable, connection-oriented network communication |
| **OpenSSL (SHA256)** | Cryptographically secure password hashing |
| **fork()** | Concurrent multi-process client handling |
| **waitpid()** | Proper child process cleanup (zombie prevention) |
| **ANSI Escape Codes** | Colored terminal output (PINK, GREEN, RED) |
| **GCC** | Compilation with Makefile build automation |

---

## 📂 File Structure

📁 Secure-Multiprocessor-TCP-Server/

│

├── 📄 server_4158.c # C server implementation

├── 📄 client_4158.py # Python client implementation

├── 📄 Makefile_4158 # Build automation

├── 📄 README.md # Project documentation

└── 📄 server_IT24104158.log # Sample audit log file

---

## 📥 Installation

### Prerequisites

```bash
sudo apt update

sudo apt install gcc make libssl-dev python3 -y
```
### Clone the Repository
```bash
git clone https://github.com/Dijenthini/Secure-Multiprocessor-TCP-Server.git

cd Secure-Multiprocessor-TCP-Server
```

### Build the Server
```bash
make -f Makefile_4158

```
---

## 🚀 Usage

### Step 1: Start the Server

```bash
./server_4158
```

**Expected output:**

=== IE2102 Assignment Server ===

Student: IT24104158

Port: 50158

SID: 1041

PID: 12345

================================



### Step 2: Run the Client

```bash
python3 client_4158.py
```

**Expected output:**

Connected to 127.0.0.1:50158

--- Menu ---
1. Register
2. Login
3. Logout
Choice:

---

## 📝 Commands

| Command | Format | Description |
|---------|--------|-------------|
| REGISTER | `REGISTER <username> <password>` | Create account |
| LOGIN | `LOGIN <username> <password>` | Authenticate |
| LOGOUT | `LOGOUT` | End session |

---

## 🔐 Security Features

### Password Hashing Flow

| Step | Action | Example |
|------|--------|---------|
| 1 | User provides password | `mypass123` |
| 2 | Generate random salt (16 bytes) | `a1b2c3d4e5f6...` |
| 3 | Combine salt + password | `a1b2c3d4...mypass123` |
| 4 | Apply SHA256 hashing | `8f4e3a2b1c0d...` |
| 5 | Store salt + hash together | `[a1b2c3...][8f4e3a2b...]` |

**✓ Result:** Original password is NEVER stored in plain text!



### Security Measures

| Feature | Implementation | Protection |
|---------|----------------|------------|
|Salted Hashing	| SHA256 + 16-byte random salt | Rainbow table attacks|
|Session Tokens	| 32-char hex, 5-min expiry	| Session hijacking|
|Rate Limiting	| 10 req/min per IP	| DoS/DDoS attacks|
|Brute-Force Lockout	| 3 attempts → 60-sec lock	| Password guessing|
|Username Validation	| 3-32 chars, alphanumeric	| Input attacks|
|Payload Rejection	| >4096 bytes rejected	| Buffer overflow|

---

## 📊 Logging Format

[YYYY-MM-DD HH:MM:SS] IP:client_ip:port PID:process_id USER:username CMD:command RESULT:result



### Sample Log Entries

[2026-04-12 15:20:35] IP:0.0.0.0:50158 PID:4507 USER:SYSTEM CMD:START RESULT:SUCCESS

[2026-04-12 15:21:36] IP:127.0.0.1:41966 PID:4510 USER:user1 CMD:REGISTER RESULT:SUCCESS

[2026-04-12 15:21:46] IP:127.0.0.1:41966 PID:4510 USER:user1 CMD:LOGIN RESULT:SUCCESS

[2026-04-12 15:23:45] IP:127.0.0.1:41966 PID:4510 USER:user1 CMD:LOGIN RESULT:FAILED

[2026-04-12 15:24:11] IP:127.0.0.1:41966 PID:4510 USER:user1 CMD:LOGIN RESULT:LOCKED

---

## ⭐ Show Your Support

Give this project a star ⭐ on GitHub!

---

## 📧 Contact

- GitHub: [@Dijenthini](https://github.com/Dijenthini)
- LinkedIn: [Dijenthini Mariya Xavier](https://www.linkedin.com/in/dijenthini-mariya-xavier-a70a21368)

---
---

Built with ❤️ and lots of C programming!
