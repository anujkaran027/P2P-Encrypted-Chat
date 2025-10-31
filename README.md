# Encrypted Chat (P2P) 🔐💬

A **real-time, end-to-end encrypted peer-to-peer chat application** built with **Python**, **Tkinter**, and **cryptography.io**. No server required — direct IP-based communication with secure key exchange.

---

## Features

- **End-to-End Encryption**: RSA for key exchange, AES-CFB for messages
- **Direct P2P Connection**: No central server
- **Secure Key Exchange**: RSA-2048 with OAEP padding
- **Thread-Safe GUI**: Tkinter with `after()` for safe updates
- **Robust Networking**: Length-prefixed messages (`send_msg`/`recv_msg`)
- **Clean Disconnect Handling**: "Chat Disabled" on both sides
- **Generator-Based Server**: Show IP/Port before `accept()`
- **Cross-Platform**: Works on Windows, macOS, Linux

---

## Screenshots

---

## How to Run

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/Encrypted-Chat-P2P.git
```

### 2. Install dependencies
```bash
pip install cryptography
```

### 3. Run the app
```bash
python chat_gui.py
```

---

## Technologies Used

* Python 3
* cryptography.io (RSA, AES, OAEP)
* Tkinter (GUI)
* socket (Networking)
* threading (Async receive)

## Future Improvements

- AES-GCM (authenticated encryption)
- Public key fingerprint verification
- Message timestamps
- Chat history save/load

## Contact

anujkaran255@gmail.com
