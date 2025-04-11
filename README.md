# 🔐 SecureLink - IoT Key Exchange & Message Encryption Tool

SecureLink is a lightweight desktop application built using Python's `tkinter` and `cryptography` libraries. It simulates a secure key agreement protocol between a client and a server using **Elliptic Curve Cryptography (ECC)**, and allows users to **encrypt/decrypt messages** with the derived session key. It also incorporates **fuzzy extraction** and **XOR logic** for enhanced security, designed for resource-constrained IoT systems.

---

## 🚀 Features

- ✅ Generate **ECC key pairs** for both client and server.
- 🔁 Perform **key exchange** using ECDH and derive a **session key** with fuzzy extraction.
- 🔐 **AES encryption** (CBC mode) for secure messaging.
- 🔓 **AES decryption** with PKCS7 unpadding.
- 🧠 XOR logic for final session key generation.
- 📜 Automatically logs key exchanges and ciphertext to `protocol_trace.log`.
- 💻 GUI built using Python's `tkinter`.

---

## 🛠️ Tech Stack

- **Frontend:** `tkinter` (Python GUI)
- **Backend:** `cryptography` library
- **Security:** ECC, ECDH, AES (CBC), HKDF, XOR
- **Language:** Python 3

---

## 📦 Requirements

Install the required packages using:

```bash
pip install cryptography
