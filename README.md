# 🔐 File Storage and Backup System

A comprehensive and secure **File Storage / Backup System** developed in Python. The system offers features like real-time log monitoring, anomaly detection, secure authentication, team-based file sharing, and automated backup with synchronization.

---

## 📌 Table of Contents

- [🎯 Project Overview](#-project-overview)
- [🚀 Features](#-features)
- [🧑‍💼 User Profiles](#-user-profiles)
- [🖥️ Interface](#-interface)
- [🗄️ File Backup & Synchronization Module](#-file-backup--synchronization-module)
- [📊 Log Monitoring & Anomaly Detection Module](#-log-monitoring--anomaly-detection-module)
- [📈 User Behavior Analysis Module](#-user-behavior-analysis-module)
- [⚙️ Technologies Used](#-technologies-used)
- [📂 Folder Structure](#-folder-structure)
- [🛠️ How to Run](#-how-to-run)
- [📎 License](#-license)

---

## 🎯 Project Overview

This system is designed to enhance file security, provide real-time log analysis, and detect suspicious user behavior. The platform supports both individual users and administrators, offering flexible backup, synchronization, and security monitoring features.

---

## 🚀 Features

- 🔑 Secure user authentication with password hashing
- 👥 Team member management and shared file access
- 📁 File upload, modification, sharing, and backup
- 🔄 Automatic synchronization between directories
- 🧾 Real-time logging and categorized log files
- ⚠️ Detection and notification of abnormal activities
- 🧠 User behavior tracking and analysis
- 📊 Admin dashboard for system-wide control

---

## 🧑‍💼 User Profiles

### 👤 Individual Users
- Register with unique username and password (hashed securely)
- Change username, send password change requests
- Upload files and share/edit with selected team members
- Receive notifications about shared files and access

### 👮 System Administrators
- Approve/reject password change requests
- Set user-specific storage limits
- Access encrypted passwords, shared files, and logs

---

## 🖥️ Interface

- Simple GUI interface created with `tkinter`
- Dynamic login system with input validation
- Real-time update display for backup and anomaly events
- Notifications and alerts displayed to relevant profiles
- No design color/style constraints

---

## 🗄️ File Backup & Synchronization Module

- **Directory Monitoring**: Watches a source directory for changes
- **Backup**: Copies files to a backup directory using `threading`
- **Synchronization**: Ensures files in source and destination directories match
- **Logging**: Logs include:
  - Start & end timestamps
  - Operation codes & status codes
  - Source directory path
  - Data size

📘 Log Categories:
- Login attempts
- Password change requests
- File uploads/downloads
- Backup operations
- Team interactions
- Anomaly events

---

## 📊 Log Monitoring & Anomaly Detection Module

- Reads log files line-by-line
- Searches for suspicious patterns and keywords (e.g., `failed login`, `unauthorized sharing`)
- Detects:
  - Backup interruptions
  - Excessive upload/download attempts
  - Unauthorized sharing attempts
  - 3+ failed login attempts within a short period
- Alerts shown in GUI and logged

---

## 📈 User Behavior Analysis Module

- Tracks login/logout activities
- Detects repeated failed login attempts
- Notifies users/admins of anomalies
- Triggers real-time anomaly detection module

---

## ⚙️ Technologies Used

- 🐍 **Python 3.x**
- 📦 Libraries:
  - `tkinter` – GUI
  - `hashlib` – Password hashing
  - `os`, `shutil`, `threading`, `time` – File ops & concurrency
  - `logging` – Log creation & management
  - `schedule` – Task scheduling
- 🧪 Custom anomaly detection algorithms

---

---

## 🛠️ How to Run

1. **Clone the repo**
   ```bash
   git clone https://github.com/tahayasincicek/file-storage-backup-system.git
   cd file-storage-backup-system

2. Install Dependencies

Make sure you have Python 3.x installed on your system. Then, install the required dependencies using the command below:

```bash
pip install -r requirements.txt
python main.py

