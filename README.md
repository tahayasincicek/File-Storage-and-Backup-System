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
- 🗄️ **SQLite Database** integration for robust data management
- 🔒 **AES File Encryption** for all uploaded files
- 🕒 **File Versioning System** to restore older file versions
- 👁️ **File Preview** for text and image files within the app
- 🖱️ **Drag and Drop** file upload support
- 📊 **Admin Dashboard** with charts and statistics (Matplotlib)
- 🔍 **Search functionality** for files, users, and logs

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

- Modern GUI interface created with `customtkinter`
- Dynamic login system with input validation
- Real-time update display for backup and anomaly events
- Notifications and alerts displayed to relevant profiles

---

## 🗄️ File Backup & Synchronization Module

- **Directory Monitoring**: Watches a source directory for changes using `watchdog`
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
  - `customtkinter` – Modern GUI framework
  - `tkinterdnd2` – Drag and Drop support
  - `sqlite3` – Core database (built-in)
  - `cryptography` – AES encryption for secure storage
  - `Pillow` – Image processing and preview
  - `matplotlib` – Admin dashboard charts and statistics
  - `hashlib` – Password hashing
  - `os`, `shutil`, `threading`, `time` – File ops & concurrency
  - `watchdog` – Directory change monitoring
- 🧪 Custom anomaly detection algorithms

---

## 📂 Folder Structure

```
File-Storage-and-Backup-System/
├── user_app.py            # Main application (GUI & logic)
├── database.py            # SQLite Database logic
├── encryption.py          # AES File Encryption logic
├── logger.py              # Event logging module
├── log_analyzer.py        # Log analysis & anomaly detection
├── app_data.db            # SQLite database file (auto-generated)
├── anomaly_report.txt     # Generated anomaly reports
├── uploaded_files/        # Directory for uploaded files (encrypted)
├── backup_files/          # Directory for backup copies
├── versions/              # Directory for file versioning
├── logs/                  # Categorized log files
└── README.md
```

---

## 🛠️ How to Run

1. **Clone the repo**
   ```bash
   git clone https://github.com/tahayasincicek/File-Storage-and-Backup-System.git
   cd File-Storage-and-Backup-System
   ```

2. **Install Dependencies**

   Make sure you have Python 3.x installed on your system. Then, install the required dependencies:

   ```bash
   pip install customtkinter watchdog cryptography matplotlib pillow tkinterdnd2
   ```

3. **Run the Application**
   ```bash
   python user_app.py
   ```

---

## 📎 License

This project is open source and available for educational purposes.
