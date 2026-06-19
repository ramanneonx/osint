# 🔍 OSINT Search Engine

<div align="center">

![OSINT Engine](https://img.shields.io/badge/OSINT-Search%20Engine-00f5d4?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xNS41IDE0aC0uNzlsLS4yOC0uMjdBNi41IDYuNSAwIDAgMCAxNiA5LjUgNi41IDYuNSAwIDAgMCA5LjUgMTYgNi41IDYuNSAwIDAgMCAxNiAxMC41YzAgMS42MS0uNTkgMy4wOS0xLjU2IDQuMjNsLjI3LjI4di43OWw1IDQuOTlMOS40OSAxNnoiLz48L3N2Zz4=)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-Educational-orange?style=for-the-badge)
![Database](https://img.shields.io/badge/Database-pCloud%20Hosted-purple?style=for-the-badge)

**A powerful browser-based OSINT tool to search through massive credential & breach datasets instantly.**

[⬇️ Download Database](https://filedn.com/lO4GDysFuFnRUboOHVSflVj/) • [🚀 Quick Start](#-quick-start) • [📖 How It Works](#-how-it-works)

</div>

---

## 🧠 What Is This?

**OSINT Search Engine** is a local web application that lets you **search through billions of leaked credential records** in seconds — directly from your browser.

Whether you're a security researcher, penetration tester, or OSINT investigator, this tool gives you a powerful search interface over combo/breach data including:

| Field | What It Finds |
|-------|--------------|
| 📧 **Email** | Find all accounts tied to an email address |
| 🌐 **Domain / URL** | Find all breached accounts from a specific site (e.g. `facebook.com`) |
| 👤 **Username** | Track a username across multiple breached services |
| 🔑 **Password** | See how common a password is across breaches |
| 📞 **Phone** | Find accounts tied to a phone number |

> **Think of it like a local, private version of HaveIBeenPwned — but you control everything.**

---

## 💾 Database Options

This tool supports **two ways to get your database**:

### 🛸 Option 1 — Use the Pre-built "Alien" Database (Recommended for beginners)

We've already compiled a massive breach dataset for you. It's hosted on pCloud for free download:

> **📥 [Click here to download the database → pCloud](https://filedn.com/lO4GDysFuFnRUboOHVSflVj/)**

This database contains **hundreds of millions of records** from major breaches. Just download the `.txt` files and drop them in the `database/` folder — you're ready to search instantly.

### 🗂️ Option 2 — Use Your Own Database (Bring Your Own Data)

Already have combo lists or breach `.txt` files? You can use your own data instead!

This tool supports any **standard combo format**, including:
```
url:username:password
email:password
username:password
url:email:password
phone:password
```

Just drop your `.txt` files into the `database/` folder and the tool will index them automatically on startup.

---

## 📁 Project Structure

```
osint/
├── 📄 index.html          → Main OSINT search UI (open in browser)
├── 📄 profiler.html        → Log profiler dashboard
├── 🐍 server.py            → Main backend API server
├── 🐍 profiler_server.py   → Profiler backend
├── 🐍 log_profiler.py      → Log file analysis engine
├── 🐍 import_breaches.py   → Breach data importer & preprocessor
├── 🖥️ start.bat            → Windows one-click launcher
├── 🖥️ run_profiler.bat      → Profiler launcher (Windows)
└── 📂 database/            → Put your .txt database files here
    └── history.json        → Search history (auto-generated)
```

---

## ⚡ Quick Start

### Step 1 — Get the Database

**Option A:** Download our pre-built alien database from pCloud:
> 📥 **[https://filedn.com/lO4GDysFuFnRUboOHVSflVj/](https://filedn.com/lO4GDysFuFnRUboOHVSflVj/)**

**Option B:** Use your own `.txt` combo files.

Place all `.txt` files inside the `database/` folder.

### Step 2 — Start the Server

**Windows (easiest):**
```
Double-click start.bat
```

**Manual:**
```bash
python server.py
```

### Step 3 — Open the UI

Open your browser and go to:
```
http://localhost:8080
```

You'll see the OSINT Search Engine interface. Start typing any email, domain, username, or password to search!

---

## 🖥️ Interface Features

- ⚡ **Real-time search** with live progress bar
- 📊 **Analytics tab** — top domains, email providers, patterns
- 📋 **Results table** — sortable, filterable, with pagination
- 📤 **Export results** — CSV, TXT, or JSON format
- 🕐 **Search history** — re-run past searches with one click
- 🎛️ **File selector** — choose which database files to search
- 🖥️ **Hardware info** — shows your CPU/GPU being used
- 🔒 **Password masking** — blurred by default for privacy

---

## 🛠️ Requirements

- **Python 3.8+** (no pip install needed, uses stdlib only)
- **Windows / Linux / macOS**
- A modern browser (Chrome, Firefox, Edge)

---

## 💡 Use Cases

- 🔍 **Check if your email/password was leaked** in a breach
- 🔐 **Penetration testing** — credential stuffing research
- 🕵️ **OSINT investigations** — trace a person across multiple breach datasets
- 🌐 **Domain exposure analysis** — see all leaked accounts from a company
- 🔑 **Password auditing** — find how common certain passwords are

---

## ⚠️ Legal Disclaimer

> This tool is provided **for educational and legal security research only**.
> 
> - ✅ Checking your own accounts
> - ✅ Authorized penetration testing
> - ✅ Security research & awareness
> - ❌ Unauthorized access to others' accounts
> - ❌ Any illegal activity
>
> **Use responsibly. You are solely responsible for how you use this tool.**

---

<div align="center">

Made with 🕵️ for the OSINT community | Star ⭐ the repo if you find it useful!

</div>
