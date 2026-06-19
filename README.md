# 🔍 OSINT Search Engine

<div align="center">

![OSINT Engine](https://img.shields.io/badge/OSINT-Search%20Engine-00f5d4?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZmlsbD0id2hpdGUiIGQ9Ik0xNS41IDE0aC0uNzlsLS4yOC0uMjdBNi41IDYuNSAwIDAgMCAxNiA5LjUgNi41IDYuNSAwIDAgMCA5LjUgMTYgNi41IDYuNSAwIDAgMCAxNiAxMC41YzAgMS42MS0uNTkgMy4wOS0xLjU2IDQuMjNsLjI3LjI4di43OWw1IDQuOTlMOS40OSAxNnoiLz48L3N2Zz4=)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![Offline](https://img.shields.io/badge/Works-100%25%20Offline-green?style=for-the-badge&logo=wifi)
![No Install](https://img.shields.io/badge/No%20Install-Zero%20Dependencies-yellow?style=for-the-badge)
![Database](https://img.shields.io/badge/Database-pCloud%20Hosted-purple?style=for-the-badge)

**A powerful 100% offline, browser-based OSINT tool to search through massive credential & breach datasets instantly.**

[⬇️ Download Database](https://filedn.com/lO4GDysFuFnRUboOHVSflVj/) • [🚀 Quick Start](#-quick-start) • [📁 Project Structure](#-project-structure)

</div>

---

## 🧠 What Is This?

**OSINT Search Engine** is a **100% offline** local web application that lets you **search through billions of leaked credential records** in seconds — directly from your browser, with **no internet connection required** after setup.

Whether you're a security researcher, penetration tester, or OSINT investigator, this tool gives you a powerful search interface over combo/breach data including:

| Field | What It Finds |
|-------|--------------|
| 📧 **Email** | Find all accounts tied to an email address |
| 🌐 **Domain / URL** | Find all breached accounts from a specific site (e.g. `facebook.com`) |
| 👤 **Username** | Track a username across multiple breached services |
| 🔑 **Password** | See how common a password is across breaches |
| 📞 **Phone** | Find accounts tied to a phone number |

> **Think of it like a local, private version of HaveIBeenPwned — but you control everything and it works offline.**

---

## 🌐 100% Offline — No Internet Needed

> ✅ **This tool runs entirely on your local machine. No data is ever sent anywhere.**

Once you've downloaded the database and the tool, you can:
- 🔌 **Disconnect from the internet completely**
- 🔍 **Search billions of records** at full speed
- 🔒 **Keep all your searches 100% private**
- 💻 **Run it on any PC, laptop, or server**

Everything runs on `localhost` — your data never leaves your computer.

---

## 💾 Database Options

This tool supports **three types of data** you can search through:

### 🛸 Option 1 — Pre-built "Alien" Database *(Recommended)*

We've already compiled a massive breach dataset for you. Hosted on pCloud for free:

> **📥 [Download the Alien Database → pCloud](https://filedn.com/lO4GDysFuFnRUboOHVSflVj/)**

This database contains **hundreds of millions of records** from major breaches worldwide. Just download the `.txt` files, drop them in the `database/` folder — done. No setup needed.

### 🦠 Option 2 — Stealer Logs

Got stealer log folders from a botnet or archive? This tool reads them directly!

Stealer logs typically look like:
```
Passwords.txt  → url:username:password
Cookies.txt    → domain data
```
Just dump your stealer log `.txt` files into the `database/` folder. The tool automatically detects and parses the format.

### 🗄️ Option 3 — Any Combo / Dump Data

Already have combo lists, database dumps, or breach `.txt` files? Works out of the box!

Supported formats (auto-detected):
```
url:username:password
email:password
username:password
url:email:password
phone:password
username:email:password
```
Drop any `.txt` file into `database/` → search it instantly. **No import step needed.**

---

## ⚡ Quick Start

### Step 1 — Clone or Download This Repo

```bash
git clone https://github.com/ramanneonx/osint.git
cd osint
```

### Step 2 — Get Your Database

**Option A — Pre-built Alien Database:**
> 📥 **[https://filedn.com/lO4GDysFuFnRUboOHVSflVj/](https://filedn.com/lO4GDysFuFnRUboOHVSflVj/)**

Download the `.txt` files and place them inside the `database/` folder.

**Option B — Your own stealer logs / combo / dump files:**

Just copy your `.txt` files into the `database/` folder. Any format works.

### Step 3 — Start the Server

**Windows (one click):**
```
Double-click  ➜  start.bat
```

**Linux / macOS / Manual:**
```bash
python server.py
```

### Step 4 — Open & Search

Open your browser and go to:
```
http://localhost:8080
```

Start searching — **no internet needed from this point on!** 🎉

---

## 📁 Project Structure

```
osint/
├── 📄 index.html           → Main OSINT search UI (open in browser)
├── 📄 profiler.html         → Log profiler dashboard
├── 🐍 server.py             → Main backend API server (runs locally)
├── 🐍 profiler_server.py    → Profiler backend
├── 🐍 log_profiler.py       → Log file analysis engine
├── 🐍 import_breaches.py    → Breach data importer & preprocessor
├── 🖥️ start.bat             → Windows one-click launcher
├── 🖥️ run_profiler.bat       → Profiler launcher (Windows)
└── 📂 database/             → ← Put ALL your .txt files here
    └── history.json         → Search history (auto-generated)
```

---

## 🖥️ Interface Features

- ⚡ **Blazing fast search** — searches billions of lines in seconds
- 📊 **Analytics tab** — top domains, email providers, patterns
- 📋 **Results table** — paginated, with copy buttons per field
- 📤 **Export results** — CSV, TXT, or JSON format
- 🕐 **Search history** — re-run past successful searches with one click
- 🎛️ **File selector** — choose exactly which database files to include
- 🖥️ **Hardware info** — shows your CPU/GPU stats live
- 🔒 **Password masking** — blurred by default, click to reveal
- 📈 **Live progress bar** — shows scan progress, matches found, time elapsed

---

## 🛠️ Requirements

| | |
|-|-|
| **Python** | 3.8 or higher |
| **Dependencies** | ❌ None — pure Python stdlib only |
| **OS** | Windows / Linux / macOS |
| **Browser** | Any modern browser (Chrome, Edge, Firefox) |
| **Internet** | ❌ Not needed after setup |

---

## 💡 Use Cases

- 🔍 **Check if your email/password was leaked** in a breach
- 🦠 **Parse & search stealer logs** from botnets or archives
- 🔐 **Penetration testing** — credential stuffing & audit research
- 🕵️ **OSINT investigations** — trace targets across multiple breach datasets
- 🌐 **Domain exposure analysis** — see all leaked accounts from a company
- 🔑 **Password auditing** — discover how widespread certain passwords are
- 🗄️ **Dump analysis** — quickly index and search any leaked database

---

## ⚠️ Legal Disclaimer

> This tool is provided **for educational and legal security research only**.
>
> - ✅ Checking your own accounts for exposure
> - ✅ Authorized penetration testing & red team ops
> - ✅ Security research & awareness
> - ❌ Unauthorized access to others' accounts
> - ❌ Any illegal or malicious activity
>
> **Use responsibly. You are solely responsible for how you use this tool.**

---

<div align="center">

Made with 🕵️ for the OSINT & security community | Star ⭐ if you find it useful!

</div>
