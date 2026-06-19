# 🔍 OSINT Tools

> Advanced OSINT (Open Source Intelligence) toolkit for log profiling, breach database analysis, and investigative research.

## 🚀 Features

- **Log Profiler** — Analyze and visualize log patterns with an interactive web dashboard
- **Breach Database Search** — Search and import breach/combo data for OSINT investigations
- **Web UI** — Clean, fast browser-based interface (`index.html` & `profiler.html`)
- **Python Backend** — Lightweight server with full API support

---

## 💾 Database Download

The breach/combo database files are hosted on pCloud (too large for GitHub).

> **📥 [Download Database from pCloud](https://filedn.com/lO4GDysFuFnRUboOHVSflVj/)**

After downloading, place the `.txt` files inside the `database/` folder and use `import_breaches.py` to import them.

---

## 📁 Project Structure

```
├── index.html          # Main OSINT search interface
├── profiler.html       # Log profiler dashboard
├── server.py           # Main backend server
├── profiler_server.py  # Profiler backend
├── log_profiler.py     # Log analysis engine
├── import_breaches.py  # Breach data importer
├── start.bat           # Quick launcher (Windows)
├── run_profiler.bat    # Profiler launcher (Windows)
└── database/           # Place downloaded database files here
    └── history.json    # Import history
```

## ⚡ Quick Start

```bash
# 1. Download the database from pCloud link above and put .txt files in database/

# 2. Import the breach data
python import_breaches.py

# 3. Start the main OSINT server
start.bat

# Or manually:
python server.py

# Start the profiler
run_profiler.bat
# Or:
python profiler_server.py
```

Then open your browser to `http://localhost:8080`

## 🛠️ Requirements

- Python 3.8+
- No external dependencies required (pure stdlib)

## ⚠️ Disclaimer

This tool is intended for **legal OSINT research only**. Use responsibly and in accordance with applicable laws.

---

Made for investigative research 🕵️
