# 🔍 OSINT Tools

> Advanced OSINT (Open Source Intelligence) toolkit for log profiling, breach database analysis, and investigative research.

## 🚀 Features

- **Log Profiler** — Analyze and visualize log patterns with an interactive web dashboard
- **Breach Database Search** — Search and import breach/combo data for OSINT investigations
- **Web UI** — Clean, fast browser-based interface (`index.html` & `profiler.html`)
- **Python Backend** — Lightweight server with full API support

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
└── database/           # Breach database storage (local only)
    └── history.json    # Import history
```

## ⚡ Quick Start

```bash
# Start the main OSINT server
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
