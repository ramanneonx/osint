#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

"""
OSINT LOG SEARCH ENGINE v4.0 - PORTABLE & MULTIPROCESSING TURBO EDITION
Uses ProcessPoolExecutor + parallel memory-mapped scanning for absolute maximum speed.
"""

import os, json, time, glob, threading, mmap, uuid, webbrowser, re
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import defaultdict, Counter
from concurrent.futures import ProcessPoolExecutor

EMAIL_PATTERN = re.compile(r'[\w\.-]+@[\w\.-]+\.([a-zA-Z]{2,63})')
PHONE_PATTERN = re.compile(r'(?:\+|00)(\d{1,4})[\s-]?\d{6,14}')

# ── CONFIG ────────────────────────────────────────────────────────────────────
PORT        = 8787
LOG_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_DIR      = os.path.join(LOG_DIR, 'database')
os.makedirs(DB_DIR, exist_ok=True)
MAX_RESULTS = 2000
HISTORY_FILE = os.path.join(DB_DIR, 'history.json')
# ──────────────────────────────────────────────────────────────────────────────

# Global Process Pool
executor = None

def get_executor():
    global executor
    if executor is None:
        cores = os.cpu_count() or 4
        executor = ProcessPoolExecutor(max_workers=cores)
    return executor

# Byte-based regex patterns for fast classification in single-line logs
EMAIL_BYTE_RE = re.compile(rb'[^@\s]+@[^@\s]+\.[^@\s]+')
URL_BYTE_RE   = re.compile(rb'(?:https?://|www\.)[^\s]+|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(?:/|$)')
PHONE_BYTE_RE = re.compile(rb'^\+?[0-9][0-9\s-]{5,14}[0-9]$')

def filter_comb_files(comb_files, query_str, search_type):
    # Extract the first positive search token
    temp_q = query_str.replace('://', '__SCHEME_COLON__')
    import re as worker_re
    tokens = worker_re.split(r'[:\s]+', temp_q)
    positives = []
    for t in tokens:
        t = t.replace('__SCHEME_COLON__', '://').strip()
        if t and not t.startswith('-'):
            positives.append(t)
    if not positives:
        return []
    
    first_token = positives[0].lower()
    if first_token.startswith('https://'):
        first_token = first_token[8:]
    elif first_token.startswith('http://'):
        first_token = first_token[7:]
    if first_token.startswith('www.'):
        first_token = first_token[4:]
        
    if not first_token:
        return []
        
    c1 = first_token[0]
    
    # Find the COMB data directory
    comb_data_dir = None
    for f in comb_files:
        f_norm = f.replace('\\', '/')
        idx = f_norm.find('CompilationOfManyBreaches/data')
        if idx != -1:
            comb_data_dir = f[:idx + len('CompilationOfManyBreaches/data')].replace('\\', '/')
            break
            
    if not comb_data_dir:
        return []
        
    # Resolve target prefix path relative to COMB data dir
    expected_rel = ""
    if not c1.isalnum():
        expected_rel = "symbols"
    else:
        p1 = os.path.join(comb_data_dir, c1)
        if os.path.isfile(p1):
            expected_rel = c1
        elif os.path.isdir(p1):
            if len(first_token) < 2:
                expected_rel = c1 + "/"
            else:
                c2 = first_token[1]
                if not c2.isalnum():
                    expected_rel = c1 + "/symbols"
                else:
                    p2 = os.path.join(p1, c2)
                    if os.path.isfile(p2):
                        expected_rel = c1 + "/" + c2
                    elif os.path.isdir(p2):
                        if len(first_token) < 3:
                            expected_rel = c1 + "/" + c2 + "/"
                        else:
                            c3 = first_token[2]
                            if not c3.isalnum():
                                expected_rel = c1 + "/" + c2 + "/symbols"
                            else:
                                expected_rel = c1 + "/" + c2 + "/" + c3
                                
    filtered = []
    expected_rel_norm = expected_rel.replace('\\', '/')
    
    for f in comb_files:
        f_norm = f.replace('\\', '/')
        data_marker = 'CompilationOfManyBreaches/data/'
        idx = f_norm.find(data_marker)
        if idx == -1:
            continue
        rel = f_norm[idx + len(data_marker):]
        
        if expected_rel_norm.endswith('/'):
            if rel.startswith(expected_rel_norm):
                filtered.append(f)
        else:
            if rel == expected_rel_norm:
                filtered.append(f)
                
    return filtered

def get_file_size(filepath):
    if filepath.endswith('_all_files.log'):
        dirpath = os.path.dirname(filepath)
        total_size = 0
        for root, _, filenames in os.walk(dirpath):
            is_comb_data = 'CompilationOfManyBreaches/data' in root.replace('\\', '/')
            for filename in filenames:
                if filename.startswith('.'):
                    continue
                fp = os.path.join(root, filename)
                if is_comb_data:
                    try:
                        total_size += os.path.getsize(fp)
                    except Exception:
                        pass
                else:
                    if filename.lower().endswith(('.txt', '.log', '.csv')):
                        try:
                            total_size += os.path.getsize(fp)
                        except Exception:
                            pass
        return total_size
    else:
        try:
            return os.path.getsize(filepath)
        except Exception:
            return 0

def get_log_files():
    results = []
    try:
        entries = os.listdir(DB_DIR)
    except Exception:
        return []
        
    for entry in entries:
        if entry.startswith('.'):
            continue
        full_path = os.path.join(DB_DIR, entry)
        if os.path.isdir(full_path):
            total_files = 0
            for root, _, filenames in os.walk(full_path):
                is_comb_data = 'CompilationOfManyBreaches/data' in root.replace('\\', '/')
                for filename in filenames:
                    if filename.startswith('.'):
                        continue
                    if is_comb_data:
                        total_files += 1
                    else:
                        if filename.lower().endswith(('.txt', '.log', '.csv')):
                            total_files += 1
            
            if total_files == 0:
                continue
                
            if total_files > 200:
                virtual_file = os.path.join(full_path, "_all_files.log")
                results.append(virtual_file)
            else:
                for root, _, filenames in os.walk(full_path):
                    is_comb_data = 'CompilationOfManyBreaches/data' in root.replace('\\', '/')
                    for filename in filenames:
                        if filename.startswith('.'):
                            continue
                        fp = os.path.join(root, filename)
                        if is_comb_data:
                            results.append(fp)
                        else:
                            if filename.lower().endswith(('.txt', '.log', '.csv')):
                                results.append(fp)
        else:
            if entry.lower().endswith(('.txt', '.log', '.csv')):
                results.append(full_path)
                
    files = sorted(results)
    
    def is_alien_file(path):
        name = os.path.basename(path).lower()
        if 'alien' in name or 'alen' in name or 'txt_alien' in name:
            return True
        rel = os.path.relpath(path, DB_DIR).lower()
        if 'alien' in rel or 'alen' in rel or 'txt_alien' in rel:
            return True
        return False

    alien_files = [f for f in files if is_alien_file(f)]
    other_files = [f for f in files if not is_alien_file(f)]
    return alien_files + other_files

def format_size(n):
    for u in ['B','KB','MB','GB','TB']:
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def detect_file_format(mm) -> str:
    """Detects if the file is 'single_line' (URL:user:pass) or 'multi_line' (block format)."""
    sample = mm[:min(8000, len(mm))]
    lines = [l.strip() for l in sample.split(b'\n') if l.strip()]
    
    block_labels = 0
    single_line_colons = 0
    
    for l in lines[:30]:
        l_lower = l.lower()
        if any(l_lower.startswith(prefix) for prefix in (b'url:', b'host:', b'domain:', b'username:', b'login:', b'password:', b'pass:', b'phone:', b'email:')):
            block_labels += 1
        elif l.count(b':') >= 2 or l.count(b'|') >= 2 or l.count(b';') >= 2:
            single_line_colons += 1
            
    if block_labels > 3:
        return 'multi_line'
    return 'single_line'

def parse_single_line_fields(raw: bytes) -> tuple:
    """
    Parses a single line into (url, user, email, phone, pass)
    by splitting on the most likely delimiter and classifying parts.
    """
    line = raw.strip()
    if not line:
        return b'', b'', b'', b'', b''
        
    # Temporarily hide colons in protocol schemes
    has_scheme = False
    if b'://' in line:
        has_scheme = True
        line = line.replace(b'://', b'__SCHEME_COLON__')
        
    # Detect delimiter
    delims = [b':', b'|', b';', b'\t', b',']
    best_delim = b':'
    max_parts = 1
    
    for d in delims:
        parts = line.split(d)
        if len(parts) > max_parts:
            max_parts = len(parts)
            best_delim = d
            
    parts = [p.strip() for p in line.split(best_delim) if p.strip()]
    
    # Restore protocol schemes
    if has_scheme:
        parts = [p.replace(b'__SCHEME_COLON__', b'://') for p in parts]
    
    url = b''
    email = b''
    phone = b''
    user = b''
    password = b''
    
    if len(parts) == 1:
        password = parts[0]
    elif len(parts) == 2:
        p1, p2 = parts[0], parts[1]
        if EMAIL_BYTE_RE.search(p1):
            email = p1
            user = p1.split(b'@')[0]
        elif PHONE_BYTE_RE.search(p1):
            phone = p1
        else:
            user = p1
        password = p2
    else:
        password = parts[-1]
        remaining = parts[:-1]
        
        # Classify remaining fields
        # 1. URL/Domain
        for p in remaining:
            if URL_BYTE_RE.search(p) or b'localhost' in p:
                url = p
                remaining.remove(p)
                break
                
        # 2. Email
        for p in remaining:
            if EMAIL_BYTE_RE.search(p):
                email = p
                remaining.remove(p)
                break
                
        # 3. Phone
        for p in remaining:
            if PHONE_BYTE_RE.search(p):
                phone = p
                remaining.remove(p)
                break
                
        # 4. Username / User
        if remaining:
            user = remaining[0]
            if len(remaining) > 1 and not phone:
                for r_part in remaining[1:]:
                    if PHONE_BYTE_RE.search(r_part):
                        phone = r_part
                        break
                        
        if email and not user:
            user = email.split(b'@')[0]
            
    return url, user, email, phone, password

def parse_line_bytes_fast(raw: bytes) -> tuple:
    return parse_single_line_fields(raw)

def parse_line_bytes(raw: bytes) -> dict | None:
    line = raw.strip()
    if not line or line[0:1] in (b'|', b'#', b'=', b' '):
        return None
    url_b, user_b, email_b, phone_b, pass_b = parse_single_line_fields(line)
    try:
        s = line.decode('utf-8', errors='replace')
    except Exception:
        return None
    return {
        'url': url_b.decode('utf-8', errors='replace'),
        'user': user_b.decode('utf-8', errors='replace'),
        'email': email_b.decode('utf-8', errors='replace'),
        'phone': phone_b.decode('utf-8', errors='replace'),
        'pass': pass_b.decode('utf-8', errors='replace'),
        'raw': s
    }

def extract_block_around(mm, idx: int, start_limit: int, end_limit: int) -> tuple:
    # Scan backward to find block start (separator or empty line, max 10 lines)
    block_start = idx
    lines_back = 0
    while block_start > start_limit and lines_back < 10:
        prev_nl = mm.rfind(b'\n', start_limit, block_start)
        if prev_nl == -1:
            block_start = start_limit
            break
        line = mm[prev_nl+1:block_start].strip()
        if not line or any(c in line for c in (b'=', b'-', b'*', b'_')) and len(line) > 3:
            block_start = prev_nl + 1
            break
        block_start = prev_nl
        lines_back += 1

    # Scan forward to find block end (separator or empty line, max 10 lines)
    block_end = idx
    lines_fwd = 0
    while block_end < end_limit and lines_fwd < 10:
        next_nl = mm.find(b'\n', block_end, end_limit)
        if next_nl == -1:
            block_end = end_limit
            break
        line = mm[block_end:next_nl].strip()
        if not line or any(c in line for c in (b'=', b'-', b'*', b'_')) and len(line) > 3:
            block_end = next_nl
            break
        block_end = next_nl + 1
        lines_fwd += 1

    return mm[block_start:block_end], block_start, block_end

def parse_block_fields(block: bytes) -> tuple:
    """Parses a multi-line block into (url, user, email, phone, pass)."""
    lines = [line.strip() for line in block.split(b'\n') if line.strip()]
    url = b''
    user = b''
    email = b''
    phone = b''
    password = b''
    
    for line in lines:
        if b':' in line:
            parts = line.split(b':', 1)
            key = parts[0].strip().lower()
            val = parts[1].strip()
            
            if key in (b'url', b'host', b'domain', b'website', b'site'):
                url = val
            elif key in (b'username', b'user', b'login'):
                user = val
                if b'@' in val:
                    email = val
            elif key in (b'email', b'mail'):
                email = val
                if not user:
                    user = val.split(b'@')[0]
            elif key in (b'phone', b'mobile', b'phone number', b'tel', b'telephone'):
                phone = val
            elif key in (b'password', b'pass', b'pw'):
                password = val
                
    return url, user, email, phone, password

# ── HARDWARE DETECTION ────────────────────────────────────────────────────────
def get_cpu_info():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
        name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
        winreg.CloseKey(key)
        return name.strip()
    except Exception:
        return os.environ.get('PROCESSOR_IDENTIFIER', 'Unknown CPU')

def get_gpu_info():
    try:
        import winreg
        path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        gpus = []
        for i in range(10):
            try:
                sub_key_name = winreg.EnumKey(key, i)
                if sub_key_name.isdigit():
                    sub_key = winreg.OpenKey(key, sub_key_name)
                    try:
                        driver_desc, _ = winreg.QueryValueEx(sub_key, "DriverDesc")
                        gpus.append(driver_desc.strip())
                    except:
                        pass
                    winreg.CloseKey(sub_key)
            except OSError:
                break
        winreg.CloseKey(key)
        if gpus:
            return ", ".join(gpus)
    except Exception:
        pass
    try:
        import subprocess
        output = subprocess.check_output("wmic path win32_VideoController get name", shell=True, stderr=subprocess.DEVNULL)
        lines = [l.decode('utf-8', errors='replace').strip() for l in output.split(b'\n') if l.strip()]
        if len(lines) > 1:
            return ", ".join(lines[1:])
    except Exception:
        pass
    return "Unknown GPU"

# ── HISTORY MANAGEMENT ────────────────────────────────────────────────────────
def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_history(history):
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[ERROR] Saving history: {e}")

def add_history_entry(query, search_type, count):
    if count == 0:
        return
    history = load_history()
    # Remove existing to place on top
    history = [h for h in history if not (h['query'] == query and h['type'] == search_type)]
    history.insert(0, {
        'query': query,
        'type': search_type,
        'count': count,
        'timestamp': int(time.time())
    })
    save_history(history[:100])

# ── PARALLEL MULTIPROCESSING SEARCH WORKER ────────────────────────────────────
def search_chunk_worker(args):
    filepath, start, end, query_str, search_type, file_format, max_results = args
    results = []
    try:
        file_size = os.path.getsize(filepath)
        if file_size == 0 or (end - start) <= 0:
            return []
            
        # Split query into positive and negative tokens (negatives start with '-')
        temp_q = query_str.replace('://', '__SCHEME_COLON__')
        import re as worker_re
        tokens = worker_re.split(r'[:\s]+', temp_q)
        
        positives = []
        negatives = []
        for t in tokens:
            t = t.replace('__SCHEME_COLON__', '://').strip()
            if not t:
                continue
            if t.startswith('-') and len(t) > 1:
                negatives.append(t[1:])
            else:
                positives.append(t)
                
        if not positives:
            return []
            
        # Compile an OR regex pattern to match any of the positive keywords simultaneously
        positives_bytes = [p.encode('utf-8', errors='replace') for p in positives]
        pattern = re.compile(rb'|'.join(re.escape(pb) for pb in positives_bytes), re.IGNORECASE)
        
        negatives_bytes = [n.encode('utf-8', errors='replace') for n in negatives]
        
        with open(filepath, 'rb') as f:
            f.seek(start)
            chunk_data = f.read(end - start)
            
        if file_format == 'auto':
            file_format = detect_file_format(chunk_data)
            
        pos = 0
        chunk_len = len(chunk_data)
        chunk_start_line = None  # Lazily calculated only if a match is found
        
        while pos < chunk_len:
            match = pattern.search(chunk_data, pos)
            if not match:
                break
            idx = match.start()
            
            if file_format == 'multi_line':
                # Scan backward to find block start (separator or empty line)
                b_start = idx
                lines_back = 0
                while b_start > 0 and lines_back < 10:
                    prev_nl = chunk_data.rfind(b'\n', 0, b_start)
                    if prev_nl == -1:
                        b_start = 0
                        break
                    line = chunk_data[prev_nl+1:b_start].strip()
                    if not line or any(c in line for c in (b'=', b'-', b'*', b'_')) and len(line) > 3:
                        b_start = prev_nl + 1
                        break
                    b_start = prev_nl
                    lines_back += 1
                
                # Scan forward to find block end (separator or empty line)
                b_end = idx
                lines_fwd = 0
                while b_end < chunk_len and lines_fwd < 10:
                    next_nl = chunk_data.find(b'\n', b_end)
                    if next_nl == -1:
                        b_end = chunk_len
                        break
                    line = chunk_data[b_end:next_nl].strip()
                    if not line or any(c in line for c in (b'=', b'-', b'*', b'_')) and len(line) > 3:
                        b_end = next_nl
                        break
                    b_end = next_nl + 1
                    lines_fwd += 1
                    
                pos = b_end
                block = chunk_data[b_start:b_end]
                
                # Verify no negative keywords exist in the block
                has_negative = False
                for neg in negatives_bytes:
                    if neg.lower() in block.lower():
                        has_negative = True
                        break
                if has_negative:
                    continue
                
                url_b, user_b, email_b, phone_b, pass_b = parse_block_fields(block)
                if search_type != 'any':
                    if search_type in ('domain', 'url'):
                        zone = url_b
                    elif search_type == 'email':
                        zone = email_b
                    elif search_type == 'username':
                        zone = user_b
                    elif search_type == 'phone':
                        zone = phone_b
                    elif search_type == 'password':
                        zone = pass_b
                    else:
                        zone = block
                        
                    # Verify at least one positive keyword matches in the selected field
                    zone_match = False
                    for kb in positives_bytes:
                        if kb.lower() in zone.lower():
                            zone_match = True
                            break
                    if not zone_match:
                        continue
                
                # Lazily calculate chunk_start_line
                if chunk_start_line is None:
                    chunk_start_line = 1
                    if start > 0:
                        with open(filepath, 'rb') as f_count:
                            remaining = start
                            while remaining > 0:
                                read_size = min(remaining, 16 * 1024 * 1024)
                                buf = f_count.read(read_size)
                                if not buf:
                                    break
                                chunk_start_line += buf.count(b'\n')
                                remaining -= len(buf)
                
                line_num = chunk_start_line + chunk_data.count(b'\n', 0, b_start)
                parsed = {
                    'url': url_b.decode('utf-8', errors='replace'),
                    'user': user_b.decode('utf-8', errors='replace'),
                    'email': email_b.decode('utf-8', errors='replace'),
                    'phone': phone_b.decode('utf-8', errors='replace'),
                    'pass': pass_b.decode('utf-8', errors='replace'),
                    'raw': block.decode('utf-8', errors='replace'),
                    'line_num': line_num
                }
                results.append(parsed)
                if len(results) >= max_results:
                    break
            else:  # single_line format
                ls = chunk_data.rfind(b'\n', 0, idx)
                ls = 0 if ls == -1 else ls + 1
                
                le = chunk_data.find(b'\n', idx)
                if le == -1:
                    le = chunk_len
                    
                raw = chunk_data[ls:le]
                pos = le + 1
                
                # Verify no negative keywords exist in the line
                has_negative = False
                for neg in negatives_bytes:
                    if neg.lower() in raw.lower():
                        has_negative = True
                        break
                if has_negative:
                    continue
                
                url_b, user_b, email_b, phone_b, pass_b = parse_line_bytes_fast(raw)
                if search_type != 'any':
                    if search_type in ('domain', 'url'):
                        zone = url_b
                    elif search_type == 'email':
                        zone = email_b
                    elif search_type == 'username':
                        zone = user_b
                    elif search_type == 'phone':
                        zone = phone_b
                    elif search_type == 'password':
                        zone = pass_b
                    else:
                        zone = raw
                        
                    # Verify at least one positive keyword matches in the selected field
                    zone_match = False
                    for kb in positives_bytes:
                        if kb.lower() in zone.lower():
                            zone_match = True
                            break
                    if not zone_match:
                        continue
                
                # Lazily calculate chunk_start_line
                if chunk_start_line is None:
                    chunk_start_line = 1
                    if start > 0:
                        with open(filepath, 'rb') as f_count:
                            remaining = start
                            while remaining > 0:
                                read_size = min(remaining, 16 * 1024 * 1024)
                                buf = f_count.read(read_size)
                                if not buf:
                                    break
                                chunk_start_line += buf.count(b'\n')
                                remaining -= len(buf)
                                
                line_num = chunk_start_line + chunk_data.count(b'\n', 0, ls)
                parsed = parse_line_bytes(raw)
                if parsed:
                    parsed['line_num'] = line_num
                    results.append(parsed)
                    if len(results) >= max_results:
                        break
    except Exception as e:
        print(f"[ERROR] worker scan error: {e}")
    return results

def search_batch_worker(tasks_batch):
    batch_res = []
    for task in tasks_batch:
        filepath = task[0]
        start = task[1]
        end = task[2]
        chunk_results = search_chunk_worker(task[:7])
        batch_res.append((filepath, end - start, chunk_results))
    return batch_res

# ── ANALYTICS ─────────────────────────────────────────────────────────────────
def extract_domain(url):
    try:
        if '://' not in url: url = 'http://' + url
        return urllib.parse.urlparse(url).netloc or url
    except: return url

KNOWN_SERVICES = {
    'facebook':'Facebook','google':'Google','gmail':'Gmail','yahoo':'Yahoo',
    'microsoft':'Microsoft','live':'Microsoft Live','outlook':'Outlook',
    'apple':'Apple','netflix':'Netflix','amazon':'Amazon','steam':'Steam',
    'discord':'Discord','roblox':'Roblox','epicgames':'Epic Games',
    'twitch':'Twitch','instagram':'Instagram','twitter':'Twitter',
    'tiktok':'TikTok','linkedin':'LinkedIn','paypal':'PayPal',
    'spotify':'Spotify','riot':'Riot Games','activision':'Activision',
    'ubisoft':'Ubisoft','minecraft':'Minecraft','battle.net':'Battle.net',
    'nintendo':'Nintendo','github':'GitHub','zoom':'Zoom','uber':'Uber',
}

def analyze_results(results):
    domains = defaultdict(int); tlds = defaultdict(int)
    services = defaultdict(int); email_providers = defaultdict(int)
    for r in results:
        dom = extract_domain(r.get('url',''))
        domains[dom] += 1
        parts = dom.split('.')
        if len(parts) >= 2: tlds['.'+parts[-1]] += 1
        dl = dom.lower()
        for k,v in KNOWN_SERVICES.items():
            if k in dl: services[v] += 1; break
        u = r.get('user','')
        if '@' in u: email_providers[u.split('@')[-1].lower()] += 1
    return {
        'top_domains':        sorted(domains.items(),        key=lambda x:-x[1])[:20],
        'top_tlds':           sorted(tlds.items(),           key=lambda x:-x[1])[:15],
        'top_services':       sorted(services.items(),       key=lambda x:-x[1])[:15],
        'top_email_providers':sorted(email_providers.items(),key=lambda x:-x[1])[:15],
        'total_analyzed': len(results),
    }

# ── SESSION ────────────────────────────────────────────────────────────────────
search_sessions: dict = {}
sessions_lock = threading.Lock()

class SearchSession:
    def __init__(self, sid, query, search_type, files, all_files_count=None):
        self.sid          = sid
        self.query        = query
        self.search_type  = search_type
        
        # Expand any virtual files in the files list before partition splitting
        expanded = []
        for f in files:
            if f.endswith('_all_files.log'):
                dirpath = os.path.dirname(f)
                for root, _, filenames in os.walk(dirpath):
                    is_comb_data = 'CompilationOfManyBreaches/data' in root.replace('\\', '/')
                    for filename in filenames:
                        if filename.startswith('.'):
                            continue
                        fp = os.path.join(root, filename)
                        if is_comb_data:
                            expanded.append(fp)
                        else:
                            if filename.lower().endswith(('.txt', '.log', '.csv')):
                                expanded.append(fp)
            else:
                expanded.append(f)
        files = expanded

        # Separate COMB files and non-COMB files
        comb_files = []
        other_files = []
        for f in files:
            if 'CompilationOfManyBreaches/data' in f.replace('\\', '/'):
                comb_files.append(f)
            else:
                other_files.append(f)
                
        # If the user selected a custom subset of files (e.g. checked folders/files in UI),
        # only prefix-filter if they have selected the entire COMB dataset (or didn't filter files).
        is_subset = False
        if all_files_count is not None:
            # Count the total COMB files available globally on the system
            # Since get_log_files() returns everything in DB_DIR, let's call it to get the absolute total COMB files count.
            global_files = get_log_files()
            total_comb_on_disk = 0
            for gf in global_files:
                path = gf["path"] if isinstance(gf, dict) else gf
                if 'CompilationOfManyBreaches/data' in path.replace('\\', '/'):
                    total_comb_on_disk += 1
            # If the user selected fewer files than the total COMB files, it is a custom folder/file selection subset
            is_subset = len(comb_files) < total_comb_on_disk
            
        # Filter COMB files if applicable and not a custom narrow selection
        if comb_files:
            if not is_subset:
                filtered_comb = filter_comb_files(comb_files, query, search_type)
                if not filtered_comb and len(comb_files) > 100:
                    print(f"[COMB] Skipping {len(comb_files)} COMB files because query '{query}' cannot be prefix-filtered for search type '{search_type}'.")
                comb_files = filtered_comb
            else:
                # If the user selected specific COMB files/folders, we do not bypass them unless they match the query prefix.
                filtered_comb = filter_comb_files(comb_files, query, search_type)
                if filtered_comb:
                    intersected = list(set(comb_files).intersection(set(filtered_comb)))
                    if intersected:
                        comb_files = intersected
            
        self.files        = other_files + comb_files
        self.results      = []
        self.current_file = ''
        self.bytes_read   = 0
        self.total_bytes  = sum(os.path.getsize(f) for f in self.files if os.path.exists(f))
        self.lines_scanned= 0
        self.elapsed      = 0
        self.done         = False
        self.error        = None
        self.started_at   = time.time()
        self.result_count_live = 0

    def to_dict(self):
        return {
            'session_id':   self.sid,
            'query':        self.query,
            'search_type':  self.search_type,
            'results':      self.results,
            'current_file': self.current_file,
            'bytes_read':   self.bytes_read,
            'total_bytes':  self.total_bytes,
            'lines_scanned':self.lines_scanned,
            'elapsed':      self.elapsed,
            'done':         self.done,
            'error':        self.error,
            'result_count': len(self.results),
            'analytics':    analyze_results(self.results) if self.done and self.results else None,
        }

def run_search(session: SearchSession):
    try:
        cores = os.cpu_count() or 4
        all_tasks = []
        future_to_info = {}
        bytes_completed = 0
        
        # Parallelize os.path.getsize calls
        import concurrent.futures
        def get_file_info(filepath):
            try:
                if os.path.exists(filepath):
                    return filepath, os.path.getsize(filepath)
            except Exception:
                pass
            return filepath, 0
            
        with concurrent.futures.ThreadPoolExecutor(max_workers=64) as executor:
            file_infos = list(executor.map(get_file_info, session.files))
            
        for filepath, file_size in file_infos:
            if file_size == 0:
                continue
                
            # If the file is small, we do not need to read/seek chunk boundaries!
            # We can just submit it as a single chunk task and detect file_format on worker.
            if file_size <= 5 * 1024 * 1024: # <= 5MB
                all_tasks.append((filepath, 0, file_size, session.query, session.search_type, 'auto', MAX_RESULTS, 0, bytes_completed))
            else:
                # Large file, split into chunks for parallel speed!
                try:
                    with open(filepath, 'rb') as f:
                        sample = f.read(8000)
                        file_format = detect_file_format(sample)
                except Exception:
                    file_format = 'auto'
                    
                chunk_size = max(file_size // (cores * 4), 1024 * 1024)
                pos = 0
                
                try:
                    with open(filepath, 'rb') as f:
                        while pos < file_size:
                            end = min(pos + chunk_size, file_size)
                            if end < file_size:
                                f.seek(end)
                                buf = f.read(8192)
                                nl = buf.find(b'\n')
                                if nl != -1:
                                    end = end + nl + 1
                                else:
                                    end = file_size
                            
                            all_tasks.append((filepath, pos, end, session.query, session.search_type, file_format, MAX_RESULTS, 0, bytes_completed))
                            pos = end
                except Exception:
                    pass
            
            bytes_completed += file_size
            
        if not all_tasks:
            session.done = True
            return

        # Group all_tasks into batches
        # batch limit: 300 files or 10 MB total chunk size
        batches = []
        current_batch = []
        current_batch_size = 0
        for task in all_tasks:
            filepath, pos, end, _, _, _, _, _, _ = task
            chunk_size = end - pos
            if len(current_batch) >= 300 or (current_batch_size + chunk_size > 10 * 1024 * 1024):
                if current_batch:
                    batches.append(current_batch)
                current_batch = []
                current_batch_size = 0
            current_batch.append(task)
            current_batch_size += chunk_size
        if current_batch:
            batches.append(current_batch)

        # Submit all batches in parallel
        pool = get_executor()
        futures = []
        for batch in batches:
            f = pool.submit(search_batch_worker, batch)
            futures.append(f)
            # Calculate total batch size
            batch_size = sum(t[2] - t[1] for t in batch)
            future_to_info[f] = {
                'tasks': batch,
                'chunk_size': batch_size
            }

        pending_futures = list(futures)
        
        while pending_futures:
            done_futures = [f for f in pending_futures if f.done()]
            for f in done_futures:
                pending_futures.remove(f)
                info = future_to_info[f]
                try:
                    res_list = f.result()
                    for filepath, chunk_size, res in res_list:
                        rel_path = os.path.relpath(filepath, DB_DIR).replace('\\', '/')
                        for r in res:
                            r['file'] = rel_path
                        
                        with sessions_lock:
                            room = MAX_RESULTS - len(session.results)
                            if room > 0:
                                session.results.extend(res[:room])
                except Exception as ex:
                    print(f"[ERROR] worker future result error: {ex}")
            
            # Update progress dynamically based on completed batches
            total_bytes_read = 0
            current_active_file = "Finishing..."
            for f in futures:
                info = future_to_info[f]
                if f.done():
                    total_bytes_read += info['chunk_size']
                else:
                    current_active_file = os.path.relpath(info['tasks'][-1][0], DB_DIR).replace('\\', '/')
                    
            with sessions_lock:
                session.bytes_read = min(total_bytes_read, session.total_bytes)
                session.lines_scanned = int(session.bytes_read / 65.78)
                session.elapsed = round(time.time() - session.started_at, 2)
                session.current_file = current_active_file
                
                # Early stop if MAX_RESULTS reached
                if len(session.results) >= MAX_RESULTS:
                    for f in pending_futures:
                        f.cancel()
                    break
                    
            time.sleep(0.05)
            
        with sessions_lock:
            session.bytes_read = session.total_bytes
            session.lines_scanned = int(session.total_bytes / 65.78)
            session.done = True
            
            # Save history if matches found
            if len(session.results) > 0:
                add_history_entry(session.query, session.search_type, len(session.results))
                
    except Exception as e:
        session.error = str(e)
        session.done = True

# ── HTTP SERVER ────────────────────────────────────────────────────────────────
class OSINTHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # silence

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type',   'application/json; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path, ctype):
        with open(path, 'rb') as f: body = f.read()
        self.send_response(200)
        self.send_header('Content-Type',   ctype)
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_POST(self):
        p  = urllib.parse.urlparse(self.path)
        path = p.path

        if path == '/api/search':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
            except Exception:
                self.send_json({'error': 'Invalid JSON'}, 400); return

            query = data.get('q', '').strip()
            stype = data.get('type', 'any')
            sel_files = data.get('files', [])

            if not query:
                self.send_json({'error': 'Empty query'}, 400); return

            all_files = get_log_files()
            if not all_files:
                self.send_json({'error': 'No log files found in database folder'}, 404); return

            # Filter database files based on selected file relative paths
            if sel_files and len(sel_files) > 0:
                sel_files_set = set(sel_files)
                files_to_scan = []
                for f in all_files:
                    rel_name = os.path.relpath(f, DB_DIR).replace('\\', '/')
                    if rel_name in sel_files_set:
                        files_to_scan.append(f)
            else:
                files_to_scan = all_files

            if not files_to_scan:
                self.send_json({'error': 'No files selected to scan'}, 400); return

            sid     = str(uuid.uuid4())[:8]
            session = SearchSession(sid, query, stype, files_to_scan, len(all_files))
            with sessions_lock:
                if len(search_sessions) > 50:
                    sorted_sids = sorted(search_sessions.keys(), key=lambda k: search_sessions[k].started_at)
                    for old_sid in sorted_sids[:len(search_sessions) - 50]:
                        del search_sessions[old_sid]
                search_sessions[sid] = session
            threading.Thread(target=run_search, args=(session,), daemon=True).start()
            self.send_json({'session_id': sid, 'started': True})
        else:
            self.send_response(404); self.end_headers()

    def do_GET(self):
        p  = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(p.query)
        path = p.path

        if path == '/':
            self.send_file(os.path.join(LOG_DIR, 'index.html'), 'text/html; charset=utf-8')

        elif path == '/api/info':
            files = get_log_files()
            total = 0
            info  = []
            for f in files:
                sz = get_file_size(f)
                total += sz
                info.append({'name': os.path.relpath(f, DB_DIR).replace('\\', '/'), 'size': sz,
                             'size_human': format_size(sz), 'path': f})
            self.send_json({'files': info, 'total_files': len(files),
                            'total_size': total, 'total_size_human': format_size(total),
                            'max_results': MAX_RESULTS, 'server_version': '4.0-multiprocessing'})

        elif path == '/api/search':
            query = qs.get('q',[''])[0].strip()
            stype = qs.get('type',['any'])[0]
            if not query:
                self.send_json({'error': 'Empty query'}, 400); return
            all_files = get_log_files()
            if not all_files:
                self.send_json({'error': 'No log files found in database folder'}, 404); return
            sid     = str(uuid.uuid4())[:8]
            session = SearchSession(sid, query, stype, all_files, len(all_files))
            with sessions_lock:
                if len(search_sessions) > 50:
                    sorted_sids = sorted(search_sessions.keys(), key=lambda k: search_sessions[k].started_at)
                    for old_sid in sorted_sids[:len(search_sessions) - 50]:
                        del search_sessions[old_sid]
                search_sessions[sid] = session
            threading.Thread(target=run_search, args=(session,), daemon=True).start()
            self.send_json({'session_id': sid, 'started': True})

        elif path == '/api/status':
            sid = qs.get('id',[''])[0]
            with sessions_lock:
                session = search_sessions.get(sid)
            if not session:
                self.send_json({'error': 'Session not found'}, 404); return
            self.send_json(session.to_dict())

        elif path == '/api/history':
            self.send_json(load_history())

        elif path == '/api/history/clear':
            save_history([])
            self.send_json({'success': True})

        elif path == '/api/hardware':
            cpu_name = get_cpu_info()
            cpu_cores = os.cpu_count() or 0
            gpu_name = get_gpu_info()
            self.send_json({
                'cpu_name': cpu_name,
                'cpu_cores': cpu_cores,
                'gpu_name': gpu_name
            })

        elif path == '/api/export':
            sid = qs.get('id',[''])[0]
            fmt = qs.get('format',['json'])[0]
            with sessions_lock:
                session = search_sessions.get(sid)
            if not session:
                self.send_json({'error': 'Not found'}, 404); return
            res = session.results
            if fmt == 'csv':
                rows = ['URL,Username,Email,Phone,Password,File,Line']
                for r in res:
                    rows.append('"{url}","{user}","{email}","{phone}","{p}","{f}",{ln}'.format(
                        url=r.get('url','').replace('"','""'),
                        user=r.get('user','').replace('"','""'),
                        email=r.get('email','').replace('"','""'),
                        phone=r.get('phone','').replace('"','""'),
                        p=r.get('pass','').replace('"','""'),
                        f=r.get('file','').replace('"','""'),
                        ln=r.get('line_num','1')
                    ))
                body = '\n'.join(rows).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type','text/csv')
                self.send_header('Content-Disposition',f'attachment; filename="osint_{sid}.csv"')
                self.send_header('Content-Length', len(body))
                self.end_headers(); self.wfile.write(body)
            elif fmt == 'txt':
                lines = [f"OSINT Results - Query: {session.query}",
                         f"Type: {session.search_type} | Count: {len(res)}", "="*80]
                lines += [r.get('raw','') for r in res]
                body = '\n'.join(lines).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type','text/plain')
                self.send_header('Content-Disposition',f'attachment; filename="osint_{sid}.txt"')
                self.send_header('Content-Length', len(body))
                self.end_headers(); self.wfile.write(body)
            else:
                self.send_json({'results': res, 'total': len(res)})
        else:
            self.send_response(404); self.end_headers()

def main():
    import multiprocessing
    multiprocessing.freeze_support()
    # Warm up persistent process pool
    get_executor()

    print("=" * 60)
    print("  OSINT LOG SEARCH ENGINE v4.0 - MULTIPROCESSING PORTABLE")
    print("=" * 60)
    files = get_log_files()
    total = sum(get_file_size(f) for f in files)
    print(f"  Database dir: {DB_DIR}")
    print(f"  Files Found : {len(files)}")
    for f in files[:15]:
        print(f"    - {os.path.basename(f)} ({format_size(get_file_size(f))})")
    if len(files) > 15:
        print(f"    ... and {len(files) - 15} more files")
    print(f"  Total Size  : {format_size(total)}")
    print(f"  CPU Cores   : {os.cpu_count() or 4} parallel search workers")
    print(f"  Host CPU    : {get_cpu_info()}")
    print(f"  Host GPU    : {get_gpu_info()}")
    print(f"  Local URL   : http://localhost:{PORT}")
    print("=" * 60)

    def open_browser():
        time.sleep(2.0)
        webbrowser.open(f'http://localhost:{PORT}')
    threading.Thread(target=open_browser, daemon=True).start()

    try:
        from http.server import ThreadingHTTPServer
        server = ThreadingHTTPServer(('localhost', PORT), OSINTHandler)
    except ImportError:
        server = HTTPServer(('localhost', PORT), OSINTHandler)
    print("  [OK] Server running! Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")

if __name__ == '__main__':
    main()
