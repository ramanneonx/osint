#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

"""
OSINT LOG PROFILER SERVER v1.0
Dedicated server for log profiling, format detection, and country-origin analysis.
"""

import os, json, time, threading, mmap, uuid, webbrowser, re
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from collections import defaultdict, Counter
import concurrent.futures


EMAIL_PATTERN = re.compile(r'[\w\.-]+@[\w\.-]+\.([a-zA-Z]{2,63})')
PHONE_PATTERN = re.compile(r'(?:\+|00)(\d{1,4})[\s-]?\d{6,14}')

COUNTRY_MAP = {
    "91": ("India", "🇮🇳"),
    "in": ("India", "🇮🇳"),
    "1": ("USA/Canada", "🇺🇸"),
    "us": ("USA/Canada", "🇺🇸"),
    "ca": ("Canada", "🇨🇦"),
    "44": ("United Kingdom", "🇬🇧"),
    "uk": ("United Kingdom", "🇬🇧"),
    "49": ("Germany", "🇩🇪"),
    "de": ("Germany", "🇩🇪"),
    "33": ("France", "🇫🇷"),
    "fr": ("France", "🇫🇷"),
    "7": ("Russia/Kazakhstan", "🇷🇺"),
    "ru": ("Russia/Kazakhstan", "🇷🇺"),
    "su": ("Russia/Kazakhstan", "🇷🇺"),
    "kz": ("Kazakhstan", "🇰🇿"),
    "81": ("Japan", "🇯🇵"),
    "jp": ("Japan", "🇯🇵"),
    "86": ("China", "🇨🇳"),
    "cn": ("China", "🇨🇳"),
    "55": ("Brazil", "🇧🇷"),
    "br": ("Brazil", "🇧🇷"),
    "39": ("Italy", "🇮🇹"),
    "it": ("Italy", "🇮🇹"),
    "34": ("Spain", "🇪🇸"),
    "es": ("Spain", "🇪🇸"),
    "61": ("Australia", "🇦🇺"),
    "au": ("Australia", "🇦🇺"),
    "31": ("Netherlands", "🇳🇱"),
    "nl": ("Netherlands", "🇳🇱"),
    "48": ("Poland", "🇵🇱"),
    "pl": ("Poland", "🇵🇱"),
    "90": ("Turkey", "🇹🇷"),
    "tr": ("Turkey", "🇹🇷"),
    "82": ("South Korea", "🇰🇷"),
    "kr": ("South Korea", "🇰🇷"),
    "62": ("Indonesia", "🇮🇩"),
    "id": ("Indonesia", "🇮🇩"),
    "92": ("Pakistan", "🇵🇰"),
    "pk": ("Pakistan", "🇵🇰"),
    "380": ("Ukraine", "🇺🇦"),
    "ua": ("Ukraine", "🇺🇦"),
    "84": ("Vietnam", "🇻🇳"),
    "vn": ("Vietnam", "🇻🇳"),
    "60": ("Malaysia", "🇲🇾"),
    "my": ("Malaysia", "🇲🇾"),
    "63": ("Philippines", "🇵🇭"),
    "ph": ("Philippines", "🇵🇭"),
    "66": ("Thailand", "🇹🇭"),
    "th": ("Thailand", "🇹🇭"),
    "971": ("UAE", "🇦🇪"),
    "ae": ("UAE", "🇦🇪"),
    "966": ("Saudi Arabia", "🇸🇦"),
    "sa": ("Saudi Arabia", "🇸🇦"),
    "20": ("Egypt", "🇪🇬"),
    "eg": ("Egypt", "🇪🇬"),
    "234": ("Nigeria", "🇳🇬"),
    "ng": ("Nigeria", "🇳🇬"),
    "27": ("South Africa", "🇿🇦"),
    "za": ("South Africa", "🇿🇦"),
}

def determine_country_origin(tld_counter, cc_counter):
    generic_tlds = {'com', 'net', 'org', 'info', 'biz', 'xyz', 'online', 'top', 'club', 'vip', 'pro', 'icu', 'site', 'work', 'fun', 'edu', 'gov', 'mil', 'mobi', 'tech', 'store', 'app'}
    country_weights = defaultdict(float)
    
    total_tlds = sum(count for tld, count in tld_counter.items() if tld not in generic_tlds)
    if total_tlds > 0:
        for tld, count in tld_counter.items():
            if tld in generic_tlds:
                continue
            if tld in COUNTRY_MAP:
                country_name, flag = COUNTRY_MAP[tld]
                country_weights[country_name] += (count / total_tlds) * 0.5
                
    total_ccs = sum(cc_counter.values())
    if total_ccs > 0:
        for cc, count in cc_counter.items():
            if cc in COUNTRY_MAP:
                country_name, flag = COUNTRY_MAP[cc]
                country_weights[country_name] += (count / total_ccs) * 0.5
                
    if not country_weights:
        return {
            "country": "Unknown / Global",
            "flag": "🌐",
            "confidence": "Low",
            "score": 0.0,
            "breakdown": []
        }
        
    sorted_countries = sorted(country_weights.items(), key=lambda x: -x[1])
    top_country, score = sorted_countries[0]
    
    flag = "🌐"
    for k, v in COUNTRY_MAP.items():
        if v[0] == top_country:
            flag = v[1]
            break
            
    total_samples = total_tlds + total_ccs
    if total_samples > 0:
        if score > 0.4:
            confidence = "High"
        elif score > 0.15:
            confidence = "Medium"
        else:
            confidence = "Low"
    else:
        confidence = "Low"
        
    breakdown = []
    total_weight = sum(country_weights.values())
    if total_weight > 0:
        for cname, weight in sorted_countries[:5]:
            cflag = "🌐"
            for k, v in COUNTRY_MAP.items():
                if v[0] == cname:
                    cflag = v[1]
                    break
            pct = int((weight / total_weight) * 100)
            if pct > 0:
                breakdown.append({"country": cname, "flag": cflag, "percentage": pct})
                
    return {
        "country": top_country,
        "flag": flag,
        "confidence": confidence,
        "score": round(score, 3),
        "breakdown": breakdown
    }

# ── CONFIG ────────────────────────────────────────────────────────────────────
PORT        = 8788
LOG_DIR     = os.path.dirname(os.path.abspath(__file__))
DB_DIR      = os.path.join(LOG_DIR, 'database')
os.makedirs(DB_DIR, exist_ok=True)
# ──────────────────────────────────────────────────────────────────────────────

def profile_single_file(filepath, rel_path):
    try:
        file_size = os.path.getsize(filepath)
    except Exception:
        return rel_path, None

    if file_size == 0:
        return rel_path, {
            "file_size": 0,
            "file_size_human": "0.0 B",
            "total_lines_sampled": 0,
            "total_lines_estimated": 0,
            "format": "unknown",
            "top_tlds": [],
            "top_ccs": [],
            "is_folder": False
        }

    tld_counter = Counter()
    cc_counter = Counter()
    total_lines = 0
    sample_limit = 50000
    format_detected = "unknown"
    
    try:
        with open(filepath, 'rb') as f:
            sample = f.read(8000)
            format_detected = detect_file_format(sample)
    except Exception:
        pass

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            # Read at most 4MB to get a 50k line sample
            chunk = f.read(4 * 1024 * 1024)
            
            idx = -1
            for _ in range(sample_limit):
                idx = chunk.find('\n', idx + 1)
                if idx == -1:
                    break
            if idx != -1:
                content = chunk[:idx]
                total_lines = sample_limit
            else:
                content = chunk
                total_lines = chunk.count('\n') + 1

            emails = EMAIL_PATTERN.findall(content)
            tld_counter.update(t.lower() for t in emails)
            
            phones = PHONE_PATTERN.findall(content)
            cc_counter.update(phones)
    except Exception as e:
        print(f"Error profiling {filepath}: {e}")
        
    origin_info = determine_country_origin(tld_counter, cc_counter)
        
    return rel_path, {
        "file_size": file_size,
        "file_size_human": format_size(file_size),
        "total_lines_sampled": total_lines,
        "total_lines_estimated": int(file_size / 65.78),
        "format": format_detected,
        "top_tlds": sorted(tld_counter.items(), key=lambda x: -x[1])[:10],
        "top_ccs": sorted(cc_counter.items(), key=lambda x: -x[1])[:10],
        "is_folder": False,
        "country_origin": origin_info
    }


def profile_directory_aggregated(dirpath, rel_path):
    tld_counter = Counter()
    cc_counter = Counter()
    total_lines = 0
    total_size = 0
    
    files_to_scan = []
    for root, _, filenames in os.walk(dirpath):
        for filename in filenames:
            if filename.lower().endswith(('.txt', '.log', '.csv')) and not filename.startswith('.'):
                files_to_scan.append(os.path.join(root, filename))
                
    for f in files_to_scan:
        try:
            total_size += os.path.getsize(f)
        except Exception:
            pass
            
    total_files_count = len(files_to_scan)
    if len(files_to_scan) > 200:
        step = len(files_to_scan) / 200
        sampled_files = [files_to_scan[int(i * step)] for i in range(200)]
    else:
        sampled_files = files_to_scan
        
    formats = Counter()
    for fp in sampled_files:
        try:
            fs = os.path.getsize(fp)
            if fs == 0:
                continue
            with open(fp, 'rb') as f:
                sample = f.read(8000)
                fmt = detect_file_format(sample)
                formats[fmt] += 1
                
            with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024 * 1024)
                lines = content.count('\n') + 1
                total_lines += lines
                
                emails = EMAIL_PATTERN.findall(content)
                tld_counter.update(t.lower() for t in emails)
                
                phones = PHONE_PATTERN.findall(content)
                cc_counter.update(phones)
        except Exception:
            pass
            
    format_detected = formats.most_common(1)[0][0] if formats else "single_line"
    origin_info = determine_country_origin(tld_counter, cc_counter)
    
    return rel_path, {
        "file_size": total_size,
        "file_size_human": format_size(total_size),
        "total_lines_sampled": total_lines,
        "total_lines_estimated": int(total_size / 65.78),
        "format": format_detected,
        "top_tlds": sorted(tld_counter.items(), key=lambda x: -x[1])[:10],
        "top_ccs": sorted(cc_counter.items(), key=lambda x: -x[1])[:10],
        "is_folder": True,
        "total_files": total_files_count,
        "sampled_files": len(sampled_files),
        "country_origin": origin_info
    }


def profile_single_file_or_virtual(filepath, rel_path):
    if filepath.endswith('_all_files.log'):
        dirpath = os.path.dirname(filepath)
        return profile_directory_aggregated(dirpath, rel_path)
    else:
        return profile_single_file(filepath, rel_path)


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
            total_size = 0
            for root, _, filenames in os.walk(full_path):
                for filename in filenames:
                    if filename.lower().endswith(('.txt', '.log', '.csv')) and not filename.startswith('.'):
                        total_files += 1
                        try:
                            total_size += os.path.getsize(os.path.join(root, filename))
                        except Exception:
                            pass
            
            if total_files == 0:
                continue
                
            if total_files > 200:
                virtual_file = os.path.join(full_path, "_all_files.log")
                rel_name = os.path.relpath(virtual_file, DB_DIR).replace('\\', '/')
                results.append({
                    "path": virtual_file,
                    "rel_name": rel_name,
                    "size": total_size,
                    "is_virtual": True
                })
            else:
                for root, _, filenames in os.walk(full_path):
                    for filename in filenames:
                        if filename.lower().endswith(('.txt', '.log', '.csv')) and not filename.startswith('.'):
                            fp = os.path.join(root, filename)
                            try:
                                sz = os.path.getsize(fp)
                            except Exception:
                                sz = 0
                            rel_name = os.path.relpath(fp, DB_DIR).replace('\\', '/')
                            results.append({
                                "path": fp,
                                "rel_name": rel_name,
                                "size": sz,
                                "is_virtual": False
                            })
        else:
            if entry.lower().endswith(('.txt', '.log', '.csv')):
                try:
                    sz = os.path.getsize(full_path)
                except Exception:
                    sz = 0
                rel_name = os.path.relpath(full_path, DB_DIR).replace('\\', '/')
                results.append({
                    "path": full_path,
                    "rel_name": rel_name,
                    "size": sz,
                    "is_virtual": False
                })
                
    return sorted(results, key=lambda x: x["rel_name"])

def format_size(n):
    for u in ['B','KB','MB','GB','TB']:
        if n < 1024: return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"

def detect_file_format(mm) -> str:
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

# ── HTTP SERVER ────────────────────────────────────────────────────────────────
class OSINTProfilerHandler(BaseHTTPRequestHandler):
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

        if path == '/api/profile':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data.decode('utf-8'))
            except Exception:
                self.send_json({'error': 'Invalid JSON'}, 400); return

            sel_files = data.get('files', [])
            files_to_profile = []
            if sel_files and len(sel_files) > 0:
                for rel_name in sel_files:
                    rel_name_norm = os.path.normpath(rel_name)
                    if rel_name_norm.startswith('..') or os.path.isabs(rel_name_norm):
                        continue
                    filepath = os.path.join(DB_DIR, rel_name_norm)
                    files_to_profile.append(filepath)
            else:
                files_to_profile = [f["path"] for f in get_log_files()]

            if not files_to_profile:
                self.send_json({'error': 'No files selected to profile'}, 400); return

            report = {}
            max_workers = min(32, (os.cpu_count() or 4) * 4)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(profile_single_file_or_virtual, fp, os.path.relpath(fp, DB_DIR).replace('\\', '/'))
                    for fp in files_to_profile
                ]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        rel_path, res = future.result()
                        if res is not None:
                            report[rel_path] = res
                    except Exception as e:
                        print(f"Error in future: {e}")

            self.send_json({"success": True, "report": report})
        else:
            self.send_response(404); self.end_headers()

    def do_GET(self):
        p  = urllib.parse.urlparse(self.path)
        path = p.path

        if path == '/':
            self.send_file(os.path.join(LOG_DIR, 'profiler.html'), 'text/html; charset=utf-8')

        elif path == '/api/info':
            files = get_log_files()
            total = sum(f["size"] for f in files)
            info  = []
            for f in files:
                info.append({
                    'name': f["rel_name"],
                    'size': f["size"],
                    'size_human': format_size(f["size"]),
                    'path': f["path"],
                    'is_virtual': f["is_virtual"]
                })
            self.send_json({'files': info, 'total_files': len(files),
                            'total_size': total, 'total_size_human': format_size(total),
                            'server_version': '1.0-profiler'})

        elif path == '/api/hardware':
            cpu_name = get_cpu_info()
            cpu_cores = os.cpu_count() or 0
            gpu_name = get_gpu_info()
            self.send_json({
                'cpu_name': cpu_name,
                'cpu_cores': cpu_cores,
                'gpu_name': gpu_name
            })
        else:
            self.send_response(404); self.end_headers()

def main():
    print("=" * 60)
    print("  OSINT DATABASE PROFILER & ANALYZER v1.0")
    print("=" * 60)
    files = get_log_files()
    total = sum(f["size"] for f in files)
    print(f"  Database dir: {DB_DIR}")
    print(f"  Files Found : {len(files)}")
    print(f"  Total Size  : {format_size(total)}")
    print(f"  Local URL   : http://localhost:{PORT}")
    print("=" * 60)

    def open_browser():
        time.sleep(2.0)
        webbrowser.open(f'http://localhost:{PORT}')
    threading.Thread(target=open_browser, daemon=True).start()

    try:
        from http.server import ThreadingHTTPServer
        server = ThreadingHTTPServer(('localhost', PORT), OSINTProfilerHandler)
    except ImportError:
        server = HTTPServer(('localhost', PORT), OSINTProfilerHandler)
    print("  [OK] Profiler Server running! Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")

if __name__ == '__main__':
    main()
