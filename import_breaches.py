#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINT Database Importer & Indexer v1.0
High-performance script to import and index flat credential dumps
directly into the fast alphabetical COMB database structure.
"""

import os
import sys
import time
from collections import defaultdict

# Config
LOG_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(LOG_DIR, 'database')
COMB_DATA_DIR = os.path.join(DB_DIR, 'CompilationOfManyBreaches', 'data')

def get_target_file(line_lower, comb_data_dir):
    if not line_lower:
        return None
    c1 = line_lower[0]
    if not c1.isalnum():
        return os.path.join(comb_data_dir, 'symbols')
    
    p1 = os.path.join(comb_data_dir, c1)
    if os.path.isfile(p1):
        return p1
    elif os.path.isdir(p1):
        if len(line_lower) < 2:
            return os.path.join(p1, 'symbols')
        c2 = line_lower[1]
        if not c2.isalnum():
            return os.path.join(p1, 'symbols')
        
        p2 = os.path.join(p1, c2)
        if os.path.isfile(p2):
            return p2
        elif os.path.isdir(p2):
            if len(line_lower) < 3:
                return os.path.join(p2, 'symbols')
            c3 = line_lower[2]
            if not c3.isalnum():
                return os.path.join(p2, 'symbols')
            
            p3 = os.path.join(p2, c3)
            if os.path.isfile(p3):
                return p3
            else:
                return os.path.join(p2, 'symbols')
    return None

def main():
    print("=" * 60)
    print("  OSINT HIGH-PERFORMANCE BREACH INDEXER & IMPORTER")
    print("=" * 60)
    
    if not os.path.isdir(COMB_DATA_DIR):
        print(f"[ERROR] COMB data directory not found: {COMB_DATA_DIR}")
        sys.exit(1)
        
    # Discover files to import
    files_to_import = []
    for root, dirs, files in os.walk(DB_DIR):
        if 'CompilationOfManyBreaches' in root:
            continue
        for filename in files:
            if filename.lower().endswith(('.txt', '.log', '.csv')) and not filename.startswith('.'):
                files_to_import.append(os.path.join(root, filename))
                
    if not files_to_import:
        print("[!] No flat breach files found outside CompilationOfManyBreaches.")
        sys.exit(0)
        
    print(f"[*] Found {len(files_to_import)} files to import and index into COMB.")
    for f in files_to_import[:10]:
        print(f"    - {os.path.relpath(f, DB_DIR)} ({os.path.getsize(f) / (1024*1024):.1f} MB)")
    if len(files_to_import) > 10:
        print(f"    ... and {len(files_to_import) - 10} more files.")
        
    print("\n[*] Starting high-performance stream parsing...")
    
    buffers = defaultdict(list)
    buffer_limit = 500000  # lines buffered before writing
    buffer_count = 0
    modified_files = set()
    total_imported = 0
    
    start_time = time.time()
    
    for idx, filepath in enumerate(files_to_import):
        rel_path = os.path.relpath(filepath, DB_DIR)
        file_size = os.path.getsize(filepath)
        print(f"\n[*] Processing [{idx+1}/{len(files_to_import)}]: {rel_path} ({file_size / (1024*1024):.1f} MB)")
        
        file_imported_count = 0
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_clean = line.strip()
                    if not line_clean or '@' not in line_clean:
                        continue
                        
                    # Find partition target path
                    target_path = get_target_file(line_clean.lower(), COMB_DATA_DIR)
                    if target_path:
                        buffers[target_path].append(line_clean + '\n')
                        modified_files.add(target_path)
                        buffer_count += 1
                        file_imported_count += 1
                        
                        if buffer_count >= buffer_limit:
                            # Flush buffers to disk
                            for path, lines in buffers.items():
                                with open(path, 'a', encoding='utf-8', errors='ignore') as out:
                                    out.writelines(lines)
                            buffers.clear()
                            buffer_count = 0
                            print(f"    -> Flushed {buffer_limit} lines to COMB index partitions...")
                            
            total_imported += file_imported_count
            print(f"    [OK] Imported {file_imported_count:,} credentials from {rel_path}.")
        except Exception as e:
            print(f"    [ERROR] Reading file {rel_path}: {e}")
            
    # Flush remaining buffers
    if buffer_count > 0:
        for path, lines in buffers.items():
            with open(path, 'a', encoding='utf-8', errors='ignore') as out:
                out.writelines(lines)
        buffers.clear()
        
    print(f"\n[OK] Raw import completed! Total imported lines: {total_imported:,}")
    print(f"[*] Sorting and deduplicating {len(modified_files)} modified COMB partition files...")
    
    sort_start = time.time()
    for s_idx, path in enumerate(sorted(modified_files)):
        if (s_idx + 1) % 50 == 0 or s_idx == len(modified_files) - 1:
            print(f"    -> Sorting progress: [{s_idx+1}/{len(modified_files)}] partition files sorted...")
        try:
            if not os.path.isfile(path):
                continue
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            # Unique sorted lines
            lines_uniq = sorted(list(set(lines)))
            with open(path, 'w', encoding='utf-8') as f:
                f.writelines(lines_uniq)
        except Exception as e:
            print(f"    [ERROR] Sorting partition {os.path.basename(path)}: {e}")
            
    elapsed = time.time() - start_time
    print("\n" + "=" * 60)
    print("  IMPORT & INDEXING PROCESS COMPLETED SUCCESSFUL!")
    print("=" * 60)
    print(f"  Total Files Processed : {len(files_to_import)}")
    print(f"  Total Lines Imported  : {total_imported:,}")
    print(f"  Partitions Modified   : {len(modified_files)}")
    print(f"  Deduplicated & Sorted : Yes (sort-unique)")
    print(f"  Total Elapsed Time    : {elapsed:.2f} seconds ({elapsed/60:.1f} minutes)")
    print("=" * 60)

if __name__ == '__main__':
    main()
