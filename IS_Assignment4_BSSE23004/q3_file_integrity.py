"""
=============================================================================
Question 3: File Hashing and Integrity Checker
=============================================================================
Tool  : SPHINX-WATCH – File Integrity Monitoring Tool
Usage :
  python q3_file_integrity.py --scan   <folder>            # first/baseline scan
  python q3_file_integrity.py --check  <folder>            # compare against baseline
  python q3_file_integrity.py --demo   <folder>            # run full automated demo

How it works:
  1. Scans every file in the target folder recursively.
  2. Computes the SHA-256 hash of each file's content.
  3. Saves all hashes + metadata to a JSON baseline file ("hashes.json").
  4. On the next run (--check), recomputes all hashes and compares:
       - MODIFIED : hash changed
       - DELETED  : file was in baseline but no longer exists
       - ADDED    : file exists now but was not in baseline
  5. All changes are logged with timestamps to "integrity_log.txt".
=============================================================================
"""

import hashlib
import json
import os
import sys
import time
import random
import string
import shutil
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
BASELINE_FILE = "hashes.json"
LOG_FILE      = "integrity_log.txt"


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def sha256_of_file(filepath: str) -> str:
    """Compute the SHA-256 hash of a file.  Reads in 64 KB chunks."""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def scan_folder(folder: str) -> dict:
    """
    Recursively scan `folder` and return a dict:
      { relative_path : { 'sha256': ..., 'size': ..., 'mtime': ... } }
    """
    folder  = os.path.abspath(folder)
    entries = {}
    for root, _, files in os.walk(folder):
        for fname in files:
            full   = os.path.join(root, fname)
            rel    = os.path.relpath(full, folder)
            stat   = os.stat(full)
            try:
                sha = sha256_of_file(full)
            except (PermissionError, OSError) as e:
                sha = f"ERROR: {e}"
            entries[rel] = {
                'sha256': sha,
                'size'  : stat.st_size,
                'mtime' : stat.st_mtime,
            }
    return entries


def save_baseline(folder: str, entries: dict):
    baseline_path = os.path.join(folder, BASELINE_FILE)
    data = {
        'scanned_at': datetime.now().isoformat(),
        'folder'    : folder,
        'files'     : entries,
    }
    with open(baseline_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Baseline saved  : {baseline_path}")
    print(f"  Files scanned   : {len(entries)}")


def load_baseline(folder: str) -> dict | None:
    baseline_path = os.path.join(folder, BASELINE_FILE)
    if not os.path.exists(baseline_path):
        return None
    with open(baseline_path) as f:
        return json.load(f)


def compare(baseline: dict, current: dict) -> dict:
    """
    Compare baseline entries against current scan.
    Returns dict with lists: modified, deleted, added.
    """
    old_files = set(baseline.keys())
    new_files = set(current.keys())

    modified = []
    for f in old_files & new_files:
        if baseline[f]['sha256'] != current[f]['sha256']:
            modified.append({
                'file'   : f,
                'old_hash': baseline[f]['sha256'],
                'new_hash': current[f]['sha256'],
            })

    deleted = sorted(old_files - new_files)
    added   = sorted(new_files - old_files)

    return {
        'modified': sorted(modified, key=lambda x: x['file']),
        'deleted' : deleted,
        'added'   : added,
    }


def log_changes(folder: str, changes: dict, scan_time: str, baseline_time: str):
    """Append a change report to the log file."""
    log_path = os.path.join(folder, LOG_FILE)
    with open(log_path, 'a') as lf:
        lf.write("\n" + "=" * 70 + "\n")
        lf.write(f"Integrity Check Report\n")
        lf.write(f"Timestamp       : {scan_time}\n")
        lf.write(f"Baseline taken  : {baseline_time}\n")
        lf.write(f"Folder          : {folder}\n")
        lf.write("-" * 70 + "\n")

        total = len(changes['modified']) + len(changes['deleted']) + len(changes['added'])
        if total == 0:
            lf.write("Result: NO CHANGES DETECTED\n")
        else:
            lf.write(f"Result: {total} change(s) detected\n\n")

            if changes['modified']:
                lf.write(f"[MODIFIED – {len(changes['modified'])} file(s)]\n")
                for m in changes['modified']:
                    lf.write(f"  {m['file']}\n")
                    lf.write(f"    Old SHA-256 : {m['old_hash']}\n")
                    lf.write(f"    New SHA-256 : {m['new_hash']}\n")

            if changes['deleted']:
                lf.write(f"\n[DELETED – {len(changes['deleted'])} file(s)]\n")
                for d in changes['deleted']:
                    lf.write(f"  {d}\n")

            if changes['added']:
                lf.write(f"\n[ADDED – {len(changes['added'])} file(s)]\n")
                for a in changes['added']:
                    lf.write(f"  {a}\n")

        lf.write("=" * 70 + "\n")
    return log_path


def print_report(changes: dict):
    total = len(changes['modified']) + len(changes['deleted']) + len(changes['added'])

    if total == 0:
        print("  Result          : NO CHANGES DETECTED – all files intact.")
        return

    print(f"  Total changes   : {total}")
    print()

    if changes['modified']:
        print(f"  [MODIFIED – {len(changes['modified'])} file(s)]")
        for m in changes['modified']:
            print(f"    {m['file']}")
            print(f"      Old : {m['old_hash'][:32]}...")
            print(f"      New : {m['new_hash'][:32]}...")

    if changes['deleted']:
        print(f"\n  [DELETED – {len(changes['deleted'])} file(s)]")
        for d in changes['deleted']:
            print(f"    {d}")

    if changes['added']:
        print(f"\n  [ADDED – {len(changes['added'])} file(s)]")
        for a in changes['added']:
            print(f"    {a}")


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

def cmd_scan(folder: str):
    print(f"\n  Scanning folder : {folder}")
    entries = scan_folder(folder)
    # Exclude the baseline and log file itself from tracking
    entries.pop(BASELINE_FILE, None)
    entries.pop(LOG_FILE, None)
    save_baseline(folder, entries)
    print()


def cmd_check(folder: str):
    print(f"\n  Checking folder : {folder}")
    data = load_baseline(folder)
    if data is None:
        print("  ERROR: No baseline found. Run --scan first.")
        return

    current = scan_folder(folder)
    current.pop(BASELINE_FILE, None)
    current.pop(LOG_FILE, None)

    baseline_entries = data['files']
    changes          = compare(baseline_entries, current)
    scan_time        = datetime.now().isoformat()

    print_report(changes)

    log_path = log_changes(folder, changes, scan_time, data['scanned_at'])
    print(f"\n  Log updated     : {log_path}")
    print()


# ---------------------------------------------------------------------------
# Automated Demo
# ---------------------------------------------------------------------------

def _rand_text(n: int = 200) -> str:
    words = ("the quick brown fox jumps over the lazy dog "
             "information security cryptography network protocol "
             "hash sha256 integrity monitor detect change").split()
    return ' '.join(random.choices(words, k=n))


def cmd_demo(demo_folder: str):
    """
    Fully automated demo:
      1. Create a folder with 20 sample files.
      2. Run baseline scan.
      3. Modify 3 files, delete 2 files, add 3 new files.
      4. Run integrity check and display the report.
    """
    print("\n" + "=" * 72)
    print("   File Integrity Monitor – Full Demo")
    print("=" * 72)

    # Clean up previous demo
    if os.path.exists(demo_folder):
        shutil.rmtree(demo_folder)
    os.makedirs(demo_folder)
    os.makedirs(os.path.join(demo_folder, "subdir"), exist_ok=True)

    # ------------------------------------------------------------------ #
    # Step 1 – Create 20 files                                            #
    # ------------------------------------------------------------------ #
    print("\n  [Step 1] Creating 20 sample files ...\n")

    file_names = [f"file_{i:02d}.txt" for i in range(1, 16)] + \
                 [f"subdir/doc_{i:02d}.txt" for i in range(1, 6)]

    for fname in file_names:
        path = os.path.join(demo_folder, fname)
        with open(path, 'w') as f:
            f.write(_rand_text(50))
        print(f"    Created : {fname}")

    print(f"\n    Total files created : {len(file_names)}")

    # ------------------------------------------------------------------ #
    # Step 2 – Baseline scan                                              #
    # ------------------------------------------------------------------ #
    print("\n  [Step 2] Running baseline scan ...\n")
    entries = scan_folder(demo_folder)
    entries.pop(BASELINE_FILE, None)
    entries.pop(LOG_FILE, None)
    save_baseline(demo_folder, entries)

    # ------------------------------------------------------------------ #
    # Step 3 – Tamper with files                                          #
    # ------------------------------------------------------------------ #
    print("\n  [Step 3] Simulating changes (modify 3, delete 2, add 3) ...\n")
    time.sleep(1)  # ensure mtime difference is detectable

    # Modify 3 files
    to_modify = ["file_01.txt", "file_07.txt", "subdir/doc_03.txt"]
    for fname in to_modify:
        path = os.path.join(demo_folder, fname)
        with open(path, 'a') as f:
            f.write("\n[TAMPERED] " + _rand_text(10))
        print(f"    Modified : {fname}")

    # Delete 2 files
    to_delete = ["file_10.txt", "subdir/doc_05.txt"]
    for fname in to_delete:
        os.remove(os.path.join(demo_folder, fname))
        print(f"    Deleted  : {fname}")

    # Add 3 new files
    to_add = ["new_file_A.txt", "new_file_B.txt", "subdir/new_doc_C.txt"]
    for fname in to_add:
        path = os.path.join(demo_folder, fname)
        with open(path, 'w') as f:
            f.write("[NEW FILE] " + _rand_text(30))
        print(f"    Added    : {fname}")

    # ------------------------------------------------------------------ #
    # Step 4 – Integrity check                                            #
    # ------------------------------------------------------------------ #
    print("\n  [Step 4] Running integrity check ...\n")

    data    = load_baseline(demo_folder)
    current = scan_folder(demo_folder)
    current.pop(BASELINE_FILE, None)
    current.pop(LOG_FILE, None)

    changes   = compare(data['files'], current)
    scan_time = datetime.now().isoformat()

    print("  ---- Change Report ----")
    print_report(changes)

    log_path = log_changes(demo_folder, changes, scan_time, data['scanned_at'])
    print(f"\n  Log written to  : {log_path}")

    # ------------------------------------------------------------------ #
    # Print log content                                                   #
    # ------------------------------------------------------------------ #
    print("\n  ---- Log File Contents ----")
    with open(log_path) as f:
        print(f.read())

    print("=" * 72)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python q3_file_integrity.py --scan  <folder>   # create baseline")
        print("  python q3_file_integrity.py --check <folder>   # compare with baseline")
        print("  python q3_file_integrity.py --demo  <folder>   # run automated demo")
        sys.exit(0)

    command = sys.argv[1].lower()
    folder  = sys.argv[2]

    if command == "--scan":
        cmd_scan(folder)
    elif command == "--check":
        cmd_check(folder)
    elif command == "--demo":
        cmd_demo(folder)
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
