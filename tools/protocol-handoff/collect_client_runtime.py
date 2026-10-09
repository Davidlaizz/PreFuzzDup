"""Collect the Linux/WSL runtime used for client C++ computation (not the Python host)."""
import argparse
import json
import platform
import sqlite3
import subprocess
import sys
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    cpu = Path('/proc/cpuinfo').read_text()
    report = dict(platform=platform.platform(), python=sys.version, sqlite_python_version=sqlite3.sqlite_version,
                  cpu_model=next((line.split(':', 1)[1].strip() for line in cpu.splitlines() if line.startswith('model name')), ''),
                  memory=Path('/proc/meminfo').read_text(),
                  compiler=subprocess.check_output(['g++', '--version'], text=True),
                  openssl=subprocess.check_output(['openssl', 'version'], text=True),
                  execution='Linux/WSL C++ worker; captured after preparation',
                  compile_flags='-std=c++20 -O2 -lcrypto -lsqlite3', os_page_cache_cleared=False)
    with args.out.open('x') as f:
        json.dump(report, f, indent=2)


if __name__ == '__main__':
    main()
