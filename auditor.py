#!/usr/bin/env python3
"""
auditor.py  —  Email Domain Security Auditor (CLI entry point)
CNS 3104 | John Paul Opondo (193309)

Usage:
    python auditor.py --domain example.com
    python auditor.py --domain example.com --json
    python auditor.py --history
"""

from cli import main

if __name__ == "__main__":
    main()