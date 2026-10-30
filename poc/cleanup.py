#!/usr/bin/env python3
"""Stage 8 — overwrite planted files with inert 1-pixel GIFs.

Usage:
  python cleanup.py <user> <password> [file ...]
"""
import sys

import common as c

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_FILES = [
    "remote_app.php", "remote_app.phtml", "remote_app.phar",
    "remote_app.php4", "remote_app.php5", "proof.html",
]


def main(argv):
    if len(argv) < 2:
        c.out("usage: python cleanup.py <user> <password> [file ...]")
        return 2
    user, password = argv[0], argv[1]
    files = argv[2:] or DEFAULT_FILES

    cookies = c.login(user, password)
    if not cookies:
        c.out("[!] login failed")
        return 1

    for name in files:
        status, body = c.upload(cookies, name, c.GIF_1X1)
        c.out("  %-20s %s %s" % (name, status, body[:50]))
    c.out("\n[+] planted files overwritten with inert GIFs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
