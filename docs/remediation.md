# Remediation

Ordered by impact. Items 1–2 close the CVE class; 3–5 close the application chain.

## 1. Patch PHP

Move off the EOL 7.4 branch. Fixed releases for CVE-2026-109618 / CVE-2026-109619:

| Branch | Fixed |
|--------|-------|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 7.4 | none (EOL) — use the PHP source backport or a distro backport |

PMB 4.5 already requires PHP ≥ 8.2, so 8.2.35 is the natural target. Keep `ondrej/php`
current for future advisories.

## 2. Interim mitigations (cannot patch yet)

- `session.upload_progress.enabled = Off`
- Low `memory_limit`, `post_max_size` below it
- Restart Apache workers after suspicious traffic
- WAF rule in front of the proxy

These are not complete fixes.

## 3. Parameterise the SQL injection

`ajax.php?id=` is interpolated. Use a prepared statement / bound parameter. The injection is
unauthenticated and gives `LOAD_FILE`, so it is the entry point for everything else.

## 4. Strong admin credentials

The install used `maha` / `maha`. Enforce a password policy and rotate defaults. Consider
2FA on the PMB admin panel.

## 5. Harden `camera_upload.php`

- Allow-list extensions (`.jpg`, `.png`, `.gif` only) — or store outside the web root.
- Validate with `getimagesize()` **and** re-encode through GD/Imagick so appended PHP is
  stripped.
- If PHP execution in the upload directory is not needed, disable it via
  `php_admin_flag engine off` or an `.htaccess` handler rule.

## 6. Detect

- Watch for `camera_upload.php` POSTs with `imgBase64` starting `data:image/` followed by a
  non-image tail.
- Alert on new `.php` files in the PMB web root.
- Log and review `LOAD_FILE`-heavy query patterns.
