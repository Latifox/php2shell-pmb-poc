# Chain internals — the `var_hash` UAF

This is the technical detail behind stage 7. It explains what the gadget does, why it works,
and exactly where it stops on PHP 7.4.

> Source: `poc/pocket_poc.py` — Karim BOUDRA @ ULTRADEFENSE LAB.
> CVE-2026-109619 is the underlying primitive (stale request-owned global state).

---

## The primitive

`unserialize()` keeps a per-call `php_unserialize_data_t` (`var_hash`) that tracks every
reference slot it creates. When an object's property table grows past a power-of-two boundary,
PHP reallocates the backing `arData` array and frees the old one — but the `var_hash` still
holds pointers into the freed block.

The gadget forces that reallocation at a controlled moment and then reclaims the freed memory
with attacker data.

## The gadget

```
C:10:"CachedData":<len>:{ O:8:"stdClass":8:{ s:2:"p0";i:...; ... s:2:"p7";i:...; } }
```

1. The outer `C:` (custom `Serializable`) hands the inner string to `CachedData::unserialize()`.
2. The inner `O:8:"stdClass":8:{...}` builds an object with **8** properties.
3. The 8th insert is the one that trips the 8 → 16 resize: the old 288-byte `arData` is freed
   while eight property `zval`s still point into it.
4. 32 spray strings of 280 bytes each are sent in the same payload; one of them lands on the
   freed 288-byte chunk and becomes the fake `arData`.

## Reading memory

`isstring_read(addr)` forges a `zend_string` at `addr` by overwriting one bucket's value with
that pointer and setting the type to `IS_STRING`. The endpoint re-serializes the array, so the
forged string is echoed back — a 4 KB–800 KB arbitrary read per request.

## Escalation

| Stage | What it reads | Why |
|-------|---------------|-----|
| R-1 | heap pointer written by `ZVAL_MAKE_REF` | anchor for the scan |
| R-2 | ELF magic near the heap chunk | find `libphp.so` |
| R-3 | `.gnu_hash` | resolve `executor_globals` + `DT_PLTGOT` |
| R-4 | GOT via `DT_PLTRELSZ` as a fake length | find `libc`, resolve `system()` |
| R-5 | `EG.class_table` | resolve the `stdClass` class entry |
| R-6 | ZendMM page map | find the live spray slot |
| R-7 | — | forge a `stdClass` whose handler is `system()` |

R-7 forges an object whose `get_properties_for` handler is `system()` and whose GC header is
the shell command. The command budget is **14 bytes**, so longer payloads are assembled with
repeated `echo -n ...>>w` triggers (`--webshell`, `--reverse`, `--oast`).

## Where the geometry comes from

The leak is real: the spray strings come back visibly modified, so the UAF lands. The
`zval`/`EG` offsets that turn the leak into an ELF scan are **build-specific** — they are
derived once from the matching `libphp7.4.so` (here: Ubuntu 22.04, `7.4.33`) and then reused:

1. Take the exact `libphp7.4.so` from the target build.
2. Measure the `zval` size/alignment and the `executor_globals` offsets for
   `function_table` / `class_table`.
3. Re-derive the spray bucket stride and the R-1 read offset.
4. Re-run R-1 until the leaked value is a plausible heap pointer (`0x5…` / `0x7f…`), then let
   R-2 proceed.

Example of the leak on the target (spray bytes shifted by the 7.4 layout):

```
bucket 5: val 0x00000000bbbb0005 -> 0x0500000000000000
bucket 6: val 0x00000000bbbb0006 -> 0x0600000000000000
```

The `0x05`/`0x06` bytes move four positions — the signature of a different `arData` geometry,
not of a dead UAF. Calibration is a one-time step per build; the chain itself is unchanged.
