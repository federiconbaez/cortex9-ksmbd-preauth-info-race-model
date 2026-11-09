# cortex9-ksmbd-preauth-info-race-model

Interleaving model of **CVE-2026-72422** (Linux kernel, ksmbd): the SMB2
send path `smb3_preauth_hash_rsp()` tested `conn->preauth_info` and then
used it without `conn_lock`, while a concurrent NEGOTIATE handler could
`kfree()` it and store NULL under that lock, so the reader could use a
freed object. The fix, commit 0c054227479e (mainline 7.2, with stable
backports), takes `ksmbd_conn_lock(conn)` around the check and the use.
Educational, deterministic, C11 checked with ASan/UBSan. **No kernel code,
no ksmbd, no SMB traffic, no threads:** the model is a small state machine
whose every interleaving is enumerated.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## What is modelled (tied to the patch, `fs/smb/server/smb2pdu.c`)

| Patch line | Code | Model step |
|---|---|---|
| old 9371-9372 | `if (... SMB2_NEGOTIATE_HE && conn->preauth_info)` | `pre`: `CHECK` |
| old 9373-9374 | `ksmbd_gen_preauth_integrity_hash(conn, ..., conn->preauth_info->Preauth_HashValue)` | `pre`: `LOAD`, `USE` |
| new 9372, 9376 | `ksmbd_conn_lock(conn)` ... `ksmbd_conn_unlock(conn)` | `post`: `LOCK` ... `UNLOCK` |
| new 9373-9375 | the same check and use, inside the lock | `post`: `CHECK`, `LOAD`, `USE` |
| commit message, 2nd paragraph | the negotiate handler allocates, and on failure `kfree`s and NULLs, all under `ksmbd_conn_lock` | handler: `LOCK`, [`ALLOC`], `FREE`, `SETNULL`, `UNLOCK` |

`LOAD` has two modes because the C source reads `conn->preauth_info` twice
and the compiler may reload it (`reload`) or reuse the value from the check
(`cached`). Handler variants: `fail_only` (frees an object that already
exists), `alloc_fail` (allocates, then fails), `alloc_ok` (negative control,
nothing freed); the pointer starts `null` or `live`; 1-3 negotiate rounds;
1-2 send-path threads. Which variant matches real traffic is **not** in the
sources.

## Differential evidence (`results/`)

| Schedule (`N` handler, `S` sender) | pre | post |
|---|---|---|
| `SNNNNSS` (check, whole handler, use), cached / reload | `UAF` / `NULL_DEREF` | `INFEASIBLE`: `N` cannot lock while `S` holds it |
| `SNNSNNS` (load between `kfree` and the NULL store) | `UAF` | `INFEASIBLE` |
| `NNSNSNSN` (`alloc_fail`: read inside the handler) | `UAF` | `INFEASIBLE` |
| `SSSNNNN` / `NNNNS` | `OK` / `SKIP` | `OK` / `SKIP` |

`results/sweep.csv` enumerates all 144 configurations. Every `pre`
configuration that frees an object has UAF schedules (for example 18 of 33
with `fail_only`, `live`, `reload`, one round, one sender); every `post`
configuration has none, and `alloc_ok` has none in either version.

## Run

```sh
sh scripts/build.sh test              # -Wall -Wextra -Werror, ASan + UBSan
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/ksrace case pre cached fail_only live 1 1 SNNNNSS
```

`fixtures/cases.tsv` holds hand-derived schedules (positive, negative,
edge and malformed). `fixtures/expected.tsv` comes from
`scripts/derive_expected.py`, which counts schedules with a memoised
recursion instead of the C depth-first walk; the C tests compare every
outcome and every count, and also check that all `N`/`S` strings up to full
length add up to the enumeration.

A model is not a finding: see [LIMITATIONS.md](LIMITATIONS.md) and
[SOURCES.md](SOURCES.md). License: Apache-2.0.
