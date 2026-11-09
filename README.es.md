# cortex9-ksmbd-preauth-info-race-model

Modelo de intercalaciones de **CVE-2026-72422** (kernel Linux, ksmbd): el
camino de envío SMB2 `smb3_preauth_hash_rsp()` comprobaba
`conn->preauth_info` y después lo usaba sin `conn_lock`, mientras un
handler NEGOTIATE concurrente podía hacer `kfree()` y guardar NULL bajo ese
lock, así que el lector podía usar un objeto liberado. El fix, commit
0c054227479e (mainline 7.2, con backports a stable), toma
`ksmbd_conn_lock(conn)` alrededor de la comprobación y el uso. Educativo,
determinista, C11 verificado con ASan/UBSan. **Sin código del kernel, sin
ksmbd, sin tráfico SMB y sin hilos:** el modelo es una máquina de estados
chica y se enumeran todas sus intercalaciones.

English: [README.md](README.md). Ejercicios: [PRACTICE.md](PRACTICE.md).

## Qué se modela (atado al patch, `fs/smb/server/smb2pdu.c`)

- `pre` (viejas 9371-9374): `CHECK`, `LOAD`, `USE`, sin lock.
- `post` (nuevas 9371-9377): `LOCK` (9372), `CHECK` (9373), `LOAD`/`USE`
  (9374-9375), `UNLOCK` (9376).
- Handler, según el mensaje del commit (segundo párrafo): `LOCK`, [`ALLOC`],
  `FREE`, `SETNULL`, `UNLOCK`, todo bajo `ksmbd_conn_lock`.
- `LOAD` en dos modos (`reload` o `cached`), porque el código lee el campo
  dos veces y el compilador puede recargarlo o no. Variantes del handler:
  `fail_only`, `alloc_fail` y `alloc_ok` (control negativo). Cuál
  corresponde al tráfico real no está en las fuentes.

## Evidencia diferencial (`results/`)

- `SNNNNSS` (check, handler completo, uso): `UAF` (cached) o `NULL_DEREF`
  (reload) antes; `INFEASIBLE` después, porque `N` no puede tomar el lock
  mientras lo tiene `S`.
- `SNNSNNS` (carga entre el `kfree` y el NULL): `UAF` antes, `INFEASIBLE`
  después.
- `results/sweep.csv`: 144 configuraciones; toda configuración `pre` que
  libera tiene schedules con UAF; ninguna `post` los tiene, y `alloc_ok` no
  los tiene en ninguna versión.

## Uso

```sh
sh scripts/build.sh test
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
sh scripts/build.sh results /tmp/r && diff -r results /tmp/r
./build/ksrace case post cached fail_only live 1 1 SNNNNSSSS
```

Un modelo no es un hallazgo: ver [LIMITATIONS.md](LIMITATIONS.md) y
[SOURCES.md](SOURCES.md). Licencia: Apache-2.0.
