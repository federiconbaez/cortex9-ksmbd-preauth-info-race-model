# Guía práctica (6 niveles)

Ejercicios **offline** sobre una carrera check-then-use y cómo la cierra un
lock. No hay código del kernel, ni ksmbd, ni tráfico SMB: solo una máquina
de estados cuyas intercalaciones se enumeran. Cada respuesta está
comprobada en `tests/test_model.c` (`test_practice_levels`, "level N"),
compilado con ASan/UBSan. Si querés estudiar el kernel real, hacelo solo en
una VM propia, sin red y con tu propio servidor, nunca contra servidores
SMB de terceros.

Comandos: `sh scripts/build.sh test`; después de `sh scripts/build.sh
results /tmp/r`: `./build/ksrace case <version> <mode> <variant> <init>
<rounds> <senders> <schedule>` (`N` = handler, `S`/`T` = senders).

**Básico**

1. **Sin solapamiento.** `pre cached fail_only live 1 1 SSSNNNN`.
   (level 1: `OK`)
2. **Check, free, use.** `SNNNNSS` con `cached`. (level 2: `UAF`)

**Intermedio**

3. **El NULL no alcanza.** El mismo orden con `reload`, y después
   `SNNSNNS`. ¿Por qué el commit dice que el NULL guard solo no cierra la
   ventana? (level 3: `NULL_DEREF` y `UAF`: entre el `kfree` y el NULL el
   puntero todavía apunta al objeto liberado)
4. **El lock.** `post cached fail_only live 1 1 SNNNNSSSS`. (level 4:
   `INFEASIBLE`; la configuración entera tiene solo 2 schedules, los dos
   sin falla)

**Avanzado**

5. **El objeto nuevo.** `pre reload alloc_fail null 1 1 NNSNSNSN`: el
   lector toma el objeto que el mismo handler va a liberar. (level 5:
   `UAF`)
6. **Control negativo.** `alloc_ok` con 3 rondas y 2 senders. (level 6:
   ningún `UAF` ni `NULL_DEREF`: sin `kfree` no hay carrera de este tipo)

Más allá: agregá un schedule a `fixtures/cases.tsv` con su resultado a
mano, regenerá `fixtures/expected.tsv` con `scripts/derive_expected.py` y
comprobá que el modelo en C coincide. En tu propio código, buscá punteros
compartidos que se comprueban fuera del lock que protege su liberación.
