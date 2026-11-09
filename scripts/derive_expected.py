#!/usr/bin/env python3
"""Independent derivation of fixtures/expected.tsv (no C code involved).

Written from the ksmbd fix 0c054227479e (fs/smb/server/smb2pdu.c) and its
commit message:
- send path, smb3_preauth_hash_rsp(), NEGOTIATE branch
    pre  (old 9371-9374): if (conn->preauth_info) use conn->preauth_info->...
    post (new 9371-9377): ksmbd_conn_lock; if (...) use ...; ksmbd_conn_unlock
- negotiate handler: allocation, kfree and the NULL store all happen under
  ksmbd_conn_lock(conn), held across the handler body (message, 2nd paragraph).
The schedules are counted with a memoised recursion over states (the C code
uses a plain depth-first walk). Prints "case" rows (fixture id, outcome) and
"sweep" rows (configuration, counts).
"""
import os
import sys
from functools import lru_cache

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cx9_util import read_cases  # noqa: E402

NULL = None


def programs(version, variant, rounds, senders):
    handler = []
    for _ in range(rounds):
        handler.append("lock")
        if variant in ("alloc_fail", "alloc_ok"):
            handler.append("alloc")
        if variant in ("fail_only", "alloc_fail"):
            handler += ["free", "null"]
        handler.append("unlock")
    send = ["check", "load", "use"]
    if version == "post":
        send = ["lock"] + send + ["unlock"]
    return (tuple(handler),) + (tuple(send),) * senders


def initial(init, nthreads):
    objs = (True,) if init == "live" else ()
    ptr = 0 if init == "live" else NULL
    # (pcs, ptr, objs, owner, seen, addr, results)
    return ((0,) * nthreads, ptr, objs, NULL, (NULL,) * nthreads, (NULL,) * nthreads,
            ("OK",) * nthreads)


def runnable(progs, st, t):
    pcs, _ptr, _objs, owner = st[0], st[1], st[2], st[3]
    if pcs[t] >= len(progs[t]):
        return False
    return not (progs[t][pcs[t]] == "lock" and owner is not NULL)


def advance(version, mode, progs, st, t):
    pcs, ptr, objs, owner, seen, addr, res = st
    pcs, objs, seen, addr, res = list(pcs), list(objs), list(seen), list(addr), list(res)
    op = progs[t][pcs[t]]
    pcs[t] += 1
    if op == "lock":
        owner = t
    elif op == "unlock":
        owner = NULL
    elif op == "alloc":
        objs.append(True)
        ptr = len(objs) - 1
    elif op == "free":
        if ptr is not NULL:
            objs[ptr] = False
    elif op == "null":
        ptr = NULL
    elif op == "check":
        seen[t] = ptr
        if ptr is NULL:
            res[t] = "SKIP"
            pcs[t] = progs[t].index("unlock") if version == "post" else len(progs[t])
    elif op == "load":
        addr[t] = ptr if mode == "reload" else seen[t]
    elif op == "use":
        if addr[t] is NULL:
            res[t] = "NULL_DEREF"
        elif not objs[addr[t]]:
            res[t] = "UAF"
        else:
            res[t] = "OK"
    return (tuple(pcs), ptr, tuple(objs), owner, tuple(seen), tuple(addr), tuple(res))


def verdict(res):
    senders = res[1:]
    if "UAF" in senders:
        return "UAF"
    if "NULL_DEREF" in senders:
        return "NULL_DEREF"
    if all(r == "SKIP" for r in senders):
        return "SKIP"
    return "OK"


def run_schedule(version, mode, variant, init, rounds, senders, schedule):
    progs = programs(version, variant, rounds, senders)
    st = initial(init, len(progs))
    letters = {"N": 0, "S": 1, "T": 2}
    for ch in schedule:
        t = letters.get(ch)
        if t is None or t >= len(progs):
            return "BAD_INPUT"
        if not runnable(progs, st, t):
            return "INFEASIBLE"
        st = advance(version, mode, progs, st, t)
    if any(st[0][t] < len(progs[t]) for t in range(len(progs))):
        return "INFEASIBLE"
    return verdict(st[6])


def count(version, mode, variant, init, rounds, senders):
    progs = programs(version, variant, rounds, senders)
    keys = ("OK", "SKIP", "UAF", "NULL_DEREF")

    @lru_cache(maxsize=None)
    def walk(st):
        moves = [t for t in range(len(progs)) if runnable(progs, st, t)]
        if not moves:
            assert all(st[0][t] >= len(progs[t]) for t in range(len(progs))), "deadlock"
            v = verdict(st[6])
            return tuple(1 if k == v else 0 for k in keys)
        total = [0, 0, 0, 0]
        for t in moves:
            sub = walk(advance(version, mode, progs, st, t))
            total = [a + b for a, b in zip(total, sub)]
        return tuple(total)

    c = walk(initial(init, len(progs)))
    return (sum(c),) + c


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    for row in read_cases(os.path.join(here, "..", "fixtures", "cases.tsv")):
        cid, version, mode, variant, init, rounds, senders, schedule = row[0], *row[2:9]
        print("case\t%s\t%s" % (cid, run_schedule(version, mode, variant, init, int(rounds),
                                                   int(senders), schedule)))
    for version in ("pre", "post"):
        for mode in ("reload", "cached"):
            for variant in ("fail_only", "alloc_fail", "alloc_ok"):
                for init in ("null", "live"):
                    for rounds in (1, 2, 3):
                        for senders in (1, 2):
                            c = count(version, mode, variant, init, rounds, senders)
                            print("sweep\t%s\t%s\t%s\t%s\t%d\t%d\t%s" % (
                                version, mode, variant, init, rounds, senders, "\t".join(map(str, c))))


if __name__ == "__main__":
    main()
