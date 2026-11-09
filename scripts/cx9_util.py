"""TSV escapes shared by derive_expected.py (same rules as src/cx9_util.c,
written separately)."""
import re

_ESC = {"\\": "\\", "t": "\t", "n": "\n", "r": "\r"}


def unescape(s):
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        e = s[i + 1]
        if e in _ESC:
            out.append(_ESC[e])
            i += 2
        elif e == "x":
            v = int(s[i + 2:i + 4], 16)
            if v == 0:
                raise ValueError("NUL")
            out.append(chr(v))
            i += 4
        else:
            raise ValueError("bad escape")
    return "".join(out)


def escape(s):
    out = []
    for c in s:
        o = ord(c)
        if c == "\\":
            out.append("\\\\")
        elif c == "\t":
            out.append("\\t")
        elif c == "\n":
            out.append("\\n")
        elif c == "\r":
            out.append("\\r")
        elif o < 0x20 or o >= 0x7f:
            out.append("\\x%02x" % o)
        else:
            out.append(c)
    return "".join(out)


def read_cases(path):
    rows = []
    for line in open(path, encoding="ascii"):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        rows.append(line.split("\t"))
    return rows
