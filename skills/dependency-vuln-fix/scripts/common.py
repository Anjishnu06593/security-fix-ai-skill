#!/usr/bin/env python3
"""Shared helpers for the dependency-vuln-fix scripts (standard library only).

- cached HTTP GET/POST for JSON and text (offline-tolerant)
- semver and Maven version comparison, npm range satisfaction
- CVSS v3.x base-score calculator
"""
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request

USER_AGENT = "dependency-vuln-fix-skill/1.0"
CACHE_DIR = os.environ.get(
    "SECFIX_CACHE_DIR", os.path.join(tempfile.gettempdir(), "secfix-cache")
)


def eprint(*args):
    print(*args, file=sys.stderr)


# --------------------------------------------------------------------------- HTTP

def _cache_path(key):
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, hashlib.sha1(key.encode()).hexdigest() + ".json")


def http(url, body=None, ttl=3600, timeout=25, headers=None, as_text=False):
    """GET (or POST when body is a dict) with an on-disk cache.

    Returns parsed JSON (or text when as_text). Raises RuntimeError on failure;
    a stale cache entry is used as a fallback when the network is unavailable.
    """
    key = url + (json.dumps(body, sort_keys=True) if body is not None else "")
    path = _cache_path(key)
    stale = None
    if os.path.exists(path):
        age = time.time() - os.path.getmtime(path)
        with open(path, "r", encoding="utf-8") as fh:
            stale = fh.read()
        if age < ttl:
            return stale if as_text else json.loads(stale)
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        if stale is not None:
            eprint(f"[warn] network failed for {url} ({exc}); using stale cache")
            return stale if as_text else json.loads(stale)
        raise RuntimeError(f"request failed for {url}: {exc}") from exc
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return text if as_text else json.loads(text)


# --------------------------------------------------------------------------- semver

_SEMVER = re.compile(
    r"^[vV=]?\s*(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?$"
)


def parse_semver(text):
    """Return (major, minor, patch, prerelease_tuple) or None."""
    m = _SEMVER.match(str(text).strip())
    if not m:
        return None
    nums = []
    for g in m.groups()[:3]:
        nums.append(0 if g is None or g in "xX*" else int(g))
    pre = tuple(m.group(4).split(".")) if m.group(4) else ()
    return (nums[0], nums[1], nums[2], pre)


def _pre_key(pre):
    # no prerelease sorts after any prerelease
    if not pre:
        return (1,)
    return (0,) + tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre)


def semver_key(text):
    p = parse_semver(text)
    if p is None:
        return None
    return (p[0], p[1], p[2], _pre_key(p[3]))


def semver_cmp(a, b):
    ka, kb = semver_key(a), semver_key(b)
    if ka is None or kb is None:
        return (str(a) > str(b)) - (str(a) < str(b))
    return (ka > kb) - (ka < kb)


def is_prerelease(version):
    p = parse_semver(version)
    return bool(p and p[3])


def bump_kind(current, candidate):
    c, n = parse_semver(current), parse_semver(candidate)
    if not c or not n:
        return "unknown"
    if n[0] != c[0]:
        return "major"
    if n[1] != c[1]:
        return "minor"
    return "patch"


def _comparator(op, v):
    return lambda ver: {
        "=": semver_cmp(ver, v) == 0,
        ">": semver_cmp(ver, v) > 0,
        ">=": semver_cmp(ver, v) >= 0,
        "<": semver_cmp(ver, v) < 0,
        "<=": semver_cmp(ver, v) <= 0,
    }[op]


def _expand_partial(token):
    """Expand ^, ~, x-ranges and bare versions into comparator tuples."""
    token = token.strip()
    if token in ("", "*", "x", "X", "latest"):
        return [(">=", "0.0.0")]
    m = re.match(r"^(\^|~>?|>=|<=|>|<|=)?\s*v?(.+)$", token)
    op, rest = m.group(1) or "", m.group(2)
    parts = rest.split("-", 1)[0].split(".")
    wild = len(parts) < 3 or any(p in ("x", "X", "*") for p in parts)
    p = parse_semver(rest)
    if p is None:
        return [("=", rest)]
    maj, mino, pat = p[0], p[1], p[2]
    base = f"{maj}.{mino}.{pat}" + (("-" + ".".join(p[3])) if p[3] else "")
    if op in ("^",):
        if maj > 0 or len(parts) == 1:
            return [(">=", base), ("<", f"{maj + 1}.0.0")]
        if mino > 0 or len(parts) == 2:
            return [(">=", base), ("<", f"0.{mino + 1}.0")]
        return [(">=", base), ("<", f"0.0.{pat + 1}")]
    if op in ("~", "~>"):
        if len(parts) == 1:
            return [(">=", base), ("<", f"{maj + 1}.0.0")]
        return [(">=", base), ("<", f"{maj}.{mino + 1}.0")]
    if op in ("", "="):
        if wild:
            if len(parts) == 1 or parts[1] in ("x", "X", "*"):
                return [(">=", f"{maj}.0.0"), ("<", f"{maj + 1}.0.0")]
            return [(">=", f"{maj}.{mino}.0"), ("<", f"{maj}.{mino + 1}.0")]
        return [("=", base)]
    return [(op, base)]


def satisfies(version, rng):
    """Best-effort npm range check (caret, tilde, x-ranges, hyphen, ||, AND)."""
    rng = (rng or "").strip()
    if not rng or rng.startswith(("git", "http", "file:", "link:", "npm:", "workspace:")):
        return None  # cannot decide
    for alt in rng.split("||"):
        alt = alt.strip()
        hy = re.match(r"^(\S+)\s+-\s+(\S+)$", alt)
        if hy:
            comps = [(">=", hy.group(1)), ("<=", hy.group(2))]
        else:
            comps = []
            tokens = re.findall(r"(?:\^|~>?|>=|<=|>|<|=)?\s*[vV]?[0-9xX*][^\s]*", alt) or [alt]
            for t in tokens:
                comps.extend(_expand_partial(t))
        if all(_comparator(op, v)(version) for op, v in comps):
            return True
    return False


# --------------------------------------------------------------------------- Maven versions

_MVN_QUALIFIERS = {
    "alpha": 1, "a": 1, "beta": 2, "b": 2, "milestone": 3, "m": 3, "rc": 4, "cr": 4,
    "snapshot": 5, "": 6, "ga": 6, "final": 6, "release": 6, "sp": 7,
}


def maven_tokens(version):
    items = []
    for tok in re.findall(r"\d+|[A-Za-z]+", str(version)):
        if tok.isdigit():
            items.append((1, int(tok), ""))
        else:
            items.append((0, _MVN_QUALIFIERS.get(tok.lower(), 8), tok.lower()))
    return items


def maven_cmp(a, b):
    """Compare Maven versions; the shorter side is padded with 0 (numeric) or 'release' (qualifier)."""
    ka, kb = maven_tokens(a), maven_tokens(b)
    for i in range(max(len(ka), len(kb))):
        x = ka[i] if i < len(ka) else None
        y = kb[i] if i < len(kb) else None
        if x is None:
            x = (1, 0, "") if y[0] == 1 else (0, _MVN_QUALIFIERS[""], "")
        if y is None:
            y = (1, 0, "") if x[0] == 1 else (0, _MVN_QUALIFIERS[""], "")
        if x != y:
            return -1 if x < y else 1
    return 0


def maven_is_stable(version):
    toks = [t.lower() for t in re.findall(r"[A-Za-z]+", str(version))]
    return not any(t in ("alpha", "a", "beta", "b", "milestone", "m", "rc", "cr", "snapshot", "dev", "preview") for t in toks)


def ecosystem_cmp(ecosystem):
    return maven_cmp if ecosystem.lower() == "maven" else semver_cmp


# --------------------------------------------------------------------------- CVSS v3.x

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x):
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector):
    """Base score from a CVSS:3.x vector string, or None if not parsable."""
    if not vector or not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(p.split(":") for p in vector.split("/")[1:])
        changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        total = 1.08 * (impact + expl) if changed else impact + expl
        return _roundup(min(total, 10))
    except (KeyError, ValueError):
        return None


def severity_from_cvss(score):
    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


# --------------------------------------------------------------------------- io helpers

def read_input(path=None):
    if path and path != "-":
        with open(path, "r", encoding="utf-8-sig") as fh:
            return fh.read()
    return sys.stdin.read()


def dump(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False))
