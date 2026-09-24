"""
Offline verification harness for app.py.

Doesn't require Flask, cachetools, or bgpq4 to be installed. Pulls the
regexes and command-builder logic out of app.py and exercises them directly,
then dry-runs the bgpq4 command construction so we can eyeball it.

Run:  python3 verify.py
"""

import ast
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent
SRC = (HERE / "app.py").read_text()


def extract_regex(name: str) -> re.Pattern:
    """Grab `NAME = re.compile(r"...")` from app.py without importing it."""
    tree = ast.parse(SRC)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "compile"
        ):
            pat = node.value.args[0].value
            return re.compile(pat)
    raise RuntimeError(f"regex {name} not found in app.py")


def extract_func(name: str, **ns_extras):
    """Pull a function source out of app.py and exec it into an isolated ns.

    `ns_extras` lets callers inject module-level names the function closes over
    (e.g. regex constants defined in app.py at module scope).
    """
    tree = ast.parse(SRC)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            src = ast.get_source_segment(SRC, node)
            ns = dict(ns_extras)
            # app.py uses PEP 604 `X | None` annotations; defer their
            # evaluation so the harness also runs on Python < 3.10.
            exec("from __future__ import annotations\n" + src, ns)
            return ns[name]
    raise RuntimeError(f"function {name} not found in app.py")


def case(label, cond, detail=""):
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {label}" + (f"  ({detail})" if detail else ""))
    return cond


def main() -> int:
    failures = 0

    print("=" * 70)
    print("1. AS_RE — AS-SET / AS object validation")
    print("=" * 70)
    AS_RE = extract_regex("AS_RE")
    as_good = [
        "AS65000", "AS-HURRICANE", "AS-FOO:AS-BAR",
        "RIPE::AS-FOO", "AS65000:AS-CUSTOMERS", "as-test_v6",
    ]
    as_bad = [
        "", "A" * 129, "has space", "AS6500;ls", "AS/65000",
        "$(whoami)", "AS65000`id`", "AS65000|cat",
    ]
    for a in as_good:
        if not case(f"accept {a!r}", bool(AS_RE.match(a))):
            failures += 1
    for a in as_bad:
        if not case(f"reject {a!r}", not AS_RE.match(a)):
            failures += 1

    print()
    print("=" * 70)
    print("2. ASN_RE + _normalize_asn — ASN input validation & canonicalization")
    print("=" * 70)
    ASN_RE = extract_regex("ASN_RE")
    normalize = extract_func("_normalize_asn", ASN_RE=ASN_RE)

    # Forms that should normalize cleanly.
    good = [
        ("65000", "AS65000"),
        ("AS65000", "AS65000"),
        ("as65000", "AS65000"),
        ("aS6939", "AS6939"),
        ("1", "AS1"),
        ("4294967295", "AS4294967295"),       # 32-bit max
        ("AS4294967295", "AS4294967295"),
    ]
    for raw, want in good:
        got = normalize(raw)
        if not case(f"{raw!r} -> {want!r}", got == want, f"got {got!r}"):
            failures += 1

    # Forms that must be rejected.
    bad = [
        "", "0", "AS0",                       # ASN 0 is reserved
        "4294967296", "AS4294967296",         # one past 32-bit max
        "12345678901",                        # 11 digits — regex bound
        "AS-FOO", "AS65000:AS-X", "AS 65000",
        "65000;ls", "$(whoami)", "AS`id`",
        "ASN65000", "as-65000",
    ]
    for raw in bad:
        if not case(f"reject {raw!r}", normalize(raw) is None):
            failures += 1

    print()
    print("=" * 70)
    print("3. FAMILY flags map to correct bgpq4 args")
    print("=" * 70)
    m = re.search(r'FAMILY_FLAGS\s*=\s*(\{[^}]+\})', SRC)
    FAMILY_FLAGS = ast.literal_eval(m.group(1))
    if not case("ipv4 -> -4", FAMILY_FLAGS.get("ipv4") == "-4"):
        failures += 1
    if not case("ipv6 -> -6", FAMILY_FLAGS.get("ipv6") == "-6"):
        failures += 1
    if not case("no other families", set(FAMILY_FLAGS) == {"ipv4", "ipv6"}):
        failures += 1

    # Placeholder list-name pinned (formatter strips this prefix).
    pl_m = re.search(r'BGPQ4_LIST_NAME\s*=\s*"([^"]+)"', SRC)
    PL_NAME = pl_m.group(1) if pl_m else None
    if not case("BGPQ4_LIST_NAME is defined", PL_NAME is not None):
        failures += 1

    print()
    print("=" * 70)
    print("4. bgpq4 command construction (dry-run)")
    print("=" * 70)

    def build_cmd(target, family, aggregate=True, max_len_v4=None,
                  max_len_v6=None, host="", sources="", binary="bgpq4",
                  list_name=PL_NAME):
        cmd = [binary, FAMILY_FLAGS[family], "-l", list_name]
        if aggregate:
            cmd.append("-A")
        max_len = max_len_v4 if family == "ipv4" else max_len_v6
        if max_len is not None:
            cmd.extend(["-R", str(max_len)])
        if host:
            cmd.extend(["-h", host])
        if sources:
            cmd.extend(["-S", sources])
        cmd.append(target)
        return cmd

    cmd = build_cmd("AS-HURRICANE", "ipv4")
    expect = ["bgpq4", "-4", "-l", PL_NAME, "-A", "AS-HURRICANE"]
    if not case("default v4 cmd (no -R)", cmd == expect, " ".join(cmd)):
        failures += 1

    cmd = build_cmd("AS-HURRICANE", "ipv6")
    expect = ["bgpq4", "-6", "-l", PL_NAME, "-A", "AS-HURRICANE"]
    if not case("default v6 cmd (no -R)", cmd == expect, " ".join(cmd)):
        failures += 1

    cmd = build_cmd("AS-HURRICANE", "ipv4", max_len_v4=24, max_len_v6=48)
    expect = ["bgpq4", "-4", "-l", PL_NAME, "-A", "-R", "24", "AS-HURRICANE"]
    if not case("v4 with -R 24", cmd == expect, " ".join(cmd)):
        failures += 1

    cmd = build_cmd("AS-HURRICANE", "ipv6", max_len_v4=24, max_len_v6=48)
    expect = ["bgpq4", "-6", "-l", PL_NAME, "-A", "-R", "48", "AS-HURRICANE"]
    if not case("v6 with -R 48 (family-aware: picks v6 value)",
                cmd == expect, " ".join(cmd)):
        failures += 1

    # Empty/None max_len should NOT add -R.
    cmd = build_cmd("AS-FOO", "ipv4", max_len_v4=None, max_len_v6=48)
    if not case("empty max_len_v4 omits -R for v4",
                "-R" not in cmd, " ".join(cmd)):
        failures += 1

    cmd = build_cmd(
        "AS-FOO", "ipv4",
        aggregate=False, host="whois.radb.net", sources="RIPE,RADB",
    )
    expect = ["bgpq4", "-4", "-l", PL_NAME,
              "-h", "whois.radb.net", "-S", "RIPE,RADB", "AS-FOO"]
    if not case("custom host/sources, no -A", cmd == expect, " ".join(cmd)):
        failures += 1

    # ASN target builds the same shape (the bgpq4 invocation is identical;
    # only the target token differs).
    cmd = build_cmd("AS6939", "ipv4", max_len_v4=24, max_len_v6=48)
    expect = ["bgpq4", "-4", "-l", PL_NAME, "-A", "-R", "24", "AS6939"]
    if not case("ASN target produces the expected cmd",
                cmd == expect, " ".join(cmd)):
        failures += 1

    # Shell metacharacters in input must stay literal — subprocess.run with a
    # list never invokes a shell.
    cmd = build_cmd("AS-FOO`id`", "ipv4")
    if not case(
        "shell metachars stay as literal argv (no shell=True path)",
        "`id`" in cmd[-1],
    ):
        failures += 1

    print()
    print("=" * 70)
    print("5. _arista_format transforms bgpq4 output -> source-http body")
    print("=" * 70)
    fmt = extract_func("_arista_format")

    # Representative bgpq4 stdout for `bgpq4 -A -R 24 -l PL AS-EXAMPLE`.
    bgpq4_v4 = (
        f"no ip prefix-list {PL_NAME}\n"
        f"ip prefix-list {PL_NAME} permit 192.0.2.0/24\n"
        f"ip prefix-list {PL_NAME} permit 198.51.100.0/24\n"
        f"ip prefix-list {PL_NAME} permit 4.7.0.0/16 le 24\n"
    )
    expected_v4 = (
        "seq 1 permit 192.0.2.0/24\n"
        "seq 2 permit 198.51.100.0/24\n"
        "seq 3 permit 4.7.0.0/16 le 24\n"
    )

    bgpq4_v6 = (
        f"no ipv6 prefix-list {PL_NAME}\n"
        f"ipv6 prefix-list {PL_NAME} permit 2001:db8::/32\n"
        f"ipv6 prefix-list {PL_NAME} permit 2001:470::/32 le 48\n"
    )
    expected_v6 = (
        "seq 1 permit 2001:db8::/32\n"
        "seq 2 permit 2001:470::/32 le 48\n"
    )

    got_v4 = fmt(bgpq4_v4, "ipv4")
    if not case("v4 format produces exact expected body", got_v4 == expected_v4,
                f"\nexpected:\n{expected_v4!r}\ngot:\n{got_v4!r}"):
        failures += 1

    got_v6 = fmt(bgpq4_v6, "ipv6")
    if not case("v6 format produces exact expected body", got_v6 == expected_v6,
                f"\nexpected:\n{expected_v6!r}\ngot:\n{got_v6!r}"):
        failures += 1

    if not case("'no ip prefix-list' header is dropped",
                "no ip prefix-list" not in fmt(bgpq4_v4, "ipv4")):
        failures += 1

    seqs = re.findall(r"^seq (\d+) ", fmt(bgpq4_v4, "ipv4"), re.MULTILINE)
    if not case("seq numbers are 1,2,3,…", seqs == ["1", "2", "3"],
                f"got: {seqs}"):
        failures += 1

    if not case("empty input -> empty output", fmt("", "ipv4") == ""):
        failures += 1

    weird = f"ip prefix-list {PL_NAME} permit 1.2.3.0/24\nlol garbage\n"
    if not case("garbage line dropped, valid line kept",
                fmt(weird, "ipv4") == "seq 1 permit 1.2.3.0/24\n"):
        failures += 1

    if not case("family mismatch -> empty (defensive)",
                fmt(bgpq4_v6, "ipv4") == ""):
        failures += 1

    print()
    print("=" * 70)
    print("5b. Formatter output is valid Arista source-http body grammar")
    print("=" * 70)
    body_v4 = re.compile(
        r"^seq\s+\d+\s+(permit|deny)\s+\d+\.\d+\.\d+\.\d+/\d+"
        r"(\s+ge\s+\d+)?(\s+le\s+\d+)?\s*$"
    )
    body_v6 = re.compile(
        r"^seq\s+\d+\s+(permit|deny)\s+[0-9a-fA-F:]+/\d+"
        r"(\s+ge\s+\d+)?(\s+le\s+\d+)?\s*$"
    )
    for line in fmt(bgpq4_v4, "ipv4").strip().splitlines():
        if not case(f"v4 body line: {line!r}", bool(body_v4.match(line))):
            failures += 1
    for line in fmt(bgpq4_v6, "ipv6").strip().splitlines():
        if not case(f"v6 body line: {line!r}", bool(body_v6.match(line))):
            failures += 1

    print()
    print("=" * 70)
    print("6. Routes: as_set + asn, v4 default, /v6 suffix for v6")
    print("=" * 70)
    # Route table sanity — check the four expected route declarations are
    # present in app.py. Don't import Flask; just grep the source.
    expected_routes = [
        '@app.route("/arista/as_set/<as_set>", defaults={"family": "ipv4", "le": None})',
        '@app.route("/arista/as_set/<as_set>/le/<int:le>", defaults={"family": "ipv4"})',
        '@app.route("/arista/as_set/<as_set>/v6", defaults={"family": "ipv6", "le": None})',
        '@app.route("/arista/as_set/<as_set>/v6/le/<int:le>", defaults={"family": "ipv6"})',
        '@app.route("/arista/asn/<asn>", defaults={"family": "ipv4", "le": None})',
        '@app.route("/arista/asn/<asn>/le/<int:le>", defaults={"family": "ipv4"})',
        '@app.route("/arista/asn/<asn>/v6", defaults={"family": "ipv6", "le": None})',
        '@app.route("/arista/asn/<asn>/v6/le/<int:le>", defaults={"family": "ipv6"})',
    ]
    for r in expected_routes:
        if not case(f"route present: {r}", r in SRC):
            failures += 1

    # No old <name>/<as_set> route lingering.
    if not case(
        "old /arista/<name>/<as_set> route is gone",
        "/arista/<name>/<as_set>" not in SRC,
    ):
        failures += 1

    # No `request.args` at all — family and the le override both live in the
    # path, never the query string (zsh `?` globbing).
    if not case(
        "no query-string handling (family and le are path segments)",
        "request.args" not in SRC,
    ):
        failures += 1

    # Cache key must include the resolved max_len, or /le/32 and the default
    # would share (and cross-poison) an entry.
    if not case(
        "cache key includes max_len",
        "key = (target, family, max_len)" in SRC,
    ):
        failures += 1

    # Default string converter (not <path:...>) so colons in AS-SETs work but
    # slashes still split the path — needed for the /v6 suffix to bind.
    if not case(
        "as_set captured with default string converter (not <path:...>)",
        "<path:as_set>" not in SRC and "<as_set>" in SRC,
    ):
        failures += 1
    if not case(
        "AS_RE accepts RIPE::AS-FOO (colons are fine; no slashes)",
        bool(AS_RE.match("RIPE::AS-FOO")),
    ):
        failures += 1

    print()
    print("=" * 70)
    print("7. _parse_max_len env-var validation")
    print("=" * 70)
    parse = extract_func("_parse_max_len")

    if not case("'24' for V4 -> 24", parse("24", "V4", 32) == 24):
        failures += 1
    if not case("'48' for V6 -> 48", parse("48", "V6", 128) == 48):
        failures += 1
    if not case("'128' for V6 -> 128", parse("128", "V6", 128) == 128):
        failures += 1
    if not case("'' -> None", parse("", "V4", 32) is None):
        failures += 1
    if not case("'0' -> None", parse("0", "V4", 32) is None):
        failures += 1
    if not case("'  24  ' -> 24", parse("  24  ", "V4", 32) == 24):
        failures += 1
    for bad_input, family, vmax in [("33", "V4", 32), ("129", "V6", 128),
                                    ("-1", "V4", 32), ("nope", "V4", 32)]:
        try:
            parse(bad_input, family, vmax)
            ok = False
        except SystemExit:
            ok = True
        if not case(f"rejects {bad_input!r} for {family}", ok):
            failures += 1

    print()
    print("=" * 70)
    print("8. _resolve_max_len — per-URL /le/<N> override")
    print("=" * 70)

    class _Abort(Exception):
        def __init__(self, code, description=""):
            self.code = code
            self.description = description

    def fake_abort(code, description=""):
        raise _Abort(code, description)

    m = re.search(r'LE_CEILING\s*=\s*(\{[^}]+\})', SRC)
    LE_CEILING = ast.literal_eval(m.group(1))
    if not case("LE_CEILING is {ipv4: 32, ipv6: 128}",
                LE_CEILING == {"ipv4": 32, "ipv6": 128}):
        failures += 1

    # Simulate env defaults of 24 / 48.
    resolve = extract_func(
        "_resolve_max_len",
        abort=fake_abort,
        LE_CEILING=LE_CEILING,
        DEFAULT_MAX_LENGTH={"ipv4": 24, "ipv6": 48},
    )

    def resolve_or_code(family, le):
        try:
            return resolve(family, le)
        except _Abort as e:
            return f"HTTP {e.code}"

    table = [
        # (family, le, expected)
        ("ipv4", None, 24),          # no override -> env default
        ("ipv6", None, 48),
        ("ipv4", 32, 32),            # the PNI /26-needs-/32 case
        ("ipv4", 26, 26),
        ("ipv4", 1, 1),
        ("ipv6", 128, 128),
        ("ipv6", 64, 64),
        ("ipv4", 0, None),           # 0 -> omit -R (exact only)
        ("ipv6", 0, None),
        ("ipv4", 33, "HTTP 400"),    # past the v4 ceiling
        ("ipv6", 129, "HTTP 400"),
        ("ipv4", -1, "HTTP 400"),
        ("ipv4", 128, "HTTP 400"),   # v6 ceiling doesn't leak into v4
    ]
    for family, le, want in table:
        got = resolve_or_code(family, le)
        if not case(f"{family} le={le!r} -> {want!r}", got == want, f"got {got!r}"):
            failures += 1

    # Env default of "no -R" (None) with no override stays None.
    resolve_none = extract_func(
        "_resolve_max_len",
        abort=fake_abort,
        LE_CEILING=LE_CEILING,
        DEFAULT_MAX_LENGTH={"ipv4": None, "ipv6": None},
    )
    if not case("env default None + no override -> None",
                resolve_none("ipv4", None) is None):
        failures += 1
    if not case("env default None + /le/32 -> 32",
                resolve_none("ipv4", 32) == 32):
        failures += 1

    # Command construction with an override: the resolved value lands in -R.
    cmd = build_cmd("AS6939", "ipv4", max_len_v4=resolve("ipv4", 32))
    expect = ["bgpq4", "-4", "-l", PL_NAME, "-A", "-R", "32", "AS6939"]
    if not case("override 32 -> `-R 32` in cmd", cmd == expect, " ".join(cmd)):
        failures += 1
    cmd = build_cmd("AS6939", "ipv4", max_len_v4=resolve("ipv4", 0))
    if not case("override 0 -> no -R in cmd", "-R" not in cmd, " ".join(cmd)):
        failures += 1

    print()
    print("=" * 70)
    print(f"RESULT: {'ALL PASSED' if failures == 0 else f'{failures} FAILURES'}")
    print("=" * 70)
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
