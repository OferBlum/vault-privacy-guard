#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
privacy_guard.py — the one privacy policy for the vault, shared by every agent runtime.

Each runtime's pre-tool hook is a thin wrapper that calls this file:

    Claude Code   .claude/privacy-guard.py                 --mode claude
    Hermes        ~/.hermes/agent-hooks/privacy-guard.py   --mode hermes  (see hermes-agent-layer)
    anything new  point its hook here too

When each runtime carried its own copy of the policy, the copies drifted, and protection
depended on which model happened to be running. One file fixes that.

THE POLICY IS ONE FOLDER (PRIVATE_DIR below):
  - Any tool call whose payload names the folder is blocked, for every tool.
  - Its contents are never read, and it is never even LISTED: every scan goes through
    iter_vault_files(), which walks explicit allowed roots and prunes the folder before
    descending, so no script maps its filenames.
  - Symlinks fail closed anywhere on a path.

There is NO frontmatter privacy flag. A Bash or Grep call names no single file, so a hook
can't check a flag it would have to open the file to read — and opening the file is the
leak. A folder name can be checked in any payload without opening anything.

KNOWN LIMIT — state it, don't paper over it: a recursive shell command started at the
vault root (find, grep -r) would descend into the folder without naming it. Agents must
start scans at a content folder; the vault-root `.ignore` file makes ripgrep-based tools
(Claude Code's Grep/Glob) skip it on their own.

Usage (reads the tool-call JSON payload on stdin):
    python3 privacy_guard.py --mode claude    # stderr + exit 2 to block; exit 0 to allow
    python3 privacy_guard.py --mode hermes    # {"decision":"block",...} / {}; always exit 0
    python3 privacy_guard.py --selftest       # run the built-in test matrix
"""
import sys, os, json, argparse, unicodedata, stat
from contextlib import contextmanager
from pathlib import Path

PRIVATE_DIR = "3 - private"
BLOCKED_DIRS = (PRIVATE_DIR,)

# The vault is two levels above this script (<vault>/0 - System/scripts/privacy_guard.py).
# VAULT_ROOT overrides it, which is what the test matrix uses.
VAULT = Path(os.environ.get("VAULT_ROOT") or Path(__file__).resolve().parents[2])


def nfc(s):
    return unicodedata.normalize("NFC", s or "")


# Folders a scan may walk. Everything else — the vault root, the private folder — is never listed.
CONTENT_ROOT_NAMES = ('7 - Wikipedia', '2 - Notes', '1 - Topics')
ALLOWED_ROOT_NAMES = CONTENT_ROOT_NAMES + ('0 - System',)


class PrivacyDenied(FileNotFoundError):
    """Excluded files have no externally visible name or existence."""

    def __init__(self):
        super().__init__('File unavailable')


def folder_blocked(path):
    # Inspect lexical components before any filesystem operation, including '..'.
    parts = Path(str(path)).parts
    return any(nfc(part) in {nfc(d) for d in BLOCKED_DIRS} for part in parts)


def has_symlink(path):
    p = Path(os.path.abspath(path))
    for item in reversed((p, *p.parents)):
        try:
            if item.is_symlink():
                return True
        except OSError:
            return True
    return False


@contextmanager
def _public_stream(path):
    """Open every component with NOFOLLOW, so parent-link races cannot redirect reads."""
    if folder_blocked(path):
        raise PrivacyDenied()
    p = Path(os.path.abspath(path))
    directory_fd = file_fd = None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW
        directory_fd = os.open(p.anchor, flags | os.O_DIRECTORY)
        for component in p.parts[1:-1]:
            next_fd = os.open(component, flags | os.O_DIRECTORY, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(p.name, flags | os.O_NONBLOCK, dir_fd=directory_fd)
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise PrivacyDenied()
        stream = os.fdopen(file_fd, 'rb', buffering=0)
        file_fd = None
        with stream:
            yield stream
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if directory_fd is not None:
            os.close(directory_fd)



def read_public_text(path):
    """Full text of a permitted file, read through the no-follow stream."""
    try:
        with _public_stream(path) as stream:
            return stream.read().decode('utf-8-sig').replace('\r\n', '\n')
    except (OSError, UnicodeError):
        raise PrivacyDenied() from None



def is_blocked(path):
    """The whole policy: the protected folder, or a symlink anywhere on the path."""
    return folder_blocked(path) or has_symlink(path)


def iter_vault_files(root=None, suffix=".md", prune=()):
    """Scan only explicit allowed directory roots; never list the vault root itself.

    Symlinks are filtered before paths cross this API. A root
    outside the allowlist is empty, including the protected area. No root globbing.
    """
    vault = Path(os.path.abspath(VAULT))
    requested = Path(os.path.abspath(root)) if root is not None else vault
    allowed = [vault / name for name in ALLOWED_ROOT_NAMES]
    if requested == vault:
        roots = allowed
    elif any(requested == p or p in requested.parents for p in allowed):
        roots = [requested]
    else:
        return
    skip = {nfc(d) for d in (*BLOCKED_DIRS, *prune, '.backup')}
    for scan_root in roots:
        if is_blocked(scan_root) or not scan_root.is_dir():
            continue
        for dirpath, dirs, files in os.walk(scan_root, followlinks=False):
            dirs[:] = sorted(d for d in dirs
                             if nfc(d) not in skip and not is_blocked(Path(dirpath) / d))
            for name in sorted(files):
                path = Path(dirpath) / name
                if (suffix is None or name.endswith(suffix)) and not is_blocked(path):
                    yield path


def collect_strings(obj, out):
    """Every string anywhere in the payload, at any nesting depth.

    Deliberately exhaustive rather than a fixed key list: a fixed list misses
    payload shapes like MultiEdit's per-edit dicts.
    """
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            collect_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            collect_strings(v, out)


def check(strings):
    """Block named protected paths; reasons never disclose excluded names."""
    for s in strings:
        if any(nfc(d) in nfc(s) for d in BLOCKED_DIRS):
            return 'Privacy boundary: unavailable input'
        if is_blocked(s):
            return 'Privacy boundary: unavailable input'
    return None


def evaluate(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get('tool_input'), dict):
        return 'Privacy boundary: invalid tool input'
    strings = []
    collect_strings(payload['tool_input'], strings)
    return check(strings)


def _unique_json(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('Duplicate JSON key')
        out[key] = value
    return out


def _invalid_constant(value):
    raise ValueError('Non-finite JSON value')


def _hook_reason(stdin_text):
    try:
        payload = json.loads(stdin_text, object_pairs_hook=_unique_json,
                             parse_constant=_invalid_constant)
        return evaluate(payload)
    except Exception:
        return 'Privacy boundary: invalid tool input'


# ---------- runtime adapters ----------

def run_claude(stdin_text):
    """Malformed or uninspectable input fails closed with a generic reason."""
    reason = _hook_reason(stdin_text)
    if reason:
        print(f'BLOCKED: {reason}', file=sys.stderr)
        return 2
    return 0


def run_hermes(stdin_text):
    """Hermes requires exit zero, but the decision must still fail CLOSED."""
    reason = _hook_reason(stdin_text)
    print(json.dumps({'decision': 'block', 'reason': reason} if reason else {},
                     ensure_ascii=False))
    return 0


def selftest():
    """Exercises the policy against a throwaway fixture vault. Prints a pass/fail matrix."""
    import tempfile, shutil, io, contextlib
    global VAULT, PRIVATE_DIR, BLOCKED_DIRS
    original_vault, original_dir, original_blocked = VAULT, PRIVATE_DIR, BLOCKED_DIRS
    # Exercise denial under a synthetic name, never construct the real area.
    PRIVATE_DIR = '9 - synthetic'
    BLOCKED_DIRS = (PRIVATE_DIR,)
    # Resolved: macOS temp dirs live under /var, a symlink the no-follow reader refuses.
    tmp = Path(tempfile.mkdtemp(prefix="pg-selftest-")).resolve()
    try:
        (tmp / PRIVATE_DIR / "journal").mkdir(parents=True)
        (tmp / PRIVATE_DIR / "journal" / "day.md").write_text("---\n---\nsecret\n", encoding="utf-8")
        (tmp / '2 - Notes').mkdir()
        flagged = tmp / '2 - Notes' / 'flagged.md'
        flagged.write_text("---\ntype: note\nprivate: true\n---\na flag is not privacy\n", encoding="utf-8")
        malformed = tmp / '2 - Notes' / 'malformed.md'
        malformed.write_text("---\na: 1\na: [\n---\nbroken header\n", encoding="utf-8")
        pub = tmp / '2 - Notes' / 'public.md'
        pub.write_text("---\ntype: note\n---\nfine\n", encoding="utf-8")
        cache = tmp / "_cache.md"
        cache.write_text("---\n---\ncache\n", encoding="utf-8")

        VAULT = tmp

        cases = [
            ("journal path",            {"tool_input": {"file_path": str(tmp / PRIVATE_DIR / "journal" / "day.md")}}, True),
            ("private dir in bash",     {"tool_input": {"command": f'ls "{PRIVATE_DIR}"'}},          True),
            ("private dir nested edit", {"tool_input": {"edits": [{"file_path": str(tmp / PRIVATE_DIR / "x.md")}]}}, True),
            ('frontmatter flag ignored', {'tool_input': {'file_path': str(flagged)}}, False),
            ('malformed header allowed', {'tool_input': {'file_path': str(malformed)}}, False),
            ("normal file",             {"tool_input": {"file_path": str(pub)}},                     False),
            ("_cache.md is readable",   {"tool_input": {"file_path": str(cache)}},                   False),
            ("non-existent path",       {"tool_input": {"file_path": str(tmp / "nope.md")}},         False),
        ]
        ok = True
        for name, payload, want_block in cases:
            got = evaluate(payload) is not None
            mark = "PASS" if got == want_block else "FAIL"
            ok &= got == want_block
            print(f"  [{mark}] {name:<26} block={got} (want {want_block})")

        # The walker must never list the private folder — not even its filenames.
        listed = []
        real_scandir = os.scandir
        def spy(path=".", *a, **kw):
            listed.append(str(path))
            return real_scandir(path, *a, **kw)
        os.scandir = spy
        try:
            found = list(iter_vault_files(tmp))
        finally:
            os.scandir = real_scandir
        unmapped = (not any(is_blocked(p) for p in listed)
                    and not any(is_blocked(p) for p in found) and pub in found)
        print(f"  [{'PASS' if unmapped else 'FAIL'}] walker never lists private dir")
        ok &= unmapped

        # Both runtimes fail closed; Hermes signals the decision in JSON.
        h_output = io.StringIO()
        with contextlib.redirect_stderr(io.StringIO()):
            c = run_claude('not json')
        with contextlib.redirect_stdout(h_output):
            h = run_hermes('not json')
        h_blocked = h == 0 and json.loads(h_output.getvalue()).get('decision') == 'block'
        print(f"  [{'PASS' if c == 2 else 'FAIL'}] malformed stdin -> claude fails closed")
        print(f"  [{'PASS' if h_blocked else 'FAIL'}] malformed stdin -> hermes fails closed")
        ok &= c == 2 and h_blocked
        print("\nSELFTEST:", "PASS" if ok else "FAIL")
        return 0 if ok else 1
    finally:
        VAULT, PRIVATE_DIR, BLOCKED_DIRS = original_vault, original_dir, original_blocked
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["claude", "hermes"], default="claude")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    stdin_text = sys.stdin.read()
    sys.exit(run_claude(stdin_text) if args.mode == "claude" else run_hermes(stdin_text))


if __name__ == "__main__":
    main()
