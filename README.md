# Vault Privacy Guard

**One folder is private. Every agent, every tool, every script is kept out of it, by one policy file.**

A vault that agents work in holds things no AI should ever see. The usual answer is a rule in the
prompt ("don't read the journal"). That rule is a request, not a guarantee. This repo turns it into
a guarantee: a pre-tool hook that blocks any tool call naming the private folder before it runs,
for every agent runtime you use.

Part of [Digital Brain](https://github.com/OferBlum/personal-digital-brain-with-ai).

## The idea

- **Privacy is a folder, not a flag.** Every private file lives in one folder. A `private: true`
  property can't be enforced: a Bash or Grep call names no single file, so a hook would have to
  open the file to read the flag, and opening the file is the leak. A folder name can be checked
  in any payload without opening anything.
- **One policy, a thin wrapper per runtime.** When each agent runtime carried its own copy of the
  rules, the copies drifted. A vault is only as private as its weakest agent. So the policy
  lives in one file, and each runtime's hook only adapts it to that runtime's contract.
- **Never mapped, not just never read.** Scripts don't `rglob` the vault and filter afterwards. They
  walk an explicit list of allowed folders, so the private folder's filenames are never listed.
- **Fail closed.** Malformed input, a missing policy file, or a symlink anywhere on a path all
  block.

## How it works

| Layer | How the folder is kept out |
|-------|----------------------------|
| Agent tool calls | The pre-tool hook blocks any call whose payload contains the folder name, for every tool |
| Search tools | A vault-root `.ignore` keeps ripgrep-based Grep/Glob out of it |
| Scripts | `iter_vault_files()` walks only allowed roots and prunes the folder before descending |
| File reads | `read_public_text()` opens every path component with `O_NOFOLLOW`, so a symlink can't redirect a read |

The hook inspects every string in the tool payload at any depth, not a fixed list of keys, so
payload shapes like multi-edit lists can't slip past it. Block reasons never repeat the blocked
name.

**Known limit:** a recursive shell command started at the vault root (`grep -r .`) would descend
into the folder without naming it. Agents start scans at a content folder; `.ignore` covers
Claude Code's own search tools.

## Files

```text
.claude/settings.json              # registers the hook for Bash, Glob, Grep, Read, Edit, Write
.claude/privacy-guard.py           # Claude Code adapter: stderr + exit 2; fails closed if the policy is missing
.ignore                            # ripgrep skips the private folder
0 - System/scripts/
  privacy_guard.py                 # THE policy: PRIVATE_DIR, allowed roots, hook logic, safe walker and reader
  test_privacy_guard.py            # regression tests against a throwaway fixture vault
```

The layout mirrors the vault it drops into
([agentic-vault-skeleton](https://github.com/OferBlum/agentic-vault-skeleton)). The private
folder's name and the allowed roots are constants at the top of `privacy_guard.py`.

## Quickstart

1. Copy these files into your vault root, then set `PRIVATE_DIR` and the allowed roots in
   `privacy_guard.py` to match your folders.
2. Prove the policy works: `python3 "0 - System/scripts/privacy_guard.py" --selftest`, then
   `python3 -m unittest discover -s "0 - System/scripts" -p "test_*.py"`.
3. Run `claude` at the vault root. Any tool call naming the private folder is refused.

Requirements: Python 3.8+, standard library only.

**Other runtimes:** `privacy_guard.py --mode hermes` speaks Hermes' hook contract (a JSON
decision, always exit 0, still fail-closed). The Hermes wrapper lives in
[hermes-agent-layer](https://github.com/OferBlum/hermes-agent-layer). For any other runtime,
write a five-line adapter that pipes the tool payload to this file.

## License

MIT, see [LICENSE](LICENSE).
