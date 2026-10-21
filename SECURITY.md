# Security and public publication policy

These repositories contain public portfolio material. They are not storage for
EKA V6 SYSTEMS LLC's engineering archive or proprietary design sources.

## Before publishing

- Keep private engineering work outside the public repository directory.
- Review every staged filename and the complete diff; get owner approval.
- Run `python3 .github/scripts/upload_guard.py --staged` before committing.
- Run `python3 .github/scripts/upload_guard.py` before pushing to inspect all
  indexed files. Run a full-history redacted secret scanner as a separate check.
- Do not publish API keys, passwords, tokens, private keys, private archives,
  proprietary Verilog/SystemVerilog/VHDL, bitstreams, private datasets, identity
  documents, or raw engineering logs.
- Verify research figures against their build-specific evidence. Clearly label
  admitted inputs, simulated clock cycles, tool timing estimates, and physical
  measurements as separate evidence.

The guard blocks files outside a small public-file allowlist, oversized/binary
content, common secret signatures, and HDL signatures. It does not print matched
values. New public files require explicit allowlist review. No secret detector
recognizes every credential, personal detail, encoded archive, or proprietary idea.
Every allowlisted file is scanned, including the guard source. Changes to the
guard, workflows, hooks, and this policy need trusted owner review. A contributor with
permission to change those controls can weaken them.

## Prevention limitations

A `.gitignore` does not protect tracked files, Git history, forced additions, or
web uploads. Local hooks are opt-in, can be bypassed, and do not run in GitHub's
web editor. CI runs after content has reached GitHub; a failing check cannot
undo public disclosure. Therefore never upload a private archive to test CI.
Use repository/user secret push protection where available, branch protection,
and a deliberate local review-and-push workflow. Push protection does not enforce
proprietary-RTL or personal-data policy.

The proposed hook is not automatically installed. An owner may approve enabling
it with `git config --local core.hooksPath .githooks` after inspecting it. This
changes only that local checkout's configuration and requires owner approval.

## Reporting a problem

Do not post secrets, personal documents, or engineering files in public issues,
pull requests, or comments. Use the published business contact only to request a
private reporting channel; do not send sensitive details in the first message.
Private vulnerability reporting must be verified as enabled before relying on it.

If a real credential is exposed, notify the owner and revoke or rotate it first.
Removing a file, changing visibility, or rewriting history cannot invalidate
copied credentials. History rewriting, deletions, repository/permission changes,
and publication of any additional evidence require explicit owner approval.

No patent license, proprietary-source release, production-readiness claim, or
security guarantee is granted by this public portfolio.
