# Safe publication workflow

1. Keep private engineering files outside this public checkout.
2. Read SECURITY.md and review the exact staged file list and diff.
3. Run `python3 .github/scripts/upload_guard.py --staged` before committing;
   run it without --staged to check the entire Git index before pushing.
4. Run a redacted full-history Gitleaks scan. Never test with a real secret.
5. Obtain owner approval before committing or pushing; use a separate branch
   and pull request. Wait for the publication-guard check and human review.
6. Merge only after explicit owner approval and verified main protection.
7. Publish GitHub Pages from the approved main branch/root only. Verify the
   live site after the deployment. Branch-source Pages must not serve private
   content, and a failing post-upload CI check cannot undo public disclosure.

The proposed local hook requires separate approval to enable:
`git config --local core.hooksPath .githooks`
GitHub web uploads bypass this hook; .gitignore does not block them.
