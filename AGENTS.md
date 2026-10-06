## Bug fixes

- Every bug fix in this fork must include a deterministic regression test that exercises its root cause.
- Reproduce the failing condition with controlled inputs, queue state, or explicit synchronization. Do not depend on sleeps, load, or probabilistic scheduling to trigger the bug; timeouts may bound a test that would otherwise hang.
- Verify that the test fails when the relevant fix is reverted, and passes with the fix applied. Keep unrelated fork changes intact during this check.

## Git author identity

- Use the user's existing global Git `user.name` and `user.email` for all new commits.
- Never override author identity in repository-local or worktree configuration, or with per-command author or committer overrides.
- Change global author configuration only when the user explicitly requests it.
