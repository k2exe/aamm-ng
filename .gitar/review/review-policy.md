# AAMM-NG Review Policy

Review the changed code and all affected security and correctness paths.

Prefer high-signal findings.

Do not report formatting or stylistic preferences as defects.

## Review priorities

Use this priority order:

1. security vulnerabilities
2. authentication or authorization failures
3. data loss or persistence failures
4. package upgrade or rollback failures
5. concurrency and race defects
6. AREDN or OpenWrt incompatibility
7. incorrect error handling
8. performance problems on constrained nodes
9. maintainability problems

Require tests for new security-sensitive or mutation behavior.

Look for tests of failure paths, not only success paths.

## Project documentation

Technical documentation must follow the project documentation guide.

@docs/documentation-style.md

Do not change commands, paths, protocol names, configuration keys, or other exact technical values only to satisfy writing-style rules.

## Known deferred findings

The following items are known technical debt.

They are not exemptions from review.

If a pull request changes one of these areas, review it normally and report regressions or new risk.

If the code is unchanged and unrelated to the pull request, do not create noise only because the known item exists.

Known deferred items include:

- TLS termination can affect the current Origin check.
- The local control server processes clients serially.
- Authentication verification does not yet have a dedicated rate limiter.
- The Go version policy can be made less patch-specific.
- `PKG_MIRROR_HASH` still requires hardening.
- Alert-message Unicode bidi and format-control policy needs more review.
- procd hardening can add `no_new_privs` and capability restrictions.
- CI action references need immutable pinning.
- Web temporary files can be moved outside the published alert directory.
- The CGI executes through the privileged AREDN web environment.
- `/www/aam` is intentionally readable without AAMM-NG authentication.
- Target-character documentation can be improved.
- Backup restore documentation can be improved.

## Do not hide regressions

Do not accept a change only because it follows an existing pattern.

If the existing pattern is unsafe and the pull request expands its use, report the increased risk.

Do not assume comments or documentation prove that an implementation is safe.

Verify the implementation.

## Scope discipline

Do not recommend unrelated refactors in a security fix.

Prefer the smallest change that fixes a confirmed problem.

Flag behavior changes that are not required by the stated purpose of the pull request.
