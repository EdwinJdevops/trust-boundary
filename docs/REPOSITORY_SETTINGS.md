# Public preview and repository controls — 2026-11-01

The owner authorized public visibility. Following the local publication scans
recorded in [the verification report](VERIFICATION_CRASH.md), the repository was
made public. An unauthenticated GitHub API request confirmed its name, URL and
public visibility. The final documentation commit was also scanned with no findings.
These bounded scans do not prove absence of secrets or constitute an external audit.

GitHub accepted and returned the following settings for main:

- Pull requests are required, including for administrators.
- Both `verify (1.26.x)` and `verify (1.27.x)` must pass, bound to the GitHub Actions
  app ID 15368. Strict status checks require an up-to-date branch.
- Force pushes and branch deletion are disabled. Linear history and resolved
  review conversations are required.
- The required approval count is **zero**. This enforces a PR/check path but does
  not require independent human approval. Independent review remains a production gate.
- Secret scanning, secret push protection and private vulnerability reporting are
  enabled and were confirmed through authenticated API readback. Their enabled
  state is not a completed secret scan or proof that every secret type is detected.

The prior private-repository HTTP 403 is historical. Public visibility made branch
protection available without purchasing a plan. No billing settings were changed.
The software remains a developer preview, not approved for production authority.

## Reproduce the settings

The JSON files below record the actual accepted requests. A trusted repository
administrator can apply them with the existing authenticated GitHub CLI:

```sh
gh api --method PUT repos/EdwinJdevops/trust-boundary/branches/main/protection --input .github/main-protection.json
gh api --method PATCH repos/EdwinJdevops/trust-boundary --input .github/security-settings.json --silent
gh api --method PUT repos/EdwinJdevops/trust-boundary/private-vulnerability-reporting --silent
```

Read back the corresponding protection, repository and private-vulnerability-reporting
endpoints after changing settings. These are administrator operations, not automatic
jobs for untrusted pull requests. No workflow receives repository-administration
credentials. A maintainer capable of changing settings remains trusted.

This record confirms configured remote controls. It does not claim that direct-push
or administrator-bypass attempts were separately exercised. Subsequent source
changes must use the protected PR and passing-check path.
