# Security Policy

The Linux Security Suite (LSS) is a security tool. Vulnerabilities in LSS itself are taken seriously and fixed quickly.

## Reporting a Vulnerability

**Do not file a public GitHub issue for security vulnerabilities.**

Email: `security@linuxsecuritysuite.com`

If you'd like to encrypt your report, request our PGP public key in your initial (unencrypted) email and we'll respond with it within 24 hours.

In your report, please include:

- The LSS version (`lss --version`)
- Linux distribution and version
- Steps to reproduce
- The expected vs. actual behavior
- Whether you believe this is exploitable, and how

## Response Commitments

| Stage | Target |
| --- | --- |
| Acknowledgement of report | Within 48 hours |
| Triage and severity classification | Within 5 business days |
| Patch released (Critical / High) | Within 30 days |
| Patch released (Medium / Low) | Within 90 days |
| Public disclosure | After patch is released, with reporter credit if desired |

## Scope

In scope:

- The `lss` CLI binary and Python package
- The rollback engine, journal, and backup mechanisms
- The HTML report generator
- The release pipeline and signed artifacts (cosign)
- Any LSS-controlled code that runs as root

Out of scope:

- Vulnerabilities in upstream dependencies (report those upstream first; we'll bump our pinned versions when fixes are available)
- Issues in the operator's own configuration of CIS controls
- Social engineering of LSS license holders

## Coordinated Disclosure

We follow a coordinated disclosure model. If you've found a vulnerability:

1. Report privately via the email above
2. We acknowledge, triage, and develop a fix
3. We publish a patch release with a CVE if warranted
4. We credit you in the release notes (unless you prefer to remain anonymous)
5. After 30 days from the patched release, you're free to publish your write-up

## Verifying LSS Releases

LSS releases are signed with cosign keyless signing tied to the GitHub Actions OIDC identity. Verify before installing:

```
cosign verify-blob \
  --certificate lss-X.Y.Z-py3-none-any.whl.crt \
  --signature   lss-X.Y.Z-py3-none-any.whl.sig \
  --certificate-identity-regexp "https://github.com/<owner>/lss/.github/workflows/release.yml@.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  lss-X.Y.Z-py3-none-any.whl
```

If `cosign verify-blob` exits non-zero, do not install. Report it.
