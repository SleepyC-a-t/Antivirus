# Windows release signing and provenance — future release procedure

**The current SentinelGuard v4.2 release candidate is unsigned.** Building
an EXE, computing a hash, or creating a GitHub artifact does not establish a
trusted publisher identity or certificate signature.

When an organization obtains a legitimate code-signing certificate, it can
use the official Windows SDK's `signtool.exe` under an identity-protected CI
runner, then verify the result. Example commands for a controlled release:

```powershell
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a SentinelGuard-4.2.exe
signtool verify /pa /v SentinelGuard-4.2.exe
Get-FileHash .\SentinelGuard-4.2.exe -Algorithm SHA256
```

The above commands are documentation, **not performed by the v4.2 CI
workflow**. Do not store PFX private keys in the repository or print CI
secrets. Prefer short-lived identity/managed key material and protected
release environments.

CI already publishes the executable as a GitHub Actions artifact. Its
SHA-256 should be published from the same Windows runner after building.
For GitHub artifact attestation, use `actions/attest-build-provenance` only
on a trusted protected release workflow with `id-token: write` and
`attestations: write` permissions, and verify signatures on a separate
machine. This is **not** a substitute for Authenticode.

Reproducible Go module versions/checksums are retained in `go.mod` and
`go.sum`; Windows WebView2 runtime remains an OS dependency.

**Design note only (not in v4.2):** Ship rule updates as signed,
versioned packages with rollbacks. Never treat unsigned remote rules as
trusted or silently change quarantine thresholds.
