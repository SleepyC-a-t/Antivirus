# SentinelGuard 4.2 — release signing and provenance

## Current state
This **draft development build is UNSIGNED**. No Authenticode certificate has been provisioned or verified. GitHub Actions builds are CI-tested, **not interactive Windows field-tested**. A ZIP SHA-256 file detects accidental or malicious replacement *only if the digest is checked against a trusted channel*; it is not a signature.

## Release procedure (future, not performed)
1. Obtain a code-signing certificate from an appropriate trusted CA, safeguard its private key in a dedicated release secret store / hardware-backed signing service, and limit access to an approved release workflow.
2. Require review, protected branches, pinned dependencies and successful Windows/Linux CI. Check all built artifact hashes and retain complete build provenance.
3. With a validated certificate and Windows SDK `signtool`, sign the final EXE. Illustrative command only (requires configured certificate selection and an approved timestamp provider):

   ```powershell
   signtool sign /fd SHA256 /tr https://YOUR-APPROVED-TIMESTAMP-SERVER /td SHA256 /sha1 CERTIFICATE_THUMBPRINT SentinelGuard-4.2.exe
   signtool verify /pa /v SentinelGuard-4.2.exe
   ```

4. After signing and rechecking, assemble the ZIP, calculate SHA-256 of both EXE and ZIP and publish hashes beside the release in a trusted location. Signing alters the EXE hash, so calculate it **after** signing.
5. Publish GitHub artifact attestations for the finalized release where supported (`actions/attest-build-provenance`, with `id-token: write` and `attestations: write` permissions); verify subjects and commit SHA before release. This is not evidence of malware-detection quality or a substitution for Authenticode.
6. Exercise real Windows install, SmartScreen/MotW, browser blocking and monitor behaviour, documenting actual screenshots/logs and test environment before marking a build Windows field-tested.

Do not distribute an unsigned development build as a replacement for Microsoft Defender / Bitdefender. Do not put certificates or signing secrets in the repository. No signing certificate or attestation was used for this draft.
