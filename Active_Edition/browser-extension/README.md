# SentinelGuard 4.2 — browser companion

The optional Manifest V3 companions block known exact phishing URL matches
from a user-opted-in OpenPhish feed. A local, DPAPI-persisted secret is
used only to verify a per-request HMAC challenge returned by the app.
The extension never sends the secret in an HTTP header to localhost.

- **Firefox:** temporarily load the Firefox `manifest.json` using
  `about:debugging#/runtime/this-firefox`. Permanent distribution requires
  Mozilla AMO unlisted signing or the add-on marketplace; not yet completed.
- **Chrome / Edge:** enable Developer Mode and Load Unpacked for local tests.
  Future official distribution would require Chrome Web Store publication
  or enterprise management policy; not yet completed.
- Copy the pairing link in SentinelGuard, paste into the popup, choose Pair.
  If you later revoke pairing in SentinelGuard, the extension is no longer
  authorized and must be paired again. Normal restarts retain the DPAPI key.

The extension checks ON/OFF about every 30 seconds, cannot block every
phishing site, and never performs HTTPS interception. It skips and reports
feed URLs with urlFilter special characters `*`, `^`, `|`, to avoid
accidental broad matching. The feed operator sees your IP address for
the optional feed download; no browsing history is transmitted.

Keep your main antivirus and browser protections enabled.
