# SentinelGuard 4.1 — optional browser phishing protection

The main SentinelGuard 4.1 application has a native Windows WebView2 desktop
interface. Browser protection is an **optional companion**, separate from local
download monitoring and from the on-demand scanner.

- **Chrome/Edge:** Load the `browser-extension` directory as an unpacked
  extension from the browser extension page, with Developer Mode enabled.
- **Firefox:** In `about:debugging#/runtime/this-firefox` choose **Load
  Temporary Add-on** and select `browser-extension-firefox/manifest.json`.
  The temporary unsigned Firefox add-on is removed when Firefox restarts.
  Permanent Firefox installation requires Mozilla signing.

## Pairing

1. In SentinelGuard 4.1, choose **Copy read-only browser pairing link**.
2. Paste into the extension popup and press **Pair / update**.
3. Enable **OpenPhish Community Feed** if you accept its personal and
   noncommercial terms and IP-address disclosure.
4. Turn live protection ON in the SentinelGuard desktop app.

Pairing is encrypted by Windows DPAPI for the signed-in user. Unless the saved
local port is in use, the browser remains paired after restarting SentinelGuard,
but **active protection is still OFF by default on each start**. The extension
proves the local app is genuine through a fresh nonce/HMAC challenge; it never
sends the pairing secret in an HTTP header. Use **Revoke browser pairing** in
SentinelGuard to invalidate all previously paired extensions.

## Rule limits and failure handling

- Uses Chrome/Firefox native `declarativeNetRequest` URL filters, avoiding
  Chrome's 1,000 regular-expression rule limit.
- Uses up to 1,200 feed entries, producing at most 2,400 dynamic blocking
  rules. Additional query parameters are matched only for entries originally
  having no query string and only on the same URL path.
- A rejected rule update preserves the previous functioning blocking list.
  The extension displays a degraded status when the feed cannot update.
- When protection is turned OFF, unpaired, or unreachable, the extension
  removes blocking rules on its next synchronization (around 30 seconds).
- The extension does not intercept page contents, HTTPS plaintext, browsing
  history, downloads, passwords or cookies. It cannot identify every phishing
  URL or block browser exploits.

The only external request is the optional feed from `openphish.com`, which
will see your IP address when requested. The application does not upload
browsing history or downloaded files.

Keep your browser's built-in phishing protection and established antivirus
enabled. These are experimental, unsigned extensions; they were tested with
offline rule simulations and manifest checks, not against live malicious sites.
