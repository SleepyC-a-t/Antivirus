# SentinelGuard 4.1 — optional browser protection

The main SentinelGuard 4.1 GUI is a native Windows desktop application.
These separate, optional extensions block exact known phishing URLs using
browser request rules (not all suspicious websites, and not all downloads).

- **Chrome/Edge**: load the `browser-extension` directory as an unpacked extension
  from the browser extensions page with Developer Mode enabled.
- **Firefox**: use `about:debugging#/runtime/this-firefox` → Load Temporary Add-on
  and select `browser-extension-firefox/manifest.json`. Firefox temporary
  unsigned extensions disappear after restart; permanent signing is needed.

In SentinelGuard 4.1 choose **Copy read-only browser pairing link**. Paste the
link in your extension popup and choose **Pair / update**. Toggle ON in
SentinelGuard to activate local monitoring; the extension checks this status
about every 30 seconds. Check the OpenPhish Community Feed box if you accept
its personal/noncommercial terms and that the feed service will see your IP.

No browsing history, passwords, cookies or downloaded files are uploaded.
The extension connects only to the loopback app and the optional feed.
It cannot change scan settings or access quarantine.

Always leave your browser built-in phishing defense and installed real-time
antivirus on.
