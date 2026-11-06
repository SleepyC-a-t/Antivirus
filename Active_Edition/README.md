# SentinelGuard Active v0.1 — experimental spin-off

SentinelGuard Active is a separate Windows executable built from the normal SentinelGuard scanning engine. It does **not** install a kernel driver or Windows service, modify system DNS/proxy settings, or turn off Microsoft Defender/Bitdefender.

## Starting and using the preview
1. Extract the entire build artifact, including `browser-extension`.
2. Run `SentinelGuard-Active.exe`. It opens a protected dashboard in your default browser.
3. In **Live protection**, click **Turn protection ON**. The default watched folder is your Windows user `Downloads` directory, if present. Use **Add folder…** to monitor other download destinations.
4. New or changed files are checked when stable after several seconds. Suspicious items appear under **Recent protection events**.
5. When enabled, only very high-confidence findings (heuristic score **110+**) are automatically moved to SentinelGuard's existing verified quarantine. Review-level detections are only reported. The automatic quarantine setting is user-controllable.
6. Closing the browser tab does not stop the executable. The active watcher runs only while the application process remains running. **Exit application** or turn protection OFF to disable it.
7. For website protection install the optional Firefox/Chrome/Edge extension from `browser-extension` and pair it using **Copy read-only browser pairing link**. Accept the noncommercial OpenPhish feed in the extension to enable exact-match phishing URL blocking. This pairing key cannot change local settings or quarantine anything.

## Security boundaries and limitations
- This is **near-real-time file review**, not kernel interception. It cannot prevent a downloaded file from being executed before inspection. Keep an established antivirus's real-time protection and the browser's built-in phishing protection enabled.
- The watcher only monitors configured filesystem directories (up to 8; max 30,000 enumerated entries/pass). It does not automatically discover every custom browser download location or inspect USB/network drives unless added.
- It intentionally waits for downloads to finish (`.crdownload`, `.part`, etc.), and checks after two stable observations. Existing files are baselined when protection is turned on.
- Automatic quarantine requires at least **110 heuristic score** and is not a guarantee of maliciousness. False positives remain possible; use the Vault tab to review and restore. Files can change while monitored or be locked.
- Website blocking is handled by the **separately installed** browser extension. It only blocks exact phishing URLs supplied by the opted-in OpenPhish Community Feed, not all unsafe websites or browser exploits. Extension changes may take 30–60 seconds to synchronize. No TLS interception, history collection or browsing upload.
- The extension sends a local ON/OFF status request using a limited-scope token. The optional feed request exposes your IP address to the feed provider; no visited sites or downloaded file contents are uploaded. The feed's terms permit noncommercial use only.
- Firefox unsigned temporary extensions loaded using `about:debugging` disappear on browser restart. Permanent installation requires signing through Mozilla.
- The application is not configured to start automatically when Windows boots. The user must start the executable. The default protection state on launch is OFF.
- The scanner and browser extension are unsigned development builds. Windows/Firefox may warn about unknown publishers. Do not disable your main antivirus to install or test them.

**This preview is not an antivirus replacement and has not been tested against real-world malicious software.**
