# SentinelGuard Active browser companion — experimental

This optional Manifest V3 extension supports Firefox 128+, Chrome 121+ and modern Chromium Edge. It uses `declarativeNetRequest` so known phishing URLs can be blocked by the browser **before navigation**.

## Install for testing
- **Firefox:** open `about:debugging#/runtime/this-firefox`, choose **Load Temporary Add-on**, select `manifest.json`. Firefox removes temporarily loaded unsigned extensions on restart. A permanent Firefox installation requires Mozilla add-on signing.
- **Chrome / Edge:** open the extensions page, enable developer mode, choose **Load unpacked** and select this directory. Developer mode should be used only for code you trust.
- Launch `SentinelGuard-Active.exe`, then click **Copy read-only browser pairing link** in its dashboard.
- Open the extension popup, paste the link and click **Pair / update**. Tick **Enable OpenPhish Community Feed** if you accept its personal/noncommercial-use terms and privacy implications.
- Turn **download protection ON** in SentinelGuard. The extension synchronizes approximately every 30 seconds; click **Refresh protection** for an immediate check.

## Protection boundaries
- The extension blocks *exact URL matches* from the OpenPhish Community Feed, which updates roughly twice a day. It does not classify every website, prevent all phishing attempts or inspect scripts, page contents, passwords, downloads or HTTPS bodies.
- Feed retrieval is optional. Only the feed file is fetched; its listed phishing URLs are **not** visited. The feed operator receives your IP address when the extension downloads the feed.
- Only the local ON/OFF state is fetched from SentinelGuard using a limited-scope pairing token. The token cannot quarantine files, delete files, or toggle protection.
- When the app is OFF, unreachable or unpaired, blocking rules are removed at the next sync (up to ~30–60 seconds). The extension does **not** send browsing history to any service.
- The downloadable application watches configured folders after files appear; it is not a kernel minifilter and cannot block the initial file write or execution before its next scan.
- Keep your primary browser phishing protection and Defender/Bitdefender enabled.

Community feed licensing: https://openphish.com/terms.html (noncommercial use only). Contact the feed provider for other usage.
