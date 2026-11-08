#!/usr/bin/env python3
"""Static visual and interaction tests for SentinelGuard's embedded dashboard.

Runs only an inert HTTP server and mocked /api responses. Never runs the
SentinelGuard executable, any scanner, or a system process under inspection.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "SentinelLite_Source" / "SentinelLite" / "src" / "ui.html"
OUTPUT = ROOT / "ui-previews"
OUTPUT.mkdir(parents=True, exist_ok=True)

SAMPLE = {
    "id":"preview-only",
    "name":"inert-example.txt",
    "path":"C:\\Demo\\Samples\\inert-example.txt",
    "source":"Heuristic review",
    "score":28,
    "severity":"Review",
    "canQuarantine":False,
    "size":512,
    "reasons":["Harmless illustrative sample used for layout testing only"]
}
REPLY = {
    "status":{"active":False,"mode":"heuristic:quick","files":9,"findings":1,
              "skipped":0,"started":None,"childProcessMonitoringAvailable":False,
              "childProcessesObserved":0,"childProcessImages":[],"resources":{}},
    "findings":[SAMPLE],
    "product":{"edition":"SentinelGuard 4.2","version":"4.2","activeEdition":False},
}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/api/snapshot"):
            body=json.dumps(REPLY).encode()
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/api/vault"):
            body=b'{"items":[]}'
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/ui.html"):
            body=HTML.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404,"Static visual test only")

    def log_message(self, fmt, *args):
        pass

def assert_equal(actual, expected, message):
    if actual!=expected:
        raise AssertionError(f"{message}: expected {expected!r}, got {actual!r}")

def main():
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    worker=Thread(target=server.serve_forever,daemon=True)
    worker.start()
    url=f"http://127.0.0.1:{server.server_port}/ui.html?token=visual-test-only"
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True)
            for width,height in [(360,740),(768,900),(1024,768),(1440,900)]:
                context=browser.new_context(viewport={"width":width,"height":height},color_scheme="dark",
                                            reduced_motion="reduce")
                page=context.new_page()
                errors=[]
                page.on("pageerror",lambda ex:errors.append(str(ex)))
                page.goto(url,wait_until="domcontentloaded")
                page.wait_for_selector("#findingRows tr")
                page.wait_for_timeout(100)
                assert_equal(page.locator("#securityHoldBanner").count(),1,"Missing security hold")
                assert_equal(page.locator("[data-appearance-option]").count(),3,"Appearance choices")
                actual=page.evaluate("""() => ({
                  viewport:window.innerWidth,
                  html:document.documentElement.scrollWidth,
                  body:document.body.scrollWidth,
                  scheme:document.documentElement.dataset.scheme,
                  table:document.querySelector('#findingRows tr')?.getBoundingClientRect().width,
                  content:document.querySelector('main')?.getBoundingClientRect().width
                })""")
                if max(actual["html"],actual["body"])>width+2:
                    raise AssertionError(f"Horizontal document overflow at {width}px: {actual}")
                if actual["table"]>actual["content"]+1 and width<600:
                    raise AssertionError(f"Finding row overflows available main panel: {actual}")
                assert_equal(actual["scheme"],"dark",f"Initial dark OS theme at width {width}")
                assert_equal(page.locator('[data-appearance-option="system"]').get_attribute("aria-pressed"),
                             "true","System mode initial selection")
                if errors: raise AssertionError(f"Browser script errors at {width}px: {errors}")
                page.screenshot(path=str(OUTPUT/f"sentinelguard-{width}-dark.png"),full_page=True)
                page.get_by_role("button",name="Light").click()
                assert_equal(page.locator("html").get_attribute("data-scheme"),"light","Light override")
                context2=page.context
                page.emulate_media(color_scheme="dark")
                assert_equal(page.locator("html").get_attribute("data-scheme"),"light","Manual light persists on dark OS")
                page.reload(wait_until="domcontentloaded")
                assert_equal(page.locator("html").get_attribute("data-appearance"),"light","Theme storage survives reload")
                page.screenshot(path=str(OUTPUT/f"sentinelguard-{width}-light.png"),full_page=True)
                page.get_by_role("button",name="System").click()
                page.emulate_media(color_scheme="light")
                assert_equal(page.locator("html").get_attribute("data-scheme"),"light","System follows light OS")
                page.emulate_media(color_scheme="dark")
                assert_equal(page.locator("html").get_attribute("data-scheme"),"dark","System follows dark OS")
                page.get_by_role("button",name="Dark").click()
                assert_equal(page.locator("html").get_attribute("data-scheme"),"dark","Manual dark override")
                print(f"PASS {width}x{height}: overflow, theme modes, storage, live system changes, safety banner, JS")
                context.close()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()

if __name__=="__main__":
    main()
