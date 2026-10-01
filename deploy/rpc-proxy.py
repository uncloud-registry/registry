#!/usr/bin/env python3
# RPC shim for the reference deployment's local dev chain.
#
# Why this exists: the pinned bee (ethersphere/bee:2.8.2) talks to the chain
# through go-ethereum, which serializes the transaction object's calldata as
# the "input" field on eth_call / eth_estimateGas / eth_sendTransaction. The
# pinned localchain image (ethersphere/bee-localchain:0.9.4, hardhat/EDR
# 0.2.0-dev) only reads the "data" field, so every bee chain interaction would
# execute with EMPTY calldata and revert ("function selector was not
# recognized and there's no fallback nor receive function"), killing bee at
# startup and postage minting. This shim copies "input" to "data" when the
# latter is absent and forwards everything else untouched. It also polyfills
# eth_maxPriorityFeePerGas (which the EDR build does not implement but bee's
# transaction sender requires): the localchain runs with
# initialBaseFeePerGas=0, so the honest tip-cap answer is 0.
#
# It is deliberately tiny and stateless: mounted read-only into a pinned
# python:3.12-alpine container (see the localchain-proxy service in
# compose.yaml), same pattern as deploy/Caddyfile. It rewrites NO responses
# and makes no other changes to the RPC surface.

import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = os.environ.get("LOCALCHAIN_RPC_UPSTREAM", "http://localchain:8545")
# Methods whose params[0] is a transaction object carrying calldata.
CALDATA_METHODS = {"eth_call", "eth_estimateGas", "eth_sendTransaction"}
# Methods the localchain EDR node does not implement but bee requires.
POLYFILLS = {
    "eth_maxPriorityFeePerGas": "0x0",
}


def normalize(body: bytes) -> bytes:
    """Copy 'input' to 'data' on transaction objects; return body unchanged on
    parse failure (let the upstream produce the real error)."""
    try:
        req = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return body
    batch = req if isinstance(req, list) else [req]
    changed = False
    for item in batch:
        if not isinstance(item, dict):
            continue
        if item.get("method") not in CALDATA_METHODS:
            continue
        params = item.get("params")
        if not isinstance(params, list) or not params:
            continue
        obj = params[0]
        if isinstance(obj, dict) and "input" in obj and "data" not in obj:
            obj["data"] = obj["input"]
            changed = True
    return json.dumps(req).encode() if changed else body


def polyfill(req) -> bytes | None:
    """Answer polyfilled methods directly (single request, not batch)."""
    if isinstance(req, dict) and req.get("method") in POLYFILLS:
        out = json.dumps(
            {"jsonrpc": req.get("jsonrpc", "2.0"), "id": req.get("id"), "result": POLYFILLS[req["method"]]}
        ).encode()
        return out
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # keep docker logs quiet
        pass

    def do_GET(self):
        if self.path.split("?")[0] == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            req = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            req = None
        if req is not None:
            direct = polyfill(req)
            if direct is not None:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(direct)))
                self.end_headers()
                self.wfile.write(direct)
                return
        fwd = normalize(body)
        try:
            upstream = urllib.request.urlopen(
                urllib.request.Request(
                    UPSTREAM,
                    data=fwd,
                    headers={"Content-Type": self.headers.get("Content-Type", "application/json")},
                ),
                timeout=30,
            )
            out = upstream.read()
        except Exception as exc:  # pragma: no cover - upstream failure path
            out = json.dumps(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": "rpc-proxy: %s" % exc}}
            ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8545), Handler).serve_forever()