#!/usr/bin/env python3
"""Tiny HTTPS static server for the lab CIMD assets.

Serves ./cimd/ so that Keycloak can fetch:
    https://<host>:<port>/client-metadata.json
    https://<host>:<port>/bundle.json          (written by scripts/mint-svid.py)

Keycloak will refuse the fetch unless it trusts the TLS certificate of this
server -- pass the lab CA to Keycloak with --truststore-paths (see
docs/AUTHN.md).

Examples
    # with a cert issued by the lab CA (preferred)
    ./serve.py --cert ~/ca/cimd.pem --key ~/ca/cimd-key.pem \
               --host cimd.lab.local --port 8444

    # throwaway self-signed cert (lab only; Keycloak still needs to trust it)
    ./serve.py --host cimd.lab.local --port 8444 --selfsigned

The request log on stderr is the point: every Keycloak CIMD fetch shows up here.
"""

from __future__ import annotations

import argparse
import functools
import http.server
import os
import ssl
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def selfsigned(host: str) -> tuple[str, str]:
    """Create a self-signed cert for *host* if one does not exist yet."""
    d = os.path.join(HERE, "tls")
    os.makedirs(d, exist_ok=True)
    cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    if not (os.path.exists(cert) and os.path.exists(key)):
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "30",
             "-subj", f"/CN={host}",
             "-addext", f"subjectAltName=DNS:{host},DNS:localhost,IP:127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print(f"# generated self-signed cert {cert}", file=sys.stderr)
    return cert, key


class Handler(http.server.SimpleHTTPRequestHandler):
    # Only these files are public. Everything else (keys/, svid.jwt, tls/) is 404.
    PUBLIC_FILES = frozenset({"client-metadata.json", "dynamic.json", "bundle.json"})

    def _public(self) -> bool:
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        name = path.lstrip("/")
        return name in self.PUBLIC_FILES and "/" not in name

    def _deny(self) -> None:
        self.send_error(404, "Not Found")

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if not self._public():
            self._deny()
            return
        super().do_GET()

    def do_HEAD(self) -> None:  # noqa: N802 - http.server API
        if not self._public():
            self._deny()
            return
        super().do_HEAD()

    def list_directory(self, path):  # noqa: ARG002 - never browse
        self._deny()
        return None

    # Keycloak sends a plain GET; keep the log short but greppable.
    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"[cimd-serve] {self.address_string()} {fmt % args}\n")

    def end_headers(self) -> None:
        # Make it obvious in the Keycloak logs that a fetch really happened.
        self.send_header("X-CIMD-Lab", "1")
        super().end_headers()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="cimd.lab.local",
                    help="hostname Keycloak will use in the client_id URL")
    ap.add_argument("--port", type=int, default=8444)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--root", default=os.path.join(HERE, "..", "cimd"))
    ap.add_argument("--cert", default=None)
    ap.add_argument("--key", default=None)
    ap.add_argument("--selfsigned", action="store_true",
                    help="generate/use a throwaway self-signed cert for --host")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    cert, key = args.cert, args.key
    if args.selfsigned or not cert:
        cert, key = selfsigned(args.host)
    for path in (cert, key):
        if not os.path.exists(path):
            print(f"error: {path} does not exist", file=sys.stderr)
            return 2

    handler = functools.partial(Handler, directory=root)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)

    httpd = http.server.ThreadingHTTPServer((args.bind, args.port), handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"serving {root}", file=sys.stderr)
    print(f"  https://{args.host}:{args.port}/client-metadata.json", file=sys.stderr)
    print(f"  https://{args.host}:{args.port}/bundle.json", file=sys.stderr)
    print(f"  cert={cert} key={key}", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("# stopped", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
