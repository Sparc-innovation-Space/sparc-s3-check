"""SPARC Cloud file storage check app (Stage 12.6), used by docs/guide/examples/test-file-storage.sh.

Python standard library only (no SDK): it signs its own S3 requests (AWS Signature Version 4), so it also shows
exactly what an app needs: the S3_* / AWS_* variables SPARC gives an app with an attached bucket.

  GET  /healthz  -> 200 "ok"
  POST /check    header X-Check-Token: <CHECK_TOKEN>   body {"key": "...", "other_bucket": "..." (optional)}
                 -> JSON with HTTP statuses only (never a key):
                    own: put / get (+ same content?) / list of the app's own bucket
                    other (when other_bucket is given): get / head / list / put / copy-into-own / copy-into-other
                    presigned_url: a GET URL for the object, signed for S3_PUBLIC_ENDPOINT, valid 10 minutes
Without CHECK_TOKEN set, /check answers 503: a throwaway app never lets strangers write into its bucket.
"""
import datetime
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8000"))


def env(name: str) -> str:
    return os.environ.get(name, "")


def _q(s: str, safe: str = "-_.~") -> str:
    return urllib.parse.quote(s, safe=safe)


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _signing_key(day: str) -> bytes:
    k = _hmac(("AWS4" + env("AWS_SECRET_ACCESS_KEY")).encode(), day)
    return _hmac(_hmac(_hmac(k, env("S3_REGION")), "s3"), "aws4_request")


def request(method: str, bucket: str, key: str = "", query: str = "", body: bytes = b"",
            extra: dict | None = None) -> tuple[int, bytes]:
    """One signed S3 request to S3_ENDPOINT (path style). Returns (status, body)."""
    base = env("S3_ENDPOINT").rstrip("/")
    path = "/" + _q(bucket) + ("/" + _q(key, "/-_.~") if key else "")
    url = base + path + ("?" + query if query else "")
    now = datetime.datetime.now(datetime.timezone.utc)
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    payload = hashlib.sha256(body).hexdigest()
    host = urllib.parse.urlsplit(base).netloc
    headers = {"host": host, "x-amz-content-sha256": payload, "x-amz-date": amz, **(extra or {})}
    names = sorted(headers)
    cq = "&".join(f"{_q(k)}={_q(v)}" for k, v in sorted(urllib.parse.parse_qsl(query, keep_blank_values=True)))
    canonical = "\n".join([method, path, cq, "".join(f"{n}:{headers[n]}\n" for n in names), ";".join(names), payload])
    scope = f"{day}/{env('S3_REGION')}/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    sig = hmac.new(_signing_key(day), to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (f"AWS4-HMAC-SHA256 Credential={env('AWS_ACCESS_KEY_ID')}/{scope}, "
                                f"SignedHeaders={';'.join(names)}, Signature={sig}")
    req = urllib.request.Request(url, data=body if method == "PUT" else None, method=method,
                                 headers={k: v for k, v in headers.items() if k != "host"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def presign_get(bucket: str, key: str, seconds: int = 600) -> str:
    """A browser URL: signed for S3_PUBLIC_ENDPOINT (no network call: signing happens here)."""
    base = env("S3_PUBLIC_ENDPOINT").rstrip("/")
    host = urllib.parse.urlsplit(base).netloc
    path = "/" + _q(bucket) + "/" + _q(key, "/-_.~")
    now = datetime.datetime.now(datetime.timezone.utc)
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    scope = f"{day}/{env('S3_REGION')}/s3/aws4_request"
    params = {"X-Amz-Algorithm": "AWS4-HMAC-SHA256", "X-Amz-Credential": f"{env('AWS_ACCESS_KEY_ID')}/{scope}",
              "X-Amz-Date": amz, "X-Amz-Expires": str(seconds), "X-Amz-SignedHeaders": "host"}
    cq = "&".join(f"{_q(k)}={_q(v)}" for k, v in sorted(params.items()))
    canonical = "\n".join(["GET", path, cq, f"host:{host}\n", "host", "UNSIGNED-PAYLOAD"])
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    sig = hmac.new(_signing_key(day), to_sign.encode(), hashlib.sha256).hexdigest()
    return f"{base}{path}?{cq}&X-Amz-Signature={sig}"


def check(key: str, other: str | None) -> dict:
    mine = env("S3_BUCKET")
    content = f"sparc 12.6 file storage check {key}".encode()
    out = {"bucket": mine, "key": key, "own": {}, "other": None}
    out["own"]["put"] = request("PUT", mine, key, body=content)[0]
    status, got = request("GET", mine, key)
    out["own"]["get"], out["own"]["same_content"] = status, got == content
    out["own"]["list"] = request("GET", mine, query="list-type=2&max-keys=10")[0]
    if other:
        src = f"/{_q(other)}/{_q(key, '/-_.~')}"
        out["other"] = {
            "get": request("GET", other, key)[0],
            "head": request("HEAD", other, key)[0],
            "list": request("GET", other, query="list-type=2&max-keys=10")[0],
            "put": request("PUT", other, key + ".planted", body=b"x")[0],
            "copy_into_own": request("PUT", mine, key + ".copied", extra={"x-amz-copy-source": src})[0],
            "copy_into_other": request("PUT", other, key + ".copied",
                                       extra={"x-amz-copy-source": f"/{_q(mine)}/{_q(key, '/-_.~')}"})[0],
        }
    out["presigned_url"] = presign_get(mine, key)
    return out


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: bytes, kind: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path in ("/", "/healthz"):
            return self._send(200, b"ok", "text/plain")
        self._send(404, b"not found", "text/plain")

    def do_POST(self):  # noqa: N802
        if self.path != "/check":
            return self._send(404, b"not found", "text/plain")
        token = env("CHECK_TOKEN")
        if not token:
            return self._send(503, b'{"error": "CHECK_TOKEN is not set"}')
        if not hmac.compare_digest(self.headers.get("X-Check-Token", ""), token):
            return self._send(403, b'{"error": "wrong token"}')
        try:
            data = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", "0")), 4096)) or b"{}")
            key = str(data["key"])[:200]
        except (ValueError, KeyError):
            return self._send(400, b'{"error": "send {\\"key\\": ...}"}')
        self._send(200, json.dumps(check(key, data.get("other_bucket"))).encode())

    def log_message(self, fmt, *args):   # one short line per request, never headers
        print(f"{self.command} {self.path.split('?')[0]} -> {args[1] if len(args) > 1 else ''}", flush=True)


if __name__ == "__main__":
    print(f"s3-check on 0.0.0.0:{PORT}, bucket {env('S3_BUCKET') or '(none attached)'}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
