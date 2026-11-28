"""Verify approved VALIDATION replay from the Pi to the backend over Tailscale."""

import argparse
import hashlib
import json
import os
import platform
import sys
from contextlib import suppress
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPException
from importlib.metadata import version
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path

SOURCE_COMMIT = "48a0a5125a108da3a076a78f95b0d5bfeb66266a"
ARTIFACT_SHA256 = {
    "predictor.py": "6975f6ac90564c884ac442dfd4bd60e436aaec3be319ef6f045ae80da8d0a6b6",
    "model.json": "cb090afa6ad4c3618e20d7c5d635e89aa2d122667ea00835a0acc2f75a4455e6",
    "freeze.json": "c9d3024579bf68c8c1ac85449a93dcbed07feb745ec89e43d2617c28b33a3397",
}
BUNDLE_MANIFEST_SHA256 = "9fac1acde3f696bb765937c997977b3d7b1e1c2fa6cd60626e910037ea1fe132"
TAILSCALE_IPV4 = IPv4Network("100.64.0.0/10")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def require_equal(step, actual, expected):
    if actual != expected:
        raise RuntimeError(f"{step}: expected {expected!r}, got {actual!r}")


def read_verified(path, expected_hash):
    data = path.read_bytes()
    require_equal(path.name + " SHA-256", hashlib.sha256(data).hexdigest(), expected_hash)
    return data


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")


class PiClient:
    def __init__(self, pi_ip, backend_ip, port):
        self.pi_ip = pi_ip
        self.backend_ip = backend_ip
        self.port = port
        self.trace = []

    def request(self, method, path, expected_status, body=None):
        connection = HTTPConnection(
            self.backend_ip, self.port, timeout=15, source_address=(self.pi_ip, 0)
        )
        try:
            connection.connect()
            source_ip, source_port = connection.sock.getsockname()
            peer_ip, peer_port = connection.sock.getpeername()
            require_equal("HTTP source IP", source_ip, self.pi_ip)
            require_equal("HTTP peer", (peer_ip, peer_port), (self.backend_ip, self.port))
            headers = {"Content-Type": "application/json"} if body is not None else {}
            if body is not None and not isinstance(body, bytes):
                body = json_bytes(body)
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read()
            self.trace.append({
                "at_utc": now(),
                "method": method,
                "path": path,
                "http_status": response.status,
                "source_port": source_port,
            })
            require_equal(f"{method} {path} HTTP status ({data[:400]!r})",
                          response.status, expected_status)
            return json.loads(data) if data else None
        finally:
            connection.close()


def predict_on_pi(artifacts, bundle):
    for filename, digest in ARTIFACT_SHA256.items():
        read_verified(artifacts / filename, digest)
    manifest = json.loads(read_verified(bundle / "manifest.json", BUNDLE_MANIFEST_SHA256))
    fixture_hashes = {
        name: manifest["files"][name]["sha256"]
        for name in ("example_input.json", "example_expected.json", "example_lineage.json")
    }
    inputs, expected, lineage = (
        json.loads(read_verified(bundle / name, digest))
        for name, digest in fixture_hashes.items()
    )
    require_equal("fixture partition", lineage["partition"].upper(), "VALIDATION")
    require_equal("fixture row widths", [len(row) for row in inputs["rows"]], [115] * 3)

    os.environ["IOTGUARD_MODEL_PATH"] = str(artifacts / "model.json")
    os.environ["IOTGUARD_FREEZE_PATH"] = str(artifacts / "freeze.json")
    sys.path.insert(0, str(artifacts))
    import predictor

    require_equal("imported predictor", Path(predictor.__file__).resolve(),
                  artifacts / "predictor.py")
    shared = predictor.get_predictor()
    require_equal("frozen feature order", inputs["feature_order"], shared.feature_order)
    actual = shared.predict(inputs["rows"])
    predicted_at = now()
    require_equal("Pi prediction", {field: actual[field] for field in expected}, expected)
    require_equal("Pi model SHA-256", actual["model_sha256"], ARTIFACT_SHA256["model.json"])
    return actual, predicted_at, inputs["feature_order"], fixture_hashes


def check_session(client, actual, predicted_at, feature_order):
    model = client.request("GET", "/model/info", 200)
    for field in ("model_id", "model_sha256", "threshold"):
        require_equal("backend model " + field, model[field], actual[field])
    require_equal("backend feature count", model["feature_count"], 115)
    require_equal("backend feature order", model["feature_order"], feature_order)

    session = client.request("POST", "/live/sessions", 201,
                             {"source_name": "pi-validation-replay-network-check"})
    base = "/live/sessions/" + session["session_id"]
    stopped = False
    try:
        require_equal("session state", session["state"], "active")
        require_equal("session model", session["model_sha256"], actual["model_sha256"])
        initial = client.request("GET", base + "/status", 200)
        require_equal("initial connection", initial["connection"], "connecting")
        require_equal("initial event count", initial["total_received"], 0)

        events = [
            {
                "event_id": f"{session['session_id']}-validation-{seq + 1}",
                "pi_seq": seq,
                "label": label,
                "probability_malicious": probability,
                "predicted_at": predicted_at,
            }
            for seq, (label, probability) in enumerate(
                zip(actual["labels"], actual["probabilities"], strict=True)
            )
        ]
        batch = json_bytes({"model_sha256": actual["model_sha256"], "events": events})
        first = client.request("POST", base + "/events", 200, batch)
        batch_counters = {"dropped_from_history": 0, "last_pi_seq": 2, "gap_detected": False}
        require_equal("first ingest", first, dict(batch_counters, accepted=3, duplicates=0))
        before_retry = client.request("GET", base + "/status", 200)
        require_equal("count before resend", before_retry["total_received"], 3)

        resend = client.request("POST", base + "/events", 200, batch)
        require_equal("resend", resend, dict(batch_counters, accepted=0, duplicates=3))
        after_retry = client.request("GET", base + "/status", 200)
        totals = {"total_received": 3, "benign": 2, "malicious": 1, "duplicates_ignored": 3}
        require_equal("counts after resend", {key: after_retry[key] for key in totals}, totals)

        cursor = 0
        stored = []
        pages = []
        for expected_ids in ([1, 2], [3], []):
            page = client.request("GET", f"{base}/events?after_seq={cursor}&limit=2", 200)
            require_equal("cursor page server sequence",
                          [item["server_seq"] for item in page["events"]], expected_ids)
            next_cursor = expected_ids[-1] if expected_ids else cursor
            require_equal("next cursor", page["next_after_seq"], next_cursor)
            pages.append({
                "after_seq": cursor,
                "next_after_seq": next_cursor,
                "server_seq": expected_ids,
            })
            cursor = next_cursor
            stored.extend(page["events"])
        for sent, received in zip(events, stored, strict=True):
            fields = ("event_id", "pi_seq", "label", "probability_malicious")
            require_equal("stored event", {field: received[field] for field in fields},
                          {field: sent[field] for field in fields})
            require_equal("stored prediction time", datetime.fromisoformat(received["predicted_at"]),
                          datetime.fromisoformat(sent["predicted_at"]))

        heartbeat = client.request("POST", base + "/heartbeat", 204, {
            "model_sha256": actual["model_sha256"], "pi_seq": 2, "sent_at": now(),
        })
        require_equal("heartbeat body", heartbeat, None)
        after_heartbeat = client.request("GET", base + "/status", 200)
        require_equal("heartbeat connection", after_heartbeat["connection"], "connected")
        require_equal("heartbeat total", after_heartbeat["total_received"], 3)
        if datetime.fromisoformat(after_heartbeat["last_seen_at"]) <= datetime.fromisoformat(
            after_retry["last_seen_at"]
        ):
            raise RuntimeError("Heartbeat did not advance the backend's last_seen_at")

        stop = client.request("POST", base + "/stop", 200)
        require_equal("stopped session", stop["state"], "stopped")
        stopped = True
        rejected = client.request("POST", base + "/events", 409, batch)
        require_equal("post-stop error code", rejected["code"], "session_stopped")
        final = client.request("GET", base + "/status", 200)
        require_equal("final session state", final["session"]["state"], "stopped")
        require_equal("final counts", {key: final[key] for key in totals}, totals)
    finally:
        if not stopped:
            with suppress(OSError, HTTPException, RuntimeError):
                client.request("POST", base + "/stop", 200)

    return {
        "backend_model": {key: model[key] for key in (
            "model_id", "model_sha256", "threshold", "feature_count", "runtime"
        )},
        "session_id": session["session_id"],
        "initial_connection": initial["connection"],
        "event_batch_sha256": hashlib.sha256(batch).hexdigest(),
        "first_ingest": first,
        "resend": resend,
        "total_before_and_after_resend": [before_retry["total_received"],
                                          after_retry["total_received"]],
        "cursor_pages": pages,
        "stored_events": stored,
        "heartbeat": {
            "http_status": 204,
            "connection": after_heartbeat["connection"],
            "last_seen_before": after_retry["last_seen_at"],
            "last_seen_after": after_heartbeat["last_seen_at"],
        },
        "stop": {"http_status": 200, "state": stop["state"], "stopped_at": stop["stopped_at"]},
        "post_stop": {"http_status": 409, "code": rejected["code"]},
        "final_counts": totals,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pi-ip", required=True, type=IPv4Address)
    parser.add_argument("--backend-ip", required=True, type=IPv4Address)
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    args = parser.parse_args()
    if (args.pi_ip not in TAILSCALE_IPV4 or args.backend_ip not in TAILSCALE_IPV4
            or args.pi_ip == args.backend_ip or not 1 <= args.port <= 65535):
        parser.error("use distinct Tailscale IPv4 addresses and a valid backend port")

    started_at = now()
    actual, predicted_at, order, fixture_hashes = predict_on_pi(
        args.artifacts.resolve(), args.bundle.resolve()
    )
    client = PiClient(str(args.pi_ip), str(args.backend_ip), args.port)
    checks = check_session(client, actual, predicted_at, order)
    device_model = Path("/proc/device-tree/model")
    receipt = {
        "status": "PASS",
        "scope": "approved VALIDATION replay on Pi over Tailscale IPv4",
        "source_commit": SOURCE_COMMIT,
        "started_at_utc": started_at,
        "finished_at_utc": now(),
        "pi": {
            "ip": client.pi_ip,
            "machine": platform.machine(),
            "device": device_model.read_text().rstrip("\0") if device_model.is_file() else None,
            "kernel": platform.release(),
            "os": platform.freedesktop_os_release()["PRETTY_NAME"],
            "python": platform.python_version(),
            "libraries": {name: version(name) for name in ("numpy", "xgboost", "scipy")},
        },
        "backend": {"ip": client.backend_ip, "port": client.port},
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "artifact_sha256": ARTIFACT_SHA256,
        "bundle_manifest_sha256": BUNDLE_MANIFEST_SHA256,
        "fixture_sha256": fixture_hashes,
        "pi_prediction": actual,
        "checks": checks,
        "http_trace": client.trace,
    }
    print(json.dumps(receipt, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
