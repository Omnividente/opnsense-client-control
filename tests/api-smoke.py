#!/usr/bin/env python3
"""Destructive-on-test-appliance HTTP smoke test for Client Control APIs.

Required environment:
  CLIENT_CONTROL_API_SMOKE=apply-to-test-appliance
  CLIENT_CONTROL_URL=https://firewall.example
  CLIENT_CONTROL_API_KEY=...
  CLIENT_CONTROL_API_SECRET=...

For a private CA, set CLIENT_CONTROL_CA_FILE. For an isolated disposable target
only, CLIENT_CONTROL_INSECURE=1 disables certificate verification.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


CONFIRMATION = "apply-to-test-appliance"
BASE_URL = os.environ.get("CLIENT_CONTROL_URL", "").rstrip("/")
API_KEY = os.environ.get("CLIENT_CONTROL_API_KEY", "")
API_SECRET = os.environ.get("CLIENT_CONTROL_API_SECRET", "")
IMPORT_ALIASES = [
    item.strip()
    for item in os.environ.get("CLIENT_CONTROL_IMPORT_ALIASES", "upr_sit7,Unlim").split(",")
    if item.strip()
]


class ApiError(RuntimeError):
    def __init__(self, status: int, payload: object):
        super().__init__(f"HTTP {status}: {payload}")
        self.status = status
        self.payload = payload


def require_environment() -> None:
    if os.environ.get("CLIENT_CONTROL_API_SMOKE") != CONFIRMATION:
        raise RuntimeError(
            f"refusing to mutate a target without CLIENT_CONTROL_API_SMOKE={CONFIRMATION}"
        )
    missing = [
        name
        for name, value in {
            "CLIENT_CONTROL_URL": BASE_URL,
            "CLIENT_CONTROL_API_KEY": API_KEY,
            "CLIENT_CONTROL_API_SECRET": API_SECRET,
        }.items()
        if not value
    ]
    if missing:
        raise RuntimeError("missing environment: " + ", ".join(missing))


def tls_context() -> ssl.SSLContext:
    ca_file = os.environ.get("CLIENT_CONTROL_CA_FILE")
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    if os.environ.get("CLIENT_CONTROL_INSECURE") == "1":
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def form_pairs(prefix: str, value: object) -> list[tuple[str, str]]:
    if isinstance(value, dict):
        result: list[tuple[str, str]] = []
        for key, child in value.items():
            name = f"{prefix}[{key}]" if prefix else str(key)
            result.extend(form_pairs(name, child))
        return result
    if isinstance(value, list):
        result = []
        for index, child in enumerate(value):
            result.extend(form_pairs(f"{prefix}[{index}]", child))
        return result
    if value is None:
        return [(prefix, "")]
    if isinstance(value, bool):
        return [(prefix, "1" if value else "0")]
    return [(prefix, str(value))]


def decode_response(raw: bytes) -> object:
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def request(method: str, path: str, payload: dict[str, object] | None = None) -> dict[str, object]:
    url = BASE_URL + path
    data = None
    headers = {
        "Accept": "application/json",
        "Authorization": "Basic "
        + base64.b64encode(f"{API_KEY}:{API_SECRET}".encode()).decode(),
    }
    if payload is not None:
        data = urllib.parse.urlencode(form_pairs("", payload)).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=tls_context(), timeout=60) as response:
            result = decode_response(response.read())
    except urllib.error.HTTPError as error:
        raise ApiError(error.code, decode_response(error.read())) from error
    if not isinstance(result, dict):
        raise RuntimeError(f"non-object API response from {path}: {result!r}")
    return result


def get(path: str) -> dict[str, object]:
    return request("GET", path)


def post(path: str, payload: dict[str, object] | None = None) -> dict[str, object]:
    return request("POST", path, payload or {})


def search_groups() -> dict[str, object]:
    return post("/api/clientcontrol/groups/search_group", {"rowCount": -1, "current": 1})


def search_clients(**filters: object) -> dict[str, object]:
    payload: dict[str, object] = {"rowCount": -1, "current": 1}
    payload.update(filters)
    return post("/api/clientcontrol/clients/search_client", payload)


def exact_apply() -> dict[str, object]:
    plan = post("/api/clientcontrol/service/plan", {"strategy": "fail"})
    if plan.get("status") != "ok":
        raise RuntimeError(f"apply plan is not safe: {plan}")
    applied = post(
        "/api/clientcontrol/service/apply",
        {
            "revision": plan["revision"],
            "strategy": "fail",
            "plan_fingerprint": plan["plan_fingerprint"],
            "confirm_enforce": plan["plan_fingerprint"],
        },
    )
    if applied.get("verified") is not True:
        raise RuntimeError(f"apply did not verify: {applied}")
    return {"plan": plan, "applied": applied}


def group_payload(name: str) -> dict[str, str]:
    return {
        "enabled": "1",
        "name": name,
        "description": "Temporary Client Control API smoke record",
        "access": "allow",
        "shaping_mode": "unlimited",
        "download": "0",
        "upload": "0",
        "metric": "Mbit",
        "schedule": "",
        "max_states": "0",
        "max_tcp_connections": "0",
        "connection_rate": "0",
        "connection_rate_seconds": "0",
        "packet_rate": "0",
        "packet_rate_seconds": "0",
    }


def client_payload(name: str, group_uuid: str, address: str) -> dict[str, object]:
    return {
        "enabled": "1",
        "name": name,
        "group": group_uuid,
        "comment": "Temporary Client Control API smoke record",
        "access_override": "inherit",
        "shaping_override": "inherit",
        "download_override": "0",
        "upload_override": "0",
        "metric_override": "Mbit",
        "endpoints": [{"kind": "ipv4", "value": address, "label": name}],
    }


def assert_true(condition: object, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def cleanup(
    created_clients: set[str],
    created_groups: set[str],
    baseline_client_ids: set[str],
    baseline_group_ids: set[str],
    client_names: set[str],
    group_names: set[str],
) -> None:
    current_clients = search_clients()
    selected_clients = sorted(
        str(row["uuid"])
        for row in current_clients.get("rows", [])
        if str(row["uuid"]) in created_clients
        or (str(row["uuid"]) not in baseline_client_ids and str(row["name"]) in client_names)
    )
    revision = int(current_clients["revision"])
    if selected_clients:
        deleted = post(
            "/api/clientcontrol/clients/del_client/" + ",".join(selected_clients),
            {"revision": revision},
        )
        revision = int(deleted["revision"])

    current_groups = search_groups()
    selected_groups = sorted(
        str(row["uuid"])
        for row in current_groups.get("rows", [])
        if str(row["uuid"]) in created_groups
        or (str(row["uuid"]) not in baseline_group_ids and str(row["name"]) in group_names)
    )
    revision = int(current_groups["revision"])
    for group_uuid in selected_groups:
        deleted = post(
            "/api/clientcontrol/groups/del_group/" + group_uuid,
            {"revision": revision},
        )
        revision = int(deleted["revision"])

    exact_apply()


def run() -> dict[str, object]:
    require_environment()
    suffix = secrets.token_hex(4)
    prefix = f"CC API Smoke {suffix}"
    ip_a = os.environ.get("CLIENT_CONTROL_TEST_IP_A", "192.0.2.250")
    ip_b = os.environ.get("CLIENT_CONTROL_TEST_IP_B", "192.0.2.251")

    baseline_groups = search_groups()
    baseline_clients = search_clients()
    baseline_group_ids = {str(row["uuid"]) for row in baseline_groups.get("rows", [])}
    baseline_client_ids = {str(row["uuid"]) for row in baseline_clients.get("rows", [])}
    created_groups: set[str] = set()
    created_clients: set[str] = set()
    group_names = {prefix + " A", prefix + " B"}
    client_names = {prefix + " 1", prefix + " 2", prefix + " duplicate"}
    result: dict[str, object] = {"prefix": prefix}

    try:
        revision = int(baseline_clients["revision"])
        group_a = post(
            "/api/clientcontrol/groups/add_group",
            {"revision": revision, "group": group_payload(prefix + " A")},
        )
        created_groups.add(str(group_a["uuid"]))
        group_b = post(
            "/api/clientcontrol/groups/add_group",
            {"revision": group_a["revision"], "group": group_payload(prefix + " B")},
        )
        created_groups.add(str(group_b["uuid"]))

        client_a = post(
            "/api/clientcontrol/clients/add_client",
            {
                "revision": group_b["revision"],
                "client": client_payload(prefix + " 1", str(group_a["uuid"]), ip_a),
            },
        )
        created_clients.add(str(client_a["uuid"]))
        client_b = post(
            "/api/clientcontrol/clients/add_client",
            {
                "revision": client_a["revision"],
                "client": client_payload(prefix + " 2", str(group_a["uuid"]), ip_b),
            },
        )
        created_clients.add(str(client_b["uuid"]))

        fetched_client = get(f"/api/clientcontrol/clients/get_client/{client_a['uuid']}")
        assert_true(
            str(fetched_client.get("client", {}).get("uuid")) == str(client_a["uuid"]),
            "get_client did not return the requested client",
        )
        assert_true(
            isinstance(fetched_client.get("effective_policy"), dict),
            "get_client did not return the effective policy",
        )
        fetched_group = get(f"/api/clientcontrol/groups/get_group/{group_a['uuid']}")
        assert_true(
            fetched_group.get("members") == 2,
            "get_group did not return the current member count",
        )

        duplicate = post(
            "/api/clientcontrol/clients/add_client",
            {
                "revision": client_b["revision"],
                "client": client_payload(prefix + " duplicate", str(group_a["uuid"]), ip_a),
            },
        )
        assert_true(duplicate.get("result") == "failed" and duplicate.get("validations"), "duplicate endpoint was accepted")

        stale_rejected = False
        try:
            post(
                f"/api/clientcontrol/clients/toggle_client/{client_a['uuid']}/0",
                {"revision": int(client_b["revision"]) - 1},
            )
        except ApiError as error:
            stale_rejected = error.status in (400, 409, 500)
        assert_true(stale_rejected, "stale revision was accepted")

        moved = post(
            "/api/clientcontrol/clients/bulk_move",
            {
                "revision": client_b["revision"],
                "client_uuids": [client_a["uuid"], client_b["uuid"]],
                "group_uuid": group_b["uuid"],
            },
        )
        assert_true(moved.get("changed") == 2, "bulk move did not update both clients")
        filtered = search_clients(group_uuid=group_b["uuid"], searchPhrase=prefix)
        assert_true(
            {str(row["uuid"]) for row in filtered.get("rows", [])}
            == {str(client_a["uuid"]), str(client_b["uuid"])},
            "group/search filters did not return both moved clients",
        )

        transfer_rejected = False
        try:
            rejected = post(
                f"/api/clientcontrol/groups/del_group/{group_b['uuid']}",
                {"revision": moved["revision"]},
            )
            transfer_rejected = rejected.get("result") == "failed"
        except ApiError:
            transfer_rejected = True
        assert_true(transfer_rejected, "a group with members was deleted without a target group")

        transferred = post(
            f"/api/clientcontrol/groups/del_group/{group_b['uuid']}",
            {
                "revision": moved["revision"],
                "target_group_uuid": group_a["uuid"],
            },
        )
        assert_true(transferred.get("moved") == 2, "group deletion did not transfer both clients")
        created_groups.discard(str(group_b["uuid"]))
        reassigned = search_clients(group_uuid=group_a["uuid"], searchPhrase=prefix)
        assert_true(
            {str(row["uuid"]) for row in reassigned.get("rows", [])}
            == {str(client_a["uuid"]), str(client_b["uuid"])},
            "group deletion did not preserve both clients in the target group",
        )
        remaining_groups = search_groups()
        assert_true(
            str(group_b["uuid"])
            not in {str(row["uuid"]) for row in remaining_groups.get("rows", [])},
            "source group still exists after atomic transfer and deletion",
        )

        scan = post("/api/clientcontrol/import/scan", {"rowCount": -1, "current": 1})
        scanned_names = {str(row["name"]) for row in scan.get("rows", [])}
        assert_true(set(IMPORT_ALIASES) <= scanned_names, "configured import aliases are not available")
        preview = post("/api/clientcontrol/import/preview", {"alias_names": IMPORT_ALIASES})
        assert_true(not preview.get("errors"), f"import preview failed: {preview.get('errors')}")
        group_names.update(str(proposal["name"]) for proposal in preview.get("groups", []))
        client_names.update(str(proposal["name"]) for proposal in preview.get("clients", []))
        imported = post(
            "/api/clientcontrol/import/apply",
            {
                "revision": transferred["revision"],
                "alias_names": preview["selected_aliases"],
                "preview_hash": preview["preview_hash"],
            },
        )
        assert_true(imported.get("result") == "saved", "import apply did not save")

        after_import_groups = search_groups()
        after_import_clients = search_clients()
        created_groups.update(
            {str(row["uuid"]) for row in after_import_groups.get("rows", [])} - baseline_group_ids
        )
        created_clients.update(
            {str(row["uuid"]) for row in after_import_clients.get("rows", [])} - baseline_client_ids
        )

        apply_result = exact_apply()
        second_plan = post("/api/clientcontrol/service/plan", {"strategy": "fail"})
        assert_true(second_plan.get("counts") == {"noop": len(second_plan.get("operations", []))}, "second apply is not a no-op")
        result.update(
            {
                "crud": "ok",
                "duplicate_rejection": "ok",
                "revision_rejection": "ok",
                "bulk_move": "ok",
                "get_contracts": "ok",
                "group_delete_transfer": "ok",
                "import": {
                    "groups_added": imported.get("groups_added"),
                    "clients_added": imported.get("clients_added"),
                    "endpoints_added": imported.get("endpoints_added"),
                },
                "apply_counts": apply_result["plan"].get("counts"),
                "idempotent_counts": second_plan.get("counts"),
            }
        )
        return result
    finally:
        cleanup(
            created_clients,
            created_groups,
            baseline_client_ids,
            baseline_group_ids,
            client_names,
            group_names,
        )


def main() -> int:
    try:
        print(json.dumps(run(), sort_keys=True))
        return 0
    except Exception as error:
        print(f"api smoke failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
