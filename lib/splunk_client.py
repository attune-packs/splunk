from __future__ import annotations

import base64
import json
import math
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


MAX_QUERY_BYTES = 100_000
MAX_EVENT_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 5_242_880
MAX_RESULTS = 1_000
_SID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_.@ -]{1,256}$")
_CONTEXT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


class SplunkPackError(RuntimeError):
    """An operator-safe pack error that never includes an HTTP body."""


def _fetch_key(ref: str) -> dict[str, Any]:
    if not isinstance(ref, str) or not ref.startswith("splunk.") or len(ref) > 256:
        raise SplunkPackError("credential_key must be a pack-owned splunk.* Key ref")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(ref, client=attune.context.client, decrypt=True)
        value = response.parsed.data.value
    except Exception as exc:
        raise SplunkPackError("unable to resolve the encrypted Splunk credential Key") from exc
    if not isinstance(value, dict):
        raise SplunkPackError("Splunk credential Key value must be an object")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SplunkPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not minimum <= value <= maximum
    ):
        raise SplunkPackError(f"{name} must be a number from {minimum} to {maximum}")
    return float(value)


def _string(value: Any, name: str, *, maximum: int = 100_000) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise SplunkPackError(f"{name} must be a non-empty string of at most {maximum} characters")
    return value


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise SplunkPackError(f"{name} must be a boolean")
    return value


def _header_value(value: Any, name: str, *, maximum: int = 16_384) -> str:
    text = _string(value, name, maximum=maximum)
    if any(ord(character) < 32 or ord(character) == 127 for character in text):
        raise SplunkPackError(f"{name} contains unsupported control characters")
    return text


def _json_bytes(value: Any, description: str) -> bytes:
    try:
        return json.dumps(
            value,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise SplunkPackError(f"{description} is not valid JSON") from None


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _optional_string(params: dict[str, Any], name: str, *, maximum: int = 4_096) -> str | None:
    value = params.get(name)
    if value is None:
        return None
    return _string(value, name, maximum=maximum)


def _base_url(value: Any, name: str) -> str:
    url = _string(value, name, maximum=2_048).rstrip("/")
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise SplunkPackError(f"{name} must be an HTTPS origin without credentials, path, query, or fragment")
    return url


def _tls_context(verify: Any, ca_bundle: Any, prefix: str) -> ssl.SSLContext:
    if not isinstance(verify, bool):
        raise SplunkPackError(f"{prefix}_verify_tls must be a boolean")
    if not verify:
        if ca_bundle is not None:
            raise SplunkPackError(f"{prefix}_ca_bundle cannot be used when TLS verification is disabled")
        return ssl._create_unverified_context()
    if ca_bundle is None:
        return ssl.create_default_context()
    path = Path(_string(ca_bundle, f"{prefix}_ca_bundle", maximum=4_096))
    if not path.is_absolute() or not path.is_file():
        raise SplunkPackError(f"{prefix}_ca_bundle must be an existing absolute file path")
    try:
        return ssl.create_default_context(cafile=str(path))
    except (OSError, ssl.SSLError) as exc:
        raise SplunkPackError(f"unable to load {prefix} CA bundle") from exc


class SplunkClient:
    def __init__(self, config: dict[str, Any]):
        if not isinstance(config, dict):
            raise SplunkPackError("Splunk credentials must be an object")
        self.config = config
        self.timeout = _integer(config.get("timeout_seconds", 30), "timeout_seconds", 1, 120)
        self.max_response_bytes = _integer(
            config.get("max_response_bytes", MAX_RESPONSE_BYTES),
            "max_response_bytes",
            1_024,
            10_485_760,
        )

    def _management_transport(self) -> tuple[str, dict[str, str], ssl.SSLContext]:
        base = _base_url(self.config.get("management_url"), "management_url")
        bearer = self.config.get("management_bearer_token")
        if bearer is not None:
            authorization = "Bearer " + _header_value(bearer, "management_bearer_token")
        else:
            username = _header_value(self.config.get("management_username"), "management_username", maximum=256)
            if ":" in username:
                raise SplunkPackError("management_username cannot contain a colon with Basic authentication")
            password = _header_value(self.config.get("management_password"), "management_password")
            encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            authorization = "Basic " + encoded
        context = _tls_context(
            self.config.get("management_verify_tls", True),
            self.config.get("management_ca_bundle"),
            "management",
        )
        return base, {"Authorization": authorization}, context

    def _hec_transport(self) -> tuple[str, dict[str, str], ssl.SSLContext]:
        base = _base_url(self.config.get("hec_url"), "hec_url")
        token = _header_value(self.config.get("hec_token"), "hec_token")
        context = _tls_context(
            self.config.get("hec_verify_tls", True),
            self.config.get("hec_ca_bundle"),
            "hec",
        )
        return base, {"Authorization": "Splunk " + token}, context

    def _request_json(
        self,
        transport: tuple[str, dict[str, str], ssl.SSLContext],
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        form: dict[str, Any] | None = None,
        body: Any = None,
        max_bytes: int | None = None,
        expect_json: bool = True,
    ) -> dict[str, Any]:
        base, auth_headers, context = transport
        if not path.startswith("/"):
            raise SplunkPackError("internal request path is invalid")
        url = base + path
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)
        headers = {**auth_headers, "Accept": "application/json"}
        data = None
        try:
            if form is not None:
                data = urllib.parse.urlencode(form, doseq=True).encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            elif body is not None:
                data = _json_bytes(body, "request body")
                headers["Content-Type"] = "application/json"
            request = urllib.request.Request(url, data=data, headers=headers, method=method)
        except (TypeError, ValueError, UnicodeEncodeError):
            raise SplunkPackError("unable to construct the Splunk request") from None
        limit = max_bytes if max_bytes is not None else self.max_response_bytes
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
                raw = response.read(limit + 1)
                status = response.status
        except urllib.error.HTTPError as exc:
            exc.close()
            raise SplunkPackError(f"Splunk request failed with HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            raise SplunkPackError(f"Splunk request failed ({type(exc).__name__})") from None
        if len(raw) > limit:
            raise SplunkPackError(f"Splunk response exceeded the {limit}-byte output limit")
        if not 200 <= status < 300:
            raise SplunkPackError(f"Splunk request failed with HTTP {status}")
        if not expect_json:
            return {}
        if not raw:
            return {}
        try:
            parsed = json.loads(raw, parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise SplunkPackError("Splunk returned an invalid JSON response") from None
        if not isinstance(parsed, dict):
            raise SplunkPackError("Splunk returned an unexpected JSON response")
        return parsed

    def management_json(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return self._request_json(self._management_transport(), method, path, **kwargs)

    def hec_json(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return self._request_json(self._hec_transport(), method, path, **kwargs)

    def create_search(self, params: dict[str, Any]) -> dict[str, Any]:
        query = _string(params.get("query"), "query", maximum=MAX_QUERY_BYTES)
        if len(query.encode("utf-8")) > MAX_QUERY_BYTES:
            raise SplunkPackError(f"query must be at most {MAX_QUERY_BYTES} UTF-8 bytes")
        form: dict[str, Any] = {"search": query, "exec_mode": "normal", "output_mode": "json"}
        for name in ("earliest_time", "latest_time"):
            value = _optional_string(params, name, maximum=256)
            if value is not None:
                form[name] = value
        if params.get("max_time_seconds") is not None:
            form["max_time"] = _integer(params["max_time_seconds"], "max_time_seconds", 1, 86_400)
        body = self.management_json("POST", "/services/search/jobs", form=form)
        sid = body.get("sid")
        if sid is None and isinstance(body.get("entry"), list) and body["entry"]:
            content = body["entry"][0].get("content", {})
            sid = content.get("sid") if isinstance(content, dict) else None
        return {"sid": _sid(sid), "created": True}

    def search_status(self, sid: Any) -> dict[str, Any]:
        safe_sid = _sid(sid)
        body = self.management_json(
            "GET",
            f"/services/search/jobs/{urllib.parse.quote(safe_sid, safe='')}",
            query={"output_mode": "json"},
        )
        entries = body.get("entry")
        if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
            raise SplunkPackError("Splunk returned an unexpected search status response")
        content = entries[0].get("content")
        if not isinstance(content, dict):
            raise SplunkPackError("Splunk returned an unexpected search status response")
        state = str(content.get("dispatchState", "UNKNOWN"))
        failed = _as_bool(content.get("isFailed")) or state.upper() in {
            "FAILED", "INTERNAL_CANCEL", "USER_CANCEL", "USER-CANCELED", "BAD_INPUT",
        }
        return {
            "sid": safe_sid,
            "dispatch_state": state,
            "done": _as_bool(content.get("isDone")),
            "failed": failed,
            "done_progress": _as_number(content.get("doneProgress")),
            "event_count": _as_int(content.get("eventCount")),
            "result_count": _as_int(content.get("resultCount")),
            "scan_count": _as_int(content.get("scanCount")),
            "run_duration": _as_number(content.get("runDuration")),
        }

    def search_results(self, sid: Any, count: Any, offset: Any) -> dict[str, Any]:
        safe_sid = _sid(sid)
        safe_count = _integer(count, "count", 1, MAX_RESULTS)
        safe_offset = _integer(offset, "offset", 0, 1_000_000_000)
        body = self.management_json(
            "GET",
            f"/services/search/v2/jobs/{urllib.parse.quote(safe_sid, safe='')}/results",
            query={"output_mode": "json", "count": safe_count, "offset": safe_offset},
        )
        results = body.get("results")
        if not isinstance(results, list):
            raise SplunkPackError("Splunk returned an unexpected search results response")
        return {
            "sid": safe_sid,
            "offset": safe_offset,
            "count": safe_count,
            "returned": len(results),
            "preview": bool(body.get("preview", False)),
            "fields": body.get("fields", []),
            "results": results,
        }

    def cancel_search(self, sid: Any) -> dict[str, Any]:
        safe_sid = _sid(sid)
        self.management_json(
            "POST",
            f"/services/search/jobs/{urllib.parse.quote(safe_sid, safe='')}/control",
            form={"action": "cancel", "output_mode": "json"},
            expect_json=False,
        )
        return {"sid": safe_sid, "cancel_requested": True}

    def send_hec_event(self, params: dict[str, Any]) -> dict[str, Any]:
        event = params.get("event")
        if not isinstance(event, dict):
            raise SplunkPackError("event must be a JSON object")
        payload: dict[str, Any] = {"event": event}
        for name in ("host", "source", "sourcetype", "index"):
            value = _optional_string(params, name)
            if value is not None:
                payload[name] = value
        if params.get("time") is not None:
            payload["time"] = _number(params["time"], "time", 0, 100_000_000_000)
        fields = params.get("fields")
        if fields is not None:
            if not isinstance(fields, dict) or not all(_flat_field_value(value) for value in fields.values()):
                raise SplunkPackError("fields must be a flat JSON object")
            payload["fields"] = fields
        serialized = _json_bytes(payload, "HEC event envelope")
        if len(serialized) > MAX_EVENT_BYTES:
            raise SplunkPackError(f"HEC event envelope exceeds the {MAX_EVENT_BYTES}-byte input limit")
        query = None
        channel = params.get("channel")
        if channel is not None:
            channel = _string(channel, "channel", maximum=128)
            if not _CONTEXT_RE.fullmatch(channel):
                raise SplunkPackError("channel contains unsupported characters")
            query = {"channel": channel}
        body = self.hec_json("POST", "/services/collector/event", query=query, body=payload)
        code = body.get("code")
        if code not in (0, "0"):
            raise SplunkPackError("HEC rejected the event")
        result = {"accepted": True, "code": 0, "text": str(body.get("text", "Success"))}
        if "ackId" in body:
            result["ack_id"] = body["ackId"]
        return result

    def _hec_admin_path(self) -> str:
        owner = self.config.get("hec_admin_owner", self.config.get("management_username"))
        app = self.config.get("hec_admin_app", "splunk_httpinput")
        owner = _string(owner, "hec_admin_owner", maximum=128)
        app = _string(app, "hec_admin_app", maximum=128)
        if owner in {".", ".."} or app in {".", ".."} or not _CONTEXT_RE.fullmatch(owner) or not _CONTEXT_RE.fullmatch(app):
            raise SplunkPackError("HEC administration owner/app contains unsupported characters")
        return f"/servicesNS/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(app, safe='')}/data/inputs/http"

    def list_hec_tokens(self, count: Any, offset: Any) -> dict[str, Any]:
        safe_count = _integer(count, "count", 1, 200)
        safe_offset = _integer(offset, "offset", 0, 1_000_000_000)
        body = self.management_json(
            "GET",
            self._hec_admin_path(),
            query={"output_mode": "json", "count": safe_count, "offset": safe_offset},
        )
        entries = body.get("entry", [])
        if not isinstance(entries, list):
            raise SplunkPackError("Splunk returned an unexpected HEC token response")
        tokens = []
        safe_fields = ("description", "disabled", "index", "indexes", "source", "sourcetype", "useACK")
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str) or entry.get("name") == "http":
                continue
            content = entry.get("content", {})
            if not isinstance(content, dict):
                content = {}
            tokens.append({"name": entry.get("name"), **{key: content.get(key) for key in safe_fields}})
        paging = body.get("paging", {})
        total = paging.get("total") if isinstance(paging, dict) else None
        return {"offset": safe_offset, "count": safe_count, "total": _as_int(total), "tokens": tokens}

    def set_hec_token_enabled(self, name: Any, enabled: Any) -> dict[str, Any]:
        token_name = _string(name, "name", maximum=256)
        if token_name in {".", "..", "http"} or not _NAME_RE.fullmatch(token_name):
            raise SplunkPackError("name must identify one application HEC token")
        if not isinstance(enabled, bool):
            raise SplunkPackError("enabled must be a boolean")
        operation = "enable" if enabled else "disable"
        path = f"{self._hec_admin_path()}/{urllib.parse.quote(token_name, safe='')}/{operation}"
        self.management_json("POST", path, form={"output_mode": "json"}, expect_json=False)
        return {"name": token_name, "enabled": enabled, "updated": True}

    def lookup_user(self, username: Any) -> dict[str, Any]:
        name = _string(username, "username", maximum=256)
        if name in {".", ".."} or not _NAME_RE.fullmatch(name):
            raise SplunkPackError("username contains unsupported characters")
        body = self.management_json(
            "GET",
            f"/services/authentication/users/{urllib.parse.quote(name, safe='')}",
            query={"output_mode": "json"},
        )
        entries = body.get("entry")
        if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
            raise SplunkPackError("Splunk returned an unexpected user response")
        content = entries[0].get("content", {})
        if not isinstance(content, dict):
            content = {}
        safe_fields = (
            "realname", "email", "roles", "defaultApp", "defaultAppIsUserOverride",
            "type", "locked-out", "force_change_pass", "tz", "capabilities",
        )
        return {"username": entries[0].get("name", name), **{key: content.get(key) for key in safe_fields}}


def _sid(value: Any) -> str:
    sid = _string(value, "sid", maximum=256)
    if sid in {".", ".."} or not _SID_RE.fullmatch(sid):
        raise SplunkPackError("sid contains unsupported characters")
    return sid


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes"}


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_number(value: Any) -> float | None:
    try:
        number = float(value)
        return number if math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def _flat_field_value(value: Any) -> bool:
    if isinstance(value, float) and not math.isfinite(value):
        return False
    if value is None or isinstance(value, (str, int, float, bool)):
        return True
    if isinstance(value, list):
        return all(item is None or isinstance(item, (str, int, float, bool)) for item in value) and all(
            not isinstance(item, float) or math.isfinite(item) for item in value
        )
    return False


def client_from_params(params: dict[str, Any]) -> SplunkClient:
    ref = params.get("credential_key", "splunk.credentials")
    return SplunkClient(_fetch_key(ref))


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    client = client_from_params(params)
    if operation == "search_create":
        return client.create_search(params)
    if operation == "search_status":
        return client.search_status(params.get("sid"))
    if operation == "search_results":
        return client.search_results(params.get("sid"), params.get("count", 100), params.get("offset", 0))
    if operation == "search_cancel":
        return client.cancel_search(params.get("sid"))
    if operation == "hec_event":
        return client.send_hec_event(params)
    if operation == "hec_token_list":
        return client.list_hec_tokens(params.get("count", 50), params.get("offset", 0))
    if operation == "hec_token_set_enabled":
        return client.set_hec_token_enabled(params.get("name"), params.get("enabled"))
    if operation == "user_lookup":
        return client.lookup_user(params.get("username"))
    if operation == "search_sync":
        wait_seconds = _integer(params.get("wait_seconds", 60), "wait_seconds", 1, 300)
        poll_interval = _number(params.get("poll_interval_seconds", 1), "poll_interval_seconds", 0.1, 10)
        cancel_on_timeout = _boolean(params.get("cancel_on_timeout", True), "cancel_on_timeout")
        count = _integer(params.get("count", 100), "count", 1, MAX_RESULTS)
        offset = _integer(params.get("offset", 0), "offset", 0, 1_000_000_000)
        created = client.create_search(params)
        sid = created["sid"]
        deadline = time.monotonic() + wait_seconds
        while True:
            status = client.search_status(sid)
            if status["failed"]:
                raise SplunkPackError(f"search job entered {status['dispatch_state']} state")
            if status["done"]:
                page = client.search_results(sid, count, offset)
                return {"status": status, **page}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if cancel_on_timeout:
                    try:
                        client.cancel_search(sid)
                    except SplunkPackError:
                        pass
                raise SplunkPackError(f"search job did not finish within {wait_seconds} seconds")
            time.sleep(min(poll_interval, remaining))
    raise SplunkPackError("unsupported Splunk action")
