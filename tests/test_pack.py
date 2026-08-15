from __future__ import annotations

import importlib.util
import io
import json
import re
import sys
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

PACK_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACK_ROOT))

from lib import splunk_client


EXPECTED_ACTIONS = {
    "search_sync", "search_create", "search_status", "search_results", "search_cancel",
    "hec_event", "hec_token_list", "hec_token_set_enabled", "user_lookup",
}


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, body: dict | bytes, status: int = 200):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, size: int) -> bytes:
        return self.body[:size]


def credentials() -> dict:
    return {
        "management_url": "https://splunk.example.invalid:8089",
        "management_username": "automation",
        "management_password": "DO_NOT_LOG_MANAGEMENT_SECRET",
        "hec_url": "https://hec.example.invalid:8088",
        "hec_token": "DO_NOT_LOG_HEC_SECRET",
        "timeout_seconds": 15,
    }


class PackTests(unittest.TestCase):
    def test_action_metadata_is_flat_and_complete(self):
        paths = sorted((PACK_ROOT / "actions").glob("*.yaml"))
        refs = set()
        for path in paths:
            text = path.read_text()
            match = re.search(r"^ref: splunk\.([a-z_]+)$", text, re.MULTILINE)
            self.assertIsNotNone(match, str(path))
            refs.add(match.group(1))
            for contract in (
                "runner_type: python", "entry_point: splunk_action.py",
                "parameter_delivery: stdin", "parameter_format: json", "output_format: json",
                "default_execution_permission_set_refs: [standard]", 'default: "splunk.credentials"',
                "  operation: {type: string, required: true}",
                "  result: {type: object, required: true}",
            ):
                self.assertIn(contract, text, str(path))
        self.assertEqual(refs, EXPECTED_ACTIONS)

    def test_pack_source_and_test_metadata(self):
        text = (PACK_ROOT / "pack.yaml").read_text()
        self.assertIn('source_revision: "6bc01ba4253e4372f829d77bba6350799a0fed31"', text)
        self.assertIn('license: "Apache-2.0"', text)
        self.assertIn("entry_point: tests/test_pack.py", text)

    def test_key_lookup_requests_decryption_and_pack_scope(self):
        calls = {}
        get_key_module = ModuleType("attune.api_client.api.secrets.get_key")

        def sync_detailed(ref, *, client, decrypt):
            calls.update(ref=ref, client=client, decrypt=decrypt)
            return SimpleNamespace(parsed=SimpleNamespace(data=SimpleNamespace(value=credentials())))

        get_key_module.sync_detailed = sync_detailed
        secrets = ModuleType("attune.api_client.api.secrets")
        secrets.get_key = get_key_module
        modules = {
            "attune": SimpleNamespace(context=SimpleNamespace(client="execution-client")),
            "attune.api_client": ModuleType("attune.api_client"),
            "attune.api_client.api": ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": secrets,
        }
        with patch.dict(sys.modules, modules):
            self.assertEqual(splunk_client._fetch_key("splunk.credentials")["timeout_seconds"], 15)
        self.assertEqual(calls, {"ref": "splunk.credentials", "client": "execution-client", "decrypt": True})
        with self.assertRaises(splunk_client.SplunkPackError):
            splunk_client._fetch_key("other.credentials")

    def test_management_and_hec_transports_are_separate(self):
        observed = []

        def fake_urlopen(request, *, timeout, context):
            observed.append((request, timeout, context))
            return FakeResponse({"code": 0, "text": "Success"})

        client = splunk_client.SplunkClient(credentials())
        with patch.object(splunk_client.urllib.request, "urlopen", side_effect=fake_urlopen):
            client.management_json("GET", "/services/server/info")
            client.hec_json("POST", "/services/collector/event", body={"event": {"message": "test"}})
        management, hec = observed[0][0], observed[1][0]
        self.assertTrue(management.full_url.startswith("https://splunk.example.invalid:8089/"))
        self.assertTrue(management.headers["Authorization"].startswith("Basic "))
        self.assertNotIn("DO_NOT_LOG_HEC_SECRET", management.headers["Authorization"])
        self.assertTrue(hec.full_url.startswith("https://hec.example.invalid:8088/"))
        self.assertEqual(hec.headers["Authorization"], "Splunk DO_NOT_LOG_HEC_SECRET")
        self.assertNotIn("DO_NOT_LOG_MANAGEMENT_SECRET", hec.headers["Authorization"])
        self.assertEqual([item[1] for item in observed], [15, 15])

    def test_urls_require_https_origins_and_tls_defaults_true(self):
        invalid = credentials()
        invalid["management_url"] = "http://splunk.example.invalid:8089"
        with self.assertRaises(splunk_client.SplunkPackError):
            splunk_client.SplunkClient(invalid).management_json("GET", "/services/server/info")
        with patch.object(splunk_client.ssl, "create_default_context", return_value=Mock()) as create_context, \
             patch.object(splunk_client.urllib.request, "urlopen", return_value=FakeResponse({})):
            splunk_client.SplunkClient(credentials()).management_json("GET", "/services/server/info")
        create_context.assert_called_once_with()

    def test_search_is_form_encoded_and_results_use_v2(self):
        client = splunk_client.SplunkClient(credentials())
        calls = []

        def management(method, path, **kwargs):
            calls.append((method, path, kwargs))
            if path == "/services/search/jobs":
                return {"sid": "scheduler_admin_search_1"}
            return {"preview": False, "fields": [{"name": "host"}], "results": [{"host": "a"}]}

        with patch.object(client, "management_json", side_effect=management):
            created = client.create_search({"query": "search index=main | stats count", "earliest_time": "-15m"})
            results = client.search_results(created["sid"], 25, 50)
        self.assertEqual(calls[0][2]["form"]["search"], "search index=main | stats count")
        self.assertNotIn("query", calls[0][2])
        self.assertEqual(calls[1][1], "/services/search/v2/jobs/scheduler_admin_search_1/results")
        self.assertEqual(calls[1][2]["query"]["count"], 25)
        self.assertEqual(results["returned"], 1)

    def test_search_status_normalizes_types_and_failure(self):
        client = splunk_client.SplunkClient(credentials())
        response = {"entry": [{"content": {
            "dispatchState": "FAILED", "isDone": "1", "doneProgress": "0.5",
            "eventCount": "2", "resultCount": "1", "scanCount": "3", "runDuration": "1.25",
        }}]}
        with patch.object(client, "management_json", return_value=response):
            status = client.search_status("sid-1")
        self.assertTrue(status["done"])
        self.assertTrue(status["failed"])
        self.assertEqual(status["scan_count"], 3)
        self.assertEqual(status["run_duration"], 1.25)
        response["entry"][0]["content"] = {"dispatchState": "USER-CANCELED", "isDone": "1"}
        with patch.object(client, "management_json", return_value=response):
            self.assertTrue(client.search_status("sid-1")["failed"])

    def test_sync_search_wait_is_bounded_and_cancels(self):
        client = Mock()
        client.create_search.return_value = {"sid": "sid-1", "created": True}
        client.search_status.return_value = {"failed": False, "done": False, "dispatch_state": "RUNNING"}
        with patch.object(splunk_client, "client_from_params", return_value=client), \
             patch.object(splunk_client.time, "monotonic", side_effect=[0.0, 0.0, 1.0]), \
             patch.object(splunk_client.time, "sleep"):
            with self.assertRaisesRegex(splunk_client.SplunkPackError, "within 1 seconds"):
                splunk_client.execute_action("search_sync", {"query": "search index=main", "wait_seconds": 1})
        client.cancel_search.assert_called_once_with("sid-1")

    def test_sync_options_are_validated_before_job_creation(self):
        client = Mock()
        with patch.object(splunk_client, "client_from_params", return_value=client):
            for params in (
                {"query": "search index=main", "cancel_on_timeout": "false"},
                {"query": "search index=main", "count": 0},
                {"query": "search index=main", "poll_interval_seconds": 0},
            ):
                with self.subTest(params=params), self.assertRaises(splunk_client.SplunkPackError):
                    splunk_client.execute_action("search_sync", params)
        client.create_search.assert_not_called()

    def test_hec_event_envelope_and_flat_fields(self):
        client = splunk_client.SplunkClient(credentials())
        with patch.object(client, "hec_json", return_value={"text": "Success", "code": 0, "ackId": 7}) as request:
            result = client.send_hec_event({
                "event": {"message": "synthetic"}, "index": "main", "fields": {"severity": "info"},
                "channel": "attune-1",
            })
        self.assertEqual(result, {"accepted": True, "code": 0, "text": "Success", "ack_id": 7})
        kwargs = request.call_args.kwargs
        self.assertEqual(kwargs["query"], {"channel": "attune-1"})
        self.assertEqual(kwargs["body"]["event"]["message"], "synthetic")
        with self.assertRaises(splunk_client.SplunkPackError):
            client.send_hec_event({"event": {}, "fields": {"nested": {"unsafe": True}}})
        with self.assertRaises(splunk_client.SplunkPackError):
            client.send_hec_event({"event": {"invalid": float("nan")}})

    def test_hec_token_output_redacts_secrets_and_global_stanza(self):
        client = splunk_client.SplunkClient(credentials())
        body = {
            "paging": {"total": 2},
            "entry": [
                {"name": "http", "content": {"token": "GLOBAL_SECRET"}},
                {"name": "attune", "content": {"token": "TOKEN_SECRET", "disabled": False, "index": "main"}},
            ],
        }
        with patch.object(client, "management_json", return_value=body):
            result = client.list_hec_tokens(50, 0)
        rendered = json.dumps(result)
        self.assertEqual([item["name"] for item in result["tokens"]], ["attune"])
        self.assertNotIn("SECRET", rendered)
        with self.assertRaises(splunk_client.SplunkPackError):
            client.set_hec_token_enabled("http", False)
        with self.assertRaises(splunk_client.SplunkPackError):
            client.set_hec_token_enabled("..", False)

    def test_mutating_controls_accept_non_json_success_bodies(self):
        client = splunk_client.SplunkClient(credentials())
        calls = []

        def fake_urlopen(request, *, timeout, context):
            calls.append(request.full_url)
            return FakeResponse(b"<response/>", status=201)

        with patch.object(splunk_client.urllib.request, "urlopen", side_effect=fake_urlopen):
            self.assertTrue(client.cancel_search("sid-1")["cancel_requested"])
            self.assertTrue(client.set_hec_token_enabled("attune", True)["updated"])
        self.assertEqual(len(calls), 2)

    def test_user_lookup_is_allowlisted(self):
        client = splunk_client.SplunkClient(credentials())
        body = {"entry": [{"name": "alice", "content": {
            "realname": "Alice", "roles": ["user"], "password": "HASH", "apiKey": "SECRET",
        }}]}
        with patch.object(client, "management_json", return_value=body):
            result = client.lookup_user("alice")
        self.assertEqual(result["username"], "alice")
        self.assertEqual(result["roles"], ["user"])
        self.assertNotIn("password", result)
        self.assertNotIn("apiKey", result)

    def test_response_limit_and_http_errors_do_not_leak_bodies(self):
        limited = credentials()
        limited["max_response_bytes"] = 1024
        client = splunk_client.SplunkClient(limited)
        with patch.object(splunk_client.urllib.request, "urlopen", return_value=FakeResponse(b"x" * 1025)):
            with self.assertRaisesRegex(splunk_client.SplunkPackError, "output limit"):
                client.management_json("GET", "/services/server/info")
        error = urllib.error.HTTPError("https://example.invalid", 401, "SECRET_RESPONSE", {}, io.BytesIO(b"SECRET_BODY"))
        with patch.object(splunk_client.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(splunk_client.SplunkPackError) as raised:
                client.management_json("GET", "/services/server/info")
        self.assertEqual(str(raised.exception), "Splunk request failed with HTTP 401")

    def test_header_controls_and_dot_path_segments_are_rejected(self):
        invalid = credentials()
        invalid["hec_token"] = "token\r\nInjected: true"
        with self.assertRaises(splunk_client.SplunkPackError):
            splunk_client.SplunkClient(invalid).hec_json("POST", "/services/collector/event", body={})
        client = splunk_client.SplunkClient(credentials())
        for sid in (".", "..", "sid/other"):
            with self.subTest(sid=sid), self.assertRaises(splunk_client.SplunkPackError):
                client.search_status(sid)

    def test_non_finite_input_json_is_rejected_without_echo(self):
        module = load_module("splunk_action_non_finite_test", PACK_ROOT / "actions" / "splunk_action.py")
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "stdin", io.StringIO('{"time":NaN,"secret":"DO_NOT_ECHO"}')), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(module.main(), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("DO_NOT_ECHO", stderr.getvalue())

    def test_entrypoint_rejects_malformed_json_without_echoing_input(self):
        module = load_module("splunk_action_test", PACK_ROOT / "actions" / "splunk_action.py")
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(sys, "stdin", io.StringIO('{"token":"DO_NOT_ECHO"')), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(module.main(), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("DO_NOT_ECHO", stderr.getvalue())

    def test_source_files_contain_no_credential_fixtures(self):
        forbidden = ["password" + ": secret", "Authorization" + ": Bearer", "BEGIN " + "PRIVATE KEY"]
        for path in PACK_ROOT.rglob("*"):
            if path.is_file() and path.suffix in {".py", ".yaml", ".md", ".txt", ".json"}:
                text = path.read_text(encoding="utf-8")
                self.assertFalse(any(value in text for value in forbidden), str(path))


if __name__ == "__main__":
    unittest.main()
