#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys

_PACK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACK_ROOT not in sys.path:
    sys.path.insert(0, _PACK_ROOT)

from lib.splunk_client import SplunkPackError, execute_action  # noqa: E402


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def main() -> int:
    try:
        raw = sys.stdin.read()
        params = json.loads(raw, parse_constant=_reject_json_constant) if raw.strip() else {}
        if not isinstance(params, dict):
            raise SplunkPackError("action parameters must be a JSON object")
        operation = os.environ.get("ATTUNE_ACTION", "").rsplit(".", 1)[-1]
        result = execute_action(operation, params)
        json.dump({"operation": operation, "result": result}, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except (json.JSONDecodeError, ValueError):
        print("splunk action failed: invalid JSON parameters", file=sys.stderr)
    except SplunkPackError as exc:
        print(f"splunk action failed: {exc}", file=sys.stderr)
    except Exception:
        print("splunk action failed: unexpected error", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
