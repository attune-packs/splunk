# Splunk Attune Pack

Attune actions for bounded Splunk Enterprise and Splunk Cloud Platform search,
HTTP Event Collector (HEC) ingestion, narrowly scoped HEC token administration,
and user lookup.

This pack is an Apache-2.0 adaptation of
[`StackStorm-Exchange/stackstorm-splunk`](https://github.com/StackStorm-Exchange/stackstorm-splunk)
version 2.3.0 at revision
`6bc01ba4253e4372f829d77bba6350799a0fed31`. See [SOURCE.md](SOURCE.md) and
[NOTICE](NOTICE) for provenance and translation decisions.

## Setup

Create an encrypted, pack-owned Attune Key with ref `splunk.credentials`.
Actions use the reserved `standard` execution permission set to decrypt the Key.
Management and HEC endpoints and authentication are intentionally separate:

```json
{
  "management_url": "https://splunk.example.invalid:8089",
  "management_username": "attune-automation",
  "management_password": "REDACTED",
  "management_verify_tls": true,
  "management_ca_bundle": "/absolute/worker/path/management-ca.pem",
  "hec_url": "https://hec.example.invalid:8088",
  "hec_token": "REDACTED",
  "hec_verify_tls": true,
  "hec_ca_bundle": "/absolute/worker/path/hec-ca.pem",
  "timeout_seconds": 30,
  "max_response_bytes": 5242880,
  "hec_admin_owner": "attune-automation",
  "hec_admin_app": "splunk_httpinput"
}
```

Use `management_bearer_token` instead of `management_username` and
`management_password` when the deployment provides a scoped Splunk bearer
token. A HEC token is never reused for management authentication. Custom CA
fields are optional absolute paths on the selected worker. TLS verification is
enabled by default and can be configured independently with
`management_verify_tls` and `hec_verify_tls`; disabling either is intended only
for controlled development environments.

Every action accepts `credential_key`, which defaults to `splunk.credentials`
and must name a pack-owned `splunk.*` Key.

## Actions

| Action | Behavior |
|---|---|
| `splunk.search_sync` | Creates a normal search job, polls for at most 1-300 seconds, optionally cancels on timeout, and returns one result page. |
| `splunk.search_create` | Creates an asynchronous search and returns its SID. |
| `splunk.search_status` | Returns normalized dispatch state, completion, counts, progress, and runtime. |
| `splunk.search_results` | Reads one page of 1-1000 records from `search/v2/jobs/{sid}/results`. |
| `splunk.search_cancel` | Requests cancellation of one validated SID. |
| `splunk.hec_event` | Sends one JSON object through `/services/collector/event`, with optional event metadata and channel. |
| `splunk.hec_token_list` | Lists up to 200 application token metadata records without token values. Enterprise administration only. |
| `splunk.hec_token_set_enabled` | Enables or disables one named application token. The global `http` stanza is rejected. Enterprise administration only. |
| `splunk.user_lookup` | Returns an allowlisted profile for one exact username. |

Inputs are one flat stdin JSON object. Every action emits a stable envelope:

```json
{"operation":"search_create","result":{"sid":"example-sid","created":true}}
```

Representative commands:

```bash
attune action execute splunk.search_sync \
  --params-json '{"query":"search index=_internal | head 10","wait_seconds":30,"count":10}' \
  --watch

attune action execute splunk.search_create \
  --params-json '{"query":"search index=main earliest=-15m | stats count by host"}' \
  --watch

attune action execute splunk.search_results \
  --params-json '{"sid":"example-sid","count":100,"offset":0}' \
  --watch

attune action execute splunk.hec_event \
  --params-json '{"event":{"message":"deployment complete","severity":"info"},"sourcetype":"_json","index":"main"}' \
  --watch
```

The pack submits SPL as an `application/x-www-form-urlencoded` value and never
concatenates it into a URL or shell command. Queries are intentionally not
rewritten; callers must provide complete SPL and must use Splunk roles and
index restrictions appropriate to the workflow.

## Splunk Cloud Platform

Splunk Cloud has endpoint and entitlement restrictions that must be planned
before deployment:

- The management REST origin normally uses
  `https://<deployment-name>.splunkcloud.com:8089`. Port 8089 may require a
  Splunk Support case, and Splunk Cloud free trials cannot use the management
  REST API.
- Splunk Cloud restricts REST endpoints and capabilities by deployment. Search
  and user actions require an allowed management endpoint and a role with the
  corresponding capabilities. An HTTP 401, 403, or 404 can represent a Cloud
  policy restriction rather than a pack defect.
- Use the exact HEC URL shown by the deployment, commonly a regional
  `https://http-inputs-<deployment>...` origin. Do not derive it from the
  management hostname, and do not append `/services/collector` to `hec_url`;
  the pack appends `/services/collector/event`.
- HEC event ingestion is supported by both Enterprise and Cloud when HEC and
  the selected token/index are enabled.
- `hec_token_list` and `hec_token_set_enabled` follow the Enterprise HEC input
  administration endpoints documented under
  `/servicesNS/{owner}/splunk_httpinput/data/inputs/http`. Do not use these
  actions for Splunk Cloud token lifecycle management. Manage Cloud HEC tokens
  through the supported Cloud UI or Splunk Support process.
- The pack does not enable deprecated v1 search APIs. Result retrieval uses the
  v2 endpoint required by current Enterprise and Cloud releases.

## Security And Limits

- Credentials exist only in an encrypted Attune Key and are sent in request
  headers. Action parameters do not accept passwords or tokens.
- Endpoint URLs must be HTTPS origins without embedded credentials, paths,
  queries, or fragments.
- Management and HEC have independent TLS verification and CA settings.
- Network calls time out after 1-120 seconds according to the credential Key.
- SPL is limited to 100,000 UTF-8 bytes. Search result pages are limited to
  1,000 records and offset pagination is explicit.
- HEC event envelopes are limited to 1 MiB. Indexed `fields` must be flat.
- HTTP responses default to a 5 MiB limit and can never be configured above
  10 MiB. An oversized response fails rather than returning partial JSON.
- SIDs, usernames, namespace values, channels, and HEC token names are
  validated before path/header use.
- HTTP error bodies are not surfaced. Entry-point failures do not echo input,
  response content, endpoints, queries, or credentials.
- HEC token output omits the `token` field. Global HEC enable/disable, token
  generation, secret retrieval, and deletion are not implemented.

Use a least-privileged management identity. Search actions need only the
capabilities and indexes required by their SPL. User lookup and HEC token
administration usually require additional capabilities and should use a
separate credential Key when operational separation is required.

## API Compatibility

Current Splunk documentation was reviewed on 2026-08-14. Beginning with Splunk
Enterprise 9.0.1 and Splunk Cloud Platform 9.0.2208, deprecated v1 search
result/export endpoints can be disabled; this pack uses
`/services/search/v2/jobs/{sid}/results`. Search job creation, status, and
control remain under `/services/search/jobs`. HEC JSON event and named HEC
input endpoints and `/services/authentication/users/{name}` remain documented
for the supported products subject to role and Cloud restrictions.

## Validation

```bash
python -m unittest discover -s tests -v
attune --output json pack check .
attune pack test . --detailed
```

Tests are deterministic, mock all HTTP behavior, verify action metadata and
Key decryption, assert transport separation and current v2 result paths, cover
bounded polling and cancellation, exercise HEC and redaction behavior, and
make no live Splunk calls.

Live validation still requires operator-provided Enterprise and Cloud tenants.
In particular, verify role capabilities, management bearer authentication,
Cloud port/endpoint entitlements, custom CA deployment, HEC index allowlists,
indexer acknowledgement behavior, and Enterprise HEC token administration
against each target release.
