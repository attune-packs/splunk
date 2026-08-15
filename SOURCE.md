# Source Metadata

- Upstream repository: `https://github.com/StackStorm-Exchange/stackstorm-splunk`
- Upstream revision: `6bc01ba4253e4372f829d77bba6350799a0fed31`
- Upstream version: `2.3.0`
- Revision date: `2023-12-07T18:00:45Z`
- Revision signature status: verified by GitHub
- Upstream license: Apache-2.0
- Translation verification date: `2026-08-14`

The upstream revision exposed one-shot search, HEC event submission, HEC token
creation/retrieval, and user lookup. This translation preserves those useful
capabilities where safe, replaces one-shot search with bounded job polling,
adds explicit asynchronous job lifecycle actions, and uses the current
`search/v2/jobs/{sid}/results` endpoint.

The source HEC token action created a fixed token and returned its secret. It
was not copied. This pack instead provides secret-redacted token listing and
per-token enable/disable actions. Global HEC state, token creation, token
deletion, and token secret retrieval are out of scope for the initial pack.

Current behavior was checked against Splunk Enterprise 10.4 search REST
documentation and Splunk Enterprise 9.4/10.4 HEC documentation. Splunk's REST
reference states that v1 search result/export endpoints are deprecated and
disabled by default beginning with Enterprise 9.0.1 and Cloud 9.0.2208; v2 is
therefore used for result retrieval. Job creation, job status/control,
authentication user lookup, HEC JSON event ingestion, and named HEC input
enable/disable endpoints remain documented.
