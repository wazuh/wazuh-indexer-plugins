# Content Manager component tests

End-to-end API tests for the Content Manager plugin, written in `pytest`. They
run against a **real, running wazuh-indexer cluster** that has the plugin and the
**Wazuh Engine** installed — there is no mock. This is the suite that catches the
contract regressions that previously only surfaced at component-validation time.

## Layout

```
tests/content-manager/
├── conftest.py            # fixtures: client, indexer_ready, reset_draft, resource fixtures
├── pytest.ini             # markers + config
├── requirements.txt
├── lib/                   # reusable, BDD-agnostic core (a future pytest-bdd layer calls this)
│   ├── assertions.py      # assertions over stored documents, incl. alias/topology checks
│   ├── client.py          # HTTP client + OpenSearch read-back helpers
│   ├── constants.py       # endpoint paths + index aliases (single source of truth)
│   └── payloads.py        # request-body builders (verified against the live API)
├── test_findings_generation.py    # resources -> promote -> detector -> event -> finding
├── test_index_topology.py         # wazuh-threatintel-* alias/physical-index checks (setup plugin)
├── test_logtest.py                # logtest validation + Sigma-modifier detection matrix
├── test_management.py             # subscription, update, version check
├── test_resources_lifecycle.py    # CRUD + policy + promotion + space reset
└── test_vulnerabilities_content.py  # vulnerabilities consumer content type coverage
```

## Prerequisites

- A reachable wazuh-indexer cluster with the `wazuh-indexer-setup` plugin,
  `wazuh-indexer-content-manager` plugin and the Engine installed, and an initial content
  update/sync completed so the  `draft`/`standard` policies exist. The suite fails fast
  (via the `indexer_ready`  fixture) if the draft policy is missing.

  The setup plugin — not the Content Manager — provisions the `wazuh-threatintel-*`
  content indices (each a physical `<alias>-a` index behind a write alias; see
  `ContentIndex` in the setup plugin and [`docs/dev/plugins/setup.md`](../../docs/dev/plugins/setup.md#threat-intel-content-indices)).
  The Content Manager waits for the setup plugin's readiness marker before its first
  write and **aborts its own initialization** if the setup plugin is absent or never
  becomes ready, rather than falling back to creating the indices itself. So on a
  cluster without the setup plugin installed, `indexer_ready` never observes a draft
  policy and the whole suite fails fast rather than exercising a half-provisioned
  deployment.

## Install & run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the whole suite:
pytest --base-url https://<host>:9200 --user admin --password admin

# Or via env vars (CM_BASE_URL / CM_USER / CM_PASSWORD):
CM_BASE_URL=https://<host>:9200 pytest

# A single area / marker:
pytest test_logtest.py
pytest -m crud
pytest -m topology
```

Markers: `smoke`, `crud`, `policy`, `promote`, `logtest`, `findings`, `vulnerabilities`,
`topology` — see `pytest.ini` for the authoritative descriptions.

## Isolation & a caveat about promotion

Most tests reset the **draft** space (`DELETE /space/draft`) for a clean slate.
The `test` and `custom` spaces are **not** API-resettable, so the `promote`,
`logtest` and `findings` scenarios permanently add content there; they name their
resources uniquely per run to stay repeatable on a long-lived cluster. For fully
repeatable runs, use a fresh cluster (which the CI model below provides).

The findings' scenario also reaches outside the Content Manager API: it creates a
Security Analytics detector (deleted on teardown), indexes an event into the
category's `wazuh-events-v5-*` data stream, and runs the detector's monitor on
demand via the Alerting `_execute` API to avoid waiting for its schedule. The
detector's `custom_rules` references the **CTI rule id** (not the SAP rule `_id`),
which is how the Wazuh SAP fork resolves promoted custom rules.

## Index topology (`test_index_topology.py`)

Every `wazuh-threatintel-*` index used by this suite is a write alias the setup
plugin points at a physical `<alias>-a` index — the Content Manager no longer
creates any of them (see Prerequisites above). `test_index_topology.py` asserts
each alias resolves to its physical index rather than to a same-named concrete
index; that second case is what happens when a write races index provisioning
and OpenSearch auto-creates the alias name itself with dynamic mappings whose
fields cannot be aggregated or sorted on (issue #1476).

This check exists because the CRUD/promotion tests in
`test_resources_lifecycle.py` and the type-distribution checks in
`test_vulnerabilities_content.py` only ever address indices by the alias name
(`client.get_doc`, `terms_agg`, ...) — they would keep passing against a
squatted index just the same, so they cannot catch this class of regression on
their own.

## CI (planned)

Per-PR the workflow will build the content-manager ZIP, provision a running
cluster with the Engine, install the freshly built plugin over it — the same way
the `sync-env.sh` helper does (`opensearch-plugin remove --purge
wazuh-indexer-content-manager` then `opensearch-plugin install file://…/wazuh-indexer-content-manager-<ver>.zip`,
restart) — and then run this suite. A fresh cluster per run sidesteps the
test/custom reset limitation above.

## Source of truth

Request/response shapes follow [`plugins/content-manager/openapi.yml`](../../plugins/content-manager/openapi.yml).
Where the spec and the running API disagreed, the suite encodes the **live**
behavior and the spec was corrected to match (e.g. decoder `metadata.author` is
a string, `trace_level` is `NONE`/`ASSET_ONLY`/`ALL`).
