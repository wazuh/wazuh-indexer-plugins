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
│   ├── client.py          # HTTP client + OpenSearch read-back helpers
│   ├── payloads.py        # request-body builders (verified against the live API)
│   ├── assertions.py      # assertions over stored documents
│   └── constants.py       # endpoint paths + index aliases (single source of truth)
├── test_*.py              # one module per area
└── NN-*/*.feature         # Gherkin specs — executed by the future pytest-bdd phase
```

## Prerequisites

- A reachable wazuh-indexer cluster with `wazuh-indexer-content-manager` (and the
  Engine) installed, and an initial content update/sync completed so the
  `draft`/`standard` policies exist. The suite fails fast (via the `indexer_ready`
  fixture) if the draft policy is missing.

## Install & run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the whole suite:
pytest --base-url https://<host>:9200 --user admin --password admin

# Or via env vars (CM_BASE_URL / CM_USER / CM_PASSWORD):
CM_BASE_URL=https://<host>:9200 pytest

# A single area / marker:
pytest test_logtest_modifiers.py
pytest -m crud
```

## Isolation & a caveat about promotion

Most tests reset the **draft** space (`DELETE /space/draft`) for a clean slate.
The `test` and `custom` spaces are **not** API-resettable, so the `promote` and
`logtest` tests permanently add content there; they name their resources uniquely
per run to stay repeatable on a long-lived cluster. For fully repeatable promote
runs, use a fresh cluster (which the CI model below provides).

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
behaviour and the spec was corrected to match (e.g. decoder `metadata.author` is
a string, `trace_level` is `NONE`/`ASSET_ONLY`/`ALL`).
