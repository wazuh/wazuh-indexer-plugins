# Events generator

Generates Wazuh Common Schema (WCS) events and findings in the Wazuh indexer, to develop and test
the integrations.

- Events go to the `wazuh-events-v5-<category>` data streams, built from the templates of
  `samples/events.json` and an agent of `samples/agents.json`.
- A share of the events produces a finding in `wazuh-findings-v5-<category>`, as the Security
  Analytics plugin does: a copy of the event, `event.doc_id` and `event.index` pointing to it, a rule
  of `samples/rules.json` under `wazuh.rule`, and the same deterministic document id as the plugin.
  The rule is one of the integration of the event, and of its `event.action` for the rules that list their `actions`.
  Findings can be indexed some time after their event, as the plugin indexes them.
- Optionally, a share of the events also goes to a custom data stream.

The samples are synthetic. The tests check that every field of them is in the WCS events and
findings modules.

## Usage

```bash
pip install -r requirements.txt
python run.py -a <wazuh indexer> -u admin -p <password> --ca <root-ca.pem>
```

| Option | Default | Description |
| --- | --- | --- |
| `-a`, `-P` | `localhost`, `9200` | Address and port of the Wazuh indexer. |
| `-u`, `-p` | `$WAZUH_INDEXER_USERNAME` or `admin`, `$WAZUH_INDEXER_PASSWORD` | Credentials. |
| `--ca` | | CA certificate of the Wazuh indexer. Without it, the certificate is not verified. |
| `-c` | `0` | Events to index. `0` runs indefinitely. |
| `-t` | `5` | Seconds between events. |
| `-f` | `0.3` | Probability of an event producing a finding. |
| `--findings-delay` | `$WAZUH_GENERATOR_FINDINGS_DELAY` or `0` | Seconds between an event and the indexing of its finding. |
| `--custom-stream` | `$WAZUH_CUSTOM_STREAM` | Data stream that also gets a share of the events (`--custom-ratio`, default `0.2`). It must exist. |
| `--categories` | all | Comma-separated categories to generate events of. |
| `--seed` | | Seed of the random choices, for repeatable output. |
| `--dry-run` | | Print the documents instead of indexing them. |

## Docker

The development environments build and run the generator from this folder. To run it alone:

```bash
docker build -t wazuh/indexer-events-generator .
docker run --rm wazuh/indexer-events-generator --dry-run -c 3 -t 0
```

## Tests

```bash
pip install -r tests/requirements.txt
python -m pytest
```
