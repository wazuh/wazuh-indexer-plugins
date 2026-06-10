#!/usr/bin/env python3
"""Build the OpenSearch Benchmark corpus + index body for the Wazuh events workload.

Reuses the project's own assets so the synthetic benchmark stays representative:
  - documents are produced by the WCS event generator
    (wcs/stateless/events/main/event-generator/event_generator.py), the same
    generator used to populate dev clusters;
  - the index body is derived from the real production template
    (plugins/setup/src/main/resources/templates/streams/events.json), keeping
    the production shard count, refresh interval and default query fields.

Outputs into workloads/wazuh-events/:
  - documents.json        NDJSON corpus (one event per line)
  - index.json            OSB index body {settings, mappings}
  - workload-params.json  doc_count / uncompressed_bytes for the workload
"""

import argparse
import importlib.util
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
GENERATOR = os.path.join(
    REPO_ROOT, "wcs", "stateless", "events", "main", "event-generator", "event_generator.py"
)
TEMPLATE = os.path.join(
    REPO_ROOT, "plugins", "setup", "src", "main", "resources", "templates", "streams", "events.json"
)
WORKLOAD_DIR = os.path.join(HERE, "workloads", "wazuh-events")


def load_generator():
    spec = importlib.util.spec_from_file_location("wcs_event_generator", GENERATOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_index_body():
    """Derive an isolated-index body from the production data-stream template.

    Drops the ISM/rollover settings (the setup plugin's policy is absent on a
    standalone benchmark cluster) and relaxes dynamic mapping to ``true`` so the
    generator's full field set always ingests. Keeps shards/replicas/refresh and
    the production mappings for representativeness.
    """
    with open(TEMPLATE) as fd:
        template = json.load(fd)
    tmpl = template["template"]

    settings = tmpl.get("settings", {})
    settings.pop("plugins.index_state_management.policy_id", None)
    settings.pop("plugins.index_state_management.rollover_alias", None)
    settings.get("index", {}).pop("auto_expand_replicas", None)

    mappings = tmpl.get("mappings", {})
    mappings["dynamic"] = "true"  # benchmark robustness; prod uses strict_allow_templates

    return {"settings": settings, "mappings": mappings}


def main():
    p = argparse.ArgumentParser(description="Generate OSB corpus + index body")
    p.add_argument("--docs", type=int, default=1_000_000, help="number of documents")
    args = p.parse_args()

    os.makedirs(WORKLOAD_DIR, exist_ok=True)
    gen = load_generator()

    docs_path = os.path.join(WORKLOAD_DIR, "documents.json")
    written = 0
    batch = 10_000
    with open(docs_path, "w") as fd:
        remaining = args.docs
        while remaining > 0:
            n = min(batch, remaining)
            for doc in gen.generate_random_data(n):
                fd.write(json.dumps(doc, separators=(",", ":")) + "\n")
                written += 1
            remaining -= n

    uncompressed_bytes = os.path.getsize(docs_path)

    with open(os.path.join(WORKLOAD_DIR, "index.json"), "w") as fd:
        json.dump(build_index_body(), fd, indent=2)

    with open(os.path.join(WORKLOAD_DIR, "workload-params.json"), "w") as fd:
        json.dump(
            {"doc_count": written, "uncompressed_bytes": uncompressed_bytes}, fd, indent=2
        )

    print(f"[INFO] Wrote {written} docs ({uncompressed_bytes} bytes) to {docs_path}")
    print(f"[INFO] Wrote index.json and workload-params.json to {WORKLOAD_DIR}")


if __name__ == "__main__":
    main()
