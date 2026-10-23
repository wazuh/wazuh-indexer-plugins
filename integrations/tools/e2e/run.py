#!/usr/bin/env python3

# End-to-end test of an integration, on its Docker Compose development environment.
#
# Starts the environment and, for every index pattern scenario (findings and events, findings
# only, events only, a custom data stream), configures Logstash for it, lets the events generator
# run, pauses it, waits for the export to catch up, and compares the time range of the scenario:
#   - the documents of the exported sources reach the destination, once each;
#   - the documents of the other sources do not;
#   - every source reaches its own destination (data stream, or Splunk index and source).
# Then imports the dashboards of the integration (Splunk: checks the dashboards of its app).
#
# Usage: run.py {elastic,opensearch,splunk} [--keep] [--scenarios ...] [--generate SECONDS]

import argparse
import datetime
import json
import os
import subprocess
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INTEGRATIONS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DOCKER = os.path.join(INTEGRATIONS, "docker")


def load_env() -> dict:
    """Settings of the development environments (docker/.env)."""
    env = {}
    with open(os.path.join(DOCKER, ".env")) as fd:
        for line in fd:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env[key] = value.strip('"')
    return env


ENV = load_env()
CUSTOM_STREAM = ENV["WAZUH_CUSTOM_STREAM"]
SCENARIOS = {
    "findings-and-events": {"indices": "wazuh-findings-v5-*,wazuh-events-v5-*", "kinds": {"findings", "events"}},
    "findings": {"indices": "wazuh-findings-v5-*", "kinds": {"findings"}},
    "events": {"indices": "wazuh-events-v5-*", "kinds": {"events"}},
    "custom": {"indices": CUSTOM_STREAM, "kinds": {"custom"}},
}
KINDS = ("findings", "events", "custom")


def log(message):
    print(f"[{datetime.datetime.now():%H:%M:%S}] {message}", flush=True)


def iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class Compose:
    def __init__(self, integration):
        self.file = os.path.join(DOCKER, f"compose.indexer-{integration}.yml")

    def run(self, *args, env=None, check=True, capture=False):
        cmd = ["docker", "compose", "-f", self.file, *args]
        result = subprocess.run(cmd, env={**os.environ, **(env or {})}, text=True,
                                capture_output=capture, cwd=DOCKER)
        if check and result.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd)} failed: {result.stderr if capture else ''}")
        return result

    def failed_services(self):
        out = self.run("ps", "-a", "--format", "{{.Service}} {{.State}} {{.ExitCode}}", capture=True).stdout
        # The test stops and starts the events generator itself.
        return [line.split()[0] for line in out.splitlines()
                if line.split()[1:2] == ["exited"] and line.split()[2] != "0" and line.split()[0] != "events-generator"]

    def logs(self, service, since=None):
        args = ["logs", "--no-color"] + (["--since", since] if since else []) + [service]
        return self.run(*args, capture=True, check=False).stdout


# Documents a scenario can compare: one search page. The default generation produces far fewer.
MAX_DOCUMENTS = 10000


def complete(hits: dict, what: str) -> list:
    """The hits of a search, failing if the page does not hold all of them."""
    if hits["total"]["value"] > len(hits["hits"]):
        raise RuntimeError(f"{hits['total']['value']} {what} in the range, more than the {MAX_DOCUMENTS} the test compares")
    return hits["hits"]


class Source:
    """The Wazuh indexer."""

    url = "https://localhost:9200"
    auth = ("admin", ENV["WAZUH_INDEXER_ADMIN_PASSWORD"])

    def ids(self, kind, start, end) -> dict:
        """{_id: data stream} of the documents of a kind with @timestamp in [start, end)."""
        target = {"findings": "wazuh-findings-v5-*", "events": "wazuh-events-v5-*", "custom": CUSTOM_STREAM}[kind]
        body = {"size": MAX_DOCUMENTS, "track_total_hits": True, "_source": False,
                "query": {"range": {"@timestamp": {"gte": iso(start), "lt": iso(end)}}}}
        r = requests.post(f"{self.url}/{target}/_search", json=body, auth=self.auth, verify=False, timeout=60)
        r.raise_for_status()
        hits = complete(r.json()["hits"], f"{kind} in the Wazuh indexer")
        return {h["_id"]: h["_index"][len(".ds-"):].rsplit("-", 1)[0] for h in hits}


def expected_dataset(kind, stream):
    category = stream.split("-v5-", 1)[1] if kind != "custom" else stream
    return f"wazuh.{kind}.{category}".replace("-", "_")


class SearchDestination:
    """Elasticsearch or OpenSearch: one data stream per source."""

    def __init__(self, url, auth):
        self.url, self.auth = url, auth

    def documents(self, kind, start, end):
        """[(_id, data stream)] of a kind with @timestamp in [start, end), duplicates included."""
        body = {"size": MAX_DOCUMENTS, "track_total_hits": True, "_source": False,
                "query": {"range": {"@timestamp": {"gte": iso(start), "lt": iso(end)}}}}
        r = requests.post(f"{self.url}/logs-wazuh.{kind}.*-*/_search?ignore_unavailable=true", json=body,
                          auth=self.auth, verify=False, timeout=60)
        if r.status_code == 404:
            return []
        r.raise_for_status()
        return [(h["_id"], h["_index"]) for h in complete(r.json()["hits"], f"{kind} in the destination")]

    def check_routing(self, kind, docs, source):
        for doc_id, index in docs:
            stream = source.get(doc_id)
            if stream is None:
                continue
            expected = f"logs-{expected_dataset(kind, stream)}-default"
            if f".ds-{expected}-" not in index:
                return f"{doc_id} from {stream} is in {index}, expected {expected}"
        return None


class SplunkDestination:
    """Splunk: one index per kind of source, the data stream as source."""

    INDEXES = {"findings": "wazuh-findings", "events": "wazuh-events", "custom": "wazuh-custom"}

    def __init__(self, compose):
        self.compose = compose

    def documents(self, kind, start, end):
        search = (f'search index="{self.INDEXES[kind]}" earliest={int(start)} latest={int(end)} '
                  f'| table wazuh_document_id, index, sourcetype, source')
        out = self.compose.run(
            "exec", "-T", "splunk", "curl", "-sk", "-u", f"admin:{ENV['SPLUNK_PASSWORD']}",
            "https://localhost:8089/services/search/jobs/export", "--data-urlencode", f"search={search}",
            "-d", "output_mode=json", capture=True).stdout
        docs = []
        for line in out.splitlines():
            result = json.loads(line).get("result") if line.strip() else None
            if result:
                docs.append((result.get("wazuh_document_id"), (result["index"], result["sourcetype"], result["source"])))
        return docs

    def check_routing(self, kind, docs, source):
        for doc_id, (index, sourcetype, stream) in docs:
            expected = (self.INDEXES[kind], f"wazuh:{kind}", source.get(doc_id))
            if doc_id in source and (index, sourcetype, stream) != expected:
                return f"{doc_id} is in {(index, sourcetype, stream)}, expected {expected}"
        return None


INTEGRATIONS_CONFIG = {
    "elastic": {"destination": lambda c: SearchDestination("https://localhost:9201", ("elastic", ENV["ELASTIC_PASSWORD"]))},
    "opensearch": {"destination": lambda c: SearchDestination("https://localhost:9201", ("admin", ENV["OPENSEARCH_ADMIN_PASSWORD"]))},
    "splunk": {"destination": lambda c: SplunkDestination(c)},
}


def minutes(value: str) -> int:
    """Minutes of a Logstash time setting of the environment, such as 5m or 1h."""
    return int(value[:-1]) * {"m": 1, "h": 60}[value[-1]]


# A window is read lookback + delay after it starts. The last window of a scenario is read by then,
# with a margin for the run itself and the destination to make the documents searchable.
SETTLE = (minutes(ENV["WAZUH_EXPORT_LOOKBACK"]) + minutes(ENV["WAZUH_EXPORT_DELAY"])) * 60 + 90
# The generator indexes the finding of an event WAZUH_GENERATOR_FINDINGS_DELAY seconds after it,
# and stopping it drops the findings still pending: only the events of the first part of a
# scenario have their findings.
GENERATE = int(ENV["WAZUH_GENERATOR_FINDINGS_DELAY"]) + 150


# Lines of the log of every failed service printed when the test fails.
LOG_LINES = 200


def print_logs(compose, services):
    for service in sorted(services):
        print(f"----- last lines of the {service} log -----")
        print("\n".join(compose.logs(service).splitlines()[-LOG_LINES:]))


def reset(compose):
    """Removes the environment, its volumes and the certificates it generated."""
    compose.run("down", "-v", "--remove-orphans", check=False, capture=True)
    subprocess.run(["docker", "run", "--rm", "-v", f"{DOCKER}:/w", "alpine:3.24.3", "sh", "-c", "rm -rf /w/certs /w/config"])


def start(compose, attempts=2):
    """
    Starts the environment, from scratch. A destination platform can fail its own first start
    now and then (the Splunk image on CI runners), so a failed start is retried once, after
    printing the logs of the services that failed.
    """
    for attempt in range(1, attempts + 1):
        reset(compose)
        try:
            compose.run("up", "-d", "--build", "--quiet-pull")
            return
        except RuntimeError:
            failed = compose.failed_services()
            if attempt == attempts:
                raise
            log(f"the environment did not start, retrying: services exited with an error: {failed}")
            print_logs(compose, failed)


def wait_for_pipeline(compose, since, timeout=600):
    """Waits until the Logstash pipeline runs. Fails on a crashed container or a pipeline error."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        failed = compose.failed_services()
        if failed:
            raise RuntimeError(f"services exited with an error: {failed}")
        logs = compose.logs("logstash", since)
        if "Pipeline error" in logs or "[FATAL]" in logs:
            raise RuntimeError("the Logstash pipeline failed:\n" + "\n".join(logs.splitlines()[-20:]))
        if "Pipelines running" in logs:
            return
        time.sleep(5)
    raise RuntimeError("the Logstash pipeline did not start")


def export_errors(compose, since):
    lines = compose.logs("logstash", since).splitlines()
    # The outputs log the writes they retry, rejected ones included, at the INFO level.
    signs = ("[ERROR]", "non-2xx", "security_exception", "Retrying failed action")
    return [line for line in lines if any(sign in line for sign in signs)]


def run_scenario(name, compose, destination, generate):
    scenario = SCENARIOS[name]
    log(f"scenario {name}: exporting {scenario['indices']}")
    since = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    compose.run("up", "-d", "--no-deps", "--force-recreate", "logstash", env={"WAZUH_EXPORT_INDICES": scenario["indices"]})
    wait_for_pipeline(compose, since)
    compose.run("up", "-d", "--no-deps", "events-generator")
    # The range starts on the next minute, so every window of it is read by this configuration.
    start = (int(time.time()) // 60 + 1) * 60
    time.sleep(start - time.time() + generate)
    compose.run("stop", "events-generator")
    end = time.time()
    # Findings of the last events are indexed after the generator stops: they are not generated.
    # Wait for the export of the documents of the range, then compare.
    time.sleep(SETTLE)

    source = {kind: Source().ids(kind, start, end) for kind in KINDS}
    problems = []
    for kind in KINDS:
        docs = destination.documents(kind, start, end)
        ids = [doc_id for doc_id, _ in docs]
        if kind in scenario["kinds"]:
            missing = set(source[kind]) - set(ids)
            duplicates = len(ids) - len(set(ids))
            extra = set(ids) - set(source[kind])
            log(f"  {kind}: source {len(source[kind])}, destination {len(ids)}, missing {len(missing)}, "
                f"duplicates {duplicates}, unknown {len(extra)}")
            if not source[kind]:
                problems.append(f"{kind}: no documents generated in the range")
            if missing or duplicates or extra:
                problems.append(f"{kind}: missing {len(missing)}, duplicates {duplicates}, unknown {len(extra)}")
            routing = destination.check_routing(kind, docs, source[kind])
            if routing:
                problems.append(f"{kind}: {routing}")
        else:
            log(f"  {kind}: not exported, destination {len(ids)}")
            if ids:
                problems.append(f"{kind}: {len(ids)} documents exported but not selected")
    errors = export_errors(compose, since)
    if errors:
        problems.append(f"{len(errors)} errors in the Logstash log, e.g. {errors[0][:300]}")
    return problems


def import_dashboards(integration, compose):
    """Imports the dashboards of the integration into its destination."""
    if integration in ("elastic", "opensearch"):
        url, auth, header = (("https://localhost:5602", ("elastic", ENV["ELASTIC_PASSWORD"]), {"kbn-xsrf": "true"})
                             if integration == "elastic" else
                             ("https://localhost:5602", ("admin", ENV["OPENSEARCH_ADMIN_PASSWORD"]), {"osd-xsrf": "true"}))
        path = os.path.join(INTEGRATIONS, integration, "dashboards.ndjson")
        for _ in range(60):
            try:
                with open(path, "rb") as fd:
                    r = requests.post(f"{url}/api/saved_objects/_import?overwrite=true", headers=header, auth=auth,
                                      files={"file": ("dashboards.ndjson", fd)}, verify=False, timeout=60)
                if r.status_code == 200:
                    result = r.json()
                    if not result.get("success"):
                        return [f"dashboards import failed: {result.get('errors')}"]
                    log(f"dashboards imported: {result.get('successCount')} objects")
                    return []
                # Up, but rejecting the file: retrying does not help.
                if r.status_code == 400:
                    return [f"dashboards import rejected: {r.text[:300]}"]
            except requests.RequestException:
                pass
            time.sleep(10)
        return ["the dashboards UI did not become available"]
    # Splunk: the dashboards are the views of the Wazuh app, installed with it.
    problems = []
    views = os.path.join(INTEGRATIONS, "splunk", "app", "wazuh_integration", "default", "data", "ui", "views")
    for name in sorted(os.listdir(views)):
        view = name.removesuffix(".xml")
        out = compose.run("exec", "-T", "splunk", "curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
                          "-u", f"admin:{ENV['SPLUNK_PASSWORD']}",
                          f"https://localhost:8089/servicesNS/nobody/wazuh_integration/data/ui/views/{view}", capture=True).stdout
        if out.strip() != "200":
            problems.append(f"the {view} dashboard of the Splunk app is not available: HTTP {out.strip()}")
    if not problems:
        log("dashboards of the Splunk app available")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="End-to-end test of an integration.")
    parser.add_argument("integration", choices=sorted(INTEGRATIONS_CONFIG))
    parser.add_argument("--scenarios", nargs="+", choices=list(SCENARIOS), default=list(SCENARIOS))
    parser.add_argument("--generate", type=int, default=GENERATE,
                        help=f"Seconds of events per scenario. Default: {GENERATE}, the delay of the findings plus 150.")
    parser.add_argument("--keep", action="store_true", help="Keep the environment running at the end.")
    args = parser.parse_args(argv)

    config = INTEGRATIONS_CONFIG[args.integration]
    compose = Compose(args.integration)
    problems = []
    try:
        log(f"starting the {args.integration} environment")
        start(compose)
        wait_for_pipeline(compose, None)
        compose.run("stop", "events-generator")
        destination = config["destination"](compose)
        for name in args.scenarios:
            found = run_scenario(name, compose, destination, args.generate)
            problems += [f"{name}: {p}" for p in found]
        problems += import_dashboards(args.integration, compose)
    except Exception as e:  # noqa: BLE001 - reported as a failure of the test
        problems.append(f"error: {e}")
    finally:
        if problems:
            # Diagnostics before the environment is removed.
            print_logs(compose, set(compose.failed_services()) | {"logstash"})
        if not args.keep:
            reset(compose)

    if problems:
        log("FAILED")
        for p in problems:
            print(f"  - {p}")
        return 1
    log("PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
