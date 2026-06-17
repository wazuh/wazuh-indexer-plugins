"""Thin HTTP client for the Content Manager API plus OpenSearch query helpers.

Wraps ``requests.Session`` with auth, TLS-skip, JSON headers and a small 429
retry — the single place request logic lives (ported from the old scripts'
``_send``). Helpers that read indices back (to assert on stored documents) live
here too so both the pytest modules and a future BDD layer share them.
"""

import time

import requests
import urllib3

from . import constants as C

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_JSON = {"Content-Type": "application/json", "Accept": "application/json"}


class CMClient:
    """Client for a running wazuh-indexer with the Content Manager plugin."""

    def __init__(self, base_url, user="admin", password="admin", max_retries=5):
        self.base_url = base_url.rstrip("/")
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.verify = False
        self.session.headers.update(_JSON)

    # ── Core request ──────────────────────────────────────────────────────

    def request(self, method, path, json=None, params=None):
        """Send a request and return the ``requests.Response`` (retries on 429)."""
        url = f"{self.base_url}{path}"
        last = None
        for attempt in range(1, self.max_retries + 1):
            last = self.session.request(method, url, json=json, params=params)
            if last.status_code != 429:
                return last
            time.sleep(attempt)
        return last

    # Convenience verbs --------------------------------------------------------

    def get(self, path, json=None, params=None):
        return self.request("GET", path, json=json, params=params)

    def post(self, path, json=None, params=None):
        return self.request("POST", path, json=json, params=params)

    def put(self, path, json=None, params=None):
        return self.request("PUT", path, json=json, params=params)

    def delete(self, path, json=None, params=None):
        return self.request("DELETE", path, json=json, params=params)

    # ── Content Manager helpers ───────────────────────────────────────────

    def create(self, path, body, integration=None):
        """POST a create request, assert 201, return the generated resource id."""
        payload = dict(body)
        if integration is not None:
            payload = {"integration": integration, **payload}
        resp = self.post(path, json=payload)
        assert resp.status_code == 201, f"create {path} -> {resp.status_code}: {resp.text}"
        return resp.json()["message"]

    def reset_space(self, space=C.SPACE_DRAFT):
        """Reset a user space (only ``draft`` is resettable) and return the response."""
        return self.delete(f"{C.SPACE}/{space}")

    # ── OpenSearch read-back helpers ──────────────────────────────────────

    def refresh(self, index):
        """Force a refresh so prior writes are visible to the next search."""
        self.post(f"/{index}/_refresh")

    def search(self, index, query=None, size=100, source=None):
        """Run an OpenSearch ``_search`` and return the parsed body.

        Refreshes first so read-backs after a create/delete are deterministic
        (the indices are near-real-time, so a bare search can miss a just-written
        or just-deleted document).
        """
        self.refresh(index)
        body = {"size": size, "track_total_hits": True}
        if query is not None:
            body["query"] = query
        if source is not None:
            body["_source"] = source
        resp = self.post(f"/{index}/_search", json=body)
        assert resp.status_code == 200, f"search {index} -> {resp.status_code}: {resp.text}"
        return resp.json()

    def search_by_space(self, index, space, size=100):
        """Return the hits for documents in a given space."""
        body = self.search(index, {"term": {"space.name": {"value": space}}}, size=size)
        return body["hits"]["hits"]

    def get_doc(self, index, doc_id):
        """Return the ``document`` source for a CTI resource id, or ``None``."""
        body = self.search(index, {"term": {"document.id": {"value": doc_id}}}, size=1)
        hits = body["hits"]["hits"]
        return hits[0]["_source"] if hits else None

    def get_doc_in_space(self, index, doc_id, space):
        """Return the ``_source`` for a resource id within a specific space, or ``None``.

        A promoted resource shares its ``document.id`` across spaces, so callers
        asserting on promotion must scope the lookup by ``space.name``.
        """
        query = {
            "bool": {
                "must": [
                    {"term": {"document.id": {"value": doc_id}}},
                    {"term": {"space.name": {"value": space}}},
                ]
            }
        }
        body = self.search(index, query, size=1)
        hits = body["hits"]["hits"]
        return hits[0]["_source"] if hits else None

    def count_by_space(self, index, space):
        """Count documents in ``index`` belonging to ``space``."""
        body = self.search(index, {"term": {"space.name": {"value": space}}}, size=0)
        return body["hits"]["total"]["value"]

    def get_policy(self, space):
        """Return the policy ``_source`` for the given space, or ``None``."""
        hits = self.search_by_space(C.INDEX_POLICIES, space, size=1)
        return hits[0]["_source"] if hits else None

    def get_draft_policy(self):
        """Return the draft policy ``_source`` (or ``None`` if absent)."""
        return self.get_policy(C.SPACE_DRAFT)

    # ── Findings pipeline (Security Analytics + Alerting) ──────────────────

    def create_detector(self, payload):
        """Create a Security Analytics detector; returns the ``requests.Response``."""
        return self.post(C.SA_DETECTORS, json=payload)

    def delete_detector(self, detector_id):
        return self.delete(f"{C.SA_DETECTORS}/{detector_id}")

    def detector_monitor_ids(self, detector_id, attempts=10, delay=2):
        """Poll the detectors-config index until the detector's monitor id(s) exist."""
        for _ in range(attempts):
            resp = self.get(f"/{C.DETECTORS_CONFIG_INDEX}/_doc/{detector_id}")
            if resp.status_code == 200:
                monitors = resp.json()["_source"]["detector"].get("monitor_id", [])
                if monitors:
                    return monitors
            time.sleep(delay)
        return []

    def execute_monitor(self, monitor_id):
        """Run an alerting monitor on demand (no wait for its schedule)."""
        return self.post(f"{C.ALERTING}/monitors/{monitor_id}/_execute")

    def index_event(self, index, doc):
        """Index a single event document into an events data stream."""
        resp = self.post(f"/{index}/_doc", json=doc)
        assert resp.status_code in (200, 201), f"index event -> {resp.status_code}: {resp.text}"
        return resp

    def findings(self, detector_type):
        """Return the Security Analytics findings body for a detector type."""
        resp = self.get(C.SA_FINDINGS, params={"detectorType": detector_type})
        assert resp.status_code == 200, f"findings search -> {resp.status_code}: {resp.text}"
        return resp.json()

    def finding_doc_ids(self, detector_type):
        """Return the set of event doc ids referenced by this detector's findings."""
        ids = set()
        for finding in self.findings(detector_type).get("findings", []):
            ids.update(finding.get("related_doc_ids", []))
        return ids


def matched_titles(logtest_response):
    """Extract matched rule titles from a logtest response body.

    Shape (validated live): ``message.detection.matches[].rule.title``.
    """
    message = logtest_response.get("message", {})
    if not isinstance(message, dict):
        return []
    matches = message.get("detection", {}).get("matches", [])
    return [m.get("rule", {}).get("title", "") for m in matches]
