"""Pytest fixtures for the Content Manager component test suite.

The suite runs against a real, running wazuh-indexer cluster that has the
Content Manager plugin (and the Wazuh Engine) installed. Point it at a cluster
with ``--base-url`` (or the ``CM_BASE_URL`` env var).
"""

import os
import time

import pytest

from lib import constants as C
from lib import payloads as P
from lib.client import CMClient


# ── CLI / configuration ────────────────────────────────────────────────────


def pytest_addoption(parser):
    parser.addoption("--base-url", action="store", default=None, help="Indexer base URL, e.g. https://localhost:9200")
    parser.addoption("--user", action="store", default=None, help="API user (default: admin)")
    parser.addoption("--password", action="store", default=None, help="API password (default: admin)")


@pytest.fixture(scope="session")
def base_url(request):
    return request.config.getoption("--base-url") or os.environ.get("CM_BASE_URL", "https://localhost:9200")


@pytest.fixture(scope="session")
def client(request, base_url):
    user = request.config.getoption("--user") or os.environ.get("CM_USER", "admin")
    password = request.config.getoption("--password") or os.environ.get("CM_PASSWORD", "admin")
    return CMClient(base_url, user=user, password=password)


@pytest.fixture(scope="session", autouse=True)
def indexer_ready(client, base_url):
    """Fail fast unless the cluster is up and the draft policy exists.

    The draft policy is created by the initial content update/sync; its absence
    means the environment isn't provisioned, so every test would fail anyway.
    """
    deadline = time.time() + 60
    last = None
    while time.time() < deadline:
        try:
            resp = client.get("/_cluster/health")
            if resp.status_code == 200 and resp.json().get("status") in ("green", "yellow"):
                if client.get_draft_policy() is not None:
                    return
                last = "cluster healthy but no draft policy (run an update/sync first)"
            else:
                last = f"cluster health status={resp.status_code}"
        except Exception as exc:  # noqa: BLE001 - surfaced verbatim below
            last = str(exc)
        time.sleep(3)
    pytest.fail(f"Indexer at {base_url} not ready: {last}")


# ── Isolation + resource fixtures ──────────────────────────────────────────


@pytest.fixture
def reset_draft(client):
    """Reset the draft space to a clean state before the test runs."""
    resp = client.reset_space(C.SPACE_DRAFT)
    assert resp.status_code == 200, f"reset draft failed: {resp.status_code} {resp.text}"
    yield


@pytest.fixture
def integration(client, reset_draft):
    """A fresh draft integration. Returns ``{'id', 'title'}``."""
    title = "ct-integration"
    iid = client.create(C.INTEGRATIONS, P.make_integration(title=title))
    return {"id": iid, "title": title}


@pytest.fixture
def decoder(client, integration):
    """A decoder linked to ``integration``; returns its id."""
    return client.create(C.DECODERS, P.make_decoder(), integration=integration["id"])


@pytest.fixture
def kvdb(client, integration):
    """A KVDB linked to ``integration``; returns its id."""
    return client.create(C.KVDBS, P.make_kvdb(), integration=integration["id"])


@pytest.fixture
def rule(client, integration):
    """A rule linked to ``integration`` (logsource.product = integration title)."""
    return client.create(C.RULES, P.make_rule(product=integration["title"]), integration=integration["id"])
