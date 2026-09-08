"""Vulnerabilities consumer content checks.

Once the vulnerabilities consumer reaches ``ready``, its first sync must have
loaded the expected document types into ``.wazuh-threatintel-vulnerabilities``.
A regression there left the index missing whole document types (OSCPE-GLOBAL,
FEED-GLOBAL, CNA-MAPPING-GLOBAL, TID, CVE) even though the consumer reported
ready, so these tests assert the ``type`` distribution directly.

The module fixture waits for ``cti:catalog:consumer:vulnerabilities`` to report
``ready`` before any assertion runs; the CI workflow already blocks on content
sync, so this is a bounded safety net rather than the primary wait.
"""

import time

import pytest

from lib import constants as C

pytestmark = [pytest.mark.vulnerabilities]

# How long to wait for the vulnerabilities consumer to become ready.
_READY_TIMEOUT = 900
_READY_POLL = 10


@pytest.fixture(scope="module")
def vulnerabilities_types(client):
    """Wait for the vulnerabilities consumer to be ready, then return the
    ``{type: doc_count}`` distribution of ``.wazuh-threatintel-vulnerabilities``."""
    deadline = time.time() + _READY_TIMEOUT
    last = None
    while time.time() < deadline:
        last = client.consumer_status(C.CONSUMER_VULNERABILITIES)
        if last == C.CONSUMER_STATUS_READY:
            break
        time.sleep(_READY_POLL)
    else:
        pytest.fail(
            f"vulnerabilities consumer '{C.CONSUMER_VULNERABILITIES}' did not reach "
            f"'{C.CONSUMER_STATUS_READY}' within {_READY_TIMEOUT}s (last status: {last!r})"
        )
    return client.terms_agg(C.INDEX_VULNERABILITIES, "type")


@pytest.mark.vulnerabilities
@pytest.mark.parametrize("doc_type", C.VULNERABILITY_REQUIRED_TYPES)
def test_required_type_present(vulnerabilities_types, doc_type):
    """At least one document of each required type is present."""
    count = vulnerabilities_types.get(doc_type, 0)
    assert count >= 1, (
        f"expected >= 1 document of type '{doc_type}' in {C.INDEX_VULNERABILITIES}, "
        f"found {count}. Present types: {sorted(vulnerabilities_types)}"
    )


@pytest.mark.vulnerabilities
def test_minimum_distinct_types(client, vulnerabilities_types):
    """The index holds at least the expected number of distinct document types."""
    # Assert on the same cardinality aggregation the issue references, and
    # cross-check it against the terms buckets used by the per-type tests.
    distinct = client.cardinality_agg(C.INDEX_VULNERABILITIES, "type")
    assert distinct >= C.VULNERABILITY_MIN_DISTINCT_TYPES, (
        f"expected >= {C.VULNERABILITY_MIN_DISTINCT_TYPES} distinct document types in "
        f"{C.INDEX_VULNERABILITIES}, cardinality reported {distinct}. "
        f"Present types: {sorted(vulnerabilities_types)}"
    )
    assert len(vulnerabilities_types) >= C.VULNERABILITY_MIN_DISTINCT_TYPES, (
        f"terms aggregation returned only {len(vulnerabilities_types)} types: "
        f"{sorted(vulnerabilities_types)}"
    )
