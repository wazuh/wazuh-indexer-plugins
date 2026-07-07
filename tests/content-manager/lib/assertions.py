"""Reusable assertions over stored Content Manager documents.

Names mirror the Java integration-test helpers (``assertResourceExistsInDraft``
etc.) so conventions stay consistent across the codebase.
"""

from . import constants as C


def assert_in_index(client, index, doc_id, space=None):
    """Assert a CTI resource id exists in ``index`` (optionally in ``space``)."""
    source = client.get_doc(index, doc_id)
    assert source is not None, f"document.id [{doc_id}] not found in [{index}]"
    if space is not None:
        assert_space_name(source, space)
    return source


def assert_not_in_index(client, index, doc_id):
    """Assert a CTI resource id is absent from ``index``."""
    assert client.get_doc(index, doc_id) is None, f"document.id [{doc_id}] still present in [{index}]"


def assert_space_name(source, expected):
    """Assert the ``space.name`` of a stored ``_source`` document."""
    actual = source.get("space", {}).get("name")
    assert actual == expected, f"expected space.name [{expected}], got [{actual}]"


def assert_hash_present(source):
    """Assert the document carries a non-empty ``hash.sha256``."""
    digest = source.get("hash", {}).get("sha256")
    assert digest, f"expected a non-empty hash.sha256, got [{digest}]"
    return digest


def space_hash(client, space):
    """Return the ``space.hash.sha256`` for a space's policy document."""
    policy = client.get_policy(space)
    assert policy is not None, f"no policy found for space [{space}]"
    return policy.get("space", {}).get("hash", {}).get("sha256")


def assert_space_hash_changed(before, after):
    """Assert two space-hash values differ (an engine-relevant change happened)."""
    assert before != after, f"expected space.hash.sha256 to change, stayed [{before}]"


def assert_listed_in_draft_policy(client, field, doc_id):
    """Assert ``doc_id`` is present in the draft policy ``field`` list (e.g. integrations)."""
    policy = client.get_draft_policy()
    assert policy is not None, "draft policy not found"
    values = policy.get("document", {}).get(field, [])
    assert doc_id in values, f"[{doc_id}] not listed in draft policy [{field}]: {values}"


def assert_in_integration_list(client, integration_id, field, doc_id):
    """Assert ``doc_id`` is listed in the integration's ``field`` (rules/decoders/kvdbs)."""
    source = client.get_doc(C.INDEX_INTEGRATIONS, integration_id)
    assert source is not None, f"integration [{integration_id}] not found"
    values = source.get("document", {}).get(field, [])
    assert doc_id in values, f"[{doc_id}] not listed in integration [{field}]: {values}"
