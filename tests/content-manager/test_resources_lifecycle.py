"""Resource lifecycle scenario: create -> update -> remove, plus policy and promotion.

Covers the full content lifecycle for every resource type (integration, decoder,
kvdb, rule, filter), the draft policy update, the promotion chain
(draft -> test -> custom) and the draft space reset.

NOTE: promotion permanently mutates the test/custom spaces (only draft is
resettable), so the promotion tests name their resources uniquely per run.
"""

import uuid

import pytest

from lib import assertions as A
from lib import constants as C
from lib import payloads as P


# ── Integrations ───────────────────────────────────────────────────────────


@pytest.mark.crud
class TestIntegrationLifecycle:
    def test_create(self, client, reset_draft):
        before = A.space_hash(client, C.SPACE_DRAFT)
        iid = client.create(C.INTEGRATIONS, P.make_integration(title="ct-create"))

        source = A.assert_in_index(client, C.INDEX_INTEGRATIONS, iid, space=C.SPACE_DRAFT)
        A.assert_hash_present(source)
        A.assert_listed_in_draft_policy(client, "integrations", iid)
        A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))

    def test_create_duplicate_title_rejected(self, client, integration):
        resp = client.post(C.INTEGRATIONS, json=P.make_integration(title=integration["title"]))
        assert resp.status_code == 400, resp.text
        assert "already exists" in resp.text

    def test_create_missing_title_rejected(self, client, reset_draft):
        body = P.make_integration()
        del body["resource"]["metadata"]["title"]
        resp = client.post(C.INTEGRATIONS, json=body)
        assert resp.status_code == 400, resp.text

    def test_update(self, client, integration):
        source = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
        body = P.integration_update(source)
        body["resource"]["metadata"]["description"] = "updated description"

        resp = client.put(f"{C.INTEGRATIONS}/{integration['id']}", json=body)
        assert resp.status_code == 200, resp.text

        updated = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
        assert updated["metadata"]["description"] == "updated description"

    def test_update_rejects_dependency_add(self, client, integration):
        source = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
        body = P.integration_update(source, decoders=["00000000-0000-0000-0000-000000000000"])

        resp = client.put(f"{C.INTEGRATIONS}/{integration['id']}", json=body)
        assert resp.status_code == 400, resp.text
        assert "cannot be added or removed" in resp.text

    def test_delete(self, client, integration):
        before = A.space_hash(client, C.SPACE_DRAFT)
        resp = client.delete(f"{C.INTEGRATIONS}/{integration['id']}")
        assert resp.status_code == 200, resp.text

        A.assert_not_in_index(client, C.INDEX_INTEGRATIONS, integration["id"])
        A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))

    def test_delete_with_dependencies_rejected(self, client, integration, decoder):
        resp = client.delete(f"{C.INTEGRATIONS}/{integration['id']}")
        assert resp.status_code == 400, resp.text
        assert "Cannot delete integration" in resp.text

    @pytest.mark.parametrize("bad_id", ["not-a-uuid", "00000000-0000-0000-0000-000000000000"])
    def test_update_unknown_id_not_found(self, client, reset_draft, bad_id):
        resp = client.put(f"{C.INTEGRATIONS}/{bad_id}", json=P.make_integration())
        assert resp.status_code == 404, resp.text

    @pytest.mark.parametrize("bad_id", ["not-a-uuid", "00000000-0000-0000-0000-000000000000"])
    def test_delete_unknown_id_not_found(self, client, reset_draft, bad_id):
        resp = client.delete(f"{C.INTEGRATIONS}/{bad_id}")
        assert resp.status_code == 404, resp.text


# ── Decoders ───────────────────────────────────────────────────────────────


@pytest.mark.crud
class TestDecoderLifecycle:
    def test_create(self, client, integration):
        before = A.space_hash(client, C.SPACE_DRAFT)
        did = client.create(C.DECODERS, P.make_decoder(), integration=integration["id"])

        source = A.assert_in_index(client, C.INDEX_DECODERS, did, space=C.SPACE_DRAFT)
        A.assert_hash_present(source)
        A.assert_in_integration_list(client, integration["id"], "decoders", did)
        A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))

    def test_create_without_integration_rejected(self, client, reset_draft):
        resp = client.post(C.DECODERS, json=P.make_decoder())
        assert resp.status_code == 400, resp.text

    def test_update(self, client, integration, decoder):
        body = P.make_decoder()
        body["resource"]["metadata"]["title"] = "Decoder updated"
        resp = client.put(f"{C.DECODERS}/{decoder}", json=body)
        assert resp.status_code == 200, resp.text
        assert client.get_doc(C.INDEX_DECODERS, decoder)["document"]["metadata"]["title"] == "Decoder updated"

    def test_delete(self, client, integration, decoder):
        resp = client.delete(f"{C.DECODERS}/{decoder}")
        assert resp.status_code == 200, resp.text
        A.assert_not_in_index(client, C.INDEX_DECODERS, decoder)
        source = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
        assert decoder not in source.get("decoders", [])


# ── KVDBs ──────────────────────────────────────────────────────────────────


@pytest.mark.crud
class TestKvdbLifecycle:
    def test_create(self, client, integration):
        before = A.space_hash(client, C.SPACE_DRAFT)
        kid = client.create(C.KVDBS, P.make_kvdb(), integration=integration["id"])

        source = A.assert_in_index(client, C.INDEX_KVDBS, kid, space=C.SPACE_DRAFT)
        A.assert_hash_present(source)
        A.assert_in_integration_list(client, integration["id"], "kvdbs", kid)
        A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))

    def test_create_without_integration_rejected(self, client, reset_draft):
        resp = client.post(C.KVDBS, json=P.make_kvdb())
        assert resp.status_code == 400, resp.text

    def test_update(self, client, integration, kvdb):
        resp = client.put(f"{C.KVDBS}/{kvdb}", json=P.make_kvdb(content={"key1": "updated"}))
        assert resp.status_code == 200, resp.text
        assert client.get_doc(C.INDEX_KVDBS, kvdb)["document"]["content"]["key1"] == "updated"

    def test_delete(self, client, integration, kvdb):
        resp = client.delete(f"{C.KVDBS}/{kvdb}")
        assert resp.status_code == 200, resp.text
        A.assert_not_in_index(client, C.INDEX_KVDBS, kvdb)
        source = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
        assert kvdb not in source.get("kvdbs", [])


# ── Rules ──────────────────────────────────────────────────────────────────


@pytest.mark.crud
class TestRuleLifecycle:
    def test_create(self, client, integration):
        before = A.space_hash(client, C.SPACE_DRAFT)
        rid = client.create(
            C.RULES, P.make_rule(product=integration["title"]), integration=integration["id"]
        )

        source = A.assert_in_index(client, C.INDEX_RULES, rid, space=C.SPACE_DRAFT)
        A.assert_hash_present(source)
        A.assert_in_integration_list(client, integration["id"], "rules", rid)
        A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))

    def test_create_product_mismatch_rejected(self, client, integration):
        body = P.make_rule(product="does-not-match-integration-title")
        resp = client.post(C.RULES, json={"integration": integration["id"], **body})
        assert resp.status_code == 400, resp.text

    def test_update(self, client, integration, rule):
        body = P.make_rule(product=integration["title"], title="Rule updated", level="medium")
        resp = client.put(f"{C.RULES}/{rule}", json=body)
        assert resp.status_code == 200, resp.text
        assert client.get_doc(C.INDEX_RULES, rule)["document"]["metadata"]["title"] == "Rule updated"

    def test_delete(self, client, integration, rule):
        resp = client.delete(f"{C.RULES}/{rule}")
        assert resp.status_code == 200, resp.text
        A.assert_not_in_index(client, C.INDEX_RULES, rule)
        source = client.get_doc(C.INDEX_INTEGRATIONS, integration["id"])["document"]
        assert rule not in source.get("rules", [])


# ── Filters ────────────────────────────────────────────────────────────────


@pytest.mark.crud
class TestFilterLifecycle:
    def test_create_and_delete(self, client, reset_draft):
        fid = client.create(C.FILTERS, P.make_filter(space=C.SPACE_DRAFT))
        A.assert_in_index(client, C.INDEX_FILTERS, fid, space=C.SPACE_DRAFT)

        resp = client.delete(f"{C.FILTERS}/{fid}")
        assert resp.status_code == 200, resp.text
        A.assert_not_in_index(client, C.INDEX_FILTERS, fid)

    def test_create_missing_title_rejected(self, client, reset_draft):
        body = P.make_filter(space=C.SPACE_DRAFT)
        del body["resource"]["metadata"]["title"]
        resp = client.post(C.FILTERS, json=body)
        assert resp.status_code == 400, resp.text


# ── Policy ─────────────────────────────────────────────────────────────────


@pytest.mark.policy
class TestPolicy:
    def test_update_draft_policy(self, client, integration, decoder):
        before = A.space_hash(client, C.SPACE_DRAFT)
        body = P.policy_body(root_decoder=decoder, integrations=[integration["id"]], enabled=True)
        resp = client.put(f"{C.POLICY}/{C.SPACE_DRAFT}", json=body)
        assert resp.status_code == 200, resp.text

        policy = client.get_draft_policy()["document"]
        assert policy["enabled"] is True
        assert policy["root_decoder"] == decoder
        A.assert_space_hash_changed(before, A.space_hash(client, C.SPACE_DRAFT))

    def test_reorder_integrations_ok(self, client, integration, decoder):
        body = P.policy_body(root_decoder=decoder, integrations=[integration["id"]])
        resp = client.put(f"{C.POLICY}/{C.SPACE_DRAFT}", json=body)
        assert resp.status_code == 200, resp.text

    def test_add_integration_rejected(self, client, integration, decoder):
        body = P.policy_body(
            root_decoder=decoder,
            integrations=[integration["id"], "00000000-0000-0000-0000-000000000000"],
        )
        resp = client.put(f"{C.POLICY}/{C.SPACE_DRAFT}", json=body)
        assert resp.status_code == 400, resp.text


# ── Promotion ──────────────────────────────────────────────────────────────


@pytest.fixture
def promotable(client, reset_draft):
    """Build a uniquely-named integration + decoder + rule in draft and wire the policy."""
    uid = uuid.uuid4().hex[:8]
    title = f"ct-promote-{uid}"
    iid = client.create(C.INTEGRATIONS, P.make_integration(title=title))
    did = client.create(C.DECODERS, P.make_decoder(name=f"decoder/{title}/0"), integration=iid)
    rid = client.create(C.RULES, P.make_rule(product=title, title=f"rule-{uid}"), integration=iid)
    resp = client.put(
        f"{C.POLICY}/{C.SPACE_DRAFT}", json=P.policy_body(root_decoder=did, integrations=[iid])
    )
    assert resp.status_code == 200, resp.text
    return {"title": title, "integration": iid, "decoder": did, "rule": rid}


def _promote(client, space):
    preview = client.get(C.PROMOTE, params={"space": space})
    assert preview.status_code == 200, preview.text
    changes = preview.json()["changes"]
    resp = client.post(C.PROMOTE, json={"space": space, "changes": changes})
    assert resp.status_code == 200, resp.text
    return changes


@pytest.mark.promote
class TestPromotion:
    def test_preview_reports_changes(self, client, promotable):
        preview = client.get(C.PROMOTE, params={"space": C.SPACE_DRAFT})
        assert preview.status_code == 200, preview.text
        changes = preview.json()["changes"]
        assert all(op["operation"] == "update" for op in changes.get("policy", []))
        assert promotable["rule"] in [c["id"] for c in changes.get("rules", [])]

    def test_promote_draft_to_test_then_custom(self, client, promotable):
        iid = promotable["integration"]

        _promote(client, C.SPACE_DRAFT)
        test_doc = client.get_doc_in_space(C.INDEX_INTEGRATIONS, iid, C.SPACE_TEST)
        assert test_doc is not None, "integration not present in test after promotion"
        draft_doc = client.get_doc_in_space(C.INDEX_INTEGRATIONS, iid, C.SPACE_DRAFT)
        assert draft_doc["hash"]["sha256"] == test_doc["hash"]["sha256"]

        _promote(client, C.SPACE_TEST)
        custom_doc = client.get_doc_in_space(C.INDEX_INTEGRATIONS, iid, C.SPACE_CUSTOM)
        assert custom_doc is not None, "integration not present in custom after promotion"
        assert test_doc["hash"]["sha256"] == custom_doc["hash"]["sha256"]

    def test_unknown_space_rejected(self, client, reset_draft):
        resp = client.get(C.PROMOTE, params={"space": "bogus"})
        assert resp.status_code == 400, resp.text


# ── Space reset ────────────────────────────────────────────────────────────


@pytest.mark.crud
class TestSpaceReset:
    def test_reset_draft_clears_resources(self, client, integration, decoder, rule):
        assert client.count_by_space(C.INDEX_INTEGRATIONS, C.SPACE_DRAFT) >= 1
        resp = client.reset_space(C.SPACE_DRAFT)
        assert resp.status_code == 200, resp.text

        assert client.count_by_space(C.INDEX_INTEGRATIONS, C.SPACE_DRAFT) == 0
        assert client.count_by_space(C.INDEX_DECODERS, C.SPACE_DRAFT) == 0
        assert client.count_by_space(C.INDEX_RULES, C.SPACE_DRAFT) == 0
        assert client.get_draft_policy() is not None

    @pytest.mark.parametrize("space", [C.SPACE_TEST, C.SPACE_CUSTOM])
    def test_reset_non_draft_rejected(self, client, space):
        resp = client.delete(f"{C.SPACE}/{space}")
        assert resp.status_code == 400, resp.text
