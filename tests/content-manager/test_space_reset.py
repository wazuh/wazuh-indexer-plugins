"""Space-reset endpoint coverage: only draft is resettable."""

import pytest

from lib import constants as C

pytestmark = [pytest.mark.smoke]


def test_reset_draft_clears_resources(client, integration, decoder, rule):
    # The fixtures populate draft with an integration, decoder and rule.
    assert client.count_by_space(C.INDEX_INTEGRATIONS, C.SPACE_DRAFT) >= 1

    resp = client.reset_space(C.SPACE_DRAFT)
    assert resp.status_code == 200, resp.text

    assert client.count_by_space(C.INDEX_INTEGRATIONS, C.SPACE_DRAFT) == 0
    assert client.count_by_space(C.INDEX_DECODERS, C.SPACE_DRAFT) == 0
    assert client.count_by_space(C.INDEX_RULES, C.SPACE_DRAFT) == 0
    # The default draft policy is regenerated.
    assert client.get_draft_policy() is not None


@pytest.mark.parametrize("space", [C.SPACE_TEST, C.SPACE_CUSTOM])
def test_reset_non_draft_rejected(client, space):
    resp = client.delete(f"{C.SPACE}/{space}")
    assert resp.status_code == 400, resp.text
