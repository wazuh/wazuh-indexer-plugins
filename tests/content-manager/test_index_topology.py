"""Threat-intel content index topology.

The setup plugin — not the Content Manager — provisions every
``wazuh-threatintel-*`` content index (``ContentIndex`` in the setup plugin):
each public alias is created pointing at a physical ``<alias>-a`` index, and
the Content Manager now waits for the setup plugin's readiness marker before
its first write and aborts its own initialization if the setup plugin is
absent, rather than falling back to creating the indices itself.

This guards against issue #1476: if a write reaches the alias name before the
setup plugin provisions the alias, OpenSearch auto-creates a concrete index
called ``<alias>`` itself, with dynamic mappings whose fields cannot be
aggregated or sorted on. The resource-lifecycle and vulnerabilities-content
tests only ever address indices by the alias name, so they would still pass
against such a squatted index — this is the one place the suite would catch
that regression.
"""

import pytest

from lib import assertions as A
from lib import constants as C

pytestmark = [pytest.mark.topology]


@pytest.mark.parametrize("alias", C.CONTENT_INDEX_ALIASES)
def test_alias_resolves_to_physical_index(client, alias):
    A.assert_alias_backed(client, alias)
