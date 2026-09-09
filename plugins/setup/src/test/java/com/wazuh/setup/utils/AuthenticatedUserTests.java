/*
 * Copyright (C) 2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.setup.utils;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.test.OpenSearchTestCase;

/**
 * Unit tests for {@link AuthenticatedUser}, which derives session ownership from the security
 * plugin's thread-context transient. This is the half of the fix that cannot be integration-tested
 * in this module: its {@code integTest} cluster runs without the security plugin, so it has exactly
 * one identity and no transient at all.
 */
public class AuthenticatedUserTests extends OpenSearchTestCase {

    public void testParseTakesTheNameBeforeTheFirstSeparator() {
        assertEquals("qadls-probe", AuthenticatedUser.parse("qadls-probe|||"));
        assertEquals(
                "wazuh-readonly",
                AuthenticatedUser.parse("wazuh-readonly|backend1,backend2|wazuh_readonly,own_index|"));
        assertEquals(
                "admin", AuthenticatedUser.parse("admin|admin|all_access,own_index|global_tenant"));
    }

    public void testParseAcceptsAValueCarryingNoSeparator() {
        assertEquals("admin", AuthenticatedUser.parse("admin"));
    }

    public void testParseFallsBackToTheSharedOwner() {
        assertEquals(AuthenticatedUser.SHARED_OWNER, AuthenticatedUser.parse(null));
        assertEquals(AuthenticatedUser.SHARED_OWNER, AuthenticatedUser.parse(""));
        assertEquals(AuthenticatedUser.SHARED_OWNER, AuthenticatedUser.parse("   "));
        // A transient whose name half is empty, e.g. a malformed value.
        assertEquals(AuthenticatedUser.SHARED_OWNER, AuthenticatedUser.parse("|roles|roles|tenant"));
    }

    public void testParseKeepsANameThatIsLiterallyTheSentinel() {
        // Not special-cased: `_shared` is treated as a real owner name, so such a document is
        // reachable only by that same name. See AuthenticatedUser#SHARED_OWNER.
        assertEquals("_shared", AuthenticatedUser.parse("_shared|||"));
    }

    public void testResolveReadsTheTransient() {
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        threadContext.putTransient(
                AuthenticatedUser.USER_INFO_TRANSIENT, "qadls-probe|backend|own_index|");
        assertEquals("qadls-probe", AuthenticatedUser.resolve(threadContext));
    }

    public void testResolveWithoutTheTransientYieldsTheSharedOwner() {
        // The security-disabled case, which is what this module's integTest cluster runs.
        assertEquals(
                AuthenticatedUser.SHARED_OWNER,
                AuthenticatedUser.resolve(new ThreadContext(Settings.EMPTY)));
        assertEquals(AuthenticatedUser.SHARED_OWNER, AuthenticatedUser.resolve(null));
    }
}
