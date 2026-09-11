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

import org.opensearch.common.util.concurrent.ThreadContext;

/**
 * Resolves the name of the authenticated caller from the security plugin's thread-context
 * transient. This is the only source of truth for session ownership: a value the client sends for
 * {@code user} is never consulted, which is what makes the field unforgeable.
 *
 * <p>The transient is read directly rather than through {@code
 * org.opensearch.commons.authuser.User}, which would pull {@code common-utils} into a plugin that
 * deliberately carries almost no dependencies. Reading it by hand means matching that canonical
 * reader exactly, escaping included — see {@link #parse(String)}.
 */
public final class AuthenticatedUser {

    /**
     * Thread-context transient the security plugin populates with the authenticated user. Literal
     * rather than {@code ConfigConstants.OPENSEARCH_SECURITY_USER_INFO_THREAD_CONTEXT}, for the
     * dependency reason given in the class Javadoc.
     */
    public static final String USER_INFO_TRANSIENT = "_opendistro_security_user_info";

    /**
     * Matches a {@code '|'} that is not preceded by a backslash, so an escaped {@code "\|"} inside a
     * field is not mistaken for a field separator. Same expression the canonical reader uses.
     */
    private static final String UNESCAPED_SEPARATOR = "(?<!\\\\)\\|";

    /**
     * Owner stamped on a session when no principal can be resolved — that is, when the security
     * plugin is not installed, as in this module's {@code integTest} cluster.
     *
     * <p>Treated as a real owner rather than as a bypass: documents are stamped with it and the
     * ownership filter matches on it, so the tests exercise the whole stamp-and-scope path. It is the
     * same sentinel the Dashboard uses ({@code CONVERSATION_OWNER_FALLBACK}). With security enabled
     * there is always a principal, so this value is unreachable in production. A cluster once run
     * without security could hold {@code _shared} documents that a later user literally named {@code
     * _shared} would inherit; the sessions ISM policy deletes them after seven days.
     */
    public static final String SHARED_OWNER = "_shared";

    private AuthenticatedUser() {}

    /**
     * Resolves the caller's name from the given thread context.
     *
     * <p>Must be called <em>before</em> the context is stashed for a privileged client call — a
     * stashed context no longer carries the transient.
     *
     * @param threadContext the thread context of the request being served.
     * @return the authenticated user's name, or {@link #SHARED_OWNER} when there is none.
     */
    public static String resolve(ThreadContext threadContext) {
        if (threadContext == null) {
            return SHARED_OWNER;
        }
        return parse(threadContext.getTransient(USER_INFO_TRANSIENT));
    }

    /**
     * Extracts the user name from a raw {@value #USER_INFO_TRANSIENT} value.
     *
     * <p>The transient is {@code name|backend_roles|roles|requested_tenant}, and the security plugin
     * escapes any {@code '|'} occurring inside a field as {@code "\|"} before joining them — {@code
     * PrivilegesEvaluatorImpl} runs the name through {@code SecurityUtils.escapePipe}. So the name is
     * everything up to the first <em>unescaped</em> separator, unescaped in turn. Cutting at the
     * first {@code '|'} instead would truncate any name that contains one.
     *
     * <p>That truncation is not cosmetic. The value stamped on a session has to equal the {@code
     * ${user.name}} the read-side DLS filter substitutes; if it does not, the owner writes sessions
     * they can never read back — the same asymmetry this whole endpoint exists to remove. Names
     * carrying a pipe are ordinary: a federated subject such as an OIDC {@code auth0|68f3c1a9} or an
     * LDAP DN, and OpenSearch accepts an internal user named {@code ad|min}. Truncating would also
     * collapse every {@code auth0|*} subject onto one shared owner.
     *
     * <p>Mirrors {@code org.opensearch.commons.authuser.User#parse} field for field, deliberately,
     * including its blind spot: the writer escapes {@code '|'} but not the backslash itself, so a
     * name ending in a backslash stays ambiguous on the wire. Agreeing with the canonical reader
     * matters more than being cleverer than it.
     *
     * @param userInfo the transient's value, or {@code null} when absent.
     * @return the caller's name, or {@link #SHARED_OWNER} when the value is null, blank, or carries
     *     no name.
     */
    public static String parse(String userInfo) {
        if (userInfo == null || userInfo.isBlank()) {
            return SHARED_OWNER;
        }
        String[] fields = userInfo.split(UNESCAPED_SEPARATOR);
        if (fields.length == 0) {
            return SHARED_OWNER;
        }
        String name = fields[0].trim().replace("\\|", "|");
        return name.isBlank() ? SHARED_OWNER : name;
    }
}
