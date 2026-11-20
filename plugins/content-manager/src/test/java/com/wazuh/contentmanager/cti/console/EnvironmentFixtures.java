/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.console;

/**
 * CTI Console answers to {@code GET /platform/environments/me}, shared by the unit and integration
 * tests of the environment pass-through in {@code GET /subscription}.
 */
public final class EnvironmentFixtures {

    /** Name of the plan of {@link #REGISTERED}. */
    public static final String PLAN_NAME = "Pro";

    /** Consumer type of the only feature of the plan of {@link #REGISTERED}. */
    public static final String FEATURE_TYPE = "cti:catalog:consumer:vulnerabilities";

    /** Resource of the only feature of the plan of {@link #REGISTERED}. */
    public static final String FEATURE_RESOURCE =
            "https://cti.example/api/v1/catalog/contexts/pro-vulnerabilities/consumers/pro-vulnerabilities";

    /**
     * A registered environment with every case the pass-through must keep as received:
     *
     * <ul>
     *   <li>fields in an order that is not alphabetical;
     *   <li>ISO 8601 UTC dates ({@code registered_at}, {@code started_at}, ...);
     *   <li>{@code null} in each field the CTI Console may leave empty ({@code interval}, {@code
     *       renews_at}, {@code expires_at}, {@code past_due_ends_at});
     *   <li>a field the plugin does not know ({@code limits}), holding an integer, a boolean, an
     *       object and an array.
     * </ul>
     */
    // spotless:off
    public static final String REGISTERED = """
        {
          "name": "environment-01",
          "registered_at": "2026-02-14T09:30:00Z",
          "organization": { "name": "Acme Corp" },
          "plans": [
            {
              "name": "Pro",
              "is_public": false,
              "features": [
                {
                  "name": "Vulnerability CVE Stream",
                  "description": "Delta updates for vulnerability entries in the Wazuh CTI catalog.",
                  "resource": "https://cti.example/api/v1/catalog/contexts/pro-vulnerabilities/consumers/pro-vulnerabilities",
                  "type": "cti:catalog:consumer:vulnerabilities"
                }
              ]
            }
          ],
          "subscriptions": [
            {
              "plan": "Pro",
              "interval": "year",
              "started_at": "2026-03-01T10:00:00Z",
              "renews_at": "2027-03-01T10:00:00Z",
              "expires_at": null,
              "past_due_ends_at": null
            },
            {
              "plan": "Pro",
              "interval": null,
              "started_at": "2025-03-01T10:00:00Z",
              "renews_at": null,
              "expires_at": "2026-03-01T10:00:00Z",
              "past_due_ends_at": null
            }
          ],
          "limits": {
            "agents": 500,
            "unlimited_retention": false,
            "support": { "tier": "standard" },
            "regions": ["eu-west", "us-east"]
          }
        }""";
    // spotless:on

    /**
     * {@link #REGISTERED} as the CTI Console answered before it added {@code registered_at} and
     * {@code subscriptions}: the same plan, without the fields the plugin does not read.
     */
    // spotless:off
    public static final String REGISTERED_PLAN_ONLY = """
        {
          "name": "environment-01",
          "organization": { "name": "Acme Corp" },
          "plans": [
            {
              "name": "Pro",
              "is_public": false,
              "features": [
                {
                  "name": "Vulnerability CVE Stream",
                  "description": "Delta updates for vulnerability entries in the Wazuh CTI catalog.",
                  "resource": "https://cti.example/api/v1/catalog/contexts/pro-vulnerabilities/consumers/pro-vulnerabilities",
                  "type": "cti:catalog:consumer:vulnerabilities"
                }
              ]
            }
          ]
        }""";
    // spotless:on

    private EnvironmentFixtures() {}
}
