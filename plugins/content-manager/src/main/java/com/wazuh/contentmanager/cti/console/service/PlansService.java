/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.console.service;

import java.util.List;

import com.wazuh.contentmanager.cti.console.client.ClosableHttpClient;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;

/** Service interface definition for managing CTI Plans. */
public interface PlansService extends ClosableHttpClient {

    /**
     * Retrieves the list of available CTI plans authorized by the provided token.
     *
     * @param token the authentication {@link Token} required to validate the request.
     * @return a {@link List} of {@link Plan} objects available to the user. Returns an empty list if
     *     no plans are found.
     */
    List<Plan> getPlans(Token token);
}
