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
package com.wazuh.contentmanager.action.cti;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.opensearch.rest.RestRequest;

import java.net.URI;

import com.wazuh.contentmanager.util.http.HttpClient;

public class GetConsumers {
    public static SimpleHttpResponse handleGet(RestRequest request) {
        if (request.hasContent()) {
            request.content();
        }
        return HttpClient.getInstance()
                .get(
                        URI.create(ContextConsumers.CVE_EXPLORER.getContextConsumerEndpoint()),
                        null,
                        (org.apache.hc.core5.http.Header) null);
    }
}
