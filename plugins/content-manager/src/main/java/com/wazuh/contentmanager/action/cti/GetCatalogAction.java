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
import org.apache.hc.core5.http.Header;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.*;
import org.opensearch.rest.BytesRestResponse;

import java.io.IOException;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.model.ctiapi.ContextConsumerCatalog;
import com.wazuh.contentmanager.privileged.PrivilegedHttpAction;

/**
 * Action class handling Catalog logic. This is mainly useful to get the last offset value, as well
 * as the link of the latest snapshot
 */
public class GetCatalogAction {

    /** Empty constructor */
    public GetCatalogAction() {}

    /**
     * Submits a catalog query to the CTI API
     *
     * @return The parsed response from the CTI API
     * @throws IOException rethrown from parse()
     * @throws IllegalArgumentException rethrown from parse()
     */
    public static BytesRestResponse run() throws IOException, IllegalArgumentException {
        XContent xContent = XContentType.JSON.xContent();
        XContentBuilder builder = XContentFactory.jsonBuilder();
        SimpleHttpResponse response =
                PrivilegedHttpAction.get(
                        ContentManagerPlugin.CTI_VD_CONSUMER_URL, null, null, (Header) null);
        ContextConsumerCatalog.parse(
                        xContent.createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.IGNORE_DEPRECATIONS,
                                response.getBodyBytes()))
                .toXContent(builder, ToXContent.EMPTY_PARAMS);
        return new BytesRestResponse(RestStatus.fromCode(response.getCode()), builder.toString());
    }
}
