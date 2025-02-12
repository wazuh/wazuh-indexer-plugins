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
package com.wazuh.contentmanager.action.commandmanager;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BytesRestResponse;

import java.io.IOException;

import com.wazuh.contentmanager.client.commandmanager.CommandManagerClient;

public class PostCommand {

    public static BytesRestResponse createCommand() throws IOException, IllegalArgumentException {
        XContent xContent = XContentType.JSON.xContent();
        XContentBuilder builder = XContentFactory.jsonBuilder();
        SimpleHttpResponse response =
                CommandManagerClient.getInstance().sendCommand("", null, (Header) null);
        return new BytesRestResponse(RestStatus.fromCode(200), "");
    }
}
