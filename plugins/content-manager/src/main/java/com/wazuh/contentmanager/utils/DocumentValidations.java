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
package com.wazuh.contentmanager.utils;

import org.opensearch.action.get.GetResponse;
import org.opensearch.transport.client.Client;

import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Space;

import static com.wazuh.contentmanager.utils.Constants.KEY_NAME;
import static com.wazuh.contentmanager.utils.Constants.KEY_SPACE;

public class DocumentValidations {

    /**
     * Validates that a document exists and is in the draft space.
     *
     * @param client the OpenSearch client
     * @param index the index to search in
     * @param docId document ID to validate
     * @param docType the document type name for error messages (e.g., "Decoder", "Integration")
     * @return an error message if validation fails, null otherwise
     */
    public static String validateDocumentInSpace(
            Client client, String index, String docId, String docType) {
        GetResponse decoderResponse = client.prepareGet(index, docId).get();

        if (!decoderResponse.isExists()) {
            return docType + " [" + docId + "] not found.";
        }

        Map<String, Object> source = decoderResponse.getSourceAsMap();
        if (source == null || !source.containsKey(KEY_SPACE)) {
            return docType + " [" + docId + "] does not have space information.";
        }

        Object spaceObj = source.get(KEY_SPACE);
        if (!(spaceObj instanceof Map)) {
            return docType + " [" + docId + "] has invalid space information.";
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> spaceMap = (Map<String, Object>) spaceObj;
        Object spaceName = spaceMap.get(KEY_NAME);

        if (!Space.DRAFT.equals(String.valueOf(spaceName))) {
            return docType + " [" + docId + "] is not in draft space.";
        }

        return null;
    }
}
