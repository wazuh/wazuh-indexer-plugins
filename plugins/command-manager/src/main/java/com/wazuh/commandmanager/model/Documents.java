/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.model;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.ArrayList;

public class Documents implements ToXContentObject {
    private ArrayList<Document> documents;

    public Documents() {
        this.documents = new ArrayList<>();
    }

    /**
     * Default constructor
     *
     * @param documents
     */
    public Documents(ArrayList<Document> documents) {
        this.documents = documents;
    }

    /**
     * Get the list of Document objects.
     *
     * @return the list of documents.
     */
    public ArrayList<Document> getDocuments() {
        return documents;
    }

    /**
     * Set the list of Document objects.
     *
     * @param documents the list of documents to set.
     */
    public void setDocuments(ArrayList<Document> documents) {
        this.documents = documents;
    }

    /**
     * Adds a document to the list of documents.
     *
     * @param document The document to add to the list.
     */
    public void addDocument(Document document) {
        this.documents.add(document);
    }

    /**
     * Fit this object into a XContentBuilder parser, preparing it for the reply of POST /commands.
     *
     * @param builder XContentBuilder builder
     * @param params ToXContent.EMPTY_PARAMS
     * @return XContentBuilder builder with the representation of this object.
     * @throws IOException parsing error.
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startArray("_documents");
        for (Document document : this.documents) {
            builder.startObject();
            builder.field("_id", document.getId());
            builder.endObject();
        }
        return builder.endArray();
    }
}
