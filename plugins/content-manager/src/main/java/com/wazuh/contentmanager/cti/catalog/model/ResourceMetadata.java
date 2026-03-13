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
package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Shared metadata model for all catalog resources. Contains the common fields that are nested under
 * {@code document.metadata} in the indexed document.
 *
 * <p>Resource-specific fields:
 *
 * <ul>
 *   <li>{@code compatibility} — used only by {@link Policy} resources.
 *   <li>{@code supports} — used by Integration, Decoder, Rule, KVDB, and Filter resources.
 * </ul>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResourceMetadata {

    private static final String TITLE_KEY = "title";
    private static final String AUTHOR_KEY = "author";
    private static final String DATE_KEY = "date";
    private static final String MODIFIED_KEY = "modified";
    private static final String DESCRIPTION_KEY = "description";
    private static final String REFERENCES_KEY = "references";
    private static final String DOCUMENTATION_KEY = "documentation";
    private static final String COMPATIBILITY_KEY = "compatibility";
    private static final String SUPPORTS_KEY = "supports";

    @JsonProperty(TITLE_KEY)
    private String title;

    @JsonProperty(AUTHOR_KEY)
    private String author;

    @JsonProperty(DATE_KEY)
    private String date;

    @JsonProperty(MODIFIED_KEY)
    private String modified;

    @JsonProperty(DESCRIPTION_KEY)
    private String description;

    @JsonProperty(REFERENCES_KEY)
    private List<String> references;

    @JsonProperty(DOCUMENTATION_KEY)
    private String documentation;

    @JsonProperty(COMPATIBILITY_KEY)
    private List<String> compatibility;

    @JsonProperty(SUPPORTS_KEY)
    private List<String> supports;

    /** Default constructor. */
    public ResourceMetadata() {}

    /**
     * Creates a new ResourceMetadata with all common fields.
     *
     * @param title the resource title
     * @param author the author name
     * @param date the creation date (ISO-8601)
     * @param modified the last modification date (ISO-8601)
     * @param description the resource description
     * @param references list of reference URLs
     * @param documentation documentation text or URL
     */
    public ResourceMetadata(
            String title,
            String author,
            String date,
            String modified,
            String description,
            List<String> references,
            String documentation) {
        this.title = title;
        this.author = author;
        this.date = date;
        this.modified = modified;
        this.description = description;
        this.references = references != null ? references : new ArrayList<>();
        this.documentation = documentation;
    }

    // --- Getters and Setters ---

    public String getTitle() {
        return this.title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getAuthor() {
        return this.author;
    }

    public void setAuthor(String author) {
        this.author = author;
    }

    public String getDate() {
        return this.date;
    }

    public void setDate(String date) {
        this.date = date;
    }

    public String getModified() {
        return this.modified;
    }

    public void setModified(String modified) {
        this.modified = modified;
    }

    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public List<String> getReferences() {
        return this.references;
    }

    public void setReferences(List<String> references) {
        this.references = references != null ? references : new ArrayList<>();
    }

    public String getDocumentation() {
        return this.documentation;
    }

    public void setDocumentation(String documentation) {
        this.documentation = documentation;
    }

    public List<String> getCompatibility() {
        return this.compatibility;
    }

    public void setCompatibility(List<String> compatibility) {
        this.compatibility = compatibility != null ? compatibility : new ArrayList<>();
    }

    public List<String> getSupports() {
        return this.supports;
    }

    public void setSupports(List<String> supports) {
        this.supports = supports != null ? supports : new ArrayList<>();
    }

    @Override
    public String toString() {
        return "ResourceMetadata{"
                + "title='"
                + this.title
                + '\''
                + ", author='"
                + this.author
                + '\''
                + ", date='"
                + this.date
                + '\''
                + ", modified='"
                + this.modified
                + '\''
                + ", description='"
                + this.description
                + '\''
                + ", references="
                + this.references
                + ", documentation='"
                + this.documentation
                + '\''
                + ", compatibility="
                + this.compatibility
                + ", supports="
                + this.supports
                + '}';
    }
}
