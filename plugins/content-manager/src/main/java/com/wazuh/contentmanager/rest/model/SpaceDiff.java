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
package com.wazuh.contentmanager.rest.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.cti.catalog.model.Space;

public class SpaceDiff {

    @JsonProperty(value = "space", required = true)
    private Space space;

    @JsonProperty(value = "changes", required = true)
    private Changes changes;

    public Space getSpace() {
        return this.space;
    }

    public void setSpace(Space space) {
        this.space = space;
    }

    public Changes getChanges() {
        return this.changes;
    }

    public void setChanges(Changes changes) {
        this.changes = changes;
    }

    public static class Changes {
        @JsonProperty(value = "policy", required = true)
        private List<OperationItem> policy;

        @JsonProperty(value = "integrations", required = true)
        private List<OperationItem> integrations;

        @JsonProperty(value = "kvdbs", required = true)
        private List<OperationItem> kvdbs;

        @JsonProperty(value = "decoders", required = true)
        private List<OperationItem> decoders;

        @JsonProperty(value = "filters", required = true)
        private List<OperationItem> filters;

        public List<OperationItem> getPolicy() {
            return this.policy;
        }

        public void setPolicy(List<OperationItem> policy) {
            this.policy = policy;
        }

        public List<OperationItem> getIntegrations() {
            return this.integrations;
        }

        public void setIntegrations(List<OperationItem> integrations) {
            this.integrations = integrations;
        }

        public List<OperationItem> getKvdbs() {
            return this.kvdbs;
        }

        public void setKvdbs(List<OperationItem> kvdbs) {
            this.kvdbs = kvdbs;
        }

        public List<OperationItem> getDecoders() {
            return this.decoders;
        }

        public void setDecoders(List<OperationItem> decoders) {
            this.decoders = decoders;
        }

        public List<OperationItem> getFilters() {
            return this.filters;
        }

        public void setFilters(List<OperationItem> filters) {
            this.filters = filters;
        }
    }

    public static class OperationItem {
        @JsonProperty("operation")
        private Operation operation;

        @JsonProperty("id")
        private String id;

        public Operation getOperation() {
            return this.operation;
        }

        public void setOperation(Operation operation) {
            this.operation = operation;
        }

        public String getId() {
            return this.id;
        }

        public void setId(String id) {
            this.id = id;
        }
    }

    public enum Operation {
        ADD,
        UPDATE,
        DELETE;

        @JsonValue
        @Override
        public String toString() {
            return this.name().toLowerCase(Locale.ROOT);
        }

        @JsonCreator
        public static Operation fromValue(String value) {
            for (Operation op : Operation.values()) {
                if (op.toString().equalsIgnoreCase(value)) {
                    return op;
                }
            }
            throw new IllegalArgumentException("Unknown operation: " + value);
        }
    }
}
