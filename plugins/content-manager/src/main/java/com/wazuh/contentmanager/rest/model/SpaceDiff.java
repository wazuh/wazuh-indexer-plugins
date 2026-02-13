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
import com.wazuh.contentmanager.utils.Constants;

public class SpaceDiff {

    @JsonProperty(value = Constants.KEY_SPACE, required = true)
    private Space space;

    @JsonProperty(value = Constants.KEY_CHANGES, required = true)
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
        @JsonProperty(value = Constants.KEY_POLICY, required = true)
        private List<OperationItem> policy;

        @JsonProperty(value = Constants.KEY_INTEGRATIONS, required = true)
        private List<OperationItem> integrations;

        @JsonProperty(value = Constants.KEY_KVDBS, required = true)
        private List<OperationItem> kvdbs;

        @JsonProperty(value = Constants.KEY_DECODERS, required = true)
        private List<OperationItem> decoders;

        @JsonProperty(value = Constants.KEY_FILTERS, required = true)
        private List<OperationItem> filters;

        @JsonProperty(value = Constants.KEY_RULES, required = true)
        private List<OperationItem> rules;

        @JsonProperty(value = Constants.KEY_IOCS, required = true)
        private List<OperationItem> iocs;

        public List<OperationItem> getRules() {
            return this.rules;
        }

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

        public void setRules(List<OperationItem> rules) {
            this.rules = rules;
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

        public List<OperationItem> getIocs() {
            return this.iocs;
        }

        public void setIocs(List<OperationItem> iocs) {
            this.iocs = iocs;
        }
    }

    public static class OperationItem {
        @JsonProperty(Constants.KEY_OPERATION)
        private Operation operation;

        @JsonProperty(Constants.KEY_ID)
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
        REMOVE;

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
