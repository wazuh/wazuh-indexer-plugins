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

public enum ContextConsumersEnum {
    CVE_EXPLORER("vdp_all_vendors", "cve-explorer"),
    VD("vd_1.0.0", "vd_4.8.0");

    private final String contextConsumerEndpoint;
    private final String context;
    private final String consumer;

    ContextConsumersEnum(String context, String consumer) {
        this.contextConsumerEndpoint = EndpointsEnum.CONTEXT_CONSUMER.format(context, consumer);
        this.context = context;
        this.consumer = consumer;
    }

    public String getConsumer() {
        return consumer;
    }

    public String getContext() {
        return context;
    }

    public String getContextConsumerEndpoint() {
        return this.contextConsumerEndpoint;
    }
}
