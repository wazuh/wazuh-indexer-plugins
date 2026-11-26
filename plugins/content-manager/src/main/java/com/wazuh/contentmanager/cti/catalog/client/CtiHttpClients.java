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
package com.wazuh.contentmanager.cti.catalog.client;

import org.apache.hc.client5.http.impl.async.HttpAsyncClientBuilder;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.ssl.TLS;
import org.apache.hc.core5.reactor.IOReactorConfig;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.Timeout;

import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Builds the HTTP clients that connect to Wazuh CTI, so that all of them handle the proxy, TLS and
 * User-Agent the same way.
 *
 * <p>The clients honour the JVM networking properties, set in {@code jvm.options.d/} or {@code
 * OPENSEARCH_JAVA_OPTS}: {@code https.proxyHost}, {@code https.proxyPort}, {@code
 * http.nonProxyHosts}, and {@code https.proxyUser} / {@code https.proxyPassword} for a proxy that
 * asks for credentials.
 */
public final class CtiHttpClients {

    private CtiHttpClients() {}

    /**
     * Returns a builder for an asynchronous CTI client.
     *
     * @param socketTimeout socket timeout of the client's I/O reactor.
     * @return the builder, to which the caller may add its own strategies before building it.
     */
    public static HttpAsyncClientBuilder asyncBuilder(Timeout socketTimeout) {
        return HttpAsyncClients.custom()
                .useSystemProperties()
                .setUserAgent(PluginSettings.getInstance().getUserAgent())
                .setIOReactorConfig(IOReactorConfig.custom().setSoTimeout(socketTimeout).build())
                .setConnectionManager(
                        PoolingAsyncClientConnectionManagerBuilder.create()
                                .setTlsStrategy(tlsStrategy().buildAsync())
                                .build());
    }

    /**
     * Returns a builder for a blocking CTI client.
     *
     * @return the builder.
     */
    public static HttpClientBuilder classicBuilder() {
        return HttpClients.custom()
                .useSystemProperties()
                .setUserAgent(PluginSettings.getInstance().getUserAgent())
                .setConnectionManager(
                        PoolingHttpClientConnectionManagerBuilder.create()
                                .setTlsSocketStrategy(tlsStrategy().buildClassic())
                                .build());
    }

    /**
     * JDK truststore and hostname verification. Honours {@code javax.net.ssl.trustStore*}, so an
     * operator behind a TLS-intercepting proxy adds its CA instead of disabling checks.
     */
    private static ClientTlsStrategyBuilder tlsStrategy() {
        return ClientTlsStrategyBuilder.create()
                .setSslContext(SSLContexts.createSystemDefault())
                .setTlsVersions(TLS.V_1_2, TLS.V_1_3);
    }
}
