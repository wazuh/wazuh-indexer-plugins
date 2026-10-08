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

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.env.Environment;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/** Client responsible for downloading CTI snapshots from a remote source. */
public class SnapshotClient {

    private static final Logger log = LogManager.getLogger(SnapshotClient.class);
    private final Environment env;
    private final ResourceUrlResolver urlResolver;
    private final String consumerType;

    /**
     * Constructs a SnapshotClient with a URL resolver.
     *
     * @param env node's environment.
     * @param urlResolver the resolver used to transform resource URLs before making HTTP requests.
     * @param consumerType the consumer the snapshots belong to (e.g. {@code
     *     cti:catalog:consumer:vulnerabilities}), named in every log message of a download.
     */
    public SnapshotClient(Environment env, ResourceUrlResolver urlResolver, String consumerType) {
        this.env = env;
        this.urlResolver = urlResolver;
        this.consumerType = consumerType;
    }

    /**
     * Constructs a SnapshotClient with an regular URL resolver.
     *
     * @param env node's environment.
     * @param consumerType the consumer the snapshots belong to, named in the log messages.
     */
    public SnapshotClient(Environment env, String consumerType) {
        this(env, new RegularUrlResolver(), consumerType);
    }

    /***
     * Downloads the CTI snapshot.
     *
     * @param snapshotURI URI to the file to download.
     * @return The downloaded file's name, or null if the download failed
     * @throws IOException If an I/O error occurs during download.
     * @throws URISyntaxException If the provided URI is invalid.
     */
    public Path downloadFile(String snapshotURI) throws IOException, URISyntaxException {
        List<Header> defaultHeaders =
                List.of(
                        new BasicHeader(HttpHeaders.USER_AGENT, PluginSettings.getInstance().getUserAgent()));
        try (CloseableHttpClient client =
                HttpClients.custom().setDefaultHeaders(defaultHeaders).build()) {
            // Setup
            final URI uri = new URI(this.urlResolver.resolve(snapshotURI));
            final HttpGet request = new HttpGet(uri);
            request.addHeader(HttpHeaders.ACCEPT_ENCODING, Constants.ACCEPT_ENCODING_GZIP);
            final String filename = uri.getPath().substring(uri.getPath().lastIndexOf('/') + 1);
            final Path path = this.env.tmpDir().resolve(filename);

            // Download
            log.info(Constants.I_LOG_SNAPSHOT_DOWNLOAD_STARTED, this.consumerType, uri);
            try (CloseableHttpResponse response = client.execute(request)) {
                if (response.getCode() < 200 || response.getCode() >= 300) {
                    log.error(
                            Constants.E_LOG_SNAPSHOT_DOWNLOAD_HTTP_STATUS, this.consumerType, response.getCode());
                    return null;
                }

                if (response.getEntity() != null) {
                    // Write to disk
                    InputStream input = response.getEntity().getContent();
                    try (OutputStream out =
                            new BufferedOutputStream(
                                    Files.newOutputStream(
                                            path,
                                            StandardOpenOption.CREATE,
                                            StandardOpenOption.WRITE,
                                            StandardOpenOption.TRUNCATE_EXISTING))) {

                        int bytesRead;
                        byte[] buffer = new byte[1024];
                        while ((bytesRead = input.read(buffer)) != -1) {
                            out.write(buffer, 0, bytesRead);
                        }
                    }
                } else {
                    log.error(Constants.E_LOG_SNAPSHOT_DOWNLOAD_EMPTY_RESPONSE, this.consumerType);
                    return null;
                }
            }
            log.info(Constants.I_LOG_SNAPSHOT_DOWNLOADED, this.consumerType, path);
            return path;
        }
    }
}
