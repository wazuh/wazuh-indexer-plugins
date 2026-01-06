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
package com.wazuh.contentmanager.cti.catalog.client;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
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

/** Client responsible for downloading CTI snapshots from a remote source. */
public class SnapshotClient {

    private static final Logger log = LogManager.getLogger(SnapshotClient.class);
    private final Environment env;

    /**
     * Default constructor.
     *
     * @param env node's environment
     */
    public SnapshotClient(Environment env) {
        this.env = env;
    }

    /***
     * Downloads the CTI snapshot.
     *
     * @param snapshotURI URI to the file to download.
     * @return The downloaded file's name
     */
    public Path downloadFile(String snapshotURI) throws IOException, URISyntaxException {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            // Setup
            final URI uri = new URI(snapshotURI);
            final HttpGet request = new HttpGet(uri);
            final String filename = uri.getPath().substring(uri.getPath().lastIndexOf('/') + 1);
            final Path path = this.env.tmpDir().resolve(filename);

            // Download
            log.info("Starting snapshot download from [{}]", uri);
            try (CloseableHttpResponse response = client.execute(request)) {
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
                }
            }
            log.info("Snapshot downloaded to [{}]", path);
            return path;
        }
    }
}
