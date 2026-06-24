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
package com.wazuh.contentmanager.cti.catalog.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.SuppressForbidden;

import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.*;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import reactor.util.annotation.NonNull;

/** Unzip utility class for extracting ZIP files. */
public class Unzip {
    private static final Logger log = LogManager.getLogger(Unzip.class);

    /**
     * Unzips an archive to the specified folder.
     *
     * @param source path of the file to unzip.
     * @param destination folder to extract to.
     * @throws IOException if the source is missing or the archive cannot be opened/read.
     */
    @SuppressForbidden(reason = "ZipFile is needed for ZIP64 support; it reads via the archive path")
    public static void unzip(@NonNull Path source, @NonNull Path destination) throws IOException {
        if (!Files.exists(source)) {
            throw new FileNotFoundException("ZIP does not exist: " + source);
        }

        // Resolve the destination root to its real path
        Path destinationRoot = destination.toRealPath();

        try (ZipFile zipFile = new ZipFile(source.toFile())) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry zipEntry = entries.nextElement();
                Path destinationFile = destinationRoot.resolve(zipEntry.getName()).normalize();
                if (!destinationFile.startsWith(destinationRoot)) {
                    throw new IOException("Bad zip entry: " + zipEntry.getName());
                }
                if (zipEntry.isDirectory()) {
                    Files.createDirectories(destinationFile);
                    continue;
                }
                Unzip.extract(zipFile, zipEntry, destinationFile);
            }
        }
        log.info("[{}] unzipped to [{}]", source.getFileName().toString(), destination.toString());
    }

    /**
     * Extracts a single entry from a ZIP file.
     *
     * @param zipFile the opened ZIP file.
     * @param zipEntry the entry to extract.
     * @param destinationFile Path (file) where the entry will be written.
     * @throws IOException if the entry cannot be read or written. Propagated so the caller can
     *     abort/retry/cleanup instead of proceeding with a truncated or missing file.
     */
    @SuppressForbidden(reason = "ZipFile is needed for ZIP64 support; it reads via the archive path")
    private static void extract(ZipFile zipFile, ZipEntry zipEntry, Path destinationFile)
            throws IOException {
        byte[] buffer = new byte[1024];

        try {
            // Ensure parent directories exist
            Files.createDirectories(destinationFile.getParent());

            try (InputStream entryStream = zipFile.getInputStream(zipEntry);
                    BufferedOutputStream bufferedOutputStream =
                            new BufferedOutputStream(
                                    Files.newOutputStream(
                                            destinationFile,
                                            StandardOpenOption.CREATE,
                                            StandardOpenOption.TRUNCATE_EXISTING))) {
                int size;
                while ((size = entryStream.read(buffer)) > 0) {
                    bufferedOutputStream.write(buffer, 0, size);
                }
            }
        } catch (IOException e) {
            log.error("Zip extraction failed for entry [{}]: {}", zipEntry.getName(), e.getMessage());
            throw e;
        }
    }
}
