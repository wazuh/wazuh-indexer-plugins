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
package com.wazuh.contentmanager.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.env.Environment;

import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.StandardOpenOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import reactor.util.annotation.NonNull;

/** Unzip utility class for extracting ZIP files. */
public class Unzip {
    private static final Logger log = LogManager.getLogger(Unzip.class);

    /**
     * Unzips a ZIP file's content to the specified folder.
     *
     * @param file ZIP file to decompress.
     * @param to extraction destination folder.
     * @param env Required to resolve files' paths. Environment will contain the configuration of the
     *     enclosed directory where the unzip process will happen.
     * @throws IOException
     */
    public static void unzip(@NonNull String file, @NonNull String to, @NonNull Environment env)
            throws IOException {
        Path path = env.resolveRepoFile(file);
        if (path == null || !Files.exists(path)) {
            throw new FileNotFoundException("ZIP file does not exist: " + path);
        }

        Path destinationPath = env.resolveRepoFile(to);
        try (ZipInputStream zipInputStream = new ZipInputStream(Files.newInputStream(path))) {
            ZipEntry zipEntry;
            while ((zipEntry = zipInputStream.getNextEntry()) != null) {
                Path destinationFile = destinationPath.resolve(zipEntry.getName()).normalize();
                if (!destinationFile.startsWith(destinationPath)) {
                    throw new IOException("Bad zip entry: " + zipEntry.getName());
                }
                extract(zipInputStream, destinationFile);
                zipInputStream.closeEntry();
            }
        }
    }

    /**
     * Extracts a file from a ZIP input stream.
     *
     * @param zipInputStream ZIP input stream.
     * @param destinationFile Path (directory) where the file will be extracted.
     */
    private static void extract(ZipInputStream zipInputStream, Path destinationFile) {
        byte[] buffer = new byte[1024];
        // Ensure parent directories exist
        try {
            Files.createDirectories(destinationFile.getParent());
        } catch (IOException e) {
            log.error("Destination directory does not exist: {}", e.getMessage());
        }

        try (BufferedOutputStream bufferedOutputStream =
                new BufferedOutputStream(
                        Files.newOutputStream(
                                destinationFile,
                                StandardOpenOption.CREATE,
                                StandardOpenOption.TRUNCATE_EXISTING))) {
            int size;
            while ((size = zipInputStream.read(buffer)) > 0) {
                bufferedOutputStream.write(buffer, 0, size);
            }
        } catch (IOException e) {
            log.error("Zip extraction failed: {}", e.getMessage());
        }
    }
}
