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
package com.wazuh.contentmanager.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import reactor.util.annotation.NonNull;

/** Unzip utility class for extracting ZIP files. */
public class Unzip {
    private static final Logger log = LogManager.getLogger(Unzip.class);

    /**
     * Unzips a ZIP file's content to the specified folder.
     *
     * @param path ZIP file to decompress.
     * @param destinationPath extraction destination folder.
     * @throws IOException rethrown from getNextEntry()
     */
    public static void unzip(@NonNull Path path, @NonNull Path destinationPath) throws IOException {
        ZipInputStream zipInputStream = new ZipInputStream(Files.newInputStream(path));
        ZipEntry zipEntry;
        while ((zipEntry = zipInputStream.getNextEntry()) != null) {
            Path destinationFile = destinationPath.resolve(zipEntry.getName()).normalize();
            extract(zipInputStream, destinationFile);
            zipInputStream.closeEntry();
        }
        log.info("[{}] file unzipped to [{}]", path.toString(), destinationPath.toString());
    }

    /**
     * Extracts a file from a ZIP input stream.
     *
     * @param zipInputStream ZIP input stream.
     * @param destinationFile Path (directory) where the file will be extracted.
     */
    private static void extract(ZipInputStream zipInputStream, Path destinationFile)
            throws IOException {
        byte[] buffer = new byte[1024];
        Files.createDirectories(destinationFile.getParent());

        BufferedOutputStream bufferedOutputStream =
                new BufferedOutputStream(
                        Files.newOutputStream(
                                destinationFile, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING));
        int size;
        while ((size = zipInputStream.read(buffer)) > 0) {
            bufferedOutputStream.write(buffer, 0, size);
        }
    }
}
