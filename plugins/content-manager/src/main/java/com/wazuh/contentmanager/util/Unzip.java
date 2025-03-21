package com.wazuh.contentmanager.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.io.PathUtils;
import org.opensearch.env.Environment;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.StandardOpenOption;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/*
 * Unzip utility class for extracting ZIP files.
 */
public class Unzip {

    private static final Logger log = LogManager.getLogger(Unzip.class);
    private static final byte[] BUFFER = new byte[1024];
    private final Environment environment;

    public Unzip(Environment environment) {
        this.environment = environment;
    }

    /*
     * Unzips a ZIP file's content in a specified folder.
     *
     * @param zipFilePath Origin ZIP file path following the format: "path/file.zip".
     * @param destinationDirectory Unzipped files destiny path following the format: "path/".
     */
    public void unzip(String zipFilePath, String destinationDirectory) throws IOException {
        Path zipPath = environment.resolveRepoFile(zipFilePath);
        Path destinationPath = environment.resolveRepoFile(destinationDirectory);

        if (!Files.exists(zipPath)) {
            throw new IOException("ZIP file does not exist: " + zipFilePath);
        }

        try (ZipInputStream zipInputStream = new ZipInputStream(Files.newInputStream(zipPath))) {
            ZipEntry entry;

            while ((entry = zipInputStream.getNextEntry()) != null) {
                Path destinationFile = destinationPath.resolve(entry.getName()).normalize();

                if (!destinationFile.startsWith(destinationPath)) { // Prevents Zip Slip attack
                    throw new IOException("Bad zip entry: " + entry.getName());
                }

                extractFile(zipInputStream, destinationFile);
                zipInputStream.closeEntry();
            }
        }
    }

    /*
     * Extracts a file from a ZIP input stream.
     *
     * @param zipInputStream ZIP input stream.
     * @param destinationFile Path (directory) where the file will be extracted.
     */
    public static void extractFile(ZipInputStream zipInputStream, Path destinationFile) throws IOException {
        Files.createDirectories(destinationFile.getParent()); // Ensure parent directories exist

        try (BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(Files.newOutputStream(destinationFile, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING))) {
            int size;
            while ((size = zipInputStream.read(BUFFER)) > 0) {
                bufferedOutputStream.write(BUFFER, 0, size);
            }
        }
    }
}
