package com.wazuh.contentmanager.tools;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.util.zip.*;

public class Unzip {

    private static final Logger log = LogManager.getLogger(Unzip.class);
    private static final byte[] BUFFER = new byte[1024];
    private static final String ZIP_MIME_TYPE = "application/zip";

    /*
     * Unzips a ZIP file's content in a specified folder
     * @param zipFilePath Origin ZIP file path following the format: "path/file.zip"
     * @param destDirectory Unzipped files destiny path following the format: "path/"
     */
    public void unzip(String zipFilePath, String destDirectory) {
        File zipFile = new File(zipFilePath);
        if (!zipFile.exists() || !zipFile.isFile()) {
            log.error("Error, ZIP file does not exist or is invalid: {}", zipFilePath); return;
        }

        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry;

            while ((entry = zipIn.getNextEntry()) != null) {
                File filePath = new File(destDirectory, entry.getName()); // Se actualiza en cada iteración

                try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath))) {
                    int len;
                    while ((len = zipIn.read(BUFFER)) > 0) {
                        bos.write(BUFFER, 0, len);
                    }
                } catch (IOException e) {
                    log.error("Error, {} could not be extracted", filePath);
                }
                zipIn.closeEntry();
            }
        } catch (IOException e) {
            log.error("Error unzipping the file due to {}", e.getMessage());
        }
    }

    public static void main(String[] args) {
        String filePath = "temp/prueba.zip";
        String destDirectory = "temp/";

        Unzip unzipper = new Unzip();
        unzipper.unzip(filePath, destDirectory);
    }
}
