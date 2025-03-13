package com.wazuh.contentmanager.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.util.zip.*;

public class Unzip {

    private static final Logger log = LogManager.getLogger(Unzip.class);
    private static final byte[] BUFFER = new byte[1024];

    /*
     * Unzips a ZIP file's content in a specified folder
     * @param zipFilePath Origin ZIP file path following the format: "path/file.zip"
     * @param destDirectory Unzipped files destiny path following the format: "path/"
     */
    public void unzip(String zipFilePath, String destDirectory) throws FileNotFoundException {
        File zipFile = new File(zipFilePath);
        if (!zipFile.exists() || !zipFile.isFile()) {
            log.error("Error, ZIP file does not exist or is invalid: {}", zipFilePath);
            throw new FileNotFoundException("Error, ZIP file does not exist or is invalid: " + zipFilePath);
        }

        try (ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry;

            while ((entry = zipIn.getNextEntry()) != null) {
                File filePath = new File(destDirectory, entry.getName());

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
}
