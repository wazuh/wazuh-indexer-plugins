package com.wazuh.contentmanager.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.util.zip.*;

/*
* Unzip utility class for extracting ZIP files.
*/
public class Unzip {

    private static final Logger log = LogManager.getLogger(Unzip.class);
    private static final byte[] BUFFER = new byte[1024];

    /*
     * Unzips a ZIP file's content in a specified folder.
     *
     * @param zipFilePath Origin ZIP file path following the format: "path/file.zip".
     * @param destinationDirectory Unzipped files destiny path following the format: "path/".
     */
    public void unzip(String zipFilePath, String destinationDirectory) throws FileNotFoundException, NullPointerException, IOException {
        try (ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry;

            while ((entry = zipInputStream.getNextEntry()) != null) {
                File destinationPath = new File(destinationDirectory, entry.getName()).toPath().normalize().toFile();
                if (!destinationPath.toPath().startsWith(new File(destinationDirectory).toPath().normalize())) { //avoid zip slip
                    throw new IOException("Bad zip entry: " + entry.getName());
                }

                extractFile (destinationPath, zipInputStream);
                zipInputStream.closeEntry();
            }
        } catch (NullPointerException e) {
            throw new NullPointerException("Pathname is null: {}", e.getMessage());
        } catch (FileNotFoundException e) {
            throw new FileNotFoundException("ZIP file does not exist or is invalid: {}. {}", zipFilePath, e.getMessage());
        } catch (IOException e) {
            log.error("Could not unzip the file due to: {}", e.getMessage());
        }
    }

    /*
     * Extracts a file from a ZIP input stream.
     *
     * @param zipInputStream ZIP input stream.
     * @param destinationPath Path where the file will be extracted.
     */
    public void extractFile(ZipInputStream zipInputStream, File destinationPath) throws IOException {
        try (BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(destinationPath))) {
            int size;
            while ((size = zipInputStream.read(BUFFER)) > 0) {
                bufferedOutputStream.write(BUFFER, 0, size);
            }
        } catch (IOException e) {
            throw new IOException("{} could not be extracted. {}", destinationPath, e.getMessage());
        }
    }
}
