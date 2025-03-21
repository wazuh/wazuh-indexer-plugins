package com.wazuh.contentmanager.util;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.common.io.PathUtils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.*;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.mockito.Mockito.mock;

public class UnzipTests extends OpenSearchTestCase {

    private Unzip unzipper;
    private Path tempZipPath;
    private Path tempDestinationDirectory;
    private String zipFileName = "test.zip";
    private String testFile = "testfile.txt";
    private String testFileMessage = "Hello, World!";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();

        // Crear un entorno de configuración con un directorio de datos temporal
        Path testHome = createTempDir();
        Settings settings = Settings.builder()
            .put("path.home", testHome.toString()) // Requerido por OpenSearch
            .build();

        Environment environment = new Environment(settings, testHome);

        unzipper = new Unzip(environment);
        tempDestinationDirectory = Files.createTempDirectory(testHome,"unzipped");
        tempZipPath = tempDestinationDirectory.resolve(zipFileName);

        try (ZipOutputStream zipOutputStream = new ZipOutputStream(new FileOutputStream(tempZipPath.toFile()))) {
            ZipEntry entry = new ZipEntry(testFile);
            zipOutputStream.putNextEntry(entry);
            zipOutputStream.write(testFileMessage.getBytes());
            zipOutputStream.closeEntry();
        }
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    public void testValidUnzip() {
        try {
            unzipper.unzip(tempZipPath.toString(), tempDestinationDirectory.toString());
            File extractedFile = tempDestinationDirectory.resolve(testFile).toFile();
            assertTrue("File should be extracted", extractedFile.exists());
            String fileContent = Files.readString(extractedFile.toPath(), StandardCharsets.UTF_8);
            assertEquals("File content should match", testFileMessage, fileContent.trim());
        } catch (IOException e) {
            fail("Unexpected IOException: " + e.getMessage());
        }
    }

    public void testNullPointerException() {
        String nullDestinationDirectory = null;
        Exception exception = assertThrows(NullPointerException.class, () -> {
            unzipper.unzip(tempZipPath.toString(), nullDestinationDirectory);
        });

        String expectedMessage = "Pathname is null: ";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testZipSlip() {
        String wrongDestinationDirectory = "../";
        Exception exception = assertThrows(IOException.class, () -> {
            unzipper.unzip(tempZipPath.toString(), wrongDestinationDirectory);
        });

        String expectedMessage = "Bad zip entry, cannot enter parent directories. ";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    @Ignore
    //test will fail due to not having permissions to access the file even though it doesn't exist (cannot be included in .policy)
    public void testUnzipFileNotFound() {
        try {
            AccessController.doPrivileged((PrivilegedExceptionAction<Void>) () -> {
                unzipper.unzip("", tempDestinationDirectory.toString());
                return null;
            });
            fail("Expected FileNotFoundException");
        } catch (PrivilegedActionException ex) {
            Throwable cause = ex.getCause();
            if (cause instanceof FileNotFoundException) {
                System.out.println("fallo1");
            } else if (cause instanceof IOException) {
                System.out.println("fallo2");
            } else {
                cause.printStackTrace();
            }
        }
    }
}
