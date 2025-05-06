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

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.net.ssl.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

/** Utility class to load PEM-based key/cert and create SSLContext. */
public class PemHelper {

    public static SSLContext createSSLContext(Path certPath, Path keyPath, Path caPath)
            throws Exception {
        // Load client certificate and private key
        X509Certificate clientCert = loadCertificate(certPath);
        PrivateKey privateKey = loadPrivateKey(keyPath);

        // Load CA certificate(s) if provided
        TrustManagerFactory trustManagerFactory = null;
        if (caPath != null && !caPath.toString().isEmpty()) {
            trustManagerFactory = createTrustManagerFactory(caPath);
        }

        // Create key manager from cert+key
        KeyManagerFactory keyManagerFactory = createKeyManagerFactory(privateKey, clientCert);

        // Build SSLContext
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(
                keyManagerFactory.getKeyManagers(),
                trustManagerFactory != null ? trustManagerFactory.getTrustManagers() : null,
                new SecureRandom());

        return sslContext;
    }

    private static X509Certificate loadCertificate(Path certPath)
            throws IOException, CertificateException {
        try (InputStream in = Files.newInputStream(certPath)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(in);
        }
    }

    private static PrivateKey loadPrivateKey(Path keyPath) throws Exception {
        try (Reader reader = Files.newBufferedReader(keyPath, StandardCharsets.UTF_8);
                PEMParser pemParser = new PEMParser(reader)) {
            Object object = pemParser.readObject();
            PEMKeyPair keyPair = (PEMKeyPair) object;
            return new JcaPEMKeyConverter().getPrivateKey(keyPair.getPrivateKeyInfo());
        }
    }

    private static TrustManagerFactory createTrustManagerFactory(Path caPath) throws Exception {
        Collection<? extends java.security.cert.Certificate> caCerts;
        try (InputStream in = Files.newInputStream(caPath)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            caCerts = factory.generateCertificates(in);
        }

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null); // initialize empty
        int i = 0;
        for (java.security.cert.Certificate cert : caCerts) {
            trustStore.setCertificateEntry("ca" + (i++), cert);
        }

        TrustManagerFactory trustFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trustStore);
        return trustFactory;
    }

    private static KeyManagerFactory createKeyManagerFactory(PrivateKey key, X509Certificate cert)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry("client", key, new char[0], new java.security.cert.Certificate[] {cert});

        KeyManagerFactory factory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keyStore, new char[0]);
        return factory;
    }
}
