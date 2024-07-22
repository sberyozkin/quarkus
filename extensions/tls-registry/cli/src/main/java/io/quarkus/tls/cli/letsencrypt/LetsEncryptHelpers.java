package io.quarkus.tls.cli.letsencrypt;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import io.smallrye.certs.CertificateUtils;

public class LetsEncryptHelpers {

    public static void writePrivateKeyAndCertificateChainsAsPem(PrivateKey pk, X509Certificate[] chain, File privateKeyFile,
            File certificateChainFile) throws Exception {
        if (pk == null) {
            throw new IllegalArgumentException("The private key cannot be null");
        }
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("The certificate chain cannot be null or empty");
        }

        CertificateUtils.writePrivateKeyToPem(pk, privateKeyFile);

        if (chain.length == 1) {
            CertificateUtils.writeCertificateToPEM(chain[0], certificateChainFile);
            return;
        }

        // For some reason the method from CertificateUtils distinguishes the first certificate and the rest of the chain
        X509Certificate[] restOfTheChain = new X509Certificate[chain.length - 1];
        System.arraycopy(chain, 1, restOfTheChain, 0, chain.length - 1);
        CertificateUtils.writeCertificateToPEM(chain[0], certificateChainFile, restOfTheChain);
    }

    public static X509Certificate loadCertificateFromPEM(String pemFilePath) throws IOException, CertificateException {
        try (PemReader pemReader = new PemReader(new FileReader(pemFilePath))) {
            PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null) {
                throw new IOException("Invalid PEM file: No PEM content found.");
            }
            byte[] content = pemObject.getContent();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(content));
        }
    }

}
