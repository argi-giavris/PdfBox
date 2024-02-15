package org.example;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;

public class GenerateCertificate {

    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

        X500Name issuerName = new X500Name("CN=Self-Signed, O=My Company, L=My City, C=MY");

        X509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(
                issuerName,
                serialNumber,
                notBefore,
                notAfter,
                issuerName,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate());

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
    }
}
