package org.example;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class SignPdf {
    public void signPdf(String path) throws Exception {
        KeyPair keyPair = GeneratePairKeys.generateRSAKeyPair();

        X509Certificate certificate = generateSelfSignedCertificate(keyPair);
        storeInKeystore(keyPair, certificate);

        File file = new File(path);
        PDDocument document = Loader.loadPDF(file);

        File outputFile = new File(path);
        signDocument(document, outputFile, keyPair.getPrivate(), certificate);

    }

    public void signDocument(PDDocument document, File outputFile, PrivateKey privateKey, X509Certificate certChain) throws IOException {
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("Signer Name");
        signature.setLocation("Signer Location");
        signature.setReason("Reason for signing");
        signature.setSignDate(Calendar.getInstance());

        SignatureOptions signatureOptions = new SignatureOptions();
        // For larger documents, consider adjusting the memory settings
        // signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE);

        document.addSignature(signature, new CreateSignature(privateKey, certChain), signatureOptions);

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            document.saveIncremental(fos);
        }
        document.close();
    }


//    static {
//        Security.addProvider(new BouncyCastleProvider());
//    }

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

    public static void storeInKeystore(KeyPair keyPair, X509Certificate certificate) throws Exception {
        String keystorePath = "mykeystore.jks";
        String keystorePassword = "keystorepassword";
        String alias = "mykey";
        char[] password = keystorePassword.toCharArray();

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(null, password); // Initialize a new keystore

        // Store the private key and certificate
        keystore.setKeyEntry(alias, keyPair.getPrivate(), password, new java.security.cert.Certificate[]{certificate});

        // Save the keystore to a file
        try (FileOutputStream fos = new FileOutputStream(keystorePath)) {
            keystore.store(fos, password);
        }
    }
}

