package org.example;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

public class CreateSignature implements SignatureInterface{

    private final PrivateKey privateKey;
    private Certificate[] certificateChain;

    CreateSignature(PrivateKey privateKey, X509Certificate certificateChain) {
        this.privateKey = privateKey;
        this.certificateChain = new X509Certificate[]{certificateChain};
    }

    @Override
    public byte[] sign(InputStream content) throws IOException {
        try {
            // First, we need to create a CMSProcessable input stream from the document content
            CMSTypedData msg = new CMSProcessableByteArray(content.readAllBytes());

            // Set up the generator
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);

            gen.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(
                            new JcaDigestCalculatorProviderBuilder().build()).build(sha256Signer, (X509Certificate) certificateChain[0]));

            // Add the certificate chain to the generator
            List<Certificate> certList = new ArrayList<>();
            for (Certificate cert : certificateChain) {
                certList.add(cert);
            }
            Store certs = new JcaCertStore(certList);
            gen.addCertificates(certs);

            // Generate the CMS Signed Data
            CMSSignedData sigData = gen.generate(msg, false);

            return sigData.getEncoded();
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}
