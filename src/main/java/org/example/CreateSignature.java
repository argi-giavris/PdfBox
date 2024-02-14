package org.example;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CreateSignature implements SignatureInterface{

    private final PrivateKey privateKey;
    private Certificate[] certificateChain;
    private String tsaUrl;

    CreateSignature(PrivateKey privateKey, X509Certificate certificateChain, String tsaUrl) {
        this.privateKey = privateKey;
        this.certificateChain = new X509Certificate[]{certificateChain};
        this.tsaUrl = tsaUrl;
    }

    public void setTsaUrl(String tsaUrl)
    {
        this.tsaUrl = tsaUrl;
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
            CMSSignedData signedData = gen.generate(msg, false);

            if (tsaUrl != null && !tsaUrl.isEmpty())
            {
                ValidationTimeStamp validation = new ValidationTimeStamp(tsaUrl);
                signedData = validation.addSignedTimeStamp(signedData);
            }

            return signedData.getEncoded();
        } catch (GeneralSecurityException | CMSException | OperatorCreationException | URISyntaxException e) {
            throw new IOException(e);
        }
    }
}
