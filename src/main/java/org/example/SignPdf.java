package org.example;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Calendar;

public class SignPdf {
    public void signPdf(String path) throws Exception {
        KeyPair keyPair = GeneratePairKeys.generateRSAKeyPair();

        X509Certificate certificate = GenerateCertificate.generateSelfSignedCertificate(keyPair);
        StoreKeys.storeInKeystore(keyPair, certificate);

        File file = new File(path);
        PDDocument document = Loader.loadPDF(file);

        File outputFile = new File(path);
        signDocument(document, outputFile, keyPair.getPrivate(), certificate);

    }


    public void signDocument(PDDocument document,  File outputFile, PrivateKey privateKey, X509Certificate certChain) throws IOException {
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("Signer Name");
        signature.setLocation("Signer Location");
        signature.setReason("Reason for signing");
        signature.setSignDate(Calendar.getInstance());

        String imagePath = "src/main/resources/test signature.png"; // Path to your signature image
        String imageInBase64 = Utils.encodeImageToBase64(imagePath);
        int pageNum = 0; // Page number where you want the visual signature to appear

        PDPage page = document.getPage(pageNum);
        PDRectangle rect = Utils.getPdRectangle(page);

        InputStream visualSignatureTemplate = CreateVisualSignatureTemplate.createVisualSignatureTemplate(document, pageNum, rect,  imageInBase64);

        SignatureOptions signatureOptions = new SignatureOptions();
        signatureOptions.setVisualSignature(visualSignatureTemplate);
        signatureOptions.setPage(pageNum);

        String tsaUrl = "http://time.certum.pl/";

        document.addSignature(signature, new CreateSignature(privateKey, certChain, tsaUrl), signatureOptions);

        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            document.saveIncremental(fos);
        }
        document.close();
    }

}

