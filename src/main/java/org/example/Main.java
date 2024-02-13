package org.example;

import java.io.IOException;
import java.security.KeyStoreException;

public class Main {
    public static void main(String[] args) throws Exception {
        SignPdf singPdf = new SignPdf();
        String relativePath = "src/main/resources/dummy-pdf_2.pdf";
        singPdf.signPdf(relativePath);
    }
}