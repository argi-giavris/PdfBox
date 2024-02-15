package org.example;

import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Base64;

public class Utils {

    public static PDRectangle getPdRectangle(PDPage page) {
        PDRectangle pageSize = page.getMediaBox();

        // Calculate the position and size for the signature field
        // Example: signature field size of 150x50 pixels at the bottom right
        float sigFieldWidth = 150;
        float sigFieldHeight = 50;
        float marginRight = 20; // Margin from the right edge of the page
        float marginBottom = 20; // Margin from the bottom edge of the page

        float lowerLeftX = pageSize.getWidth() - sigFieldWidth - marginRight;
        float lowerLeftY = marginBottom; // Position from the bottom

        PDRectangle rect = new PDRectangle(lowerLeftX, lowerLeftY, sigFieldWidth, sigFieldHeight);
        return rect;
    }

    public static String encodeImageToBase64(String imagePath) throws IOException {
        File imageFile = new File(imagePath);
        byte[] imageBytes = Files.readAllBytes(imageFile.toPath());
        return Base64.getEncoder().encodeToString(imageBytes);
    }
}
