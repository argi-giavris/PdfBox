package org.example;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class StoreKeys {

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
