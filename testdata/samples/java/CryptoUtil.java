package com.fintech.crypto;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import javax.crypto.Cipher;

public class CryptoUtil {
    public static void setupCrypto() throws Exception {
        // Quantum vulnerable RSA
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);

        // Quantum vulnerable ECDSA
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");

        // Weak classical MD5
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        // Weak classical ECB mode
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    }
}
