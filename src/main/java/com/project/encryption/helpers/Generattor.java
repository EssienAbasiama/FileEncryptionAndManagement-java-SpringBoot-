package com.project.encryption.helpers;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class Generattor {
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // 128, 192, or 256
        SecretKey secretKey = keyGen.generateKey();
        return secretKey;
    }
}
