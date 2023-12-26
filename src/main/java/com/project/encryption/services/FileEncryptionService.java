package com.project.encryption.services;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;

@Service
public class FileEncryptionService {
    private static final String ALGORITHM = "AES";

    public void encryptFile(String inputFilePath, String outputFilePath, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        FileInputStream inputStream = new FileInputStream(inputFilePath);
        CipherOutputStream outputStream = new CipherOutputStream(new FileOutputStream(outputFilePath), cipher);

        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) >= 0) {
            outputStream.write(buffer, 0, bytesRead);
        }

        outputStream.close();
        inputStream.close();
    }
}

