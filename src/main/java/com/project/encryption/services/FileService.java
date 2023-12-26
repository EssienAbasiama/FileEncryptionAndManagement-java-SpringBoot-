package com.project.encryption.services;

import com.project.encryption.helpers.Generattor;
import com.project.encryption.model.AppUser;
import com.project.encryption.model.FileEntity;
import com.project.encryption.repository.AppUserRepository;
import com.project.encryption.repository.FileEntityRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.*;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Service
public class FileService {

    private final AppUserRepository appUserRepository;
    private final FileEntityRepository fileEntityRepository;

    private final Path root = Paths.get("uploads");

    // Replace this key with a secure key management solution

//    private static final String SECRET_KEY = "6q$dlAKddC$r0ZgnGU%Lc-jdyfU%H*^AN@a7wkc1Xgr&O@h&_X#wX_&rrECU!I4=hmM-OvOMutCp*EtcY1DPLU!s_nQpPywAV&J29eu7TLI9*=5lrvz_9CQGZMwyI+jojPn=LADS%E&Z-cUN^Dg@Ot2_6e&xrqqh-sKcj^L^9-YXi4+tPMUS5I#+xk%x#vfbk7eOggUNeoi9fP2_YTHSXTDc&^283b$CC*Wr%L$p@gN7k!h2FLBJ+1$lzX5Wsxco";

    private static final byte[] SECRET_KEY_BYTES;

    static {
        try {
            SecretKey secretKey = Generattor.generateKey();
            SECRET_KEY_BYTES = secretKey.getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


    public FileService(AppUserRepository appUserRepository, FileEntityRepository fileEntityRepository) throws NoSuchAlgorithmException {
        this.appUserRepository = appUserRepository;
        this.fileEntityRepository = fileEntityRepository;
        init();
    }

    public void init() {
        try {
            Files.createDirectories(root);
        } catch (IOException e) {
            throw new RuntimeException("Could not initialize folder for upload!");
        }
    }

    public void fileUpload(Long userId, MultipartFile file) {
        AppUser appUser = appUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Could not find user"));

        // Check if the user is authenticated
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!authentication.getName().equals(appUser.getUsername())) {
            throw new RuntimeException("You are not authorized to upload files for this user.");
        }

        // Check if the user's folder exists, if not, create it
        Path userFolder = root.resolve(appUser.getUsername());
        if (!Files.exists(userFolder)) {
            try {
                Files.createDirectories(userFolder);
            } catch (IOException e) {
                throw new RuntimeException("Could not create user folder for upload!");
            }
        }

        // Encrypt and save the file to the user's folder
        encryptAndSave(file, userFolder,appUser);
    }

//    public void encryptAndSave(MultipartFile file, Path destination,AppUser appUser) {
//        String fileName = StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename()));
//
//        try {
//            // Generate a secret key from the given string
//            SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, "AES");
//
//            // Initialize the cipher
//            Cipher cipher = Cipher.getInstance("AES");
//            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
//
//            // Create a CipherOutputStream to write the encrypted data to the file
//            CipherOutputStream cipherOutputStream = new CipherOutputStream(
//                    Files.newOutputStream(destination.resolve(fileName)), cipher);
//
//
//            // Write the data to the file
//            cipherOutputStream.write(file.getBytes());
//            cipherOutputStream.close();
//
//
//        } catch (Exception e) {
//            if (e instanceof FileAlreadyExistsException) {
//                throw new RuntimeException("A file of that name already exists.");
//            }
//            throw new RuntimeException(e.getMessage());
//        }
//    }


    public void encryptAndSave(MultipartFile file, Path destination, AppUser appUser) {
        String fileName = StringUtils.cleanPath(Objects.requireNonNull(file.getOriginalFilename()));

        // Check if the file already exists in the user's folder
        Path existingFilePath = destination.resolve(fileName);
        if (Files.exists(existingFilePath)) {
            throw new RuntimeException("A file with the same name already exists.");
        }

        try {
            // Generate a secret key from the given bytes
            SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, "AES");

            // Initialize the cipher
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            // Create a CipherOutputStream to write the encrypted data to the file
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    Files.newOutputStream(destination.resolve(fileName)), cipher);

            // Write the data to the file
            cipherOutputStream.write(file.getBytes());
            cipherOutputStream.close();

            // Save file information to the database
            FileEntity newFile = new FileEntity();
            newFile.setFileName(fileName);
            newFile.setFilePath(String.valueOf(destination));
            newFile.setUser(appUser);
            fileEntityRepository.save(newFile);

        } catch (Exception e) {
            if (e instanceof FileAlreadyExistsException) {
                throw new RuntimeException("A file of that name already exists.");
            }
            throw new RuntimeException(e.getMessage());
        }
    }

    // Add a method to check authorization before downloading a file
//    public Path decryptAndGetFilePath(Long userId, String fileName) {
//        AppUser appUser = appUserRepository.findById(userId)
//                .orElseThrow(() -> new RuntimeException("Could not find user"));
//
//        // Check if the user is authenticated
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        if (!authentication.getName().equals(appUser.getUsername())) {
//            throw new RuntimeException("You are not authorized to download files for this user.");
//        }
//
//        // Check if the user's folder exists
//        Path userFolder = root.resolve(appUser.getUsername());
//        if (!Files.exists(userFolder)) {
//            throw new RuntimeException("User folder does not exist.");
//        }
//
//        // Check if the file exists
//        Path encryptedFilePath = userFolder.resolve(fileName);
//        if (!Files.exists(encryptedFilePath)) {
//            throw new RuntimeException("File not found.");
//        }
//
//        // Decrypt and return the file path
//        return decryptFile(encryptedFilePath, fileName);
//    }


    public Path decryptAndGetFilePath(Long userId,String fileName) {
        // Get the authentication context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // Check if the user is authenticated
        if (authentication != null && authentication.isAuthenticated()) {
            // Extract user details from the authentication context
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            // Find the user by ID
            AppUser appUser = appUserRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("Could not find user"));

            // Check if the user's folder exists
            Path userFolder = root.resolve(appUser.getUsername());
            if (!Files.exists(userFolder)) {
                throw new RuntimeException("User folder does not exist.");
            }

            // Check if the file exists
            Path encryptedFilePath = userFolder.resolve(fileName);
            if (!Files.exists(encryptedFilePath)) {
                throw new RuntimeException("File not found.");
            }

            // Decrypt and return the file path
            return decryptFile(encryptedFilePath, fileName);
        } else {
            throw new RuntimeException("User not authenticated.");
        }
    }



    private Path decryptFile(Path encryptedFilePath, String fileName) {
        try {
            // Generate a secret key from the given string
            SecretKey secretKey = new SecretKeySpec(SECRET_KEY_BYTES, "AES");

            // Initialize the cipher
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            // Create a CipherOutputStream to write the decrypted data to a new file
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    Files.newOutputStream(root.resolve(fileName)), cipher);

            // Write the decrypted data to the new file
            cipherOutputStream.write(Files.readAllBytes(encryptedFilePath));
            cipherOutputStream.close();

            return root.resolve(fileName);

        } catch (Exception e) {
            throw new RuntimeException("Error decrypting file: " + e.getMessage());
        }
    }

    // Other fields...

    public List<String> getAllFiles(Long userId) {
        AppUser appUser = appUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Could not find user"));

        // Check if the user's folder exists
        Path userFolder = root.resolve(appUser.getUsername());
        if (!Files.exists(userFolder)) {
            throw new RuntimeException("User folder does not exist.");
        }

        // Retrieve all files in the user's folder
        List<String> fileList = new ArrayList<>();
        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(userFolder)) {
            for (Path path : directoryStream) {
                fileList.add(path.getFileName().toString());
            }
        } catch (IOException e) {
            throw new RuntimeException("Error retrieving files: " + e.getMessage());
        }
        return fileList;
    }

    public void deleteFile(Long userId, String fileName) {
        AppUser appUser = appUserRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("Could not find user"));

        // Check if the user is authenticated
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!authentication.getName().equals(appUser.getUsername())) {
            throw new RuntimeException("You are not authorized to delete files for this user.");
        }

        // Check if the user's folder exists
        Path userFolder = root.resolve(appUser.getUsername());
        if (!Files.exists(userFolder)) {
            throw new RuntimeException("User folder does not exist.");
        }

        // Check if the file exists
        Path filePath = userFolder.resolve(fileName);
        if (!Files.exists(filePath)) {
            throw new RuntimeException("File not found.");
        }

        // Delete the file
        try {
            Files.delete(filePath);
        } catch (IOException e) {
            throw new RuntimeException("Error deleting file: " + e.getMessage());
        }
    }
}