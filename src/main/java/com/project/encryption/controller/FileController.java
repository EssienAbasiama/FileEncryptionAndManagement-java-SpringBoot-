package com.project.encryption.controller;

import com.project.encryption.model.AppUser;
import com.project.encryption.repository.AppUserRepository;
import com.project.encryption.services.FileService;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

@RestController
public class FileController {

    private final FileService fileService;
    private final AppUserRepository userRepository;

    public FileController(FileService fileService, AppUserRepository userRepository) {
        this.fileService = fileService;
        this.userRepository = userRepository;
    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<List<String>> getAllFilesForUser(@PathVariable Long userId) {
        try {
            List<String> fileList = fileService.getAllFiles(userId);
            return ResponseEntity.ok(fileList);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/upload")
    public ResponseEntity<String> handleFileUpload(@RequestPart("file") MultipartFile file) {
        Authentication authentication;
        try {
            // Get user information from authentication context
            authentication = SecurityContextHolder.getContext().getAuthentication();
//            String username = authentication.getName();
            Long userId = getUserIdFromAuthentication(authentication);

            fileService.fileUpload(userId, file);
            return ResponseEntity.status(HttpStatus.OK).body("File uploaded successfully!");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to upload file: " + e.getMessage());
        }
    }

    @GetMapping("/{fileName}")
    public ResponseEntity<byte[]> downloadFile(@PathVariable String fileName) {
        Authentication authentication;
        try {
            // Get user information from authentication context
            authentication = SecurityContextHolder.getContext().getAuthentication();
            // Call the service method to decrypt and retrieve the file path
            Long userId = getUserIdFromAuthentication(authentication);
            Path filePath = fileService.decryptAndGetFilePath(userId,fileName);

            // Read the file content into a byte array
            byte[] fileContent = Files.readAllBytes(filePath);

            // Set the Content-Disposition header to prompt download
            HttpHeaders headers = new HttpHeaders();
            headers.setContentDisposition(ContentDisposition.builder("attachment").filename(fileName).build());

            // Return the file content with appropriate headers
            return ResponseEntity.ok().headers(headers).body(fileContent);

        } catch (Exception e) {
            // Handle exceptions appropriately, e.g., return a 404 response for file not found
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/file/{fileName}")
    public ResponseEntity<Void> deleteFile(@PathVariable String fileName) {
        try {
            Authentication authentication;
                // Get user information from authentication context
                authentication = SecurityContextHolder.getContext().getAuthentication();
                // Call the service method to decrypt and retrieve the file path
                Long userId = getUserIdFromAuthentication(authentication);
            fileService.deleteFile(userId, fileName);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    private Long getUserIdFromAuthentication (Authentication authentication){
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();

            Optional<AppUser> user = userRepository.findByEmail(userDetails.getUsername());
            if (user.isPresent()) {
                return user.get().getId();
            }
        }
        // If user ID is not present or authentication is not of the expected type
        return null;
    }
}