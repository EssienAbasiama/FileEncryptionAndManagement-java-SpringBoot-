package com.project.encryption;

import com.project.encryption.services.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class EncryptionApplication implements CommandLineRunner {


	@Autowired
	private  FileService fileService;
	public static void main(String[] args) {
		SpringApplication.run(EncryptionApplication.class, args);
	}

	@Override
	public void run(String... arg) throws Exception {
//    storageService.deleteAll();
		fileService.init();
	}

}
