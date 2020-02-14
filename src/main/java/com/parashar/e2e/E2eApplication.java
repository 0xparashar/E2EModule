package com.parashar.e2e;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class E2eApplication {

	public static void main(String[] args) {
                Security.addProvider(new BouncyCastleProvider());
                SpringApplication.run(E2eApplication.class, args);
	}

}
