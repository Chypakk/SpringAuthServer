package org.chypakk.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class RsaKeyLoader {

    @Value("${jwt.public-key-path}")
    private String publicKeyPath;

    @Value("${jwt.private-key-path}")
    private String privateKeyPath;

    @Bean
    public RSAPublicKey rsaPublicKey() throws Exception{
        String key = readKeyFile(publicKeyPath)
                .replace("-----BEGIN PUBLIC KEY-----\n", "")
                .replace("\n-----END PUBLIC KEY-----", "")
                .replace("\\s", "");

        X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(spec);
    }

    @Bean
    public RSAPrivateKey rsaPrivateKey() throws Exception{
        String key = readKeyFile(privateKeyPath)
                .replace("-----BEGIN PRIVATE KEY-----\n", "")
                .replace("\n-----END PRIVATE KEY-----", "")
                .replace("\\s", "");

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }

    private String readKeyFile(String path) throws IOException {
        ClassPathResource resource = new ClassPathResource(path.replace("classpath:", ""));
        return Files.readString(resource.getFile().toPath());
    }
}
