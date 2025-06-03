package org.chypakk.keyGenerator;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class RsaKeyGenerator {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        try (FileWriter writer = new FileWriter("src/main/resources/public.pem", false)) {
            writer.write("-----BEGIN PUBLIC KEY-----\n" +
                    Base64.getEncoder().encodeToString(publicKey.getEncoded()) +
                    "\n-----END PUBLIC KEY-----"
            );
            writer.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try (FileWriter writer = new FileWriter("src/main/resources/private.pem", false)) {
            writer.write("-----BEGIN PRIVATE KEY-----\n" +
                    Base64.getEncoder().encodeToString(privateKey.getEncoded()) +
                    "\n-----END PRIVATE KEY-----");
            writer.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
