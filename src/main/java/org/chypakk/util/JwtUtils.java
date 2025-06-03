package org.chypakk.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

@Component
public class JwtUtils {
    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;
    private static final long EXPIRATION_MS = 60000;

    public JwtUtils(RSAPublicKey publicKey, RSAPrivateKey privateKey){
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String generateToken(String username) throws JOSEException {

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(username)
                .issuer("springAuthServer")
                .expirationTime(new Date(System.currentTimeMillis() + EXPIRATION_MS))
                .issueTime(new Date())
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        signedJWT.sign(new RSASSASigner(privateKey));

        return signedJWT.serialize();
    }

    public boolean validateToken(String token){
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            boolean signatureValid = signedJWT.verify(new RSASSAVerifier(publicKey));
            boolean notExpired = new Date().before(signedJWT.getJWTClaimsSet().getExpirationTime());

            return signatureValid && notExpired;
        } catch (Exception e){
            return false;
        }
    }

    public String getUsernameFromToken(String token){
        try {
            return SignedJWT.parse(token).getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            return null;
        }
    }

    public long getExpirationMs() {
        return EXPIRATION_MS;
    }
}
