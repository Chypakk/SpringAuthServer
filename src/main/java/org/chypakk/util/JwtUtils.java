package org.chypakk.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
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

    private static final long ACCESS_TOKEN_EXPIRATION_MS = 2 * 60 * 1000;
    private static final long REFRESH_TOKEN_EXPIRATION_MS = 60 * 60 * 1000;

    public JwtUtils(RSAPublicKey publicKey, RSAPrivateKey privateKey){
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public String generateAccessToken(String username) throws JOSEException {
        JWTClaimsSet claims = generateClaims(username, "access", ACCESS_TOKEN_EXPIRATION_MS);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        signedJWT.sign(new RSASSASigner(privateKey));

        return signedJWT.serialize();
    }

    public String generateRefreshToken(String username) throws JOSEException {
        JWTClaimsSet claims = generateClaims(username, "refresh", REFRESH_TOKEN_EXPIRATION_MS);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        signedJWT.sign(new RSASSASigner(privateKey));

        return signedJWT.serialize();
    }

    private JWTClaimsSet generateClaims(String username, String type, long expiration){
        return new JWTClaimsSet.Builder()
                .subject(username)
                .issuer("springAuthServer")
                .expirationTime(new Date(System.currentTimeMillis() + expiration))
                .claim("type", type)
                .issueTime(new Date())
                .build();
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

    public long getAccessTokenExpirationMs() {
        return ACCESS_TOKEN_EXPIRATION_MS;
    }

    public long getRefreshTokenExpirationMs() {
        return REFRESH_TOKEN_EXPIRATION_MS;
    }

    public boolean isRefreshToken(String token){
        try {
            return SignedJWT.parse(token).getJWTClaimsSet().getClaim("type").equals("refresh");
        } catch (ParseException e) {
            System.out.println("ERROR: " + e.getMessage());
            return false;
        }
    }
}
