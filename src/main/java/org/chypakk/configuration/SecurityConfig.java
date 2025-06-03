package org.chypakk.configuration;

import org.chypakk.filter.JwtAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.spec.SecretKeySpec;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig{

    private final UserDetailsService userDetailsService;
    private final RSAPublicKey publicKey;

    public SecurityConfig(UserDetailsService userDetailsService, RsaKeyLoader rsaKeyLoader) throws Exception {
        this.userDetailsService = userDetailsService;
        this.publicKey = rsaKeyLoader.rsaPublicKey();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("api/auth/**").permitAll()
                        .requestMatchers("public/**").permitAll()
                        .anyRequest().authenticated()
                ).oauth2ResourceServer(rs -> rs
                        .jwt(jwt -> jwt.decoder(jwtDecoder())))
                .sessionManagement(session  -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//                .addFilterBefore(
//                        new JwtAuthFilter(userDetailsService),
//                        UsernamePasswordAuthenticationFilter.class
//                );

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(){
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConf) throws Exception {
        return authConf.getAuthenticationManager();
    }

    private byte[] getKeyFromFile(String filepath){
        StringBuilder key = new StringBuilder();
        try(FileReader fileReader = new FileReader(filepath)) {
            char[] buf = new char[256];
            int chCount;
            while((chCount = fileReader.read(buf))>0){

                if(chCount < 256){
                    buf = Arrays.copyOf(buf, chCount);
                }
                key.append(buf);
            }
            System.out.println(key);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return key.toString().getBytes();
    }
}
