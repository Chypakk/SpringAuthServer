package org.chypakk.model;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(columnDefinition = "TEXT")
    private String token;
    private String username;
    private Instant expiryData;

    public RefreshToken(){}
    public RefreshToken(String token, String username, Instant expiryData){
        this.token = token;
        this.username = username;
        this.expiryData = expiryData;
    }

    public Long getId() {
        return id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Instant getExpiryData() {
        return expiryData;
    }

    public void setExpiryData(Instant expiryData) {
        this.expiryData = expiryData;
    }
}
