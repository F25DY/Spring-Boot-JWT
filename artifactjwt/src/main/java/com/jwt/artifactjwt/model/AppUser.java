package com.jwt.artifactjwt.model;

import jakarta.persistence.*;


@Entity @Table(name="app_user")

public class AppUser {

    @Id @GeneratedValue (strategy = GenerationType.IDENTITY)
    private Long id;

    @Column (nullable = false, unique = true, length =100)
    private String username;

    @Column (nullable = false)
    private String password;

    protected AppUser() {}

    public AppUser(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
