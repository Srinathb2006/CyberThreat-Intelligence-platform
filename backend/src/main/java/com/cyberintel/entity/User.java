package com.cyberintel.entity;
import jakarta.persistence.*;
import java.time.Instant;
@Entity
@Table(name="app_users")
public class User {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
 @Column(nullable=false,length=100) private String name;
 @Column(nullable=false,unique=true,length=254) private String email;
 @Column(nullable=false,length=100) private String password;
 @Enumerated(EnumType.STRING) @Column(nullable=false,length=20) private Role role=Role.USER;
 @Column(nullable=false,updatable=false) private Instant createdAt;
 @Column(nullable=false) private Instant updatedAt;
 protected User() {}
 public User(String name,String email,String password) { this.name=name; this.email=email; this.password=password; }
 @PrePersist void create() { createdAt=updatedAt=Instant.now(); }
 @PreUpdate void update() { updatedAt=Instant.now(); }
 public Long getId(){return id;} public String getName(){return name;} public String getEmail(){return email;}
 public String getPassword(){return password;} public Role getRole(){return role;}
 public Instant getCreatedAt(){return createdAt;} public Instant getUpdatedAt(){return updatedAt;}
}
