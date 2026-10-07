package com.cyberintel.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "endpoints")
public class Endpoint {
    public enum Status { ONLINE, OFFLINE, UNKNOWN }
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) private Long id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false) @JoinColumn(name = "user_id", nullable = false) private User user;
    @Column(nullable = false, length = 255) private String hostname;
    @Column(name = "device_name", nullable = false, length = 255) private String deviceName;
    @Column(name = "operating_system", nullable = false, length = 255) private String operatingSystem;
    @Column(nullable = false, length = 50) private String platform;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 20) private Status status;
    @Column(name = "last_seen_at", nullable = false) private Instant lastSeenAt;
    @Column(name = "demo_data", nullable = false) private boolean demoData = true;
    @Column(name = "created_at", nullable = false, updatable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;
    protected Endpoint() {}
    public Endpoint(User user, String hostname, String deviceName, String operatingSystem, String platform, Status status) {
        this.user = user; this.hostname = hostname; this.deviceName = deviceName; this.operatingSystem = operatingSystem;
        this.platform = platform; this.status = status; this.lastSeenAt = Instant.now();
    }
    @PrePersist void create() { Instant now = Instant.now(); if (createdAt == null) createdAt = now; if (updatedAt == null) updatedAt = now; if (lastSeenAt == null) lastSeenAt = now; }
    @PreUpdate void update() { updatedAt = Instant.now(); }
    public Long getId() { return id; } public User getUser() { return user; } public String getHostname() { return hostname; }
    public String getDeviceName() { return deviceName; } public String getOperatingSystem() { return operatingSystem; }
    public String getPlatform() { return platform; } public Status getStatus() { return status; } public Instant getLastSeenAt() { return lastSeenAt; }
    public boolean isDemoData() { return demoData; } public Instant getCreatedAt() { return createdAt; } public Instant getUpdatedAt() { return updatedAt; }
}
