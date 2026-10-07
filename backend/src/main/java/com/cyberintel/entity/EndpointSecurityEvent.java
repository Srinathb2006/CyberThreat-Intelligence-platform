package com.cyberintel.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "endpoint_security_events")
public class EndpointSecurityEvent {
    public enum Severity { LOW, MEDIUM, HIGH, CRITICAL }
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) private Long id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false) @JoinColumn(name = "endpoint_id", nullable = false) private Endpoint endpoint;
    @Column(name = "event_type", nullable = false, length = 100) private String eventType;
    @Enumerated(EnumType.STRING) @Column(nullable = false, length = 20) private Severity severity;
    @Column(nullable = false, length = 255) private String title;
    @Column(nullable = false, length = 4000) private String description;
    @Column(nullable = false, length = 255) private String source;
    @Column(name = "observed_at", nullable = false) private Instant observedAt;
    @Column(nullable = false) private boolean suspicious;
    @Column(name = "demo_data", nullable = false) private boolean demoData = true;
    @Column(name = "created_at", nullable = false, updatable = false) private Instant createdAt;
    protected EndpointSecurityEvent() {}
    public EndpointSecurityEvent(Endpoint endpoint, String eventType, Severity severity, String title, String description, String source, boolean suspicious, Instant observedAt) {
        this.endpoint = endpoint; this.eventType = eventType; this.severity = severity; this.title = title; this.description = description;
        this.source = source; this.suspicious = suspicious; this.observedAt = observedAt;
    }
    @PrePersist void create() { if (createdAt == null) createdAt = Instant.now(); if (observedAt == null) observedAt = createdAt; }
    public Long getId() { return id; } public Endpoint getEndpoint() { return endpoint; } public String getEventType() { return eventType; }
    public Severity getSeverity() { return severity; } public String getTitle() { return title; } public String getDescription() { return description; }
    public String getSource() { return source; } public Instant getObservedAt() { return observedAt; } public boolean isSuspicious() { return suspicious; }
    public boolean isDemoData() { return demoData; }
}
