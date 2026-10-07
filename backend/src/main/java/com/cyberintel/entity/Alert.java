package com.cyberintel.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name="alerts")
public class Alert {

    public enum Severity { LOW, MEDIUM, HIGH, CRITICAL }
    public enum Status { NEW, INVESTIGATING, RESOLVED, OPEN, ACKNOWLEDGED }

    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    private Long id;

    @Column(nullable=false,length=200)
    private String title;

    @Column(nullable=false,length=4000)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable=false,length=20)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    @Column(nullable=false,length=20)
    private Status status = Status.NEW;

    @Column(nullable=false,length=255)
    private String source;

    @Column(length=100)
    private String category;

    @Column(length=4000)
    private String notes;

    @Column(name="resolved_by", length=255)
    private String resolvedBy;

    @Column(name="resolved_at")
    private Instant resolvedAt;

    @Column(name="created_at", nullable=false, updatable=false)
    private Instant createdAt;

    @Column(name="updated_at")
    private Instant updatedAt;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="scan_id")
    private Scan scan;

    public Alert() {}

    public Alert(String title, String description, Severity severity, String source, Scan scan) {
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.source = source;
        this.scan = scan;
        this.status = Status.NEW;
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    public Alert(String title, String description, Severity severity, String source, String category, Scan scan) {
        this(title, description, severity, source, scan);
        this.category = category;
    }

    @PrePersist
    void create() {
        if (createdAt == null) createdAt = Instant.now();
        if (updatedAt == null) updatedAt = Instant.now();
        if (status == null) status = Status.NEW;
    }

    @PreUpdate
    void update() {
        updatedAt = Instant.now();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }

    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }

    public String getNotes() { return notes; }
    public void setNotes(String notes) { this.notes = notes; }

    public String getResolvedBy() { return resolvedBy; }
    public void setResolvedBy(String resolvedBy) { this.resolvedBy = resolvedBy; }

    public Instant getResolvedAt() { return resolvedAt; }
    public void setResolvedAt(Instant resolvedAt) { this.resolvedAt = resolvedAt; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }

    public Scan getScan() { return scan; }
    public void setScan(Scan scan) { this.scan = scan; }
}
