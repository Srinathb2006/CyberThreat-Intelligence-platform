package com.cyberintel.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name="threat_intelligence")
public class ThreatIntelligence {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
 @Column(length=2000, nullable=false) public String indicator;
 @Column(length=50, nullable=false) public String indicatorType;
 @Column(length=255) public String threatName;
 @Column(length=255) public String threatFamily;
 @Column(length=50) public String category;
 @Column(length=20) public String severity;
 @Column(length=20) public String confidence;
 @Column(length=4000) public String description;
 @Column(length=50) public String source;
 @Column(length=1000) public String tags;
 @Column public Instant firstSeen;
 @Column public Instant lastSeen;
 @Column(nullable=false) public Boolean active = true;
 @Column(nullable=false,updatable=false) public Instant createdAt = Instant.now();
 @Column(nullable=false) public Instant updatedAt = Instant.now();
 public ThreatIntelligence(){}
}