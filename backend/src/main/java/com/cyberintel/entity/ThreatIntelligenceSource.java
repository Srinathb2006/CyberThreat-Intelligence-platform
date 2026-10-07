package com.cyberintel.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name="threat_intelligence_source")
public class ThreatIntelligenceSource {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
 @Column(length=100, nullable=false) public String name;
 @Column(length=1000) public String description;
 @Column(length=20, nullable=false) public String sourceType; // LOCAL, IMPORTED, MANUAL
 @Column(length=500) public String url;
 @Column(nullable=false) public Boolean enabled = true;
 @Column(nullable=false,updatable=false) public Instant createdAt = Instant.now();
 public ThreatIntelligenceSource(){}
}