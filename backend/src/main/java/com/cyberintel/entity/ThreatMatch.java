package com.cyberintel.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name="threat_match")
public class ThreatMatch {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
 @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="ioc_id",nullable=false) public IOC ioc;
 @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="threat_intelligence_id",nullable=false) public ThreatIntelligence threatIntelligence;
 @Column(length=20) public String matchType; // EXACT, PARTIAL, PATTERN
 @Column(length=20) public String status; // MATCHED, NO_MATCH, REVIEW
 @Column(length=20) public String confidence;
 @Column(length=20) public String severity;
 @Column(nullable=false) public Instant matchedAt = Instant.now();
 @Column(length=4000) public String description;
 public ThreatMatch(){}
}