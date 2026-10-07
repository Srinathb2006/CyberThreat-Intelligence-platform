package com.cyberintel.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity @Table(name="iocs")
public class IOC {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
 @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="apk_analysis_id",nullable=false) public ApkAnalysis apkAnalysis;
 @Column(name="ioc_value",length=2000) public String value;
 @Column(length=50) public String type;
 @Column(length=50) public String source;
 @Column(length=20) public String severity;
 @Column(length=20) public String confidence;
 @Column(length=2000) public String description;
 public Instant firstSeen;
 public Instant lastSeen;
 @Column(nullable=false,updatable=false) public Instant createdAt=Instant.now();
 public IOC(){}
}