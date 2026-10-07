package com.cyberintel.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity @Table(name="yara_scans")
public class YaraScan {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
 @OneToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="apk_analysis_id",nullable=false,unique=true) public ApkAnalysis analysis;
 @Column(nullable=false,length=16) public String mode;
 @Column(nullable=false,length=32) public String status;
 @Column(nullable=false,length=500) public String message;
 @Column(nullable=false) public Instant scannedAt=Instant.now();
 @OneToMany(mappedBy="scan",cascade=CascadeType.ALL,orphanRemoval=true) public List<YaraMatch> matches=new ArrayList<>();
}
