package com.cyberintel.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.*;

@Entity @Table(name="apk_analyses")
public class ApkAnalysis {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
 @OneToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="scan_id",nullable=false,unique=true) public Scan scan;
 public String packageName, applicationName, versionName, versionCode, minSdk, targetSdk;
 @Column(nullable=false,length=64) public String sha256;
 @Column(nullable=false,length=32) public String md5;
 public long fileSize;
 @Column(nullable=false) public String storageKey;
 public String analysisMode;
 @Column(nullable=false) public String stage="Uploaded";
 public int progress;
 @Column(length=1000) public String message="Ready to analyze.";
 public String jadxStatus="NOT_RUN",apktoolStatus="NOT_RUN",aaptStatus="NOT_RUN";
 public Instant startedAt,completedAt;
 @Column(nullable=false,updatable=false) public Instant createdAt=Instant.now();
 @Column(columnDefinition="text",nullable=false) public String sourceSummary="{}";
 public boolean artifactsRetained=true;
 @OneToMany(mappedBy="analysis",cascade=CascadeType.ALL,orphanRemoval=true) public List<PermissionFinding> permissions=new ArrayList<>();
 @OneToMany(mappedBy="analysis",cascade=CascadeType.ALL,orphanRemoval=true) public List<ComponentFinding> components=new ArrayList<>();
 @OneToMany(mappedBy="analysis",cascade=CascadeType.ALL,orphanRemoval=true) public List<ApiFinding> apiFindings=new ArrayList<>();
 @OneToMany(mappedBy="analysis",cascade=CascadeType.ALL,orphanRemoval=true) public List<ExtractedString> strings=new ArrayList<>();
 public ApkAnalysis(){}
}
