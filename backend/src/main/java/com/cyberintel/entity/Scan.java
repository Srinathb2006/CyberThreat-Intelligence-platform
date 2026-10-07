package com.cyberintel.entity;
import jakarta.persistence.*;
import java.time.Instant;
@Entity @Table(name="scans")
public class Scan {
 public enum ScanType { APK, URL, PHISHING }
 public enum Status { PENDING, UPLOADED, QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED }
 public enum RiskLevel { UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL }
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
 @Enumerated(EnumType.STRING) @Column(nullable=false,length=20) private ScanType scanType;
 @Column(nullable=false,length=2048) private String target;
 @Enumerated(EnumType.STRING) @Column(nullable=false,length=20) private Status status=Status.PENDING;
 private Integer riskScore;
 @Enumerated(EnumType.STRING) @Column(nullable=false,length=20) private RiskLevel riskLevel=RiskLevel.UNKNOWN;
 @Column(nullable=false,updatable=false) private Instant createdAt;
 private Instant completedAt;
 @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="user_id",nullable=false) private User user;
 protected Scan() {}
 public Scan(ScanType type,String target,User user){this.scanType=type;this.target=target;this.user=user;}
 @PrePersist void create(){createdAt=Instant.now();}
 public Long getId(){return id;} public ScanType getScanType(){return scanType;} public String getTarget(){return target;}
 public void setStatus(Status value){status=value;}
 public void setCompletedAt(Instant value){completedAt=value;}
 public void setRiskScore(Integer value){riskScore=value;}
 public void setRiskLevel(RiskLevel value){riskLevel=value;}
 public Status getStatus(){return status;} public Integer getRiskScore(){return riskScore;} public RiskLevel getRiskLevel(){return riskLevel;}
 public Instant getCreatedAt(){return createdAt;} public Instant getCompletedAt(){return completedAt;} public User getUser(){return user;}
}
