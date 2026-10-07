package com.cyberintel.entity;
import jakarta.persistence.*;
@Entity @Table(name="permission_findings")
public class PermissionFinding {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
 @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="apk_analysis_id",nullable=false) public ApkAnalysis analysis;
 @Column(length=512) public String permissionName;
 @Column(length=255) public String category;
 @Column(length=255) public String severity;
 @Column(length=2000) public String description;
 public PermissionFinding(){}
}

