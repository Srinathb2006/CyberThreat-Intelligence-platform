package com.cyberintel.entity;
import jakarta.persistence.*;
@Entity @Table(name="component_findings")
public class ComponentFinding {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
 @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="apk_analysis_id",nullable=false) public ApkAnalysis analysis;
 @Column(length=255) public String componentType;
 @Column(length=512) public String componentName;
 public Boolean exported;
 @Column(length=512) public String permission;
 @Column(length=255) public String severity;
 public ComponentFinding(){}
}

