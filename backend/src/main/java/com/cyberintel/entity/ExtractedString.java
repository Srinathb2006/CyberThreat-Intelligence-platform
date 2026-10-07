package com.cyberintel.entity;
import jakarta.persistence.*;
@Entity @Table(name="extracted_strings")
public class ExtractedString {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
 @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="apk_analysis_id",nullable=false) public ApkAnalysis analysis;
 @Column(name="text_value",length=2000) public String value;
 @Column(length=255) public String kind;
 @Column(length=512) public String source;
 public ExtractedString(){}
}
