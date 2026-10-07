package com.cyberintel.entity;

import jakarta.persistence.*;

@Entity @Table(name="yara_matches")
public class YaraMatch {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) public Long id;
 @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="yara_scan_id",nullable=false) public YaraScan scan;
 @Column(nullable=false) public String ruleName;
 @Column(nullable=false,length=16) public String severity;
 @Column(nullable=false,length=1000) public String description;
 @Column(nullable=false,length=1000) public String evidence;
}
