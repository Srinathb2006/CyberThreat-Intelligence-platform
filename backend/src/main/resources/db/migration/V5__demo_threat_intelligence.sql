-- Demo threat intelligence data for local database
-- This provides sample indicators for testing correlation features

INSERT INTO threat_intelligence_source
    (name, description, source_type, url, enabled, created_at)
VALUES
    ('Internal Malware Lab', 'Internal malware analysis sandbox outputs', 'LOCAL', NULL, TRUE, NOW()),
    ('APK Static Analysis', 'Indicators extracted from APK static analysis', 'IMPORTED', NULL, TRUE, NOW()),
    ('Manual Entry', 'Manually added threat indicators', 'MANUAL', NULL, TRUE, NOW()),
    ('Open Source Feed', 'Public threat intelligence feeds (OTX, Abuse.ch, etc.)', 'LOCAL',
     'https://otx.alienvault.com', TRUE, NOW());

-- Sample threat intelligence indicators
INSERT INTO threat_intelligence
    (indicator, indicator_type, threat_name, threat_family, category, severity,
     confidence, description, source, tags, first_seen, last_seen, active,
     created_at, updated_at)
VALUES

-- Banking Trojans
    ('com.fake.banking', 'PACKAGE', 'FakeBank Trojan', 'BankBot', 'BANKING_TROJAN',
     'CRITICAL', 'HIGH',
     'Package name used by BankBot banking trojan family targeting financial apps',
     'Internal Malware Lab', 'banking,trojan,android',
     NOW() - INTERVAL '30 days', NOW() - INTERVAL '1 day', TRUE, NOW(), NOW()),

    ('com.secure.payments', 'PACKAGE', 'Anubis Banking Trojan', 'Anubis', 'BANKING_TROJAN',
     'CRITICAL', 'HIGH',
     'Known package for Anubis banking trojan with overlay attacks',
     'Internal Malware Lab', 'banking,trojan,overlay,anubis',
     NOW() - INTERVAL '45 days', NOW() - INTERVAL '2 days', TRUE, NOW(), NOW()),

    ('com.google.android.gms.unstable', 'PACKAGE', 'Cerberus Trojan', 'Cerberus',
     'BANKING_TROJAN', 'CRITICAL', 'HIGH',
     'Masquerading as Google Play Services - Cerberus banking trojan',
     'Open Source Feed', 'banking,trojan,masquerade,cerberus',
     NOW() - INTERVAL '60 days', NOW() - INTERVAL '5 days', TRUE, NOW(), NOW()),

-- Spyware
    ('com.android.system.update', 'PACKAGE', 'Pegasus-like Spyware', 'Pegasus',
     'SPYWARE', 'CRITICAL', 'MEDIUM',
     'Package name mimicking system update - associated with advanced spyware',
     'Open Source Feed', 'spyware,apt,pegasus,state-sponsored',
     NOW() - INTERVAL '90 days', NOW() - INTERVAL '10 days', TRUE, NOW(), NOW()),

    ('com.whatsapp.backup', 'PACKAGE', 'SpyNote RAT', 'SpyNote', 'SPYWARE',
     'HIGH', 'HIGH',
     'Disguised as WhatsApp backup - SpyNote remote access trojan',
     'Internal Malware Lab', 'spyware,rat,spynote,whatsapp',
     NOW() - INTERVAL '20 days', NOW() - INTERVAL '3 days', TRUE, NOW(), NOW()),

-- Ransomware
    ('com.encrypt.files', 'PACKAGE', 'Android Ransomware', 'WannaLocker',
     'RANSOMWARE', 'CRITICAL', 'HIGH',
     'File encryption ransomware targeting Android devices',
     'Open Source Feed', 'ransomware,encryption,wannalocker',
     NOW() - INTERVAL '120 days', NOW() - INTERVAL '15 days', TRUE, NOW(), NOW()),

    ('com.lock.screen', 'PACKAGE', 'Locker Ransomware', 'Kolor',
     'RANSOMWARE', 'HIGH', 'MEDIUM',
     'Screen locker ransomware preventing device access',
     'Manual Entry', 'ransomware,locker,kolor',
     NOW() - INTERVAL '80 days', NOW() - INTERVAL '20 days', TRUE, NOW(), NOW()),

-- Malicious URLs
    ('http://malware-c2.example.com/payload.apk', 'URL',
     'C2 Payload Delivery', 'BankBot', 'C2_INFRASTRUCTURE',
     'CRITICAL', 'HIGH',
     'Command and control server delivering BankBot payloads',
     'Open Source Feed', 'c2,payload,bankbot,delivery',
     NOW() - INTERVAL '10 days', NOW() - INTERVAL '1 day', TRUE, NOW(), NOW()),

    ('https://evil-tracker.example.net/collect', 'URL',
     'Data Exfiltration Endpoint', 'SpyNote', 'DATA_EXFILTRATION',
     'HIGH', 'HIGH',
     'Endpoint used by SpyNote for exfiltrating stolen data',
     'Internal Malware Lab', 'exfiltration,spynote,c2',
     NOW() - INTERVAL '15 days', NOW() - INTERVAL '2 days', TRUE, NOW(), NOW()),

    ('http://fake-update.example.org/update.apk', 'URL',
     'Fake Update Server', 'Cerberus', 'PAYLOAD_DELIVERY',
     'HIGH', 'MEDIUM',
     'Fake update server distributing Cerberus trojan',
     'Open Source Feed', 'fake-update,cerberus,payload',
     NOW() - INTERVAL '25 days', NOW() - INTERVAL '5 days', TRUE, NOW(), NOW()),

    ('https://phishing-bank.example.com/login', 'URL',
     'Banking Phishing Page', 'PhishKit', 'PHISHING',
     'CRITICAL', 'HIGH',
     'Phishing page mimicking major bank login',
     'Open Source Feed', 'phishing,banking,credential-harvesting',
     NOW() - INTERVAL '5 days', NOW() - INTERVAL '1 day', TRUE, NOW(), NOW()),

-- Malicious Domains
    ('c2.bankbot-malware.net', 'DOMAIN',
     'BankBot C2 Domain', 'BankBot', 'C2_INFRASTRUCTURE',
     'CRITICAL', 'HIGH',
     'Primary command and control domain for BankBot family',
     'Open Source Feed', 'c2,bankbot,domain',
     NOW() - INTERVAL '60 days', NOW() - INTERVAL '2 days', TRUE, NOW(), NOW()),

    ('exfil.spyware-collector.com', 'DOMAIN',
     'SpyNote Exfiltration Domain', 'SpyNote', 'DATA_EXFILTRATION',
     'HIGH', 'HIGH',
     'Domain used for data exfiltration by SpyNote RAT',
     'Internal Malware Lab', 'exfiltration,spynote,domain',
     NOW() - INTERVAL '30 days', NOW() - INTERVAL '3 days', TRUE, NOW(), NOW()),

    ('update.fake-services.xyz', 'DOMAIN',
     'Fake Update Domain', 'Cerberus', 'PAYLOAD_DELIVERY',
     'HIGH', 'MEDIUM',
     'Domain hosting fake updates for Cerberus distribution',
     'Open Source Feed', 'fake-update,cerberus,domain',
     NOW() - INTERVAL '40 days', NOW() - INTERVAL '7 days', TRUE, NOW(), NOW()),

    ('panel.ransomware-gang.onion', 'DOMAIN',
     'Ransomware Payment Portal', 'WannaLocker', 'RANSOMWARE',
     'CRITICAL', 'MEDIUM',
     'Tor hidden service for ransomware payment',
     'Manual Entry', 'ransomware,tor,payment,wannalocker',
     NOW() - INTERVAL '100 days', NOW() - INTERVAL '30 days', TRUE, NOW(), NOW()),

-- Malicious IPs
    ('198.51.100.42', 'IP',
     'BankBot C2 Server', 'BankBot', 'C2_INFRASTRUCTURE',
     'CRITICAL', 'HIGH',
     'IP address hosting BankBot command and control',
     'Open Source Feed', 'c2,bankbot,ip',
     NOW() - INTERVAL '20 days', NOW() - INTERVAL '1 day', TRUE, NOW(), NOW()),

    ('203.0.113.88', 'IP',
     'Spyware Exfiltration Server', 'SpyNote', 'DATA_EXFILTRATION',
     'HIGH', 'HIGH',
     'Server receiving exfiltrated data from SpyNote infections',
     'Internal Malware Lab', 'exfiltration,spynote,ip',
     NOW() - INTERVAL '18 days', NOW() - INTERVAL '2 days', TRUE, NOW(), NOW()),

    ('192.0.2.156', 'IP',
     'Ransomware Distribution', 'WannaLocker', 'PAYLOAD_DELIVERY',
     'CRITICAL', 'MEDIUM',
     'IP serving WannaLocker ransomware payloads',
     'Manual Entry', 'ransomware,wannalocker,distribution,ip',
     NOW() - INTERVAL '50 days', NOW() - INTERVAL '10 days', TRUE, NOW(), NOW()),

-- File Hashes (SHA256)
    ('a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456',
     'HASH', 'BankBot Sample', 'BankBot', 'MALWARE_SAMPLE',
     'CRITICAL', 'HIGH',
     'SHA256 of BankBot banking trojan sample',
     'Internal Malware Lab', 'hash,bankbot,sample,sha256',
     NOW() - INTERVAL '30 days', NOW() - INTERVAL '5 days', TRUE, NOW(), NOW()),

    ('f6e5d4c3b2a1098765432109876543210fedcba098765432109876543210fedc',
     'HASH', 'Anubis Sample', 'Anubis', 'MALWARE_SAMPLE',
     'CRITICAL', 'HIGH',
     'SHA256 of Anubis banking trojan sample',
     'Internal Malware Lab', 'hash,anubis,sample,sha256',
     NOW() - INTERVAL '35 days', NOW() - INTERVAL '7 days', TRUE, NOW(), NOW()),

    ('deadbeefcafebabe1234567890abcdef1234567890abcdef1234567890abcdef',
     'HASH', 'Cerberus Sample', 'Cerberus', 'MALWARE_SAMPLE',
     'CRITICAL', 'HIGH',
     'SHA256 of Cerberus banking trojan sample',
     'Open Source Feed', 'hash,cerberus,sample,sha256',
     NOW() - INTERVAL '40 days', NOW() - INTERVAL '8 days', TRUE, NOW(), NOW()),

    ('feedfacecafebeef1234567890abcdef1234567890abcdef1234567890abcdef',
     'HASH', 'SpyNote Sample', 'SpyNote', 'MALWARE_SAMPLE',
     'HIGH', 'HIGH',
     'SHA256 of SpyNote RAT sample',
     'Internal Malware Lab', 'hash,spynote,rat,sample,sha256',
     NOW() - INTERVAL '25 days', NOW() - INTERVAL '3 days', TRUE, NOW(), NOW()),

-- Suspicious APIs
    ('Landroid/telephony/SmsManager;->sendTextMessage',
     'API', 'SMS Sending Abuse', 'Generic', 'PRIVILEGE_ESCALATION',
     'MEDIUM', 'MEDIUM',
     'SMS manager used for premium SMS fraud or spam',
     'APK Static Analysis', 'api,sms,fraud,spam',
     NOW() - INTERVAL '10 days', NOW() - INTERVAL '1 day', TRUE, NOW(), NOW()),

    ('Landroid/content/pm/PackageManager;->installPackage',
     'API', 'Silent App Install', 'Generic', 'PRIVILEGE_ESCALATION',
     'HIGH', 'HIGH',
     'Programmatic app installation without user consent',
     'APK Static Analysis', 'api,install,silent,privilege',
     NOW() - INTERVAL '15 days', NOW() - INTERVAL '2 days', TRUE, NOW(), NOW()),

    ('Ljava/lang/Runtime;->exec',
     'API', 'Command Execution', 'Generic', 'CODE_EXECUTION',
     'HIGH', 'MEDIUM',
     'Runtime command execution - potential shell access',
     'APK Static Analysis', 'api,exec,shell,rce',
     NOW() - INTERVAL '20 days', NOW() - INTERVAL '3 days', TRUE, NOW(), NOW()),

    ('Landroid/telephony/TelephonyManager;->getDeviceId',
     'API', 'Device Identifier Access', 'Generic', 'DATA_COLLECTION',
     'MEDIUM', 'MEDIUM',
     'Access to persistent device identifier (IMEI/MEID)',
     'APK Static Analysis', 'api,device-id,tracking,privacy',
     NOW() - INTERVAL '5 days', NOW() - INTERVAL '1 day', TRUE, NOW(), NOW()),

-- Suspicious Strings
    ('http://c2.server.com/command',
     'STRING', 'Hardcoded C2 URL', 'Generic', 'C2_INFRASTRUCTURE',
     'HIGH', 'MEDIUM',
     'Hardcoded command and control URL in binary',
     'APK Static Analysis', 'string,c2,hardcoded,url',
     NOW() - INTERVAL '8 days', NOW() - INTERVAL '1 day', TRUE, NOW(), NOW()),

    ('super_secret_encryption_key_123',
     'STRING', 'Hardcoded Crypto Key', 'Generic', 'WEAK_CRYPTOGRAPHY',
     'MEDIUM', 'HIGH',
     'Hardcoded encryption key in application code',
     'APK Static Analysis', 'string,crypto,hardcoded,key',
     NOW() - INTERVAL '12 days', NOW() - INTERVAL '2 days', TRUE, NOW(), NOW()),

    ('admin:admin123',
     'STRING', 'Default Credentials', 'Generic', 'WEAK_AUTHENTICATION',
     'LOW', 'HIGH',
     'Default administrative credentials found in code',
     'APK Static Analysis', 'string,credentials,default,weak',
     NOW() - INTERVAL '3 days', NOW() - INTERVAL '1 day', TRUE, NOW(), NOW());