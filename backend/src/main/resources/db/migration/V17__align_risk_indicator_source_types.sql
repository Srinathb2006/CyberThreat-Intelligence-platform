ALTER TABLE risk_indicator DROP CONSTRAINT risk_indicator_source_type_check;

ALTER TABLE risk_indicator ADD CONSTRAINT risk_indicator_source_type_check CHECK (
 source_type IN (
  'malware_finding', 'threat_intelligence', 'api_finding', 'permission',
  'ioc', 'extracted_string', 'component', 'analysis_meta',
  'PERMISSION', 'API', 'STATIC_FINDING', 'IOC', 'THREAT_INTELLIGENCE',
  'URL', 'DOMAIN', 'IP', 'COMPONENT', 'OBFUSCATION', 'NATIVE_LIBRARY'
 )
);
