-- V7__security_alerts_and_reports.sql
-- Updates alerts table to support NEW, INVESTIGATING, RESOLVED statuses and report queries

ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_status_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_status_check CHECK (status IN ('NEW', 'INVESTIGATING', 'RESOLVED', 'OPEN', 'ACKNOWLEDGED'));

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved_by VARCHAR(255);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS notes VARCHAR(4000);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS category VARCHAR(100);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_risk_level ON scans(risk_level);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
