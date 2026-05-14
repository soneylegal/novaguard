-- NovaGuard Emergency Seed (Threat Intel)
-- Use este script caso a migração falhe e a tabela threat_intel não exista.

-- 1. Cria a tabela manualmente (idêntico ao ORM)
CREATE TABLE IF NOT EXISTS threat_intel (
    id UUID PRIMARY KEY,
    domain VARCHAR(253) NOT NULL UNIQUE,
    threat_type VARCHAR(50) NOT NULL DEFAULT 'malware',
    source VARCHAR(100) NOT NULL DEFAULT 'internal',
    confidence VARCHAR(10) NOT NULL DEFAULT 'high',
    added_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS ix_threat_intel_domain ON threat_intel (domain);

-- 2. Insere domínios de teste para cruzamento de inteligência
INSERT INTO threat_intel (id, domain, threat_type, source, confidence) 
VALUES 
    (gen_random_uuid(), 'google.com', 'safe', 'internal_whitelist', 'high'),
    (gen_random_uuid(), 'malware-test.com', 'malware', 'internal_blacklist', 'high'),
    (gen_random_uuid(), 'phishing-site.net', 'phishing', 'internal_blacklist', 'high')
ON CONFLICT (domain) DO UPDATE SET 
    threat_type = EXCLUDED.threat_type,
    source = EXCLUDED.source,
    added_at = EXCLUDED.added_at;
