// ============================================================
// Security Rules — Secret & PII Pattern Engine
// ============================================================

export const SECRET_PATTERNS = [
  { id: 'supabase_anon_key', severity: 'high', label: 'Supabase Anon Key', regex: /eyJ[A-Za-z0-9_-]{30,}\.eyJ[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{20,}/ },
  { id: 'supabase_service_role', severity: 'critical', label: 'Supabase Service Role Key', regex: /eyJ[A-Za-z0-9_-]{100,}/ },
  { id: 'supabase_url', severity: 'medium', label: 'Supabase Project URL', regex: /https:\/\/[a-z]{20}\.supabase\.co/ },
  { id: 'supabase_db_password', severity: 'critical', label: 'Supabase DB Password', regex: /(?:password|db_pass|DB_PASSWORD)\s*[=:]\s*['"][^'"]{8,}['"]/ },
  { id: 'openai_key', severity: 'critical', label: 'OpenAI API Key', regex: /sk-[A-Za-z0-9]{20,}/ },
  { id: 'anthropic_key', severity: 'critical', label: 'Anthropic API Key', regex: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { id: 'stripe_secret', severity: 'critical', label: 'Stripe Secret Key', regex: /sk_(?:live|test)_[A-Za-z0-9]{20,}/ },
  { id: 'stripe_publishable', severity: 'medium', label: 'Stripe Publishable Key', regex: /pk_(?:live|test)_[A-Za-z0-9]{20,}/ },
  { id: 'aws_access_key', severity: 'critical', label: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
  { id: 'aws_secret_key', severity: 'critical', label: 'AWS Secret Key', regex: /(?:aws_secret|AWS_SECRET)[A-Za-z_]*\s*[=:]\s*['"][A-Za-z0-9/+=]{30,}['"]/ },
  { id: 'github_token', severity: 'critical', label: 'GitHub Token', regex: /gh[ps]_[A-Za-z0-9_]{36,}/ },
  { id: 'jwt_secret', severity: 'critical', label: 'JWT Secret', regex: /(?:jwt_secret|JWT_SECRET|jwtSecret)\s*[=:]\s*['"][^'"]{10,}['"]/ },
  { id: 'firebase_key', severity: 'high', label: 'Firebase API Key', regex: /AIza[0-9A-Za-z_-]{35}/ },
  { id: 'sendgrid_key', severity: 'critical', label: 'SendGrid API Key', regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/ },
  { id: 'twilio_key', severity: 'critical', label: 'Twilio Auth Token', regex: /SK[0-9a-fA-F]{32}/ },
  { id: 'generic_api_key', severity: 'medium', label: 'Generic API Key', regex: /(?:api_key|apiKey|API_KEY)\s*[=:]\s*['"][A-Za-z0-9_-]{16,}['"]/ },
  { id: 'private_key_pem', severity: 'critical', label: 'Private Key (PEM)', regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
];

export const PII_PATTERNS = [
  { id: 'email', severity: 'medium', label: 'Email Address', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },
  { id: 'linkedin_url', severity: 'medium', label: 'LinkedIn Profile', regex: /linkedin\.com\/in\/[a-zA-Z0-9_-]+/ },
  { id: 'cpf', severity: 'high', label: 'CPF (Brazil)', regex: /\d{3}\.\d{3}\.\d{3}-\d{2}/ },
  { id: 'cnpj', severity: 'high', label: 'CNPJ (Brazil)', regex: /\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}/ },
  { id: 'credit_card', severity: 'critical', label: 'Credit Card Number', regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/ },
  { id: 'phone_br', severity: 'low', label: 'Phone (BR)', regex: /\+55\s?\d{2}\s?\d{4,5}-?\d{4}/ },
  { id: 'stripe_customer', severity: 'high', label: 'Stripe Customer ID', regex: /cus_[A-Za-z0-9]{14,}/ },
];

export const SENSITIVE_FILES = [
  '.env', '.env.local', '.env.production', '.env.development',
  'supabase/config.toml', 'supabase/seed.sql',
  'src/integrations/supabase/client.ts', 'src/integrations/supabase/client.js',
  'prisma/schema.prisma', 'drizzle.config.ts',
  'firebase.json', 'serviceAccountKey.json',
  '.aws/credentials', 'docker-compose.yml',
];

export function scanContent(content, source) {
  const findings = [];
  for (const pattern of SECRET_PATTERNS) {
    const match = content.match(pattern.regex);
    if (match) {
      const masked = match[0].substring(0, 8) + '•••••' + match[0].slice(-3);
      findings.push({
        id: crypto.randomUUID(), ruleId: pattern.id, severity: pattern.severity,
        title: pattern.label, vector: 'hardcoded_secret', source,
        description: `${pattern.label} found in ${source}`,
        evidence: masked, recommendation: `Rotate this ${pattern.label} immediately and move to environment variables.`,
        file: source, line: null,
      });
    }
  }
  for (const pattern of PII_PATTERNS) {
    const match = content.match(pattern.regex);
    if (match) {
      const masked = match[0].substring(0, 4) + '•••';
      findings.push({
        id: crypto.randomUUID(), ruleId: pattern.id, severity: pattern.severity,
        title: pattern.label, vector: source.includes('message') ? 'pii_in_chat' : 'pii_in_code', source,
        description: `${pattern.label} detected in ${source}`,
        evidence: masked, recommendation: `Remove PII from source code or chat history.`,
        file: source, line: null,
      });
    }
  }
  return findings;
}

export function isSensitiveFile(path) {
  return SENSITIVE_FILES.some(s => path.endsWith(s) || path.includes(s));
}
