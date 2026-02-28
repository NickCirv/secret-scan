/**
 * Secret detection patterns
 * Each pattern: { name, regex, severity, description }
 * Severities: critical, high, medium, low
 */

export const PATTERNS = [
  // ─── AWS ───────────────────────────────────────────────────────────────────
  {
    name: 'AWS Access Key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
    description: 'AWS IAM Access Key ID',
  },
  {
    name: 'AWS Secret Access Key',
    regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: 'critical',
    description: 'AWS IAM Secret Access Key',
  },
  {
    name: 'AWS Session Token',
    regex: /(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?/gi,
    severity: 'critical',
    description: 'AWS Temporary Session Token',
  },

  // ─── GitHub ────────────────────────────────────────────────────────────────
  {
    name: 'GitHub Personal Access Token',
    regex: /\bghp_[A-Za-z0-9]{36,}\b/g,
    severity: 'critical',
    description: 'GitHub Personal Access Token (classic)',
  },
  {
    name: 'GitHub Fine-Grained Token',
    regex: /\bgithub_pat_[A-Za-z0-9_]{82,}\b/g,
    severity: 'critical',
    description: 'GitHub Fine-Grained Personal Access Token',
  },
  {
    name: 'GitHub OAuth Token',
    regex: /\bgho_[A-Za-z0-9]{36,}\b/g,
    severity: 'critical',
    description: 'GitHub OAuth Access Token',
  },
  {
    name: 'GitHub Actions Token',
    regex: /\bghs_[A-Za-z0-9]{36,}\b/g,
    severity: 'critical',
    description: 'GitHub Actions Token',
  },

  // ─── Stripe ────────────────────────────────────────────────────────────────
  {
    name: 'Stripe Secret Key',
    regex: /\bsk_live_[A-Za-z0-9]{24,}\b/g,
    severity: 'critical',
    description: 'Stripe Live Secret Key',
  },
  {
    name: 'Stripe Test Secret Key',
    regex: /\bsk_test_[A-Za-z0-9]{24,}\b/g,
    severity: 'high',
    description: 'Stripe Test Secret Key',
  },
  {
    name: 'Stripe Publishable Key',
    regex: /\bpk_live_[A-Za-z0-9]{24,}\b/g,
    severity: 'high',
    description: 'Stripe Live Publishable Key',
  },
  {
    name: 'Stripe Restricted Key',
    regex: /\brk_live_[A-Za-z0-9]{24,}\b/g,
    severity: 'critical',
    description: 'Stripe Live Restricted Key',
  },
  {
    name: 'Stripe Webhook Secret',
    regex: /\bwhsec_[A-Za-z0-9]{32,}\b/g,
    severity: 'high',
    description: 'Stripe Webhook Signing Secret',
  },

  // ─── Google ────────────────────────────────────────────────────────────────
  {
    name: 'Google API Key',
    regex: /\bAIza[A-Za-z0-9\-_]{35}\b/g,
    severity: 'high',
    description: 'Google API Key',
  },
  {
    name: 'Google OAuth Client Secret',
    regex: /(?:client_secret|GOOGLE_CLIENT_SECRET)\s*[=:]\s*['"]?([A-Za-z0-9\-_]{24,})['"]?/gi,
    severity: 'high',
    description: 'Google OAuth 2.0 Client Secret',
  },
  {
    name: 'Google Service Account Key',
    regex: /"private_key_id"\s*:\s*"([a-f0-9]{40})"/g,
    severity: 'critical',
    description: 'Google Service Account Private Key ID',
  },

  // ─── Slack ─────────────────────────────────────────────────────────────────
  {
    name: 'Slack Bot Token',
    regex: /\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}\b/g,
    severity: 'high',
    description: 'Slack Bot OAuth Token',
  },
  {
    name: 'Slack User Token',
    regex: /\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32,}\b/g,
    severity: 'high',
    description: 'Slack User OAuth Token',
  },
  {
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/g,
    severity: 'high',
    description: 'Slack Incoming Webhook URL',
  },
  {
    name: 'Slack App Token',
    regex: /\bxapp-[0-9]-[A-Za-z0-9]{10,}-[0-9]{13}-[A-Za-z0-9]{64,}\b/g,
    severity: 'high',
    description: 'Slack App-Level Token',
  },

  // ─── JWT ───────────────────────────────────────────────────────────────────
  {
    name: 'JSON Web Token',
    regex: /\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/]+=*/g,
    severity: 'high',
    description: 'JSON Web Token (JWT)',
  },

  // ─── Private Keys ──────────────────────────────────────────────────────────
  {
    name: 'RSA Private Key',
    regex: /-----BEGIN RSA PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'RSA Private Key Block',
  },
  {
    name: 'EC Private Key',
    regex: /-----BEGIN EC PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'Elliptic Curve Private Key Block',
  },
  {
    name: 'OpenSSH Private Key',
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'OpenSSH Private Key Block',
  },
  {
    name: 'PGP Private Key',
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    severity: 'critical',
    description: 'PGP Private Key Block',
  },
  {
    name: 'PKCS8 Private Key',
    regex: /-----BEGIN PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'PKCS8 Private Key Block',
  },

  // ─── npm ───────────────────────────────────────────────────────────────────
  {
    name: 'npm Access Token',
    regex: /\bnpm_[A-Za-z0-9]{36,}\b/g,
    severity: 'critical',
    description: 'npm Automation / Publish Token',
  },

  // ─── Twilio ────────────────────────────────────────────────────────────────
  {
    name: 'Twilio Account SID',
    regex: /\bAC[a-f0-9]{32}\b/g,
    severity: 'high',
    description: 'Twilio Account SID',
  },
  {
    name: 'Twilio Auth Token',
    regex: /(?:TWILIO_AUTH_TOKEN|twilio_auth_token)\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/gi,
    severity: 'high',
    description: 'Twilio Auth Token',
  },

  // ─── SendGrid ──────────────────────────────────────────────────────────────
  {
    name: 'SendGrid API Key',
    regex: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/g,
    severity: 'high',
    description: 'SendGrid API Key',
  },

  // ─── Mailgun ───────────────────────────────────────────────────────────────
  {
    name: 'Mailgun API Key',
    regex: /(?:MAILGUN_API_KEY|mailgun_api_key)\s*[=:]\s*['"]?(key-[a-f0-9]{32})['"]?/gi,
    severity: 'high',
    description: 'Mailgun API Key',
  },

  // ─── Heroku ────────────────────────────────────────────────────────────────
  {
    name: 'Heroku API Key',
    regex: /(?:HEROKU_API_KEY|heroku_api_key)\s*[=:]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?/gi,
    severity: 'high',
    description: 'Heroku Platform API Key',
  },

  // ─── Azure ─────────────────────────────────────────────────────────────────
  {
    name: 'Azure Connection String',
    regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};/g,
    severity: 'high',
    description: 'Azure Storage Connection String',
  },
  {
    name: 'Azure SQL Connection String',
    regex: /Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+;/gi,
    severity: 'high',
    description: 'Azure SQL Connection String',
  },

  // ─── Firebase ──────────────────────────────────────────────────────────────
  {
    name: 'Firebase Config',
    regex: /["']apiKey["']\s*:\s*["']([A-Za-z0-9\-_]{39})["']/g,
    severity: 'medium',
    description: 'Firebase Web API Key',
  },

  // ─── Telegram ──────────────────────────────────────────────────────────────
  {
    name: 'Telegram Bot Token',
    regex: /\b[0-9]{8,10}:[A-Za-z0-9\-_]{35}\b/g,
    severity: 'high',
    description: 'Telegram Bot API Token',
  },

  // ─── Connection Strings ────────────────────────────────────────────────────
  {
    name: 'MongoDB Connection String',
    regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^\s"']+/gi,
    severity: 'high',
    description: 'MongoDB Connection String with credentials',
  },
  {
    name: 'PostgreSQL Connection String',
    regex: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s"']+/gi,
    severity: 'high',
    description: 'PostgreSQL Connection String with credentials',
  },
  {
    name: 'MySQL Connection String',
    regex: /mysql:\/\/[^:]+:[^@]+@[^\s"']+/gi,
    severity: 'high',
    description: 'MySQL Connection String with credentials',
  },
  {
    name: 'Redis Connection String',
    regex: /redis:\/\/:[^@]+@[^\s"']+/gi,
    severity: 'high',
    description: 'Redis Connection String with credentials',
  },

  // ─── Generic Passwords ─────────────────────────────────────────────────────
  {
    name: 'Generic Password Assignment',
    regex: /(?:password|passwd|pwd|pass)\s*[=:]\s*['"]([^'"]{8,})['"](?!\s*(?:placeholder|example|your|test|demo|change|xxx|abc|123))/gi,
    severity: 'medium',
    description: 'Hardcoded password in source code',
  },
  {
    name: 'Generic Secret Assignment',
    regex: /(?:secret|api_secret|app_secret|client_secret)\s*[=:]\s*['"]([A-Za-z0-9+/=\-_]{16,})['"](?!\s*(?:placeholder|example|your|test|demo|xxx))/gi,
    severity: 'medium',
    description: 'Hardcoded secret value in source code',
  },
  {
    name: 'Generic Token Assignment',
    regex: /(?:token|access_token|auth_token|bearer_token)\s*[=:]\s*['"]([A-Za-z0-9+/=\-_.]{20,})['"](?!\s*(?:placeholder|example|your|test|demo|xxx))/gi,
    severity: 'medium',
    description: 'Hardcoded token value in source code',
  },

  // ─── .env Patterns ─────────────────────────────────────────────────────────
  {
    name: 'Environment Variable with Secret',
    regex: /^(?:export\s+)?(?:[A-Z_]+(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH))\s*=\s*(?!['"]?(?:your|example|changeme|xxx|placeholder|test|demo|<|{))[^\s#]{8,}/gm,
    severity: 'medium',
    description: 'Environment variable containing a potential secret value',
  },
];

/**
 * High-entropy string detection (catches base64 secrets not matched by patterns)
 * Shannon entropy > 4.5 for strings 20+ chars that look like secrets
 */
export function calculateEntropy(str) {
  const freq = {};
  for (const c of str) {
    freq[c] = (freq[c] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function isHighEntropy(str, threshold = 4.5) {
  if (str.length < 20) return false;
  return calculateEntropy(str) > threshold;
}

export const HIGH_ENTROPY_PATTERN = {
  name: 'High-Entropy String',
  regex: /(?:['"]([A-Za-z0-9+/=]{32,})['"])/g,
  severity: 'medium',
  description: 'High-entropy string that may be an encoded secret',
  entropyCheck: true,
};
