export interface VerificationLink {
  url: string;
  targetUrl: string;
  domain: string;
  label: string;
  isTracking: boolean;
}

export interface EmailVerificationInfo {
  code: string | null;
  links: VerificationLink[];
  primaryLink: VerificationLink | null;
  preview: string | null;
}

export interface VerificationExtractInput {
  text?: string | null;
  html?: string | null;
  subject?: string | null;
}

const VERIFICATION_CODE_LABEL = String.raw`(?<![a-zA-Z0-9])(?:(?:verification|authentication|security|confirmation)\s+(?:code|pin)|one[\s-]?time\s+(?:code|password|passcode|pin)|2fa\s+(?:code|pin)|otp(?:\s+(?:code|password|passcode|pin))?|passcode|验证码|校验码|认证码|动态码)(?![a-zA-Z0-9])`;
const CODE_VALUE = String.raw`(?:[A-Z0-9]{4,10}|\d{3}-\d{3})`;

const TIME_UNIT_FOLLOWING_RE = /^\s*(?:分钟|秒钟?|小时|天|mins?|minutes?|secs?|seconds?|hours?|days?)\b/i;
const FALSE_POSITIVE_CODE_RE = /^(?:utf8|base64|sha256|sha1|md5|tls12|tls13|http2|ipv4|ipv6)$/i;

const TRACKING_QUERY_PARAMS = [
  'url',
  'u',
  'target',
  'redirect',
  'redirect_url',
  'redirect_uri',
  'dest',
  'destination',
  'next',
  'continue',
  'link',
  'to',
  'r',
  'q'
];

const TRACKING_HOST_RE = /(?:^|\.)(?:sendgrid\.net|mailgun\.org|list-manage\.com|safelinks\.protection\.outlook\.com|mandrillapp\.com|pstmrk\.it|hubspotlinks\.com|customeriomail\.com)$|^(?:click|track|links?|email)\./i;

const POSITIVE_LABEL_RE = /(?:verify|confirm|activate|sign[\s-]?in|log[\s-]?in|magic[\s-]?link|reset|password|authenticate|accept|invite|验证|确认|激活|登录|重置|授权)/i;
const POSITIVE_URL_RE = /(?:verify|confirm|activate|token=|code=|auth|magic|login|signin|reset|callback|ticket=|otp)/i;
const NEGATIVE_LINK_RE = /(?:unsubscribe|opt-?out|privacy|terms|policy|preferences|manage-preferences|退订|取消订阅|隐私|条款)/i;
const STATIC_ASSET_EXT_RE = /\.(?:png|jpe?g|gif|svg|webp|bmp|ico|css|js|woff2?|ttf|eot)(?:$|\?)/i;

export function decodeHtmlEntities(input: string): string {
  return input
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_match, dec) => {
      const codePoint = Number.parseInt(dec, 10);
      return Number.isFinite(codePoint) ? String.fromCodePoint(codePoint) : '';
    })
    .replace(/&#x([0-9a-fA-F]+);/g, (_match, hex) => {
      const codePoint = Number.parseInt(hex, 16);
      return Number.isFinite(codePoint) ? String.fromCodePoint(codePoint) : '';
    });
}

export function stripHtmlToText(html: string): string {
  if (!html) return '';
  const withoutBlocks = html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(script|style|head)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(?:p|div|tr|td|th|li|h[1-6]|section|article|header|footer|blockquote)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ');

  return decodeHtmlEntities(withoutBlocks)
    .replace(/[\u00a0\t ]+/g, ' ')
    .replace(/\n\s*\n+/g, '\n')
    .trim();
}

function isPlausibleVerificationCode(value: string, trailingText: string): boolean {
  if (!/\d/.test(value)) return false;
  if (FALSE_POSITIVE_CODE_RE.test(value)) return false;
  if (TIME_UNIT_FOLLOWING_RE.test(trailingText)) return false;
  return true;
}

function extractCodeFromPlainText(text: string): string | null {
  const withoutUrls = text.replace(/https?:\/\/[^\s<>"'\\]+/gi, ' ');
  const normalized = withoutUrls.replace(/[\u00a0\s]+/g, ' ').trim();
  if (!normalized) return null;

  const patterns = [
    new RegExp(`(?:${VERIFICATION_CODE_LABEL})[^:：\\r\\n]{0,24}[:：=][\\s]*(${CODE_VALUE})\\b`, 'i'),
    new RegExp(`(?:${VERIFICATION_CODE_LABEL})\\s+(?:is|为|是)?\\s*(${CODE_VALUE})\\b`, 'i'),
    new RegExp(`(?:${VERIFICATION_CODE_LABEL})\\s*(?:is|为|是)\\s*(${CODE_VALUE})\\b`, 'i'),
    new RegExp(`\\b(${CODE_VALUE})\\s*(?:is|为|是)\\s*(?:your|the|您的|你的)?\\s*(?:${VERIFICATION_CODE_LABEL})`, 'i')
  ];

  for (const pattern of patterns) {
    const match = normalized.match(pattern);
    const code = match?.[1];
    if (!code) continue;

    const matchIndex = match.index ?? 0;
    const trailingText = normalized.slice(matchIndex + match[0].length, matchIndex + match[0].length + 24);
    if (isPlausibleVerificationCode(code, trailingText)) {
      return code;
    }
  }

  return null;
}

export function extractVerificationCode(input: VerificationExtractInput | string): string | null {
  if (typeof input === 'string') {
    return extractCodeFromPlainText(input);
  }

  const candidates: string[] = [];
  if (input.text && input.text.trim()) {
    candidates.push(input.text);
  }
  if (input.html && input.html.trim()) {
    const stripped = stripHtmlToText(input.html);
    if (stripped) candidates.push(stripped);
  }
  if (input.subject && input.subject.trim()) {
    candidates.push(input.subject);
  }

  for (const candidate of candidates) {
    const code = extractCodeFromPlainText(candidate);
    if (code) return code;
  }

  return null;
}

export function buildVerificationCodePreview(text: string): string | null {
  const code = extractVerificationCode(text);
  return code ? `Your Verification Code: ${code}` : null;
}

function tryDecodeUrlCandidate(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  const candidates = [trimmed];
  try {
    const decoded = decodeURIComponent(trimmed);
    if (decoded !== trimmed) candidates.push(decoded);
  } catch {
    // ignore malformed URI encoding
  }

  // Try URL-safe base64 if it looks like base64
  if (/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(trimmed) && typeof atob === 'function') {
    try {
      const normalized = trimmed.replace(/-/g, '+').replace(/_/g, '/');
      const decoded = atob(normalized);
      if (/^https?:\/\//i.test(decoded)) {
        candidates.push(decoded);
      }
    } catch {
      // ignore non-base64
    }
  }

  for (const candidate of candidates) {
    if (/^https?:\/\/[^\s]+/i.test(candidate)) {
      try {
        const parsed = new URL(candidate);
        if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
          return parsed.toString();
        }
      } catch {
        // ignore invalid URL
      }
    }
  }

  return null;
}

export function unwrapTrackingUrl(rawUrl: string): { targetUrl: string; domain: string; isTracking: boolean } {
  let current = rawUrl.trim();
  let isTracking = false;

  try {
    let parsed = new URL(current);
    if (TRACKING_HOST_RE.test(parsed.hostname)) {
      isTracking = true;
    }

    for (let depth = 0; depth < 3; depth++) {
      let unwrapped: string | null = null;
      for (const param of TRACKING_QUERY_PARAMS) {
        const val = parsed.searchParams.get(param);
        if (!val) continue;
        const candidate = tryDecodeUrlCandidate(val);
        if (candidate && candidate !== current) {
          unwrapped = candidate;
          break;
        }
      }

      if (!unwrapped) break;
      isTracking = true;
      current = unwrapped;
      parsed = new URL(current);
    }

    return {
      targetUrl: parsed.toString(),
      domain: parsed.hostname.toLowerCase(),
      isTracking
    };
  } catch {
    return {
      targetUrl: rawUrl,
      domain: '',
      isTracking
    };
  }
}

interface RawLinkCandidate {
  url: string;
  label: string;
  context: string;
}

function collectLinkCandidates(input: VerificationExtractInput): RawLinkCandidate[] {
  const candidates: RawLinkCandidate[] = [];

  if (input.html) {
    const anchorRe = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
    let match: RegExpExecArray | null;
    while ((match = anchorRe.exec(input.html)) !== null) {
      const rawHref = decodeHtmlEntities((match[1] ?? match[2] ?? match[3] ?? '').trim());
      if (!/^https?:\/\//i.test(rawHref)) continue;
      const label = stripHtmlToText(match[4] || '').replace(/\s+/g, ' ').trim();
      candidates.push({
        url: rawHref,
        label: label || rawHref,
        context: label
      });
    }
  }

  const plainText = input.text?.trim() || (input.html ? stripHtmlToText(input.html) : '');
  if (plainText) {
    const urlRe = /https?:\/\/[^\s<>"'\\)\]]+/gi;
    let match: RegExpExecArray | null;
    while ((match = urlRe.exec(plainText)) !== null) {
      const cleaned = match[0].replace(/[.,;:!?]+$/, '');
      const start = Math.max(0, (match.index ?? 0) - 80);
      const context = plainText.slice(start, (match.index ?? 0) + match[0].length);
      candidates.push({
        url: cleaned,
        label: cleaned,
        context
      });
    }
  }

  return candidates;
}

function scoreVerificationLink(candidate: RawLinkCandidate, targetUrl: string): number {
  if (STATIC_ASSET_EXT_RE.test(targetUrl) || STATIC_ASSET_EXT_RE.test(candidate.url)) {
    return -100;
  }

  const combinedMeta = `${candidate.label} ${candidate.url} ${targetUrl}`;
  if (NEGATIVE_LINK_RE.test(combinedMeta)) {
    return -100;
  }

  let score = 0;
  if (POSITIVE_LABEL_RE.test(candidate.label)) {
    score += 3;
  }
  if (POSITIVE_URL_RE.test(targetUrl) || POSITIVE_URL_RE.test(candidate.url)) {
    score += 2;
  }
  if (POSITIVE_LABEL_RE.test(candidate.context)) {
    score += 2;
  }

  return score;
}

export function extractVerificationLinks(input: VerificationExtractInput): VerificationLink[] {
  const rawCandidates = collectLinkCandidates(input);
  const byTarget = new Map<string, { link: VerificationLink; score: number }>();

  for (const candidate of rawCandidates) {
    const unwrapped = unwrapTrackingUrl(candidate.url);
    if (!unwrapped.domain) continue;

    const score = scoreVerificationLink(candidate, unwrapped.targetUrl);
    if (score < 2) continue;

    const existing = byTarget.get(unwrapped.targetUrl);
    if (!existing || score > existing.score) {
      byTarget.set(unwrapped.targetUrl, {
        score,
        link: {
          url: candidate.url,
          targetUrl: unwrapped.targetUrl,
          domain: unwrapped.domain,
          label: candidate.label,
          isTracking: unwrapped.isTracking
        }
      });
    }
  }

  return Array.from(byTarget.values())
    .sort((a, b) => b.score - a.score)
    .slice(0, 5)
    .map(entry => entry.link);
}

export function extractVerificationInfo(input: VerificationExtractInput): EmailVerificationInfo | null {
  const code = extractVerificationCode(input);
  const links = extractVerificationLinks(input);
  const primaryLink = links[0] ?? null;

  if (!code && !primaryLink) {
    return null;
  }

  const preview = code
    ? `Your Verification Code: ${code}`
    : primaryLink
      ? `Verification Link: ${primaryLink.domain}`
      : null;

  return {
    code,
    links,
    primaryLink,
    preview
  };
}
