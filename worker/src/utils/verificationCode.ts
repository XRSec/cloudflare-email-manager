const VERIFICATION_CODE_LABEL = String.raw`(?:verification|authentication|security|confirmation)\s+(?:code|pin)|one[\s-]?time\s+(?:code|password|passcode|pin)|otp(?:\s+(?:code|password|passcode|pin))?|验证码|校验码|认证码|动态码`;
const CODE_VALUE = String.raw`[A-Z0-9]{4,10}`;

function isPlausibleVerificationCode(value: string): boolean {
    return /\d/.test(value);
}

/**
 * Returns a compact preview only when the text explicitly labels a nearby value
 * as a verification code.
 */
export function buildVerificationCodePreview(text: string): string | null {
    const normalized = text.replace(/[\u00a0\s]+/g, ' ').trim();
    if (!normalized) return null;

    const patterns = [
        new RegExp(`(?:${VERIFICATION_CODE_LABEL})[\\s]*(?:is|为|是)?[\\s]*[:：=-]?[\\s]*(${CODE_VALUE})\\b`, 'i'),
        new RegExp(`\\b(${CODE_VALUE})[\\s]*(?:is|为|是)[\\s]*(?:your|the|您的|你的)?[\\s]*(?:${VERIFICATION_CODE_LABEL})`, 'i')
    ];

    for (const pattern of patterns) {
        const code = normalized.match(pattern)?.[1];
        if (code && isPlausibleVerificationCode(code)) {
            return `Your Verification Code: ${code}`;
        }
    }

    return null;
}
