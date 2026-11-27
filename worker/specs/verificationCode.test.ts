import assert from 'node:assert/strict';
import test from 'node:test';
import {
    buildVerificationCodePreview,
    extractVerificationInfo,
    unwrapTrackingUrl
} from '../src/utils/verificationCode.ts';

test('builds the requested preview for an account verification email', () => {
    const text = `You are currently performing an account verification operation. Your
verification code is: 154585`;

    assert.equal(buildVerificationCodePreview(text), 'Your Verification Code: 154585');
});

test('supports common Chinese and OTP labels', () => {
    assert.equal(buildVerificationCodePreview('您的验证码为：832104，请勿泄露。'), 'Your Verification Code: 832104');
    assert.equal(buildVerificationCodePreview('OTP code: A7B9C2'), 'Your Verification Code: A7B9C2');
});

test('supports explanatory text between a Chinese label and the code', () => {
    assert.equal(
        buildVerificationCodePreview('请使用以下验证码完成操作：722215'),
        'Your Verification Code: 722215'
    );
});

test('does not summarize unlabeled numbers or labels without a code', () => {
    assert.equal(buildVerificationCodePreview('Your order 154585 has shipped.'), null);
    assert.equal(buildVerificationCodePreview('Start account verification now.'), null);
    assert.equal(buildVerificationCodePreview('验证码将在 5 分钟后失效，请尽快完成验证。'), null);
    assert.equal(buildVerificationCodePreview('Your verification code expires in 3600 seconds.'), null);
});

test('does not misidentify URLs or tracking parameters containing otp as verification codes', () => {
    const discordTrackingUrl = 'https://click.discord.com/ls/click?upn=u001.k-2FIo5kiED2wa9kxk39-2Beamj9lHglNtIACTNG6ZyT-2FHB3La2Ge9j2KL-2BddFgbERpyrRQCEzkM3cx9I3xPP5VvzdSDbAdpFO5uXM0srxgmBHJUpoTFcIDi0SZre5XRC00dt7cDGnbia38nLrBwfXriEYRDr-2FsLDeBisuygxBW0SsJQXssa5-2FyUNk3GyOTp8k5mkJI-3DAkNL_h8EjUyYzKMB2p2vfGZuONMMQB5XF8';
    assert.equal(buildVerificationCodePreview(discordTrackingUrl), null);
    assert.equal(buildVerificationCodePreview('GyOTp8k5mkJI-3DAkNL'), null);
});

test('extracts verification links and unwraps ESP tracking URLs', () => {
    const html = `
      <p>Click the button below to verify your email:</p>
      <a href="https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fapp.example.com%2Fauth%2Fverify%3Ftoken%3Dabc123">Verify Email</a>
      <a href="https://app.example.com/unsubscribe?id=1">Unsubscribe</a>
    `;

    const info = extractVerificationInfo({ html });
    assert.ok(info);
    assert.equal(info.code, null);
    assert.equal(info.links.length, 1);
    assert.equal(info.primaryLink?.targetUrl, 'https://app.example.com/auth/verify?token=abc123');
    assert.equal(info.primaryLink?.domain, 'app.example.com');
    assert.equal(info.primaryLink?.isTracking, true);
    assert.equal(info.preview, 'Verification Link: app.example.com');
});

test('unwraps nested base64 or query redirect tracking links', () => {
    const target = 'https://github.com/login/verify?code=xyz';
    const encoded = Buffer.from(target).toString('base64url');
    const tracking = `https://click.mail.example.org/track?u=${encoded}`;

    const unwrapped = unwrapTrackingUrl(tracking);
    assert.equal(unwrapped.targetUrl, target);
    assert.equal(unwrapped.domain, 'github.com');
    assert.equal(unwrapped.isTracking, true);
});
