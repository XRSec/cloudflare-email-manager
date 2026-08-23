import assert from 'node:assert/strict';
import test from 'node:test';
import { buildVerificationCodePreview } from '../src/utils/verificationCode.ts';

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
});
