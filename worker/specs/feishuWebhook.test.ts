import assert from 'node:assert/strict';
import test from 'node:test';
import { buildFeishuWebhookPayload } from '../src/utils/feishuWebhook.ts';
import type { Email } from '../src/types/index.ts';

function createEmail(content: string): Email {
    return {
        id: 'email-id',
        subject: 'Account verification',
        from_address: 'security@example.com',
        to_address: 'user@example.com',
        content,
        is_read: 0,
        attachment_count: 0,
        message_id: null,
        headers_json: null,
        size_bytes: null,
        date: null,
        reply_to: null,
        cc: null,
        bcc: null,
        content_type: 'text/plain',
        received_at: '2026-08-06 12:00:00'
    };
}

test('uses verification code content in the Feishu card title', () => {
    const payload = buildFeishuWebhookPayload(createEmail('Your Verification Code: 154585'));

    assert.equal(payload.msg_type, 'interactive');
    assert.equal(payload.card.header.title.content, '新邮件通知：Your Verification Code: 154585');
    assert.equal(payload.card.elements[3].text.content, '**内容摘要：**\nYour Verification Code: 154585');
});

test('keeps the Feishu card for regular email content', () => {
    const payload = buildFeishuWebhookPayload(createEmail('A regular email preview.'));

    assert.equal(payload.msg_type, 'interactive');
    assert.equal(payload.card.header.title.content, '新邮件通知：Account verification');
});
