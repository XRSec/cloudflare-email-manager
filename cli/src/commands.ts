import fs from 'node:fs';
import { extractVerificationInfo, stripHtmlToText } from '../../shared/verification.ts';
import { CemClient, type EmailDetailItem, type EmailListItem } from './client.ts';
import { getConfigPath, maskToken, readStoredConfig, resolveConfig, writeStoredConfig } from './config.ts';
import { CLI_VERSION } from './version.ts';

export interface ParsedArgs {
  positionals: string[];
  flags: Record<string, string | boolean>;
}

export function parseArgv(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) {
      positionals.push(arg);
      continue;
    }

    const eqIdx = arg.indexOf('=');
    if (eqIdx > -1) {
      flags[arg.slice(2, eqIdx)] = arg.slice(eqIdx + 1);
      continue;
    }

    const key = arg.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags[key] = next;
      i++;
    } else {
      flags[key] = true;
    }
  }

  return { positionals, flags };
}

function getStringFlag(flags: Record<string, string | boolean>, name: string): string | undefined {
  const val = flags[name];
  return typeof val === 'string' ? val : undefined;
}

function printJson(value: unknown) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

function formatEmailList(items: EmailListItem[]) {
  if (items.length === 0) {
    process.stdout.write('No emails found.\n');
    return;
  }

  for (const item of items) {
    const flag = item.is_read ? ' ' : '*';
    const ver = item.verification?.code
      ? ` [CODE: ${item.verification.code}]`
      : item.verification?.primaryLink
        ? ` [LINK: ${item.verification.primaryLink.domain}]`
        : '';
    process.stdout.write(
      `${flag} ${item.id}  ${item.received_at}  ${item.from} -> ${item.to}  ${item.subject || '(no subject)'}${ver}\n`
    );
  }
}

function formatEmailDetail(email: EmailDetailItem, rawHtml = false) {
  const verification =
    email.verification ??
    extractVerificationInfo({
      text: email.full_content_type === 'text' ? email.full_content : email.content,
      html: email.full_content_type === 'html' ? email.full_content : null,
      subject: email.subject
    });

  const body =
    rawHtml || email.full_content_type !== 'html'
      ? (email.full_content || email.content || '')
      : stripHtmlToText(email.full_content || email.content || '');

  const lines = [
    `ID:      ${email.id}`,
    `Subject: ${email.subject || '(no subject)'}`,
    `From:    ${email.from}`,
    `To:      ${email.to}`,
    `Date:    ${email.received_at}`,
    `Status:  ${email.status}`
  ];

  if (verification?.code) {
    lines.push(`Code:    ${verification.code}`);
  }
  if (verification?.primaryLink) {
    lines.push(`Link:    ${verification.primaryLink.targetUrl} (${verification.primaryLink.domain})`);
  }
  if (email.attachments && email.attachments.length > 0) {
    lines.push(
      `Attach:  ${email.attachments.map(a => `${a.id} (${a.filename}, ${a.size_bytes}B)`).join(', ')}`
    );
  }

  lines.push('---', body);
  process.stdout.write(lines.join('\n') + '\n');
}

export function printHelp() {
  process.stdout.write(`cem - Cloudflare Email Manager CLI

Usage:
  cem --version | -v
  cem config set [--base-url <url>] [--token <token>] [--from <email>]
  cem config show
  cem health
  cem list|ls [--folder inbox|sent] [--status read|unread] [--to <addr>] [--from <addr>] [--search <q>] [--limit <n>] [--page <n>] [--json]
  cem read <id> [--raw-html] [--json]
  cem latest [--to <addr>] [--from <addr>] [--search <q>] [--code-only] [--link-only] [--json]
  cem watch [--to <addr>] [--from <addr>] [--search <q>] [--interval <ms>] [--timeout <ms>] [--code-only] [--json]
  cem attachment <emailId> <attachmentId> [--out <path>]
  cem raw <id> [--out <path>]
  cem mark <id> (--read | --unread)
  cem delete <id>
  cem send --to <addr> --subject <subj> (--text <body> | --html <html>) [--from <addr>] [--method internal|cf|resend]
  cem forward <id> (--to <addr> [--method internal|cf|resend] [--from <addr>] | --channel <id>)
`);
}

export async function runCli(argv: string[]): Promise<void> {
  if (argv.includes('--version') || argv.includes('-v')) {
    process.stdout.write(`cem v${CLI_VERSION}\n`);
    return;
  }

  const { positionals, flags } = parseArgv(argv);
  const cmd = positionals[0];

  if (!cmd || cmd === 'help' || flags.help) {
    printHelp();
    return;
  }

  if (cmd === 'config') {
    const sub = positionals[1];
    if (sub === 'set') {
      const updated = writeStoredConfig({
        baseUrl: getStringFlag(flags, 'base-url'),
        token: getStringFlag(flags, 'token'),
        defaultFrom: getStringFlag(flags, 'from')
      });
      process.stdout.write(
        `Saved config to ${getConfigPath()} (baseUrl=${updated.baseUrl || '(unset)'}, token=${maskToken(updated.token)}, defaultFrom=${updated.defaultFrom || '(unset)'})\n`
      );
      return;
    }

    if (sub === 'show') {
      const stored = readStoredConfig();
      const effectiveBaseUrl = process.env.CEM_BASE_URL ?? stored.baseUrl ?? '';
      const effectiveToken = process.env.CEM_TOKEN ?? stored.token ?? '';
      const effectiveFrom = process.env.CEM_FROM ?? stored.defaultFrom ?? '';
      printJson({
        configPath: getConfigPath(),
        baseUrl: effectiveBaseUrl || null,
        token: maskToken(effectiveToken),
        defaultFrom: effectiveFrom || null
      });
      return;
    }

    throw new Error(`Unknown config subcommand: ${sub || '(missing)'}`);
  }

  const config = resolveConfig();
  const client = new CemClient(config);
  const asJson = Boolean(flags.json);

  switch (cmd) {
    case 'health': {
      const data = await client.health();
      printJson(data);
      return;
    }

    case 'list':
    case 'ls': {
      const data = await client.listEmails({
        folder: getStringFlag(flags, 'folder'),
        status: getStringFlag(flags, 'status'),
        recipient: getStringFlag(flags, 'to'),
        sender: getStringFlag(flags, 'from'),
        search: getStringFlag(flags, 'search'),
        limit: getStringFlag(flags, 'limit') ?? 20,
        page: getStringFlag(flags, 'page') ?? 1
      });
      if (asJson) {
        printJson(data);
      } else {
        formatEmailList(data.items);
      }
      return;
    }

    case 'read': {
      const id = positionals[1];
      if (!id) throw new Error('Missing <id> for `cem read`');
      const email = await client.readEmail(id);
      if (asJson) {
        printJson(email);
      } else {
        formatEmailDetail(email, Boolean(flags['raw-html']));
      }
      return;
    }

    case 'latest': {
      const list = await client.listEmails({
        recipient: getStringFlag(flags, 'to'),
        sender: getStringFlag(flags, 'from'),
        search: getStringFlag(flags, 'search'),
        limit: 1,
        page: 1
      });
      const first = list.items[0];
      if (!first) {
        throw new Error('No matching email found');
      }
      const email = await client.readEmail(first.id);
      if (flags['code-only']) {
        if (!email.verification?.code) throw new Error('No verification code found in latest email');
        process.stdout.write(email.verification.code + '\n');
        return;
      }
      if (flags['link-only']) {
        if (!email.verification?.primaryLink) throw new Error('No verification link found in latest email');
        process.stdout.write(email.verification.primaryLink.targetUrl + '\n');
        return;
      }
      if (asJson) {
        printJson(email);
      } else {
        formatEmailDetail(email, Boolean(flags['raw-html']));
      }
      return;
    }

    case 'watch': {
      const interval = Number(getStringFlag(flags, 'interval') ?? 3000);
      const timeout = Number(getStringFlag(flags, 'timeout') ?? 60000);
      const since = getStringFlag(flags, 'since') ?? new Date().toISOString();
      const deadline = Date.now() + timeout;

      while (Date.now() <= deadline) {
        const list = await client.listEmails({
          recipient: getStringFlag(flags, 'to'),
          sender: getStringFlag(flags, 'from'),
          search: getStringFlag(flags, 'search'),
          start_date: since,
          limit: 5,
          page: 1
        });
        const match = list.items[0];
        if (match) {
          const email = await client.readEmail(match.id);
          if (flags['code-only']) {
            if (!email.verification?.code) throw new Error('Matched email has no verification code');
            process.stdout.write(email.verification.code + '\n');
            return;
          }
          if (asJson) {
            printJson(email);
          } else {
            formatEmailDetail(email, Boolean(flags['raw-html']));
          }
          return;
        }
        await new Promise(resolve => setTimeout(resolve, interval));
      }

      throw new Error(`Timed out after ${timeout}ms waiting for matching email`);
    }

    case 'attachment': {
      const emailId = positionals[1];
      const attId = positionals[2];
      if (!emailId || !attId) throw new Error('Usage: cem attachment <emailId> <attachmentId> [--out <path>]');
      const { bytes } = await client.requestBytes(
        `/api/emails/${encodeURIComponent(emailId)}/attachments/${encodeURIComponent(attId)}`
      );
      const outPath = getStringFlag(flags, 'out');
      if (outPath) {
        fs.writeFileSync(outPath, bytes);
        process.stdout.write(`Saved ${bytes.byteLength} bytes to ${outPath}\n`);
      } else {
        process.stdout.write(bytes);
      }
      return;
    }

    case 'raw': {
      const id = positionals[1];
      if (!id) throw new Error('Usage: cem raw <id> [--out <path>]');
      const { bytes } = await client.requestBytes(`/api/emails/${encodeURIComponent(id)}/raw`);
      const outPath = getStringFlag(flags, 'out');
      if (outPath) {
        fs.writeFileSync(outPath, bytes);
        process.stdout.write(`Saved ${bytes.byteLength} bytes to ${outPath}\n`);
      } else {
        process.stdout.write(bytes);
      }
      return;
    }

    case 'mark': {
      const id = positionals[1];
      if (!id) throw new Error('Usage: cem mark <id> (--read | --unread)');
      if (!flags.read && !flags.unread) {
        throw new Error('Specify --read or --unread');
      }
      const isRead = Boolean(flags.read);
      await client.markReadStatus(id, isRead);
      process.stdout.write(`Marked ${id} as ${isRead ? 'read' : 'unread'}\n`);
      return;
    }

    case 'delete': {
      const id = positionals[1];
      if (!id) throw new Error('Usage: cem delete <id>');
      await client.deleteEmail(id);
      process.stdout.write(`Deleted ${id}\n`);
      return;
    }

    case 'send': {
      const to = getStringFlag(flags, 'to');
      const subject = getStringFlag(flags, 'subject');
      const text = getStringFlag(flags, 'text');
      const html = getStringFlag(flags, 'html');
      const from = getStringFlag(flags, 'from') ?? config.defaultFrom;
      const method = (getStringFlag(flags, 'method') ?? 'internal') as 'internal' | 'cf' | 'resend';
      if (!to || !subject || (!text && !html)) {
        throw new Error('Usage: cem send --to <addr> --subject <subj> (--text <body> | --html <html>)');
      }
      const result = await client.sendEmail({
        to,
        from,
        subject,
        content: (html ?? text)!,
        content_type: html ? 'html' : 'text',
        delivery_method: method
      });
      printJson(result);
      return;
    }

    case 'forward': {
      const id = positionals[1];
      if (!id) throw new Error('Usage: cem forward <id> (--to <addr> | --channel <id>)');
      const to = getStringFlag(flags, 'to');
      const channel = getStringFlag(flags, 'channel');
      if (channel) {
        const result = await client.forwardEmail(id, { mode: 'webhook', channelId: Number(channel) });
        printJson(result);
        return;
      }
      if (to) {
        const method = getStringFlag(flags, 'method') as 'internal' | 'cf' | 'resend' | undefined;
        const from = getStringFlag(flags, 'from') ?? config.defaultFrom;
        const result = await client.forwardEmail(id, {
          mode: 'recipient',
          targetEmail: to,
          targetForwardType: method,
          from
        });
        printJson(result);
        return;
      }
      throw new Error('Specify --to <addr> or --channel <id>');
    }

    default:
      throw new Error(`Unknown command: ${cmd}`);
  }
}
