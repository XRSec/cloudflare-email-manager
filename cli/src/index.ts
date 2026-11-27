#!/usr/bin/env node
import { runCli } from './commands.ts';
import { checkForCliUpdate } from './version.ts';

async function main() {
  await checkForCliUpdate();
  await runCli(process.argv.slice(2));
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`Error: ${message}\n`);
  process.exit(1);
});
