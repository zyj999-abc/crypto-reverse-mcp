#!/usr/bin/env node
/**
 * crypto-reverse-mcp entry point
 * Started via `npx crypto-reverse-mcp`
 */
import { runServer } from './server.js';

runServer().catch((err) => {
  console.error('[crypto-reverse-mcp] fatal:', err);
  process.exit(1);
});
