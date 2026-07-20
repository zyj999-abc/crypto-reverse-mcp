/**
 * crypto-reverse-mcp server core
 * Registers all tools and starts stdio transport
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { detectCrypto } from './tools/detect_crypto.js';
import { identifyObfuscation } from './tools/identify_obfuscation.js';
import { reconstructAlgorithm } from './tools/reconstruct_algorithm.js';
import { generateSdk } from './tools/generate_sdk.js';
import { bypassAntiDebug } from './tools/bypass_anti_debug.js';
import { extractCryptoConstants } from './tools/extract_constants.js';

const server = new McpServer({
  name: 'crypto-reverse-mcp',
  version: '0.1.0',
});

// Tool 1: detect_crypto
server.tool(
  'detect_crypto',
  'Detect cryptographic algorithms used in JavaScript source code. Identifies AES/RSA/SM2/SM3/SM4/HMAC/MD5/SHA family algorithms with evidence, key/IV source tracking, and cipher mode. Input: JS source code string. Returns list of detected crypto usages with algorithm type, location (line/col), evidence snippet, key source, IV source, and mode (CBC/ECB/GCM/CTR etc).',
  {
    source: z.string().describe('JavaScript source code to analyze'),
    options: z
      .object({
        includeNative: z
          .boolean()
          .optional()
          .describe('Include Web Crypto API / Node crypto module detection (default: true)'),
        includeConstants: z
          .boolean()
          .optional()
          .describe('Scan for crypto constants like S-box, initial hash values (default: true)'),
        includeMinified: z
          .boolean()
          .optional()
          .describe('Attempt detection on minified code by tracking variable flows (default: false)'),
      })
      .optional()
      .describe('Detection options'),
  },
  async ({ source, options }) => detectCrypto(source, options ?? {}),
);

// Tool 2: identify_obfuscation
server.tool(
  'identify_obfuscation',
  'Identify the obfuscation/packing technique used in JavaScript code. Detects webpack bundles, AAEncode, JJEncode, JSFuck, obfuscator.io, JavaScript obfuscator, babel minified, packer (Dean Edwards), UPX-style, eval-based loaders, and control-flow flattening. Input: JS source code. Returns obfuscation type, confidence, unpack hints, and recommended deobfuscation strategy.',
  {
    source: z.string().describe('JavaScript source code to analyze'),
  },
  async ({ source }) => identifyObfuscation(source),
);

// Tool 3: reconstruct_algorithm
server.tool(
  'reconstruct_algorithm',
  'Reconstruct a standalone implementation of a cryptographic algorithm from JS source + captured input/output samples. Given the original JS code and (optionally) sample input→output pairs, generate a self-contained Python implementation that reproduces the same transformation. Supports common AES/RSA/HMAC/MD5/SHA/SM2/SM3/SM4 patterns. Input: source code, optional samples (array of {input, output} pairs), target language (python/node). Returns reconstructed code + verification notes.',
  {
    source: z.string().describe('JS source code containing the crypto function'),
    samples: z
      .array(
        z.object({
          input: z.string().describe('Input value (hex/base64/string)'),
          output: z.string().describe('Expected output (hex/base64/string)'),
          inputEncoding: z
            .enum(['utf8', 'hex', 'base64'])
            .optional()
            .describe('Input encoding (default: utf8)'),
          outputEncoding: z
            .enum(['utf8', 'hex', 'base64'])
            .optional()
            .describe('Output encoding (default: hex)'),
        }),
      )
      .optional()
      .describe('Sample input/output pairs for verification'),
    targetLanguage: z
      .enum(['python', 'node'])
      .optional()
      .describe('Output language (default: python)'),
    functionName: z
      .string()
      .optional()
      .describe('Name of the target function to reconstruct (if known)'),
  },
  async ({ source, samples, targetLanguage, functionName }) =>
    reconstructAlgorithm(source, {
      samples,
      targetLanguage: targetLanguage ?? 'python',
      functionName,
    }),
);

// Tool 4: generate_sdk
server.tool(
  'generate_sdk',
  'Generate a ready-to-use SDK (Python/Node/Go) from a reversed API contract. Given endpoint URL, HTTP method, headers, body template, and the signature/encryption algorithm spec, produce a complete SDK file with: request construction, crypto signing, error handling, and usage example. Input: API spec (url, method, sign algorithm description, params). Returns SDK code in requested language.',
  {
    apiSpec: z.object({
      url: z.string().describe('API endpoint URL'),
      method: z
        .enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        .optional()
        .describe('HTTP method (default: POST)'),
      headers: z
        .record(z.string())
        .optional()
        .describe('Static headers (key-value)'),
      bodyTemplate: z
        .string()
        .optional()
        .describe('Request body template with placeholders like {{param}}'),
      signSpec: z
        .object({
          algorithm: z
            .string()
            .describe('Algorithm name: AES-CBC, HMAC-SHA256, SM2, RSA-SHA1, MD5, custom, etc'),
          keySource: z
            .string()
            .describe('Where the key comes from: static, appkey+secret, timestamp-based, etc'),
          signLocation: z
            .enum(['header', 'query', 'body'])
            .optional()
            .describe('Where to put the signature (default: header)'),
          signField: z
            .string()
            .optional()
            .describe('Field name for the signature (default: sign)'),
          paramsToSign: z
            .array(z.string())
            .optional()
            .describe('Ordered list of param names to include in signature'),
        })
        .optional()
        .describe('Signature specification'),
      loginSpec: z
        .object({
          url: z.string().describe('Login endpoint'),
          usernameField: z.string().describe('Username field name'),
          passwordField: z.string().describe('Password field name'),
          passwordEncryption: z
            .string()
            .optional()
            .describe('Password encryption algorithm (e.g. RSA, SM2, MD5)'),
          tokenField: z
            .string()
            .optional()
            .describe('Token field in response (default: token)'),
        })
        .optional()
        .describe('Login flow specification'),
    }),
    language: z
      .enum(['python', 'node', 'go'])
      .optional()
      .describe('SDK output language (default: python)'),
  },
  async ({ apiSpec, language }) => generateSdk(apiSpec, language ?? 'python'),
);

// Tool 5: bypass_anti_debug
server.tool(
  'bypass_anti_debug',
  'Generate anti-debugging bypass scripts for common anti-debug techniques. Detects and generates bypass for: debugger statement loops, setInterval debugger, devtools detection (window size, console access, Function.toString), timing checks, console.log getter traps, and CodeMirror/eruda detection. Input: JS source code or technique name. Returns bypass injection script + injection instructions.',
  {
    source: z
      .string()
      .optional()
      .describe('JS source code to analyze (if empty, generate universal bypass)'),
    techniques: z
      .array(
        z.enum([
          'debugger_loop',
          'setInterval_debugger',
          'devtools_window_size',
          'devtools_console_access',
          'timing_check',
          'console_getter_trap',
          'function_toString_check',
          'all',
        ]),
      )
      .optional()
      .describe('Specific techniques to bypass (default: all)'),
    outputFormat: z
      .enum(['inject_script', 'fiddler_rule', 'chrome_devtools_snippet'])
      .optional()
      .describe('Output format (default: inject_script)'),
  },
  async ({ source, techniques, outputFormat }) =>
    bypassAntiDebug({
      source,
      techniques: techniques ?? ['all'],
      outputFormat: outputFormat ?? 'inject_script',
    }),
);

// Tool 6: extract_crypto_constants
server.tool(
  'extract_crypto_constants',
  'Extract cryptographic constants from JS source code. Identifies S-boxes (AES/DES), initial hash values (SHA-256/SHA-1/MD5/SM3), round constants, elliptic curve parameters (SM2/NIST curves), magic numbers, and known crypto constant arrays. Input: JS source code. Returns list of found constants with their crypto algorithm association and location.',
  {
    source: z.string().describe('JavaScript source code to analyze'),
  },
  async ({ source }) => extractCryptoConstants(source),
);

export async function runServer(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[crypto-reverse-mcp] started, stdio transport ready');
  console.error('[crypto-reverse-mcp] 6 tools registered: detect_crypto, identify_obfuscation, reconstruct_algorithm, generate_sdk, bypass_anti_debug, extract_crypto_constants');
}
