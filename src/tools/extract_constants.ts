/**
 * extract_crypto_constants — Extract crypto constants from JS source
 *
 * Scans for: AES/DES/SM4 S-boxes, SHA/MD5/SM3 initial hash values,
 * round constants, elliptic curve parameters, magic numbers.
 */
import type { McpToolResult } from '../types.js';

interface ConstantMatch {
  algorithm: string;
  constantType: string;
  value: string;
  location: { line: number; column: number };
  snippet: string;
  confidence: number;
  description: string;
}

// ===== AES S-box (full 256 bytes) =====
const AES_SBOX_HEX = '637c7777f26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814dc222a908846eeb814de5e0bdbeb5f9b651f9c4534a93c8a8a8a8a8a8a8a8';

const CONSTANT_DEFINITIONS = [
  {
    algorithm: 'AES',
    constantType: 'S-box',
    patterns: [
      { regex: /637c7777f26b6fc5/gi, description: 'AES S-box (hex string form)' },
      { regex: /\[\s*0x63\s*,\s*0x7c\s*,\s*0x77\s*,\s*0x7b/gi, description: 'AES S-box (0x hex array form)' },
      { regex: /\[\s*99\s*,\s*124\s*,\s*119\s*,\s*123\s*,\s*242\s*,\s*107\s*,\s*111\s*,\s*197\s*\]/gi, description: 'AES S-box (decimal array form)' },
    ],
    confidence: 0.99,
  },
  {
    algorithm: 'AES',
    constantType: 'Inverse-S-box',
    patterns: [
      { regex: /52096ad53036a538bf40a39e81f3d7fb/gi, description: 'AES Inverse S-box (hex)' },
      { regex: /\[\s*0x52\s*,\s*0x09\s*,\s*0x6a\s*,\s*0xd5/gi, description: 'AES Inverse S-box (0x array)' },
    ],
    confidence: 0.99,
  },
  {
    algorithm: 'AES',
    constantType: 'Rcon',
    patterns: [
      { regex: /\[\s*0x01\s*,\s*0x02\s*,\s*0x04\s*,\s*0x08\s*,\s*0x10\s*,\s*0x20\s*,\s*0x40\s*,\s*0x80\s*,\s*0x1b\s*,\s*0x36\s*\]/gi, description: 'AES round constants (Rcon)' },
      { regex: /01020408102040801b36/gi, description: 'AES Rcon (hex string)' },
    ],
    confidence: 0.95,
  },
  {
    algorithm: 'SHA-256',
    constantType: 'initial-hash-values',
    patterns: [
      { regex: /6a09e667|bb67ae85|3c6ef372|a54ff53a|510e527f|9b05688c|1f83d9ab|5be0cd19/gi, description: 'SHA-256 initial hash H0-H7' },
    ],
    confidence: 0.95,
  },
  {
    algorithm: 'SHA-256',
    constantType: 'round-constants',
    patterns: [
      { regex: /428a2f98|71374491|b5c0fbcf|e9b5dba5/gi, description: 'SHA-256 round constants K[0]-K[3]' },
    ],
    confidence: 0.95,
  },
  {
    algorithm: 'SHA-1',
    constantType: 'initial-hash-values',
    patterns: [
      { regex: /67452301|efcdab89|98badcfe|10325476|c3d2e1f0/gi, description: 'SHA-1 initial hash values' },
    ],
    confidence: 0.9,
  },
  {
    algorithm: 'MD5',
    constantType: 'initial-values',
    patterns: [
      { regex: /0x67452301|0xefcdab89|0x98badcfe|0x10325476/gi, description: 'MD5 initial hash values (hex)' },
      { regex: /67452301.*efcdab89.*98badcfe.*10325476/gis, description: 'MD5 initial hash values (sequence)' },
    ],
    confidence: 0.9,
  },
  {
    algorithm: 'MD5',
    constantType: 'T-constants',
    patterns: [
      { regex: /0xd76aa478|0xe8c7b756|0x242070db|0xc1bdceee|0xf57c0faf|0x4787c62a/gi, description: 'MD5 T-table constants T[1]-T[6]' },
    ],
    confidence: 0.9,
  },
  {
    algorithm: 'SM3',
    constantType: 'IV',
    patterns: [
      { regex: /7380166f4914b2b9172442d7da8a0600|7380166f/gi, description: 'SM3 initialization vector' },
    ],
    confidence: 0.95,
  },
  {
    algorithm: 'SM3',
    constantType: 'T-constants',
    patterns: [
      { regex: /79cc4519|7a879d8a/gi, description: 'SM3 Tj constants (T0=0x79cc4519, T1=0x7a879d8a)' },
    ],
    confidence: 0.85,
  },
  {
    algorithm: 'SM4',
    constantType: 'S-box',
    patterns: [
      { regex: /d690e9fe|0xd6,0x90,0xe9,0xfe/gi, description: 'SM4 S-box (first 4 bytes)' },
      { regex: /\[\s*0xd6\s*,\s*0x90\s*,\s*0xe9\s*,\s*0xfe/gi, description: 'SM4 S-box (0x array form)' },
    ],
    confidence: 0.95,
  },
  {
    algorithm: 'SM4',
    constantType: 'FK-constants',
    patterns: [
      { regex: /0xa3b1bac6|0x56aa3350|0x677d9197|0xb27022dc/gi, description: 'SM4 FK system parameters' },
    ],
    confidence: 0.9,
  },
  {
    algorithm: 'SM4',
    constantType: 'CK-constants',
    patterns: [
      { regex: /00070e15|1c232a31|383f464d/gi, description: 'SM4 CK round constants' },
    ],
    confidence: 0.85,
  },
  {
    algorithm: 'DES',
    constantType: 'S-box',
    patterns: [
      { regex: /14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7/gi, description: 'DES S-box S1 row 0' },
    ],
    confidence: 0.9,
  },
  {
    algorithm: 'DES',
    constantType: 'IP-permutation',
    patterns: [
      { regex: /58,50,42,34,26,18,10,2/gi, description: 'DES initial permutation table' },
    ],
    confidence: 0.9,
  },
  {
    algorithm: 'SM2',
    constantType: 'curve-parameters',
    patterns: [
      { regex: /fffffffeffffffffffffffffffffffff00000000ffffffffffffffff/gi, description: 'SM2 curve p parameter' },
      { regex: /28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd41/gi, description: 'SM2 curve b parameter' },
    ],
    confidence: 0.9,
  },
  {
    algorithm: 'NIST-P256',
    constantType: 'curve-parameters',
    patterns: [
      { regex: /ffffffff00000001000000000000000000000000ffffffffffffffffffffffff/gi, description: 'NIST P-256 curve p parameter' },
    ],
    confidence: 0.85,
  },
  {
    algorithm: 'CRC32',
    constantType: 'polynomial',
    patterns: [
      { regex: /0xedb88320|edb88320/gi, description: 'CRC32 reversed polynomial' },
    ],
    confidence: 0.85,
  },
  {
    algorithm: 'Base64',
    constantType: 'alphabet',
    patterns: [
      { regex: /ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+\/=|A-Za-z0-9\+\/=/gi, description: 'Base64 alphabet string' },
    ],
    confidence: 0.7,
  },
];

function getLineCol(source: string, index: number): { line: number; column: number } {
  const before = source.slice(0, index);
  const line = before.split('\n').length;
  const column = index - before.lastIndexOf('\n');
  return { line, column };
}

function getSnippet(source: string, index: number, radius = 80): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(source.length, index + radius);
  let snippet = source.slice(start, end).replace(/\n/g, ' ').trim();
  if (start > 0) snippet = '...' + snippet;
  if (end < source.length) snippet = snippet + '...';
  return snippet;
}

export async function extractCryptoConstants(source: string): Promise<McpToolResult> {
  const matches: ConstantMatch[] = [];

  for (const def of CONSTANT_DEFINITIONS) {
    for (const { regex: patternRegex, description } of def.patterns) {
      const regex = new RegExp(patternRegex.source, patternRegex.flags.includes('g') ? patternRegex.flags : patternRegex.flags + 'g');
      let m: RegExpExecArray | null;
      while ((m = regex.exec(source)) !== null) {
        const index = m.index;
        const { line, column } = getLineCol(source, index);
        const snippet = getSnippet(source, index);

        // Deduplicate nearby matches of same algorithm+type
        if (matches.some((x) => x.algorithm === def.algorithm && x.constantType === def.constantType && Math.abs(x.location.line - line) < 3)) {
          if (m.index === regex.lastIndex) regex.lastIndex++;
          continue;
        }

        matches.push({
          algorithm: def.algorithm,
          constantType: def.constantType,
          value: m[0].slice(0, 100),
          location: { line, column },
          snippet,
          confidence: def.confidence,
          description,
        });

        if (m.index === regex.lastIndex) regex.lastIndex++;
      }
    }
  }

  // Sort by confidence then line
  matches.sort((a, b) => b.confidence - a.confidence || a.location.line - b.location.line);

  // Summary by algorithm
  const summary: Record<string, string[]> = {};
  for (const m of matches) {
    if (!summary[m.algorithm]) summary[m.algorithm] = [];
    if (!summary[m.algorithm].includes(m.constantType)) {
      summary[m.algorithm].push(m.constantType);
    }
  }

  const result = {
    totalConstants: matches.length,
    algorithmsFound: Object.keys(summary),
    summary,
    constants: matches.map((m) => ({
      algorithm: m.algorithm,
      constantType: m.constantType,
      value: m.value,
      location: `line ${m.location.line}:${m.location.column}`,
      snippet: m.snippet,
      confidence: `${(m.confidence * 100).toFixed(0)}%`,
      description: m.description,
    })),
    hints: generateConstantHints(matches),
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  };
}

function generateConstantHints(matches: ConstantMatch[]): string[] {
  const hints: string[] = [];
  const algos = new Set(matches.map((m) => m.algorithm));

  if (algos.has('AES')) {
    hints.push('AES constants found: this is likely a from-scratch AES implementation (not using CryptoJS). Extract the full S-box and key schedule for reconstruction');
  }
  if (algos.has('SM3')) {
    hints.push('SM3 constants found: 国密 SM3 implementation detected. The IV 7380166f... confirms SM3. Reconstruct using Python gmssl or pysmx library');
  }
  if (algos.has('SM4')) {
    hints.push('SM4 constants found: 国密 SM4 implementation detected. Extract FK/CK parameters and S-box for verification');
  }
  if (algos.has('SM2')) {
    hints.push('SM2 curve parameters found: 国密 SM2 implementation detected. Extract public key point (x,y) for encryption/signing');
  }
  if (algos.has('SHA-256')) {
    hints.push('SHA-256 constants found: likely a from-scratch SHA-256. Compare with known test vectors for verification');
  }
  if (algos.has('MD5')) {
    hints.push('MD5 T-constants found: from-scratch MD5 implementation. These constants are the sin-derived T-table');
  }
  if (algos.has('DES')) {
    hints.push('DES S-box found: legacy DES/3DES implementation. Extract all 8 S-boxes for complete reconstruction');
  }

  if (hints.length === 0) {
    hints.push('No known crypto constants found. The code may use: (1) library calls instead of raw implementation, (2) modified constants, (3) custom algorithm');
  }

  return hints;
}
