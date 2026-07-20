/**
 * detect_crypto — Detect cryptographic algorithms in JS source code
 *
 * Detection strategies:
 * 1. Library API patterns (CryptoJS, JSEncrypt, jsrsasign, sm-crypto, forge, etc.)
 * 2. Web Crypto API / Node crypto module calls
 * 3. Crypto constants (S-boxes, initial hash values, round constants)
 * 4. Function name heuristics (encrypt, decrypt, sign, hmac, md5, sha, etc.)
 * 5. Cipher mode detection (CBC, ECB, GCM, CTR, CFB, OFB)
 */
import type { McpToolResult } from '../types.js';

export interface CryptoDetection {
  algorithm: string;
  category: 'symmetric' | 'asymmetric' | 'hash' | 'mac' | 'kdf' | 'encoding' | 'random';
  library?: string;
  location: { line: number; column: number; snippet: string };
  confidence: number; // 0-1
  evidence: string;
  keySource?: string;
  ivSource?: string;
  mode?: string;
  padding?: string;
}

export interface DetectOptions {
  includeNative?: boolean;
  includeConstants?: boolean;
  includeMinified?: boolean;
}

// ===== Pattern library =====

interface CryptoPattern {
  algorithm: string;
  category: CryptoDetection['category'];
  library?: string;
  regex: RegExp;
  confidence: number;
  description: string;
  extractMode?: (match: string) => string | undefined;
  extractKey?: (match: string, fullSource: string, matchIndex: number) => string | undefined;
}

const PATTERNS: CryptoPattern[] = [
  // ===== CryptoJS =====
  {
    algorithm: 'AES',
    category: 'symmetric',
    library: 'CryptoJS',
    regex: /CryptoJS\.AES\.(encrypt|decrypt)\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS AES encrypt/decrypt call',
  },
  {
    algorithm: 'DES',
    category: 'symmetric',
    library: 'CryptoJS',
    regex: /CryptoJS\.DES\.(encrypt|decrypt)\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS DES encrypt/decrypt call',
  },
  {
    algorithm: 'TripleDES',
    category: 'symmetric',
    library: 'CryptoJS',
    regex: /CryptoJS\.TripleDES\.(encrypt|decrypt)\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS TripleDES encrypt/decrypt call',
  },
  {
    algorithm: 'Rabbit',
    category: 'symmetric',
    library: 'CryptoJS',
    regex: /CryptoJS\.Rabbit\.(encrypt|decrypt)\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS Rabbit stream cipher',
  },
  {
    algorithm: 'RC4',
    category: 'symmetric',
    library: 'CryptoJS',
    regex: /CryptoJS\.RC4\.(encrypt|decrypt)\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS RC4 stream cipher',
  },
  {
    algorithm: 'MD5',
    category: 'hash',
    library: 'CryptoJS',
    regex: /CryptoJS\.MD5\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS MD5 hash',
  },
  {
    algorithm: 'SHA-1',
    category: 'hash',
    library: 'CryptoJS',
    regex: /CryptoJS\.SHA1\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS SHA-1 hash',
  },
  {
    algorithm: 'SHA-256',
    category: 'hash',
    library: 'CryptoJS',
    regex: /CryptoJS\.SHA256\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS SHA-256 hash',
  },
  {
    algorithm: 'SHA-512',
    category: 'hash',
    library: 'CryptoJS',
    regex: /CryptoJS\.SHA512\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS SHA-512 hash',
  },
  {
    algorithm: 'SHA-3',
    category: 'hash',
    library: 'CryptoJS',
    regex: /CryptoJS\.SHA3\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS SHA-3 hash',
  },
  {
    algorithm: 'HMAC',
    category: 'mac',
    library: 'CryptoJS',
    regex: /CryptoJS\.HmacMD5\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS HmacMD5',
  },
  {
    algorithm: 'HMAC-SHA256',
    category: 'mac',
    library: 'CryptoJS',
    regex: /CryptoJS\.HmacSHA256\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS HmacSHA256',
  },
  {
    algorithm: 'PBKDF2',
    category: 'kdf',
    library: 'CryptoJS',
    regex: /CryptoJS\.PBKDF2\s*\(/gi,
    confidence: 0.95,
    description: 'CryptoJS PBKDF2 key derivation',
  },
  {
    algorithm: 'AES',
    category: 'symmetric',
    library: 'CryptoJS',
    regex: /CryptoJS\.enc\.Utf8\.parse\s*\(/gi,
    confidence: 0.4,
    description: 'CryptoJS encoding (often used with AES key/IV preparation)',
  },

  // ===== JSEncrypt (RSA) =====
  {
    algorithm: 'RSA',
    category: 'asymmetric',
    library: 'JSEncrypt',
    regex: /new\s+JSEncrypt\s*\(/gi,
    confidence: 0.9,
    description: 'JSEncrypt RSA instantiation',
  },
  {
    algorithm: 'RSA',
    category: 'asymmetric',
    library: 'JSEncrypt',
    regex: /\.(setPublicKey|setPrivateKey|encrypt|decrypt|sign)\s*\(/gi,
    confidence: 0.5,
    description: 'JSEncrypt RSA operation (context-dependent)',
  },

  // ===== jsrsasign =====
  {
    algorithm: 'RSA',
    category: 'asymmetric',
    library: 'jsrsasign',
    regex: /rsa\.encrypt\s*\(/gi,
    confidence: 0.85,
    description: 'jsrsasign RSA encrypt',
  },
  {
    algorithm: 'ECDSA',
    category: 'asymmetric',
    library: 'jsrsasign',
    regex: /KJUR\.Signature\s*\(/gi,
    confidence: 0.85,
    description: 'jsrsasign digital signature',
  },

  // ===== sm-crypto (国密) =====
  {
    algorithm: 'SM2',
    category: 'asymmetric',
    library: 'sm-crypto',
    regex: /sm2\.(doEncrypt|doDecrypt|doSignature|doVerifySignature)\s*\(/gi,
    confidence: 0.95,
    description: 'sm-crypto SM2 operation',
  },
  {
    algorithm: 'SM3',
    category: 'hash',
    library: 'sm-crypto',
    regex: /sm3\s*\(\s*\(/gi,
    confidence: 0.9,
    description: 'sm-crypto SM3 hash',
  },
  {
    algorithm: 'SM4',
    category: 'symmetric',
    library: 'sm-crypto',
    regex: /sm4\.(encrypt|decrypt)\s*\(/gi,
    confidence: 0.95,
    description: 'sm-crypto SM4 symmetric cipher',
  },

  // ===== node-forge =====
  {
    algorithm: 'AES',
    category: 'symmetric',
    library: 'node-forge',
    regex: /forge\.cipher\.createCipher\s*\(\s*['"]AES/gi,
    confidence: 0.9,
    description: 'node-forge AES cipher',
  },
  {
    algorithm: 'RSA',
    category: 'asymmetric',
    library: 'node-forge',
    regex: /forge\.pki\.rsa\.(encrypt|decrypt|sign)\s*\(/gi,
    confidence: 0.9,
    description: 'node-forge RSA operation',
  },
  {
    algorithm: 'MD5',
    category: 'hash',
    library: 'node-forge',
    regex: /forge\.md\.md5\.create\s*\(/gi,
    confidence: 0.9,
    description: 'node-forge MD5',
  },
  {
    algorithm: 'SHA-256',
    category: 'hash',
    library: 'node-forge',
    regex: /forge\.md\.sha256\.create\s*\(/gi,
    confidence: 0.9,
    description: 'node-forge SHA-256',
  },

  // ===== Web Crypto API =====
  {
    algorithm: 'AES',
    category: 'symmetric',
    regex: /crypto\.subtle\.(encrypt|decrypt)\s*\(\s*['"`]AES/gi,
    confidence: 0.9,
    description: 'Web Crypto API AES operation',
  },
  {
    algorithm: 'RSA',
    category: 'asymmetric',
    regex: /crypto\.subtle\.(encrypt|decrypt)\s*\(\s*['"`]RSA/gi,
    confidence: 0.9,
    description: 'Web Crypto API RSA operation',
  },
  {
    algorithm: 'ECDSA',
    category: 'asymmetric',
    regex: /crypto\.subtle\.sign\s*\(\s*['"`]ECDSA/gi,
    confidence: 0.9,
    description: 'Web Crypto API ECDSA sign',
  },
  {
    algorithm: 'HMAC',
    category: 'mac',
    regex: /crypto\.subtle\.sign\s*\(\s*['"`]HMAC/gi,
    confidence: 0.9,
    description: 'Web Crypto API HMAC',
  },
  {
    algorithm: 'SHA-256',
    category: 'hash',
    regex: /crypto\.subtle\.digest\s*\(\s*['"`]SHA-256/gi,
    confidence: 0.9,
    description: 'Web Crypto API SHA-256 digest',
  },
  {
    algorithm: 'SHA-1',
    category: 'hash',
    regex: /crypto\.subtle\.digest\s*\(\s*['"`]SHA-1/gi,
    confidence: 0.9,
    description: 'Web Crypto API SHA-1 digest',
  },
  {
    algorithm: 'PBKDF2',
    category: 'kdf',
    regex: /crypto\.subtle\.deriveBits\s*\(\s*['"`]PBKDF2/gi,
    confidence: 0.9,
    description: 'Web Crypto API PBKDF2',
  },

  // ===== Node.js crypto module =====
  {
    algorithm: 'AES',
    category: 'symmetric',
    regex: /crypto\.createCipher(?:iv)?\s*\(\s*['"]aes/gi,
    confidence: 0.9,
    description: 'Node.js crypto AES cipher',
  },
  {
    algorithm: 'MD5',
    category: 'hash',
    regex: /crypto\.createHash\s*\(\s*['"]md5/gi,
    confidence: 0.9,
    description: 'Node.js crypto MD5',
  },
  {
    algorithm: 'SHA-256',
    category: 'hash',
    regex: /crypto\.createHash\s*\(\s*['"]sha256/gi,
    confidence: 0.9,
    description: 'Node.js crypto SHA-256',
  },
  {
    algorithm: 'HMAC',
    category: 'mac',
    regex: /crypto\.createHmac\s*\(\s*['"]sha/gi,
    confidence: 0.85,
    description: 'Node.js crypto HMAC',
  },

  // ===== sjcl (Stanford JavaScript Crypto Library) =====
  {
    algorithm: 'AES',
    category: 'symmetric',
    library: 'sjcl',
    regex: /sjcl\.encrypt\s*\(/gi,
    confidence: 0.85,
    description: 'sjcl encrypt (usually AES)',
  },

  // ===== aes-js / crypto-js pure =====
  {
    algorithm: 'AES',
    category: 'symmetric',
    library: 'aes-js',
    regex: /aesjs?\.(ModeOfOperation)\.(cbc|ecb|ctr|ofb|cfb)/gi,
    confidence: 0.9,
    description: 'aes-js AES mode',
  },

  // ===== Function name heuristics (lower confidence) =====
  {
    algorithm: 'MD5',
    category: 'hash',
    regex: /function\s+(md5|h_md5|hex_md5)\s*\(/gi,
    confidence: 0.6,
    description: 'MD5 function definition (heuristic)',
  },
  {
    algorithm: 'SHA-1',
    category: 'hash',
    regex: /function\s+(sha1|sha_1)\s*\(/gi,
    confidence: 0.6,
    description: 'SHA-1 function definition (heuristic)',
  },
  {
    algorithm: 'Base64',
    category: 'encoding',
    regex: /\bbtoa\s*\(|\batob\s*\(|base64\.encode\s*\(|base64\.decode\s*\(/gi,
    confidence: 0.7,
    description: 'Base64 encode/decode',
  },
  {
    algorithm: 'URL-encode',
    category: 'encoding',
    regex: /\bencodeURIComponent\s*\(|\bencodeURI\s*\(/gi,
    confidence: 0.5,
    description: 'URL encoding',
  },
];

// ===== Crypto constants =====

interface CryptoConstant {
  algorithm: string;
  category: CryptoDetection['category'];
  constantType: string;
  pattern: RegExp;
  confidence: number;
  description: string;
}

// AES S-box first 16 bytes (very distinctive)
const AES_SBOX_START = '0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5';
const AES_SBOX_START_HEX = '637c777bf26b6fc5';

// SHA-256 initial hash values
const SHA256_K_START = '428a2f98';

// MD5 constants
const MD5_T_CONST = /0xd76aa478|0xe8c7b756|0x242070db|0xc1bdceee/gi;

// SM3 IV
const SM3_IV = '7380166f4914b2b9172442d7da8a0600';

const CONSTANTS: CryptoConstant[] = [
  {
    algorithm: 'AES',
    category: 'symmetric',
    constantType: 'S-box',
    pattern: new RegExp(AES_SBOX_START.replace(/0x/g, '\\\\d*0x').replace(/,/g, '\\\\s*,\\\\s*0x'), 'i'),
    confidence: 0.99,
    description: 'AES S-box lookup table (first 8 bytes)',
  },
  {
    algorithm: 'AES',
    category: 'symmetric',
    constantType: 'S-box',
    pattern: /637c7777f26b6fc5/i,
    confidence: 0.99,
    description: 'AES S-box as hex string',
  },
  {
    algorithm: 'AES',
    category: 'symmetric',
    constantType: 'S-box',
    pattern: /\[\s*99\s*,\s*124\s*,\s*119\s*,\s*123\s*,\s*242\s*\]/i,
    confidence: 0.95,
    description: 'AES S-box as decimal array (first 5 values)',
  },
  {
    algorithm: 'SHA-256',
    category: 'hash',
    constantType: 'round-constant',
    pattern: new RegExp(SHA256_K_START, 'i'),
    confidence: 0.95,
    description: 'SHA-256 round constant K[0]',
  },
  {
    algorithm: 'SHA-256',
    category: 'hash',
    constantType: 'initial-hash',
    pattern: /6a09e667|bb67ae85|3c6ef372|a54ff53a/i,
    confidence: 0.95,
    description: 'SHA-256 initial hash value H0-H3',
  },
  {
    algorithm: 'SHA-1',
    category: 'hash',
    constantType: 'initial-hash',
    pattern: /67452301|efcdab89|98badcfe|10325476|c3d2e1f0/i,
    confidence: 0.9,
    description: 'SHA-1 initial hash values',
  },
  {
    algorithm: 'MD5',
    category: 'hash',
    constantType: 't-constant',
    pattern: MD5_T_CONST,
    confidence: 0.9,
    description: 'MD5 T-table constant',
  },
  {
    algorithm: 'MD5',
    category: 'hash',
    constantType: 'initial-hash',
    pattern: /0x67452301|0xefcdab89|0x98badcfe|0x10325476/i,
    confidence: 0.85,
    description: 'MD5 initial hash values',
  },
  {
    algorithm: 'SM3',
    category: 'hash',
    constantType: 'IV',
    pattern: new RegExp(SM3_IV, 'i'),
    confidence: 0.95,
    description: 'SM3 initialization vector',
  },
  {
    algorithm: 'SM4',
    category: 'symmetric',
    constantType: 'S-box',
    pattern: /0xd6,0x90,0xe9,0xfe|0xd690e9fe/i,
    confidence: 0.95,
    description: 'SM4 S-box (first 4 bytes)',
  },
  {
    algorithm: 'DES',
    category: 'symmetric',
    constantType: 'S-box',
    pattern: /14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7/i,
    confidence: 0.9,
    description: 'DES S-box S1 row 0',
  },
];

// ===== Cipher mode detection =====

function detectCipherMode(source: string, nearIndex: number): string | undefined {
  // Search within ±200 chars of the crypto call for mode indicators
  const window = source.slice(Math.max(0, nearIndex - 200), nearIndex + 200);
  const modePatterns: Array<[RegExp, string]> = [
    [/CryptoJS\.mode\.(CBC|ECB|CFB|OFB|CTR|GCM)/i, '$1'],
    [/mode\s*:\s*['"]?(CBC|ECB|CFB|OFB|CTR|GCM)['"]?/i, '$1'],
    [/\b(CBC|ECB|CFB|OFB|CTR|GCM)\b/i, '$1'],
  ];
  for (const [regex, mode] of modePatterns) {
    const match = window.match(regex);
    if (match) return mode.replace('$1', match[1] ?? match[0]);
  }
  return undefined;
}

function detectPadding(source: string, nearIndex: number): string | undefined {
  const window = source.slice(Math.max(0, nearIndex - 200), nearIndex + 200);
  const match = window.match(/CryptoJS\.pad\.(Pkcs7|ZeroPadding|Iso10126|AnsiX923|NoPadding)/i);
  if (match) return match[1];
  const match2 = window.match(/padding\s*:\s*['"]?(Pkcs7|ZeroPadding|NoPadding)['"]?/i);
  if (match2) return match2[1];
  return undefined;
}

// ===== Key/IV source detection =====

function detectKeySource(source: string, nearIndex: number): string | undefined {
  const window = source.slice(Math.max(0, nearIndex - 300), nearIndex + 300);
  const patterns: Array<[RegExp, string]> = [
    [/CryptoJS\.enc\.Utf8\.parse\s*\(\s*['"`]([^'"`]{1,60})['"`]/i, 'static key: "$1"'],
    [/CryptoJS\.enc\.Hex\.parse\s*\(\s*['"`]([0-9a-fA-F]{8,})['"`]/i, 'static hex key: $1'],
    [/key\s*[:=]\s*['"`]([^'"`]{1,60})['"`]/i, 'static key string: "$1"'],
    [/key\s*[:=]\s*([a-zA-Z_$][\w$]*)/i, 'key from variable: $1'],
    [/(?:app_?key|appkey|api_?key|secret|access_?key)\s*[:=]/i, 'key from app config'],
    [/localStorage\.getItem\s*\(/i, 'key from localStorage'],
    [/document\.cookie/i, 'key from cookie'],
  ];
  for (const [regex, template] of patterns) {
    const match = window.match(regex);
    if (match) {
      return template.replace('$1', match[1] ?? '');
    }
  }
  return undefined;
}

function detectIvSource(source: string, nearIndex: number): string | undefined {
  const window = source.slice(Math.max(0, nearIndex - 300), nearIndex + 300);
  const patterns: Array<[RegExp, string]> = [
    [/CryptoJS\.enc\.Utf8\.parse\s*\(\s*['"`]([^'"`]{1,60})['"`]/i, 'static IV: "$1"'],
    [/iv\s*[:=]\s*['"`]([^'"`]{1,60})['"`]/i, 'static IV string: "$1"'],
    [/iv\s*[:=]\s*([a-zA-Z_$][\w$]*)/i, 'IV from variable: $1'],
  ];
  for (const [regex, template] of patterns) {
    const match = window.match(regex);
    if (match) {
      return template.replace('$1', match[1] ?? '');
    }
  }
  return undefined;
}

// ===== Line/column lookup =====

function getLineCol(source: string, index: number): { line: number; column: number } {
  const before = source.slice(0, index);
  const line = before.split('\n').length;
  const column = index - before.lastIndexOf('\n');
  return { line, column };
}

function getSnippet(source: string, index: number, radius = 60): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(source.length, index + radius);
  let snippet = source.slice(start, end).replace(/\n/g, ' ').trim();
  if (start > 0) snippet = '...' + snippet;
  if (end < source.length) snippet = snippet + '...';
  return snippet;
}

// ===== Main detection function =====

export async function detectCrypto(
  source: string,
  options: DetectOptions,
): Promise<McpToolResult> {
  const includeNative = options.includeNative !== false;
  const includeConstants = options.includeConstants !== false;
  const detections: CryptoDetection[] = [];

  // 1. Pattern matching
  for (const pattern of PATTERNS) {
    // Skip native API patterns if disabled
    if (!includeNative && !pattern.library) continue;

    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(source)) !== null) {
      const index = match.index;
      const { line, column } = getLineCol(source, index);
      const snippet = getSnippet(source, index);

      // Skip duplicate detections of same algorithm at same location
      if (detections.some((d) => d.algorithm === pattern.algorithm && d.location.line === line)) {
        continue;
      }

      detections.push({
        algorithm: pattern.algorithm,
        category: pattern.category,
        library: pattern.library,
        location: { line, column, snippet },
        confidence: pattern.confidence,
        evidence: pattern.description,
        mode: pattern.category === 'symmetric' ? detectCipherMode(source, index) : undefined,
        padding: pattern.category === 'symmetric' ? detectPadding(source, index) : undefined,
        keySource: pattern.category === 'symmetric' ? detectKeySource(source, index) : undefined,
        ivSource: pattern.category === 'symmetric' ? detectIvSource(source, index) : undefined,
      });

      // Avoid infinite loop on zero-length matches
      if (match.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  // 2. Constant detection
  if (includeConstants) {
    for (const constant of CONSTANTS) {
      const regex = new RegExp(constant.pattern.source, constant.pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(source)) !== null) {
        const index = match.index;
        const { line, column } = getLineCol(source, index);
        const snippet = getSnippet(source, index);

        // Skip if already detected this algorithm nearby
        if (detections.some((d) => d.algorithm === constant.algorithm && Math.abs(d.location.line - line) < 5)) {
          continue;
        }

        detections.push({
          algorithm: constant.algorithm,
          category: constant.category,
          location: { line, column, snippet },
          confidence: constant.confidence,
          evidence: `${constant.description} (${constant.constantType})`,
        });

        if (match.index === regex.lastIndex) regex.lastIndex++;
      }
    }
  }

  // Sort by confidence descending, then by line number
  detections.sort((a, b) => b.confidence - a.confidence || a.location.line - b.location.line);

  // Deduplicate by algorithm + library
  const seen = new Set<string>();
  const unique = detections.filter((d) => {
    const key = `${d.algorithm}-${d.library ?? 'native'}-${d.location.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Summary
  const summary: Record<string, number> = {};
  for (const d of unique) {
    summary[d.algorithm] = (summary[d.algorithm] ?? 0) + 1;
  }

  const result = {
    totalDetections: unique.length,
    summary,
    detections: unique.map((d) => ({
      algorithm: d.algorithm,
      category: d.category,
      library: d.library ?? 'native/unknown',
      location: `line ${d.location.line}:${d.location.column}`,
      snippet: d.location.snippet,
      confidence: `${(d.confidence * 100).toFixed(0)}%`,
      evidence: d.evidence,
      mode: d.mode ?? 'N/A',
      padding: d.padding ?? 'N/A',
      keySource: d.keySource ?? 'unknown',
      ivSource: d.ivSource ?? 'unknown',
    })),
    hints: generateHints(unique),
  };

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(result, null, 2),
      },
    ],
  };
}

function generateHints(detections: CryptoDetection[]): string[] {
  const hints: string[] = [];
  const algos = new Set(detections.map((d) => d.algorithm));

  if (algos.has('AES')) {
    hints.push('AES detected: verify key length (16/24/32 bytes for AES-128/192/256) and mode (CBC needs IV, ECB does not)');
  }
  if (algos.has('RSA')) {
    hints.push('RSA detected: extract public key (usually PEM or base64 DER), check padding scheme (PKCS1 vs OAEP)');
  }
  if (algos.has('SM2')) {
    hints.push('SM2 (国密) detected: extract public key hex, note that SM2 uses its own signature format');
  }
  if (algos.has('SM3')) {
    hints.push('SM3 (国密) detected: 256-bit output, often combined with SM2 for signing');
  }
  if (algos.has('SM4')) {
    hints.push('SM4 (国密) detected: 128-bit key, check mode (CBC/ECB/CTR)');
  }
  if (algos.has('MD5')) {
    hints.push('MD5 detected: 32-char hex output, commonly used for password hashing or request signing');
  }
  if (algos.has('HMAC') || algos.has('HMAC-SHA256')) {
    hints.push('HMAC detected: identify the secret key source, HMAC is often used for API request signing');
  }

  if (algos.has('RSA') && algos.has('AES')) {
    hints.push('RSA+AES hybrid encryption detected: likely RSA encrypts AES key, AES encrypts body. Extract both');
  }
  if (algos.has('MD5') && detections.some((d) => d.category === 'mac')) {
    hints.push('MD5+HMAC combo: common in legacy API signing (e.g. md5(params + secret))');
  }

  if (hints.length === 0) {
    hints.push('No crypto detected. Try with includeMinified:true if the code is minified, or check for custom implementations.');
  }

  return hints;
}
