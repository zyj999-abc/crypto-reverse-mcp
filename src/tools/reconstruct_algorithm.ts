/**
 * reconstruct_algorithm — Reconstruct standalone crypto implementation
 *
 * Given JS source + optional input/output samples, generate a self-contained
 * Python or Node implementation that reproduces the same crypto transform.
 *
 * Strategy:
 * 1. Detect algorithm type via pattern matching
 * 2. Extract parameters (key, IV, mode, padding) from source
 * 3. Generate implementation using standard libraries (pycryptodome / gmssl)
 * 4. If samples provided, include verification code
 */
import type { McpToolResult } from '../types.js';

interface Sample {
  input: string;
  output: string;
  inputEncoding?: 'utf8' | 'hex' | 'base64';
  outputEncoding?: 'utf8' | 'hex' | 'base64';
}

interface ReconstructOptions {
  samples?: Sample[];
  targetLanguage: 'python' | 'node';
  functionName?: string;
}

interface AlgoSpec {
  algorithm: string;
  library?: string;
  mode?: string;
  padding?: string;
  keySource?: string;
  ivSource?: string;
  keyHex?: string;
  ivHex?: string;
}

function detectAlgorithm(source: string, functionName?: string): AlgoSpec {
  const spec: AlgoSpec = { algorithm: 'unknown' };

  // CryptoJS AES
  const aesMatch = source.match(/CryptoJS\.AES\.(encrypt|decrypt)\s*\(\s*([^,]+),\s*([^,]+)/i);
  if (aesMatch) {
    spec.algorithm = 'AES';
    spec.library = 'CryptoJS';
    spec.keySource = aesMatch[3].trim();

    // Try to extract key as string literal
    const keyStrMatch = aesMatch[3].match(/['"`]([^'"`]+)['"`]/);
    if (keyStrMatch) {
      spec.keyHex = Buffer.from(keyStrMatch[1], 'utf8').toString('hex');
    }

    // Mode detection
    const modeMatch = source.match(/CryptoJS\.mode\.(CBC|ECB|CFB|OFB|CTR|GCM)/i);
    if (modeMatch) spec.mode = modeMatch[1].toUpperCase();
    else spec.mode = 'CBC'; // CryptoJS default

    const padMatch = source.match(/CryptoJS\.pad\.(Pkcs7|ZeroPadding|NoPadding|Iso10126)/i);
    if (padMatch) spec.padding = padMatch[1];
    else spec.padding = 'Pkcs7';
    return spec;
  }

  // CryptoJS DES
  const desMatch = source.match(/CryptoJS\.DES\.(encrypt|decrypt)\s*\(/i);
  if (desMatch) {
    spec.algorithm = 'DES';
    spec.library = 'CryptoJS';
    spec.mode = 'CBC';
    spec.padding = 'Pkcs7';
    return spec;
  }

  // CryptoJS TripleDES
  const tdesMatch = source.match(/CryptoJS\.TripleDES\.(encrypt|decrypt)\s*\(/i);
  if (tdesMatch) {
    spec.algorithm = 'TripleDES';
    spec.library = 'CryptoJS';
    spec.mode = 'CBC';
    spec.padding = 'Pkcs7';
    return spec;
  }

  // CryptoJS HMAC-SHA256
  const hmacMatch = source.match(/CryptoJS\.HmacSHA256\s*\(\s*([^,]+),\s*([^)]+)/i);
  if (hmacMatch) {
    spec.algorithm = 'HMAC-SHA256';
    spec.library = 'CryptoJS';
    spec.keySource = hmacMatch[2].trim();
    const keyStrMatch = hmacMatch[2].match(/['"`]([^'"`]+)['"`]/);
    if (keyStrMatch) {
      spec.keyHex = Buffer.from(keyStrMatch[1], 'utf8').toString('hex');
    }
    return spec;
  }

  // CryptoJS HmacMD5
  if (/CryptoJS\.HmacMD5\s*\(/i.test(source)) {
    spec.algorithm = 'HMAC-MD5';
    spec.library = 'CryptoJS';
    return spec;
  }

  // CryptoJS MD5
  if (/CryptoJS\.MD5\s*\(/i.test(source)) {
    spec.algorithm = 'MD5';
    spec.library = 'CryptoJS';
    return spec;
  }

  // CryptoJS SHA-256
  if (/CryptoJS\.SHA256\s*\(/i.test(source)) {
    spec.algorithm = 'SHA-256';
    spec.library = 'CryptoJS';
    return spec;
  }

  // sm-crypto SM2
  if (/sm2\.(doEncrypt|doSignature)\s*\(/i.test(source)) {
    spec.algorithm = 'SM2';
    spec.library = 'sm-crypto';
    return spec;
  }

  // sm-crypto SM3
  if (/sm3\s*\(/i.test(source)) {
    spec.algorithm = 'SM3';
    spec.library = 'sm-crypto';
    return spec;
  }

  // sm-crypto SM4
  const sm4Match = source.match(/sm4\.(encrypt|decrypt)\s*\(/i);
  if (sm4Match) {
    spec.algorithm = 'SM4';
    spec.library = 'sm-crypto';
    spec.mode = 'CBC';
    return spec;
  }

  // JSEncrypt RSA
  if (/new\s+JSEncrypt|\.setPublicKey\s*\(/i.test(source)) {
    spec.algorithm = 'RSA';
    spec.library = 'JSEncrypt';
    const keyMatch = source.match(/setPublicKey\s*\(\s*['"`]([^'"`]+)['"`]/s);
    if (keyMatch) {
      spec.keySource = keyMatch[1].slice(0, 80) + '...';
    }
    return spec;
  }

  // Web Crypto API
  const webCryptoMatch = source.match(/crypto\.subtle\.(encrypt|decrypt|sign|digest)\s*\(\s*['"`]([^'"`]+)['"`]/i);
  if (webCryptoMatch) {
    spec.algorithm = webCryptoMatch[2];
    spec.library = 'WebCrypto';
    return spec;
  }

  // Base64
  if (/\bbtoa\s*\(/i.test(source)) {
    spec.algorithm = 'Base64';
    return spec;
  }

  // Function name heuristic
  if (spec.algorithm === 'unknown' && functionName) {
    const lowerName = functionName.toLowerCase();
    if (lowerName.includes('md5')) spec.algorithm = 'MD5';
    else if (lowerName.includes('sha1')) spec.algorithm = 'SHA-1';
    else if (lowerName.includes('sha256')) spec.algorithm = 'SHA-256';
    else if (lowerName.includes('aes')) spec.algorithm = 'AES';
    else if (lowerName.includes('rsa')) spec.algorithm = 'RSA';
    else if (lowerName.includes('sign')) spec.algorithm = 'HMAC';
    else if (lowerName.includes('encrypt') || lowerName.includes('enc')) spec.algorithm = 'AES';
  }

  return spec;
}

function generatePython(spec: AlgoSpec, samples?: Sample[]): string {
  const lines: string[] = [];
  lines.push('#!/usr/bin/env python3');
  lines.push('# Reconstructed by crypto-reverse-mcp');
  lines.push('# Algorithm: ' + spec.algorithm + (spec.library ? ` (from ${spec.library})` : ''));
  lines.push('');
  lines.push('"""');
  lines.push(`Reconstructed ${spec.algorithm} implementation.`);
  if (spec.mode) lines.push(`Mode: ${spec.mode}`);
  if (spec.padding) lines.push(`Padding: ${spec.padding}`);
  if (spec.keySource) lines.push(`Key source: ${spec.keySource}`);
  lines.push('"""');
  lines.push('');

  switch (spec.algorithm) {
    case 'AES':
      lines.push('from Crypto.Cipher import AES');
      lines.push('from Crypto.Util.Padding import pad, unpad');
      lines.push('import base64');
      lines.push('import binascii');
      lines.push('');
      lines.push(`# Key (hex): ${spec.keyHex ?? '<extract from JS>'}`);
      lines.push(`KEY = bytes.fromhex('${spec.keyHex ?? '00000000000000000000000000000000'}')  # TODO: replace with actual key`);
      if (spec.mode === 'ECB') {
        lines.push('');
        lines.push('def aes_encrypt(plaintext: str, key: bytes = KEY) -> str:');
        lines.push('    """AES-${spec.mode} encrypt, returns base64"""');
        lines.push('    cipher = AES.new(key, AES.MODE_ECB)');
        lines.push('    padded = pad(plaintext.encode("utf-8"), AES.block_size)');
        lines.push('    encrypted = cipher.encrypt(padded)');
        lines.push('    return base64.b64encode(encrypted).decode()');
        lines.push('');
        lines.push('def aes_decrypt(ciphertext_b64: str, key: bytes = KEY) -> str:');
        lines.push('    """AES-${spec.mode} decrypt"""');
        lines.push('    cipher = AES.new(key, AES.MODE_ECB)');
        lines.push('    decrypted = cipher.decrypt(base64.b64decode(ciphertext_b64))');
        lines.push('    return unpad(decrypted, AES.block_size).decode("utf-8")');
      } else {
        lines.push(`# IV (hex): ${spec.ivHex ?? '<extract from JS or use key-derived>'}`);
        lines.push(`IV = bytes.fromhex('${spec.ivHex ?? '00000000000000000000000000000000'}')  # TODO: replace with actual IV`);
        lines.push('');
        lines.push(`def aes_encrypt(plaintext: str, key: bytes = KEY, iv: bytes = IV) -> str:`);
        lines.push(`    """AES-${spec.mode} encrypt, returns base64"""`);
        lines.push(`    cipher = AES.new(key, AES.MODE_${spec.mode ?? 'CBC'}, iv)`);
        lines.push(`    padded = pad(plaintext.encode("utf-8"), AES.block_size)`);
        lines.push(`    encrypted = cipher.encrypt(padded)`);
        lines.push(`    return base64.b64encode(encrypted).decode()`);
        lines.push('');
        lines.push(`def aes_decrypt(ciphertext_b64: str, key: bytes = KEY, iv: bytes = IV) -> str:`);
        lines.push(`    """AES-${spec.mode} decrypt"""`);
        lines.push(`    cipher = AES.new(key, AES.MODE_${spec.mode ?? 'CBC'}, iv)`);
        lines.push(`    decrypted = cipher.decrypt(base64.b64decode(ciphertext_b64))`);
        lines.push(`    return unpad(decrypted, AES.block_size).decode("utf-8")`);
      }
      break;

    case 'DES':
      lines.push('from Crypto.Cipher import DES');
      lines.push('from Crypto.Util.Padding import pad, unpad');
      lines.push('import base64');
      lines.push('');
      lines.push("KEY = b'8bytekey'  # TODO: replace with actual key");
      lines.push('');
      lines.push('def des_encrypt(plaintext: str, key: bytes = KEY) -> str:');
      lines.push('    cipher = DES.new(key, DES.MODE_CBC, key)  # IV=key is common');
      lines.push('    padded = pad(plaintext.encode(), DES.block_size)');
      lines.push('    return base64.b64encode(cipher.encrypt(padded)).decode()');
      lines.push('');
      lines.push('def des_decrypt(ciphertext_b64: str, key: bytes = KEY) -> str:');
      lines.push('    cipher = DES.new(key, DES.MODE_CBC, key)');
      lines.push('    decrypted = cipher.decrypt(base64.b64decode(ciphertext_b64))');
      lines.push('    return unpad(decrypted, DES.block_size).decode()');
      break;

    case 'TripleDES':
      lines.push('from Crypto.Cipher import DES3');
      lines.push('from Crypto.Util.Padding import pad, unpad');
      lines.push('import base64');
      lines.push('');
      lines.push("KEY = b'24bytekeyfor3des cipher!'  # TODO: replace");
      lines.push('');
      lines.push('def triple_des_encrypt(plaintext: str, key: bytes = KEY) -> str:');
      lines.push('    cipher = DES3.new(key, DES3.MODE_CBC, key[:8])');
      lines.push('    return base64.b64encode(cipher.encrypt(pad(plaintext.encode(), 8))).decode()');
      break;

    case 'MD5':
      lines.push('import hashlib');
      lines.push('');
      lines.push('def md5(text: str) -> str:');
      lines.push('    """MD5 hash, returns 32-char hex string"""');
      lines.push('    return hashlib.md5(text.encode("utf-8")).hexdigest()');
      lines.push('');
      lines.push('# CryptoJS.MD5 returns WordArray, .toString() gives hex');
      lines.push('# Equivalent to: hashlib.md5(text.encode()).hexdigest()');
      break;

    case 'SHA-1':
      lines.push('import hashlib');
      lines.push('');
      lines.push('def sha1(text: str) -> str:');
      lines.push('    return hashlib.sha1(text.encode("utf-8")).hexdigest()');
      break;

    case 'SHA-256':
      lines.push('import hashlib');
      lines.push('');
      lines.push('def sha256(text: str) -> str:');
      lines.push('    """SHA-256 hash, returns 64-char hex string"""');
      lines.push('    return hashlib.sha256(text.encode("utf-8")).hexdigest()');
      break;

    case 'HMAC-SHA256':
      lines.push('import hmac');
      lines.push('import hashlib');
      lines.push('');
      lines.push(`# Key: ${spec.keySource ?? '<extract from JS>'}`);
      lines.push("SECRET = b'your_secret_here'  # TODO: replace with actual secret");
      lines.push('');
      lines.push('def hmac_sha256(message: str, secret: bytes = SECRET) -> str:');
      lines.push('    """HMAC-SHA256, returns hex string"""');
      lines.push('    return hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()');
      lines.push('');
      lines.push('# Note: CryptoJS.HmacSHA256(msg, key).toString() == hex output');
      break;

    case 'HMAC-MD5':
      lines.push('import hmac');
      lines.push('import hashlib');
      lines.push('');
      lines.push("SECRET = b'your_secret_here'  # TODO: replace");
      lines.push('');
      lines.push('def hmac_md5(message: str, secret: bytes = SECRET) -> str:');
      lines.push('    return hmac.new(secret, message.encode("utf-8"), hashlib.md5).hexdigest()');
      break;

    case 'RSA':
      lines.push('from Crypto.PublicKey import RSA');
      lines.push('from Crypto.Cipher import PKCS1_v1_5');
      lines.push('import base64');
      lines.push('');
      lines.push('# Public key extracted from JSEncrypt.setPublicKey()');
      lines.push('PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----');
      lines.push('<paste key here>');
      lines.push('-----END PUBLIC KEY-----"""');
      lines.push('');
      lines.push('def rsa_encrypt(plaintext: str, public_key_pem: str = PUBLIC_KEY_PEM) -> str:');
      lines.push('    """RSA encrypt with PKCS1 v1.5 padding (JSEncrypt default)"""');
      lines.push('    key = RSA.import_key(public_key_pem)');
      lines.push('    cipher = PKCS1_v1_5.new(key)');
      lines.push('    encrypted = cipher.encrypt(plaintext.encode("utf-8"))');
      lines.push('    return base64.b64encode(encrypted).decode()');
      lines.push('');
      lines.push('# Note: JSEncrypt uses PKCS1 v1.5 by default.');
      lines.push('# If OAEP is needed, use PKCS1_OAEP instead.');
      break;

    case 'SM2':
      lines.push('# pip install gmssl');
      lines.push('from gmssl import sm2');
      lines.push('import binascii');
      lines.push('');
      lines.push('# SM2 public key (hex, 04 + x + y, 130 chars total)');
      lines.push('PUBLIC_KEY = "04<paste_x_y_hex_here>"  # TODO: extract from sm2.doEncrypt()');
      lines.push('');
      lines.push('def sm2_encrypt(plaintext: str, public_key: str = PUBLIC_KEY) -> str:');
      lines.push('    """SM2 encrypt, returns hex string"""');
      lines.push('    sm2_obj = sm2.CryptSM2(public_key=public_key, private_key="")');
      lines.push('    encrypted = sm2_obj.encrypt(plaintext.encode("utf-8"))');
      lines.push('    return binascii.hexlify(encrypted).decode()');
      break;

    case 'SM3':
      lines.push('# pip install gmssl');
      lines.push('from gmssl import sm3, func');
      lines.push('');
      lines.push('def sm3_hash(text: str) -> str:');
      lines.push('    """SM3 hash, returns 64-char hex string"""');
      lines.push('    data = bytes.fromhex(text.encode("utf-8").hex())');
      lines.push('    return sm3.sm3_hash(func.bytes_to_list(data))');
      break;

    case 'SM4':
      lines.push('# pip install gmssl');
      lines.push('from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT');
      lines.push('import binascii');
      lines.push('');
      lines.push("KEY = bytes.fromhex('0123456789abcdeffedcba9876543210')  # TODO: replace");
      lines.push("IV = bytes.fromhex('00000000000000000000000000000000')  # TODO: replace");
      lines.push('');
      lines.push('def sm4_encrypt(plaintext: str, key: bytes = KEY, iv: bytes = IV) -> str:');
      lines.push('    """SM4-CBC encrypt, returns hex"""');
      lines.push('    sm4 = CryptSM4()');
      lines.push('    sm4.set_key(key, SM4_ENCRYPT)');
      lines.push('    encrypted = sm4.crypt_cbc(iv, plaintext.encode("utf-8"))');
      lines.push('    return binascii.hexlify(encrypted).decode()');
      break;

    case 'Base64':
      lines.push('import base64');
      lines.push('');
      lines.push('def base64_encode(text: str) -> str:');
      lines.push('    return base64.b64encode(text.encode("utf-8")).decode()');
      lines.push('');
      lines.push('def base64_decode(b64: str) -> str:');
      lines.push('    return base64.b64decode(b64).decode("utf-8")');
      break;

    default:
      lines.push('# Could not auto-detect algorithm. Provide more context or samples.');
      lines.push('# Common patterns:');
      lines.push('#   - If output is 32 hex chars → MD5');
      lines.push('#   - If output is 64 hex chars → SHA-256 or SM3');
      lines.push('#   - If output is 40 hex chars → SHA-1');
      lines.push('#   - If output is base64 and length is multiple of 16 → AES/DES');
      lines.push('#   - If output is 256+ hex chars → RSA');
  }

  // Add verification code if samples provided
  if (samples && samples.length > 0) {
    lines.push('');
    lines.push('');
    lines.push('# ===== Verification with provided samples =====');
    lines.push('if __name__ == "__main__":');
    for (let i = 0; i < samples.length; i++) {
      const s = samples[i];
      lines.push(`    # Sample ${i + 1}`);
      lines.push(`    input_${i + 1} = ${JSON.stringify(s.input)}`);
      lines.push(`    expected_${i + 1} = ${JSON.stringify(s.output)}`);
      lines.push(`    # TODO: call the function above and compare with expected_${i + 1}`);
    }
    lines.push('    pass  # Remove after implementing verification');
  }

  return lines.join('\n');
}

function generateNode(spec: AlgoSpec, samples?: Sample[]): string {
  const lines: string[] = [];
  lines.push('#!/usr/bin/env node');
  lines.push('// Reconstructed by crypto-reverse-mcp');
  lines.push(`// Algorithm: ${spec.algorithm}${spec.library ? ` (from ${spec.library})` : ''}`);
  lines.push('');
  lines.push("const crypto = require('crypto');");
  lines.push('');

  switch (spec.algorithm) {
    case 'AES':
      lines.push(`// Key (hex): ${spec.keyHex ?? '<extract from JS>'}`);
      lines.push(`const KEY = Buffer.from('${spec.keyHex ?? '00000000000000000000000000000000'}', 'hex'); // TODO: replace`);
      if (spec.mode === 'ECB') {
        lines.push('');
        lines.push('function aesEncrypt(plaintext, key = KEY) {');
        lines.push("  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);");
        lines.push("  cipher.setAutoPadding(true);");
        lines.push('  let encrypted = cipher.update(plaintext, "utf8", "base64");');
        lines.push('  encrypted += cipher.final("base64");');
        lines.push('  return encrypted;');
        lines.push('}');
      } else {
        lines.push(`const IV = Buffer.from('${spec.ivHex ?? '00000000000000000000000000000000'}', 'hex'); // TODO: replace`);
        lines.push('');
        lines.push(`function aesEncrypt(plaintext, key = KEY, iv = IV) {`);
        lines.push(`  const cipher = crypto.createCipheriv('aes-128-${(spec.mode ?? 'cbc').toLowerCase()}', key, iv);`);
        lines.push(`  let encrypted = cipher.update(plaintext, 'utf8', 'base64');`);
        lines.push(`  encrypted += cipher.final('base64');`);
        lines.push(`  return encrypted;`);
        lines.push(`}`);
        lines.push('');
        lines.push(`function aesDecrypt(ciphertextB64, key = KEY, iv = IV) {`);
        lines.push(`  const decipher = crypto.createDecipheriv('aes-128-${(spec.mode ?? 'cbc').toLowerCase()}', key, iv);`);
        lines.push(`  let decrypted = decipher.update(ciphertextB64, 'base64', 'utf8');`);
        lines.push(`  decrypted += decipher.final('utf8');`);
        lines.push(`  return decrypted;`);
        lines.push(`}`);
      }
      break;

    case 'MD5':
      lines.push('function md5(text) {');
      lines.push("  return crypto.createHash('md5').update(text, 'utf8').digest('hex');");
      lines.push('}');
      break;

    case 'SHA-256':
      lines.push('function sha256(text) {');
      lines.push("  return crypto.createHash('sha256').update(text, 'utf8').digest('hex');");
      lines.push('}');
      break;

    case 'HMAC-SHA256':
      lines.push("const SECRET = 'your_secret_here'; // TODO: replace");
      lines.push('function hmacSha256(message, secret = SECRET) {');
      lines.push("  return crypto.createHmac('sha256', secret).update(message, 'utf8').digest('hex');");
      lines.push('}');
      break;

    case 'RSA':
      lines.push("const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----\n<paste key here>\n-----END PUBLIC KEY-----`;");
      lines.push('function rsaEncrypt(plaintext, publicKey = PUBLIC_KEY) {');
      lines.push("  const buffer = Buffer.from(plaintext, 'utf8');");
      lines.push("  const encrypted = crypto.publicEncrypt({");
      lines.push("    key: publicKey,");
      lines.push("    padding: crypto.constants.RSA_PKCS1_PADDING, // JSEncrypt default");
      lines.push("  }, buffer);");
      lines.push("  return encrypted.toString('base64');");
      lines.push('}');
      break;

    case 'Base64':
      lines.push('function base64Encode(text) {');
      lines.push("  return Buffer.from(text, 'utf8').toString('base64');");
      lines.push('}');
      lines.push('function base64Decode(b64) {');
      lines.push("  return Buffer.from(b64, 'base64').toString('utf8');");
      lines.push('}');
      break;

    default:
      lines.push('// Could not auto-detect. See Python output for algorithm hints.');
  }

  if (samples && samples.length > 0) {
    lines.push('');
    lines.push('// ===== Verification =====');
    lines.push('if (require.main === module) {');
    for (let i = 0; i < samples.length; i++) {
      lines.push(`  // Sample ${i + 1}: input=${JSON.stringify(samples[i].input)} → expected=${JSON.stringify(samples[i].output)}`);
    }
    lines.push('}');
  }

  return lines.join('\n');
}

export async function reconstructAlgorithm(
  source: string,
  options: ReconstructOptions,
): Promise<McpToolResult> {
  const spec = detectAlgorithm(source, options.functionName);
  const code =
    options.targetLanguage === 'python'
      ? generatePython(spec, options.samples)
      : generateNode(spec, options.samples);

  const result = {
    detectedAlgorithm: spec.algorithm,
    detectedLibrary: spec.library ?? 'unknown',
    detectedMode: spec.mode ?? 'N/A',
    detectedPadding: spec.padding ?? 'N/A',
    keySource: spec.keySource ?? 'not found in source',
    ivSource: spec.ivSource ?? 'not found in source',
    language: options.targetLanguage,
    verificationSamples: options.samples?.length ?? 0,
    code,
    notes: generateReconstructNotes(spec),
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  };
}

function generateReconstructNotes(spec: AlgoSpec): string[] {
  const notes: string[] = [];

  notes.push(`Detected: ${spec.algorithm}${spec.library ? ` via ${spec.library}` : ''}`);

  if (spec.algorithm === 'AES' && !spec.keyHex) {
    notes.push('WARNING: Key not extracted from source. Look for: (1) CryptoJS.enc.Utf8.parse("key"), (2) variable passed as 2nd arg to AES.encrypt, (3) key derived from app config');
  }
  if (spec.algorithm === 'AES' && spec.mode === 'CBC' && !spec.ivHex) {
    notes.push('WARNING: IV not found. CBC mode requires IV. Common patterns: (1) IV = key (weak), (2) IV = first 16 bytes of key, (3) IV prepended to ciphertext, (4) IV from separate config');
  }
  if (spec.algorithm === 'RSA') {
    notes.push('RSA: extract the public key PEM string from JSEncrypt.setPublicKey() call. JSEncrypt uses PKCS1 v1.5 padding by default');
  }
  if (spec.algorithm === 'HMAC-SHA256' && !spec.keyHex) {
    notes.push('HMAC: identify the secret key. Common sources: (1) app config, (2) hardcoded string, (3) derived from appkey+timestamp, (4) server-issued');
  }
  if (spec.algorithm === 'unknown') {
    notes.push('Could not auto-detect. Try: (1) provide functionName parameter, (2) check output length — 32 hex=MD5, 40 hex=SHA1, 64 hex=SHA256/SM3, (3) provide input/output samples for pattern analysis');
  }

  notes.push('Always verify reconstructed implementation against real samples before using in production');

  return notes;
}
