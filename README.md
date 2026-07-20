# crypto-reverse-mcp

[![npm version](https://img.shields.io/npm/v/crypto-reverse-mcp.svg)](https://www.npmjs.com/package/crypto-reverse-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **The missing "last mile" of JS reverse engineering.** A Model Context Protocol (MCP) server that detects cryptographic algorithms, identifies obfuscation, reconstructs standalone implementations, generates SDKs, and bypasses anti-debugging — designed to complement browser-debugging MCP servers like [js-reverse-mcp](https://github.com/zhizhuodemao/js-reverse-mcp).

English | [中文](README_zh.md)

## Why this exists

Existing JS-reverse MCP servers focus on **browser debugging** (breakpoints, network capture, script analysis). They help you *find* the encryption function. But they don't answer:

- **What algorithm is this?** (AES? SM2? custom?)
- **Where does the key come from?** (static? derived? from server?)
- **How do I reproduce it in Python?**
- **How do I generate a complete SDK?**
- **How do I bypass the anti-debugging that blocks my breakpoints?**

`crypto-reverse-mcp` fills these gaps. It's a **complement**, not a replacement — pair it with `js-reverse-mcp` for the full workflow:

```
js-reverse-mcp:  open page → find script → set breakpoint → capture I/O
crypto-reverse-mcp: identify algorithm → extract key → reconstruct Python → generate SDK
```

## Features

| Tool | What it does |
|------|-------------|
| `detect_crypto` | Identify AES/DES/RSA/SM2/SM3/SM4/HMAC/MD5/SHA + key/IV source + cipher mode |
| `identify_obfuscation` | Detect webpack/JSFuck/AAEncode/obfuscator.io/packer/control-flow-flattening |
| `extract_crypto_constants` | Find S-boxes, initial hash values, round constants, curve parameters |
| `reconstruct_algorithm` | Generate standalone Python/Node implementation from JS source + samples |
| `generate_sdk` | Produce complete Python/Node/Go SDK with signing, login, error handling |
| `bypass_anti_debug` | Generate injection scripts to neutralize debugger loops, devtools detection, timing checks |

## Quick Start

### Claude Desktop / Cursor / VS Code Copilot

```json
{
  "mcpServers": {
    "crypto-reverse": {
      "command": "npx",
      "args": ["-y", "crypto-reverse-mcp@latest"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add crypto-reverse -- npx -y crypto-reverse-mcp@latest
```

### Codex CLI

```bash
codex mcp add crypto-reverse -- npx -y crypto-reverse-mcp@latest
```

### VS Code Copilot

```bash
code --add-mcp '{"name":"crypto-reverse","command":"npx","args":["-y","crypto-reverse-mcp@latest"]}'
```

## Requirements

- Node.js 18+

## Tool Details

### `detect_crypto`

**Input:** JS source code (string)

**Output:** List of detected crypto usages with:
- Algorithm name (AES, RSA, SM2, SM3, SM4, MD5, SHA-1, SHA-256, HMAC, PBKDF2, etc.)
- Category (symmetric / asymmetric / hash / mac / kdf / encoding)
- Library (CryptoJS, JSEncrypt, sm-crypto, node-forge, jsrsasign, WebCrypto, Node crypto)
- Location (line:column) + code snippet
- Confidence score (0-100%)
- Key source (static string / variable / localStorage / cookie / app config)
- IV source (for symmetric ciphers)
- Cipher mode (CBC/ECB/GCM/CTR/CFB/OFB)
- Padding (Pkcs7/ZeroPadding/NoPadding)

**Detection methods:**
1. Library API patterns (50+ regex patterns)
2. Web Crypto API / Node crypto module calls
3. Crypto constants (AES S-box, SHA-256 initial hash, SM3 IV, SM4 S-box, DES S-box, etc.)
4. Function name heuristics

### `identify_obfuscation`

**Input:** JS source code

**Output:** Obfuscation type + confidence + unpack strategy

**Detects:** webpack-bundle, obfuscator.io, JSFuck, AAEncode, JJEncode, dean-edwards-packer, eval-loader, control-flow-flattening, string-array, dead-code-injection, minified, terser-minified

Each detection includes:
- Confidence score
- Evidence (what pattern matched)
- Unpack hint (how to approach unpacking)
- Deobfuscation strategy (step-by-step)
- Recommended tools

### `extract_crypto_constants`

**Input:** JS source code

**Output:** List of found crypto constants

**Detects:**
- AES S-box / Inverse S-box / Rcon
- SHA-256 initial hash values + round constants
- SHA-1 initial hash values
- MD5 initial values + T-constants
- SM3 IV + Tj constants
- SM4 S-box + FK + CK constants
- DES S-box + IP permutation
- SM2 / NIST P-256 curve parameters
- CRC32 polynomial
- Base64 alphabet

### `reconstruct_algorithm`

**Input:** JS source code + optional input/output samples + target language

**Output:** Self-contained Python or Node implementation

**How it works:**
1. Detects algorithm type from source patterns
2. Extracts parameters (key, IV, mode, padding)
3. Generates implementation using standard libraries (pycryptodome, gmssl)
4. If samples provided, includes verification code

**Supported algorithms:** AES (CBC/ECB/GCM/CTR), DES, TripleDES, MD5, SHA-1, SHA-256, HMAC-SHA256, HMAC-MD5, RSA (PKCS1), SM2, SM3, SM4, Base64

### `generate_sdk`

**Input:** API specification (URL, method, headers, sign spec, login spec) + target language

**Output:** Complete SDK file with:
- Request construction with auto-signing
- Crypto signature generation (HMAC/MD5/custom)
- Login flow (with password encryption hook)
- Error handling
- Usage example

**Languages:** Python (requests), Node.js (http/https), Go (net/http)

### `bypass_anti_debug`

**Input:** JS source code (optional) + techniques to bypass + output format

**Output:** Bypass injection script

**Techniques:**
- `debugger_loop` — Neutralize `debugger` statements in loops
- `setInterval_debugger` — Block `setInterval` callbacks containing `debugger`
- `devtools_window_size` — Fix `outerWidth - innerWidth` detection
- `devtools_console_access` — Prevent console object inspection
- `timing_check` — Cap `Date.now()` / `performance.now()` deltas
- `console_getter_trap` — Undo `Object.defineProperty(console, ...)`
- `function_toString_check` — Make `Function.toString()` return native code

**Output formats:** `inject_script` (Tampermonkey/snippet), `fiddler_rule` (Fiddler OnBeforeResponse), `chrome_devtools_snippet` (DevTools Snippets)

## Typical Workflow

```
1. [js-reverse-mcp]     new_page → navigate to target site
2. [js-reverse-mcp]     search_in_sources for "encrypt" / "sign"
3. [crypto-reverse-mcp] detect_crypto on found script → identify AES-CBC
4. [crypto-reverse-mcp] extract_crypto_constants → confirm S-box present
5. [js-reverse-mcp]     set_breakpoint_on_text → capture input/output
6. [crypto-reverse-mcp] reconstruct_algorithm with samples → get Python code
7. [crypto-reverse-mcp] generate_sdk → complete API SDK
8. [crypto-reverse-mcp] bypass_anti_debug → if blocked by debugger
```

## Local Development

```bash
git clone https://github.com/crypto-reverse/crypto-reverse-mcp.git
cd crypto-reverse-mcp
npm install
npm run build
npm start
```

### Debug with MCP Inspector

```bash
npx @modelcontextprotocol/inspector node build/src/index.js
```

### Test stdio communication

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0.0"}}}' | node build/src/index.js
```

## Configuration

No configuration required. All tools are stateless and work offline.

## Comparison with other JS-reverse MCP servers

| Feature | js-reverse-mcp | js-reverse-pro-mcp | mcp-reverse-server | **crypto-reverse-mcp** |
|---------|---------------|--------------------|--------------------|-----------------------|
| Browser debugging | ✅ | ✅ | ✅ | ❌ |
| Breakpoints | ✅ | ✅ | ✅ | ❌ |
| Network capture | ✅ | ✅ | ✅ | ❌ |
| Hook framework | ❌ | ✅ | ❌ | ❌ |
| Deobfuscation | ❌ | ✅ (Babel) | ✅ (AST) | ⚠️ (identify only) |
| JSVMP analysis | ❌ | ❌ | ✅ | ❌ |
| **Crypto algorithm detection** | ❌ | ⚠️ (keyword scan) | ⚠️ | ✅ **(50+ patterns)** |
| **Crypto constants extraction** | ❌ | ❌ | ❌ | ✅ **(S-box, IV, curves)** |
| **Algorithm reconstruction** | ❌ | ❌ | ❌ | ✅ **(Python/Node)** |
| **SDK generation** | ❌ | ❌ | ❌ | ✅ **(Python/Node/Go)** |
| **Anti-debug bypass** | ❌ | ❌ | ❌ | ✅ **(7 techniques)** |
| Obfuscation identification | ❌ | ❌ | ❌ | ✅ **(11 types)** |

**Use together for maximum coverage.** `crypto-reverse-mcp` is designed to be complementary.

## Roadmap

- [ ] v0.2: `trace_crypto_chain` — trace encryption from ciphertext back to plaintext
- [ ] v0.2: Improved minified code analysis (variable flow tracking)
- [ ] v0.3: WASM crypto module detection
- [ ] v0.3: Custom algorithm identification via I/O analysis
- [ ] v0.4: Java SDK generation
- [ ] v0.4: RPC-style API SDK generation (gRPC, GraphQL)

## License

MIT
