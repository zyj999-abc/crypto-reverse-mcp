/**
 * identify_obfuscation — Identify JS obfuscation/packing technique
 *
 * Detects: webpack bundles, AAEncode, JJEncode, JSFuck, obfuscator.io,
 * babel minified, Dean Edwards packer, eval loaders, control-flow flattening,
 * string array rotation, dead code injection.
 */
import type { McpToolResult } from '../types.js';

interface ObfuscationDetection {
  type: string;
  confidence: number; // 0-1
  evidence: string;
  unpackHint: string;
  deobfuscationStrategy: string;
  tools?: string[];
}

export async function identifyObfuscation(source: string): Promise<McpToolResult> {
  const detections: ObfuscationDetection[] = [];
  const lines = source.split('\n');
  const lineCount = lines.length;
  const charCount = source.length;

  // ===== Webpack bundle =====
  if (/!\s*function\s*\(\s*\)\s*\{[^}]*__webpack_require__|webpackChunk|__webpack_modules__/.test(source)) {
    detections.push({
      type: 'webpack-bundle',
      confidence: 0.95,
      evidence: 'Found __webpack_require__ / webpackChunk / __webpack_modules__',
      unpackHint: 'Use webpack-unpack or reverse-engineering: extract entry module, find the module containing target code',
      deobfuscationStrategy: '1. Use https://github.com/j4k0xb/webpack-unpack or Webpack Analyzer\n2. Or extract individual modules via __webpack_require__(moduleId)\n3. Identify target module by searching for crypto-related strings',
      tools: ['webpack-unpack', 'webpack-bundle-analyzer', 'reverse-sourcemap'],
    });
  }

  // ===== obfuscator.io =====
  if (/_0x[0-9a-f]{4,6}\b/.test(source) && /String\(\)\.fromCharCode|parseInt.*toString\(16\)|atob\s*\(/.test(source)) {
    detections.push({
      type: 'obfuscator.io',
      confidence: 0.9,
      evidence: 'Found _0x hex variable names + string array decoding pattern',
      unpackHint: 'obfuscator.io uses a string array with rotation. Find the decode function and evaluate it',
      deobfuscationStrategy: '1. Use https://obf-io.deobfuscate.io/\n2. Or use webcrack: npx webcrack input.js\n3. Manual: locate string array function, locate rotation function, inline decoded strings\n4. Replace _0x names with meaningful names via AST',
      tools: ['webcrack', 'obf-io.deobfuscate.io', 'de4js', 'babel-based AST transformer'],
    });
  }

  // ===== JSFuck =====
  // JSFuck uses only []()!+ characters
  const jsfuckCheck = source.replace(/\s/g, '');
  const jsfuckRatio = (jsfuckCheck.match(/[\[\]\(\)\!\+]/g) ?? []).length / Math.max(jsfuckCheck.length, 1);
  if (jsfuckRatio > 0.8 && jsfuckCheck.length > 100) {
    detections.push({
      type: 'JSFuck',
      confidence: 0.95,
      evidence: `Code is ${(jsfuckRatio * 100).toFixed(0)}% composed of []()!+ characters`,
      unpackHint: 'JSFuck encodes JS using only 6 characters. Evaluate it directly or use a decoder',
      deobfuscationStrategy: '1. Wrap in console.log and evaluate: node -e "console.log(<code>)"\n2. Or use https://ooze.ninja/javascript/jsfuck-decoder\n3. For partial JSFuck (mixed), identify the encoded segments and decode individually',
      tools: ['js-decrypt', 'jsfuck decoder'],
    });
  }

  // ===== AAEncode =====
  // AAEncode uses Japanese-style emoticons
  if (/ﾟﾉ|ﾟωﾟ|ﾟΘﾟ|ﾟДﾟ|c\^\w+/.test(source) && source.includes('_')) {
    detections.push({
      type: 'AAEncode',
      confidence: 0.85,
      evidence: 'Found AAEncode signature characters (ﾟωﾟ, ﾟΘﾟ, ﾟДﾟ)',
      unpackHint: 'AAEncode encodes JS as emoticons. Replace the final eval with console.log',
      deobfuscationStrategy: '1. Find the final (c^... ) expression\n2. Replace eval-like execution with console.log\n3. Or use online AAEncode decoder',
      tools: ['AAEncode decoder', 'manual eval→log replacement'],
    });
  }

  // ===== JJEncode =====
  // JJEncode starts with ~function and uses specific patterns
  if (/~function\s*\(\s*\)\s*\{|j\s*=\s*~\[\]/.test(source) || /^[$=_]/.test(source.trim()) && /\$\$\$\$/.test(source)) {
    detections.push({
      type: 'JJEncode',
      confidence: 0.8,
      evidence: 'Found JJEncode patterns (~function, j=~[], $ sequences)',
      unpackHint: 'JJEncode uses $ _ characters. Execute in browser/sandbox and capture output',
      deobfuscationStrategy: '1. Run in Node.js/browser sandbox with eval replaced by console.log\n2. Or use https://utf-8.jp/public/jjencode.html decoder',
      tools: ['JJEncode decoder', 'sandbox eval'],
    });
  }

  // ===== Dean Edwards Packer =====
  if (/eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)/.test(source)) {
    detections.push({
      type: 'dean-edwards-packer',
      confidence: 0.95,
      evidence: 'Found Dean Edwards packer signature: eval(function(p,a,c,k,e,d...))',
      unpackHint: 'Replace the outer eval() with document.write or console.log to get unpacked code',
      deobfuscationStrategy: '1. Replace eval( with console.log(\n2. Execute in Node.js\n3. The output is the unpacked (but possibly still minified) source\n4. Run through prettier for readability',
      tools: ['manual eval→log', 'unpack.js (Dean Edwards)', 'prettier'],
    });
  }

  // ===== eval-based loader =====
  const evalCount = (source.match(/\beval\s*\(/g) ?? []).length;
  if (evalCount > 0 && /atob|unescape|decodeURIComponent|fromCharCode/.test(source)) {
    detections.push({
      type: 'eval-loader',
      confidence: 0.75,
      evidence: `Found ${evalCount} eval() call(s) + decoding function (atob/unescape/fromCharCode)`,
      unpackHint: 'Replace eval with console.log to reveal the real code',
      deobfuscationStrategy: '1. Replace all eval( with console.log(\n2. If eval is indirect (window[\'eval\']), redirect it\n3. Execute in sandbox\n4. May need multiple rounds if evals are nested',
      tools: ['manual eval→log', 'sandbox'],
    });
  }

  // ===== Control-flow flattening =====
  if (/while\s*\(\s*!!\[\]\s*\)\s*\{|switch\s*\(\s*\w+\s*\+\s*\w+/.test(source) || /while\s*\(!\s*\[\]\s*\)/.test(source)) {
    detections.push({
      type: 'control-flow-flattening',
      confidence: 0.85,
      evidence: 'Found while(!![]) or while(![]) + switch pattern — classic control-flow flattening',
      unpackHint: 'Control-flow flattening breaks code into a switch-inside-while-loop. Need to trace execution order',
      deobfuscationStrategy: '1. Identify the state variable (usually incremented in switch cases)\n2. Map each case to its execution order\n3. Reconstruct linear control flow via AST transformation\n4. Use babel + control-flow-unflattening plugin',
      tools: ['babel', 'control-flow-unflatten', 'webcrack (handles this)'],
    });
  }

  // ===== String array obfuscation =====
  if (/function\s+\w+\s*\(\s*\)\s*\{\s*var\s+\w+\s*=\s*\[/.test(source) || /_0x[0-9a-f]+\s*=\s*\[/.test(source)) {
    detections.push({
      type: 'string-array',
      confidence: 0.8,
      evidence: 'Found string array declaration pattern (function returning var = [...])',
      unpackHint: 'String array obfuscation stores strings in an array, accessed via index function',
      deobfuscationStrategy: '1. Locate the string array function\n2. Locate the accessor function (usually takes index, returns string)\n3. Inline all accessor calls with actual string values\n4. Use babel AST transformer to automate',
      tools: ['babel', 'webcrack', 'deobfuscator'],
    });
  }

  // ===== Dead code injection =====
  if (/if\s*\(\s*0\s*\)|if\s*\(\s*false\s*\)|if\s*\(\s*!0x1\s*\)/.test(source)) {
    const deadBranchCount = (source.match(/if\s*\(\s*(?:0|false|!0x1)\s*\)/g) ?? []).length;
    detections.push({
      type: 'dead-code-injection',
      confidence: 0.85,
      evidence: `Found ${deadBranchCount} dead branch(es) (if(0), if(false), if(!0x1))`,
      unpackHint: 'Dead code branches are never executed. Safe to remove entirely',
      deobfuscationStrategy: '1. AST transformation: remove all IfStatement nodes with falsy test\n2. Also remove unreachable code after return/throw\n3. babel-plugin-minify-dead-code-elimination',
      tools: ['babel', 'dead-code-elimination plugin'],
    });
  }

  // ===== Minified (not obfuscated, just small) =====
  const avgLineLength = charCount / Math.max(lineCount, 1);
  if (avgLineLength > 500 && lineCount < 20) {
    detections.push({
      type: 'minified',
      confidence: 0.7,
      evidence: `Avg line length ${avgLineLength.toFixed(0)} chars over ${lineCount} lines — likely minified`,
      unpackHint: 'Minified code is just compressed, not obfuscated. Beautify first',
      deobfuscationStrategy: '1. Run through prettier or js-beautify\n2. Rename single-letter variables to meaningful names based on usage\n3. Add type annotations if reconstructing TypeScript',
      tools: ['prettier', 'js-beautify', 'webcrack'],
    });
  }

  // ===== Babel/terser minified =====
  if (/function\s*\(\s*\)/.test(source) && source.length > 1000 && !source.includes('\n  ')) {
    detections.push({
      type: 'terser-minified',
      confidence: 0.6,
      evidence: 'Single-line or few-line large file with arrow functions — likely terser/babel minified',
      unpackHint: 'Beautify with prettier, then analyze. Source maps if available are gold',
      deobfuscationStrategy: '1. Beautify: npx prettier --write input.js\n2. Check for sourceMappingURL comment at end\n3. If source map exists, use shuji or source-map-explorer to recover original',
      tools: ['prettier', 'shuji', 'source-map-explorer'],
    });
  }

  // Sort by confidence
  detections.sort((a, b) => b.confidence - a.confidence);

  // If nothing detected
  if (detections.length === 0) {
    detections.push({
      type: 'none-detected',
      confidence: 0.5,
      evidence: 'No known obfuscation pattern matched',
      unpackHint: 'The code may be clean, custom-obfuscated, or a new technique',
      deobfuscationStrategy: '1. Beautify with prettier\n2. Look for custom string encoding functions\n3. Check for WASM modules that may contain logic\n4. Use AST analysis to identify opaque predicates or custom transforms',
    });
  }

  const result = {
    totalDetections: detections.length,
    primaryType: detections[0]?.type ?? 'unknown',
    detections: detections.map((d) => ({
      type: d.type,
      confidence: `${(d.confidence * 100).toFixed(0)}%`,
      evidence: d.evidence,
      unpackHint: d.unpackHint,
      deobfuscationStrategy: d.deobfuscationStrategy,
      recommendedTools: d.tools ?? [],
    })),
    stats: {
      lineCount,
      charCount,
      avgLineLength: Math.round(charCount / Math.max(lineCount, 1)),
    },
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  };
}
