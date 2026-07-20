/**
 * bypass_anti_debug — Generate anti-debugging bypass scripts
 *
 * Detects and generates bypass for:
 * - debugger statement loops
 * - setInterval debugger
 * - devtools detection (window size, console access)
 * - timing checks
 * - console.log getter traps
 * - Function.prototype.toString checks
 */
import type { McpToolResult } from '../types.js';

interface BypassOptions {
  source?: string;
  techniques: string[];
  outputFormat: 'inject_script' | 'fiddler_rule' | 'chrome_devtools_snippet';
}

interface DetectedTechnique {
  technique: string;
  evidence: string;
  location?: { line: number; column: number };
  severity: 'low' | 'medium' | 'high';
}

export async function bypassAntiDebug(options: BypassOptions): Promise<McpToolResult> {
  const detected: DetectedTechnique[] = [];

  // Detect techniques in source
  if (options.source) {
    detected.push(...detectTechniques(options.source));
  }

  // Generate bypass for requested or detected techniques
  const techniquesToBypass = options.techniques.includes('all')
    ? detected.length > 0
      ? detected.map((d) => d.technique)
      : ['debugger_loop', 'setInterval_debugger', 'devtools_window_size', 'devtools_console_access', 'timing_check', 'console_getter_trap', 'function_toString_check']
    : options.techniques;

  let output = '';
  switch (options.outputFormat) {
    case 'inject_script':
      output = generateInjectScript(techniquesToBypass);
      break;
    case 'fiddler_rule':
      output = generateFiddlerRule(techniquesToBypass);
      break;
    case 'chrome_devtools_snippet':
      output = generateChromeSnippet(techniquesToBypass);
      break;
  }

  const result = {
    detectedTechniques: detected.map((d) => ({
      technique: d.technique,
      evidence: d.evidence,
      location: d.location ? `${d.location.line}:${d.location.column}` : 'N/A',
      severity: d.severity,
    })),
    techniquesBypassed: techniquesToBypass,
    outputFormat: options.outputFormat,
    bypassScript: output,
    injectionInstructions: getInjectionInstructions(options.outputFormat),
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  };
}

function detectTechniques(source: string): DetectedTechnique[] {
  const techniques: DetectedTechnique[] = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // debugger loop
    if (/debugger\s*;/i.test(line) && /while|for|setInterval|setTimeout/i.test(source.slice(source.indexOf(line) - 100, source.indexOf(line) + 100))) {
      techniques.push({
        technique: 'debugger_loop',
        evidence: `Line ${lineNum}: debugger statement near loop`,
        location: { line: lineNum, column: line.indexOf('debugger') + 1 },
        severity: 'high',
      });
    }

    // setInterval debugger
    if (/setInterval\s*\([^)]*debugger/i.test(line) || /setInterval\s*\(\s*\(\s*\)\s*=>\s*{[^}]*debugger/i.test(source)) {
      techniques.push({
        technique: 'setInterval_debugger',
        evidence: `Line ${lineNum}: setInterval with debugger`,
        location: { line: lineNum, column: 1 },
        severity: 'high',
      });
    }

    // devtools window size check
    if (/window\.outerWidth\s*-\s*window\.innerWidth|window\.outerHeight\s*-\s*window\.innerHeight/i.test(line)) {
      techniques.push({
        technique: 'devtools_window_size',
        evidence: `Line ${lineNum}: window outer/inner size comparison`,
        location: { line: lineNum, column: 1 },
        severity: 'medium',
      });
    }

    // console access detection
    if (/console\.\w+\s*&&|typeof\s+console|console\.log\.toString\(\)\.length/i.test(line)) {
      techniques.push({
        technique: 'devtools_console_access',
        evidence: `Line ${lineNum}: console object inspection`,
        location: { line: lineNum, column: 1 },
        severity: 'medium',
      });
    }

    // timing check
    if (/Date\.now\s*\(\s*\)\s*-|performance\.now\s*\(\s*\)\s*-/i.test(line) && /\d{3,}/.test(line)) {
      techniques.push({
        technique: 'timing_check',
        evidence: `Line ${lineNum}: timing-based detection`,
        location: { line: lineNum, column: 1 },
        severity: 'medium',
      });
    }

    // console getter trap
    if (/Object\.defineProperty\s*\(\s*console|console\.__defineGetter__/i.test(line)) {
      techniques.push({
        technique: 'console_getter_trap',
        evidence: `Line ${lineNum}: console property trap`,
        location: { line: lineNum, column: 1 },
        severity: 'high',
      });
    }

    // Function.toString check
    if (/Function\.prototype\.toString|\.toString\(\)\.length|\.toString\(\)\.indexOf/i.test(line) && /native\s*code/i.test(source.slice(Math.max(0, source.indexOf(line) - 200), source.indexOf(line) + 200))) {
      techniques.push({
        technique: 'function_toString_check',
        evidence: `Line ${lineNum}: Function.toString inspection`,
        location: { line: lineNum, column: 1 },
        severity: 'medium',
      });
    }
  }

  // Deduplicate
  const seen = new Set<string>();
  return techniques.filter((t) => {
    if (seen.has(t.technique)) return false;
    seen.add(t.technique);
    return true;
  });
}

function generateInjectScript(techniques: string[]): string {
  const parts: string[] = [];
  parts.push('// Anti-debug bypass script — inject before page scripts');
  parts.push('// Generated by crypto-reverse-mcp');
  parts.push('');

  if (techniques.includes('debugger_loop') || techniques.includes('setInterval_debugger') || techniques.includes('all')) {
    parts.push('// === 1. Neutralize debugger statements ===');
    parts.push('(function() {');
    parts.push('  // Override Function constructor to strip debugger');
    parts.push('  const origFunction = window.Function;');
    parts.push('  window.Function = new Proxy(origFunction, {');
    parts.push('    construct(target, args) {');
    parts.push('      if (args.length > 0 && typeof args[args.length - 1] === "string") {');
    parts.push('        args[args.length - 1] = args[args.length - 1].replace(/debugger\\s*;?/g, "");');
    parts.push('      }');
    parts.push('      return Reflect.construct(target, args);');
    parts.push('    },');
    parts.push('    apply(target, thisArg, args) {');
    parts.push('      if (args.length > 0 && typeof args[args.length - 1] === "string") {');
    parts.push('        args[args.length - 1] = args[args.length - 1].replace(/debugger\\s*;?/g, "");');
    parts.push('      }');
    parts.push('      return Reflect.apply(target, thisArg, args);');
    parts.push('    }');
    parts.push('  });');
    parts.push('  // Block setInterval/setTimeout that contains debugger');
    parts.push('  const origSetInterval = window.setInterval;');
    parts.push('  window.setInterval = function(fn, delay, ...args) {');
    parts.push('    const fnStr = typeof fn === "string" ? fn : (fn && fn.toString ? fn.toString() : "");');
    parts.push('    if (/debugger/.test(fnStr)) {');
    parts.push('      console.warn("[bypass] blocked setInterval with debugger");');
    parts.push('      return 0; // return fake timer id');
    parts.push('    }');
    parts.push('    return origSetInterval.call(this, fn, delay, ...args);');
    parts.push('  };');
    parts.push('  const origSetTimeout = window.setTimeout;');
    parts.push('  window.setTimeout = function(fn, delay, ...args) {');
    parts.push('    const fnStr = typeof fn === "string" ? fn : (fn && fn.toString ? fn.toString() : "");');
    parts.push('    if (/debugger/.test(fnStr) && delay < 100) {');
    parts.push('      console.warn("[bypass] blocked suspicious setTimeout with debugger");');
    parts.push('      return 0;');
    parts.push('    }');
    parts.push('    return origSetTimeout.call(this, fn, delay, ...args);');
    parts.push('  };');
    parts.push('})();');
    parts.push('');
  }

  if (techniques.includes('devtools_window_size') || techniques.includes('all')) {
    parts.push('// === 2. Fix window size detection ===');
    parts.push('(function() {');
    parts.push('  // Make outer/inner dimensions equal so size check fails');
    parts.push('  Object.defineProperty(window, "outerWidth", { get: () => window.innerWidth, configurable: true });');
    parts.push('  Object.defineProperty(window, "outerHeight", { get: () => window.innerHeight, configurable: true });');
    parts.push('})();');
    parts.push('');
  }

  if (techniques.includes('devtools_console_access') || techniques.includes('console_getter_trap') || techniques.includes('all')) {
    parts.push('// === 3. Prevent console access detection ===');
    parts.push('(function() {');
    parts.push('  // Prevent console.log getter traps');
    parts.push('  const consoleProps = ["log", "warn", "error", "info", "debug", "dir", "trace"];');
    parts.push('  for (const prop of consoleProps) {');
    parts.push('    try {');
    parts.push('      const orig = console[prop];');
    parts.push('      Object.defineProperty(console, prop, {');
    parts.push('        value: orig,');
    parts.push('        writable: true,');
    parts.push('        configurable: true,');
    parts.push('      });');
    parts.push('    } catch(e) {}');
    parts.push('  }');
    parts.push('})();');
    parts.push('');
  }

  if (techniques.includes('timing_check') || techniques.includes('all')) {
    parts.push('// === 4. Defeat timing-based detection ===');
    parts.push('(function() {');
    parts.push('  // Override Date.now and performance.now to return consistent values');
    parts.push('  // when called in quick succession');
    parts.push('  const origDateNow = Date.now;');
    parts.push('  const origPerfNow = performance.now.bind(performance);');
    parts.push('  let lastDateNow = origDateNow();');
    parts.push('  let lastPerfNow = origPerfNow();');
    parts.push('  Date.now = function() {');
    parts.push('    const t = origDateNow();');
    parts.push('    // Cap time delta to 50ms max');
    parts.push('    if (t - lastDateNow > 50) {');
    parts.push('      lastDateNow = lastDateNow + 50;');
    parts.push('    } else {');
    parts.push('      lastDateNow = t;');
    parts.push('    }');
    parts.push('    return lastDateNow;');
    parts.push('  };');
    parts.push('  performance.now = function() {');
    parts.push('    const t = origPerfNow();');
    parts.push('    if (t - lastPerfNow > 50) {');
    parts.push('      lastPerfNow = lastPerfNow + 50;');
    parts.push('    } else {');
    parts.push('      lastPerfNow = t;');
    parts.push('    }');
    parts.push('    return lastPerfNow;');
    parts.push('  };');
    parts.push('})();');
    parts.push('');
  }

  if (techniques.includes('function_toString_check') || techniques.includes('all')) {
    parts.push('// === 5. Make Function.toString return native code ===');
    parts.push('(function() {');
    parts.push('  // Preserve original toString');
    parts.push('  const origToString = Function.prototype.toString;');
    parts.push('  const nativePattern = /^function \\w+\\(\\)\\s*\\{\\s*\\[native code\\]\\s*\\}$/;');
    parts.push('  Function.prototype.toString = function() {');
    parts.push('    // If this function was wrapped, return native-looking string');
    parts.push('    const result = origToString.call(this);');
    parts.push('    // Check if caller is checking for "native code"');
    parts.push('    const stack = new Error().stack || "";');
    parts.push('    if (/toString|native|\\[native code\\]/.test(stack) && !nativePattern.test(result)) {');
    parts.push('      return "function " + (this.name || "") + "() { [native code] }";');
    parts.push('    }');
    parts.push('    return result;');
    parts.push('  };');
    parts.push('})();');
    parts.push('');
  }

  parts.push('console.log("[crypto-reverse-mcp] anti-debug bypass injected");');

  return parts.join('\n');
}

function generateFiddlerRule(techniques: string[]): string {
  const script = generateInjectScript(techniques);
  return `// Fiddler Script (OnBeforeResponse)
// Add this to Fiddler's CustomRules.js > OnBeforeResponse handler
static function OnBeforeResponse(oSession: Session) {
    if (oSession.oResponse.headers.ExistsAndContains("Content-Type", "text/html")) {
        var bypassScript = ${JSON.stringify(script)};
        var body = oSession.GetResponseBodyAsString();
        body = body.replace("<head>", "<head><script>" + bypassScript + "</" + "script>");
        oSession.utilSetResponseBody(body);
    }
}`;
}

function generateChromeSnippet(techniques: string[]): string {
  const script = generateInjectScript(techniques);
  return `// Chrome DevTools Snippet
// Sources > Snippets > New snippet > paste this
// Run before navigating to the target page
${script}`;
}

function getInjectionInstructions(format: string): string {
  switch (format) {
    case 'inject_script':
      return 'Inject this script via:\n1. Browser extension (e.g. Tampermonkey/Greasemonkey)\n2. Chrome DevTools "Sources > Snippets"\n3. Fiddler/Charles response rewriting\n4. MCP js-reverse-mcp inject_before_load tool\n5. Patchright addInitScript';
    case 'fiddler_rule':
      return '1. Open Fiddler > Rules > Customize Rules\n2. Find OnBeforeResponse handler\n3. Paste the code inside the handler\n4. Save and reload target page';
    case 'chrome_devtools_snippet':
      return '1. Open Chrome DevTools (F12)\n2. Go to Sources > Snippets\n3. Click "+ New snippet"\n4. Paste the code\n5. Run (Ctrl+Enter) before navigating to target page';
    default:
      return 'See format-specific instructions above.';
  }
}
