// Test script (ESM, runs directly with node)
import { detectCrypto } from '../build/src/tools/detect_crypto.js';
import { identifyObfuscation } from '../build/src/tools/identify_obfuscation.js';
import { extractCryptoConstants } from '../build/src/tools/extract_constants.js';
import { reconstructAlgorithm } from '../build/src/tools/reconstruct_algorithm.js';
import { bypassAntiDebug } from '../build/src/tools/bypass_anti_debug.js';
import { generateSdk } from '../build/src/tools/generate_sdk.js';

const testSource = `
var CryptoJS = require('crypto-js');
function encryptPassword(password) {
  var key = CryptoJS.enc.Utf8.parse('1234567890abcdef');
  var iv = CryptoJS.enc.Utf8.parse('abcdef9876543210');
  var encrypted = CryptoJS.AES.encrypt(password, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  return encrypted.toString();
}

function sign(data) {
  return CryptoJS.HmacSHA256(data, 'secret_key').toString();
}

function md5Hash(text) {
  return CryptoJS.MD5(text).toString();
}

var encrypt = new JSEncrypt();
encrypt.setPublicKey('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...');
var rsaResult = encrypt.encrypt('hello');

var sm2 = require('sm-crypto').sm2;
var cipher = sm2.doEncrypt('data', publicKey);

var sbox = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76];
`;

async function runTests() {
  console.log('===== Test 1: detect_crypto =====');
  const cryptoResult = await detectCrypto(testSource, {});
  const cryptoData = JSON.parse(cryptoResult.content[0].text);
  console.log('Summary:', cryptoData.summary);
  console.log('Detections:');
  for (const d of cryptoData.detections) {
    console.log(`  [${d.confidence}] ${d.algorithm} (${d.library}) at ${d.location} - mode:${d.mode} key:${d.keySource}`);
  }
  console.log('Hints:', cryptoData.hints.length, 'hints');

  console.log('\n===== Test 2: extract_crypto_constants =====');
  const constResult = await extractCryptoConstants(testSource);
  const constData = JSON.parse(constResult.content[0].text);
  console.log('Algorithms found:', constData.algorithmsFound);
  for (const c of constData.constants) {
    console.log(`  [${c.confidence}] ${c.algorithm} ${c.constantType} at ${c.location}: ${c.value.slice(0, 50)}`);
  }

  console.log('\n===== Test 3: identify_obfuscation =====');
  const obfSource = '!function(){var e={123:function(e,t,r){r.r(t),console.log("hi")}},t={};function r(n){if(t[n])return t[n].exports;var o=t[n]={l:!1,exports:{}};return e[n].call(o.exports,o,o.exports,r),o.l=!0,o.exports}r.m=e,r.c=t}();';
  const obfResult = await identifyObfuscation(obfSource);
  const obfData = JSON.parse(obfResult.content[0].text);
  console.log('Primary type:', obfData.primaryType);
  for (const d of obfData.detections) {
    console.log(`  [${d.confidence}] ${d.type}: ${d.evidence}`);
  }

  console.log('\n===== Test 4: reconstruct_algorithm (AES) =====');
  const reconResult = await reconstructAlgorithm(testSource, { targetLanguage: 'python' });
  const reconData = JSON.parse(reconResult.content[0].text);
  console.log('Detected:', reconData.detectedAlgorithm, reconData.detectedMode);
  console.log('Code preview (first 10 lines):');
  console.log(reconData.code.split('\n').slice(0, 15).join('\n'));

  console.log('\n===== Test 5: bypass_anti_debug =====');
  const bypassResult = await bypassAntiDebug({ source: 'setInterval(function(){debugger;}, 100);', techniques: ['all'], outputFormat: 'inject_script' });
  const bypassData = JSON.parse(bypassResult.content[0].text);
  console.log('Detected techniques:', bypassData.detectedTechniques.map((t) => t.technique));
  console.log('Bypass script length:', bypassData.bypassScript.length, 'chars');

  console.log('\n===== Test 6: generate_sdk =====');
  const sdkResult = await generateSdk({
    url: 'https://api.example.com/v1',
    method: 'POST',
    signSpec: { algorithm: 'HMAC-SHA256', keySource: 'app_secret', signLocation: 'header', signField: 'X-Sign' },
    loginSpec: { url: '/login', usernameField: 'username', passwordField: 'password', passwordEncryption: 'RSA' },
  }, 'python');
  const sdkData = JSON.parse(sdkResult.content[0].text);
  console.log('SDK class:', sdkData.sdk.split('\n').find((l) => l.includes('class')));
  console.log('SDK code length:', sdkData.sdk.length, 'chars');

  console.log('\n===== All 6 tools tested successfully =====');
}

runTests().catch((err) => {
  console.error('Test failed:', err);
  process.exit(1);
});
