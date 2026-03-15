/**
 * UMBRA - Cryptography Engine
 * core/crypto.js v1.0.0
 *
 * Contains implementations for all supported cipher/encoding algorithms.
 * Each algorithm exports: { encode, decode, info }
 * Algorithms are grouped by category and registered in ALGOS map.
 *
 * Adding new algorithms: see CONTRIBUTING section at bottom of file.
 */

'use strict';

/* ============================================================
   UTILITY HELPERS
   ============================================================ */

const Utils = {
  /** Convert string to UTF-8 byte array */
  strToBytes(str) {
    return new TextEncoder().encode(str);
  },

  /** Convert byte array to string */
  bytesToStr(bytes) {
    return new TextDecoder().decode(bytes);
  },

  /** Convert hex string to byte array */
  hexToBytes(hex) {
    hex = hex.replace(/\s+/g, '');
    if (hex.length % 2 !== 0) throw new Error('Hex string must have even length');
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  },

  /** Convert byte array to hex string */
  bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /** Modular arithmetic (always positive) */
  mod(n, m) { return ((n % m) + m) % m; },

  /** Validate base64 */
  isBase64(str) {
    return /^[A-Za-z0-9+/]*={0,2}$/.test(str.replace(/\s/g, ''));
  },

  /** Validate hex */
  isHex(str) {
    return /^[0-9a-fA-F\s]+$/.test(str) && str.replace(/\s/g, '').length % 2 === 0;
  },

  /** GCD for affine cipher */
  gcd(a, b) { while (b) { [a, b] = [b, a % b]; } return a; },

  /** Modular inverse for affine cipher */
  modInverse(a, m) {
    a = Utils.mod(a, m);
    for (let x = 1; x < m; x++) {
      if ((a * x) % m === 1) return x;
    }
    return null;
  },
};


/* ============================================================
   CLASSIC CIPHERS
   ============================================================ */

// ── Caesar Cipher ────────────────────────────────────────────
const Caesar = {
  info: {
    name: 'Caesar Cipher',
    category: 'classic',
    description: 'Rotational substitution cipher. Each letter is shifted by a fixed number (key) in the alphabet. ROT13 is a special case with shift=13.',
    keyRequired: true,
    keyType: 'number',
    keyLabel: 'Shift (0-25)',
    keyHint: 'Integer, e.g. 3 for classic Caesar, 13 for ROT13',
  },

  encode(text, shift) {
    shift = Utils.mod(parseInt(shift) || 3, 26);
    return text.replace(/[a-zA-Z]/g, ch => {
      const base = ch >= 'a' ? 97 : 65;
      return String.fromCharCode(Utils.mod(ch.charCodeAt(0) - base + shift, 26) + base);
    });
  },

  decode(text, shift) {
    return Caesar.encode(text, -parseInt(shift) || -3);
  },

  bruteforce(text) {
    const results = [];
    for (let shift = 0; shift < 26; shift++) {
      results.push({ key: shift, result: Caesar.decode(text, shift) });
    }
    return results;
  },
};

// ── ROT13 ─────────────────────────────────────────────────────
const ROT13 = {
  info: {
    name: 'ROT13',
    category: 'classic',
    description: 'Caesar cipher with fixed shift of 13. Self-inverse: applying twice returns the original. Common in online forums to hide spoilers.',
    keyRequired: false,
  },
  encode: (text) => Caesar.encode(text, 13),
  decode: (text) => Caesar.encode(text, 13),
};

// ── ROT47 ─────────────────────────────────────────────────────
const ROT47 = {
  info: {
    name: 'ROT47',
    category: 'classic',
    description: 'ROT13 extended to all printable ASCII characters (33–126). Self-inverse.',
    keyRequired: false,
  },
  encode(text) {
    return text.replace(/[\x21-\x7e]/g, ch => {
      return String.fromCharCode(Utils.mod(ch.charCodeAt(0) - 33 + 47, 94) + 33);
    });
  },
  decode(text) { return ROT47.encode(text); },
};

// ── Atbash ────────────────────────────────────────────────────
const Atbash = {
  info: {
    name: 'Atbash Cipher',
    category: 'classic',
    description: 'Hebrew/Latin substitution. Each letter is mapped to its reverse (A↔Z, B↔Y, etc.). Self-inverse.',
    keyRequired: false,
  },
  encode(text) {
    return text.replace(/[a-zA-Z]/g, ch => {
      const base = ch >= 'a' ? 97 : 65;
      return String.fromCharCode(25 - (ch.charCodeAt(0) - base) + base);
    });
  },
  decode(text) { return Atbash.encode(text); },
};

// ── Vigenère Cipher ───────────────────────────────────────────
const Vigenere = {
  info: {
    name: 'Vigenère Cipher',
    category: 'classic',
    description: 'Polyalphabetic substitution using a repeating keyword. Each letter is shifted by the corresponding keyword letter\'s value.',
    keyRequired: true,
    keyType: 'text',
    keyLabel: 'Keyword',
    keyHint: 'Alphabetic string, e.g. SECRET',
  },

  encode(text, key) {
    if (!key) throw new Error('Key required for Vigenère');
    key = key.toUpperCase().replace(/[^A-Z]/g, '');
    if (!key) throw new Error('Key must contain alphabetic characters');
    let ki = 0;
    return text.replace(/[a-zA-Z]/g, ch => {
      const base = ch >= 'a' ? 97 : 65;
      const shift = key.charCodeAt(ki % key.length) - 65;
      ki++;
      return String.fromCharCode(Utils.mod(ch.charCodeAt(0) - base + shift, 26) + base);
    });
  },

  decode(text, key) {
    if (!key) throw new Error('Key required for Vigenère');
    key = key.toUpperCase().replace(/[^A-Z]/g, '');
    if (!key) throw new Error('Key must contain alphabetic characters');
    let ki = 0;
    return text.replace(/[a-zA-Z]/g, ch => {
      const base = ch >= 'a' ? 97 : 65;
      const shift = key.charCodeAt(ki % key.length) - 65;
      ki++;
      return String.fromCharCode(Utils.mod(ch.charCodeAt(0) - base - shift, 26) + base);
    });
  },
};

// ── Beaufort Cipher ───────────────────────────────────────────
const Beaufort = {
  info: {
    name: 'Beaufort Cipher',
    category: 'classic',
    description: 'Variant of Vigenère. Self-inverse (same key encrypts and decrypts). Formula: C = (K - P) mod 26.',
    keyRequired: true,
    keyType: 'text',
    keyLabel: 'Keyword',
    keyHint: 'Alphabetic string',
  },
  encode(text, key) {
    if (!key) throw new Error('Key required');
    key = key.toUpperCase().replace(/[^A-Z]/g, '');
    let ki = 0;
    return text.replace(/[a-zA-Z]/g, ch => {
      const base = ch >= 'a' ? 97 : 65;
      const p = ch.charCodeAt(0) - base;
      const k = key.charCodeAt(ki++ % key.length) - 65;
      return String.fromCharCode(Utils.mod(k - p, 26) + base);
    });
  },
  decode(text, key) { return Beaufort.encode(text, key); },
};

// ── Playfair Cipher ───────────────────────────────────────────
const Playfair = {
  info: {
    name: 'Playfair Cipher',
    category: 'classic',
    description: 'Digraph substitution cipher using a 5×5 key square (I/J combined). Encrypts pairs of letters using row/column rules.',
    keyRequired: true,
    keyType: 'text',
    keyLabel: 'Keyword',
    keyHint: 'Alphabetic string to build 5×5 matrix',
  },

  buildMatrix(key) {
    key = key.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
    const seen = new Set();
    const matrix = [];
    const all = key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
    for (const ch of all) {
      if (!seen.has(ch)) { seen.add(ch); matrix.push(ch); }
    }
    return matrix;
  },

  findPos(matrix, ch) {
    const i = matrix.indexOf(ch);
    return [Math.floor(i / 5), i % 5];
  },

  prepareText(text) {
    text = text.toUpperCase().replace(/J/g, 'I').replace(/[^A-Z]/g, '');
    let result = '';
    for (let i = 0; i < text.length; i++) {
      result += text[i];
      if (i + 1 < text.length && text[i] === text[i + 1]) result += 'X';
    }
    if (result.length % 2 !== 0) result += 'X';
    return result;
  },

  encode(text, key) {
    if (!key) throw new Error('Key required');
    const matrix = this.buildMatrix(key);
    const prepared = this.prepareText(text);
    let result = '';
    for (let i = 0; i < prepared.length; i += 2) {
      const a = prepared[i], b = prepared[i + 1];
      const [ar, ac] = this.findPos(matrix, a);
      const [br, bc] = this.findPos(matrix, b);
      if (ar === br) {
        result += matrix[ar * 5 + (ac + 1) % 5] + matrix[br * 5 + (bc + 1) % 5];
      } else if (ac === bc) {
        result += matrix[((ar + 1) % 5) * 5 + ac] + matrix[((br + 1) % 5) * 5 + bc];
      } else {
        result += matrix[ar * 5 + bc] + matrix[br * 5 + ac];
      }
    }
    return result;
  },

  decode(text, key) {
    if (!key) throw new Error('Key required');
    const matrix = this.buildMatrix(key);
    text = text.toUpperCase().replace(/[^A-Z]/g, '');
    if (text.length % 2 !== 0) throw new Error('Ciphertext length must be even');
    let result = '';
    for (let i = 0; i < text.length; i += 2) {
      const a = text[i], b = text[i + 1];
      const [ar, ac] = this.findPos(matrix, a);
      const [br, bc] = this.findPos(matrix, b);
      if (ar === br) {
        result += matrix[ar * 5 + Utils.mod(ac - 1, 5)] + matrix[br * 5 + Utils.mod(bc - 1, 5)];
      } else if (ac === bc) {
        result += matrix[Utils.mod(ar - 1, 5) * 5 + ac] + matrix[Utils.mod(br - 1, 5) * 5 + bc];
      } else {
        result += matrix[ar * 5 + bc] + matrix[br * 5 + ac];
      }
    }
    return result;
  },
};

// ── Affine Cipher ─────────────────────────────────────────────
const Affine = {
  info: {
    name: 'Affine Cipher',
    category: 'classic',
    description: 'Mathematical substitution: C = (aP + b) mod 26. Key has two parts: multiplier a (must be coprime to 26) and shift b.',
    keyRequired: true,
    keyType: 'text',
    keyLabel: 'Key (a,b)',
    keyHint: 'Two integers separated by comma, e.g. 5,8  (a must be coprime to 26)',
  },

  parseKey(key) {
    const parts = key.split(',').map(s => parseInt(s.trim()));
    if (parts.length < 2 || isNaN(parts[0]) || isNaN(parts[1])) throw new Error('Key format: a,b (e.g. 5,8)');
    const [a, b] = parts;
    if (Utils.gcd(a, 26) !== 1) throw new Error(`a=${a} is not coprime to 26. Valid values: 1,3,5,7,9,11,15,17,19,21,23,25`);
    return { a, b };
  },

  encode(text, key) {
    const { a, b } = this.parseKey(key);
    return text.replace(/[a-zA-Z]/g, ch => {
      const base = ch >= 'a' ? 97 : 65;
      const p = ch.charCodeAt(0) - base;
      return String.fromCharCode(Utils.mod(a * p + b, 26) + base);
    });
  },

  decode(text, key) {
    const { a, b } = this.parseKey(key);
    const aInv = Utils.modInverse(a, 26);
    if (aInv === null) throw new Error(`No modular inverse for a=${a}`);
    return text.replace(/[a-zA-Z]/g, ch => {
      const base = ch >= 'a' ? 97 : 65;
      const c = ch.charCodeAt(0) - base;
      return String.fromCharCode(Utils.mod(aInv * (c - b), 26) + base);
    });
  },
};

// ── Rail Fence Cipher ─────────────────────────────────────────
const RailFence = {
  info: {
    name: 'Rail Fence Cipher',
    category: 'classic',
    description: 'Transposition cipher. Text is written in a zigzag pattern across N rails, then read row by row.',
    keyRequired: true,
    keyType: 'number',
    keyLabel: 'Number of Rails',
    keyHint: 'Integer ≥ 2, e.g. 3',
  },

  encode(text, rails) {
    rails = parseInt(rails) || 3;
    if (rails < 2) throw new Error('Rails must be ≥ 2');
    const fence = Array.from({ length: rails }, () => []);
    let rail = 0, dir = 1;
    for (const ch of text) {
      fence[rail].push(ch);
      if (rail === 0) dir = 1;
      else if (rail === rails - 1) dir = -1;
      rail += dir;
    }
    return fence.flat().join('');
  },

  decode(text, rails) {
    rails = parseInt(rails) || 3;
    if (rails < 2) throw new Error('Rails must be ≥ 2');
    const n = text.length;
    const pattern = new Array(n);
    let rail = 0, dir = 1;
    for (let i = 0; i < n; i++) {
      pattern[i] = rail;
      if (rail === 0) dir = 1;
      else if (rail === rails - 1) dir = -1;
      rail += dir;
    }
    const indices = pattern.map((r, i) => ({ r, i })).sort((a, b) => a.r - b.r || a.i - b.i);
    const result = new Array(n);
    for (let i = 0; i < n; i++) result[indices[i].i] = text[i];
    return result.join('');
  },
};

// ── Columnar Transposition ────────────────────────────────────
const Columnar = {
  info: {
    name: 'Columnar Transposition',
    category: 'classic',
    description: 'Text is written in rows of length=key length, then columns are read in alphabetical key order.',
    keyRequired: true,
    keyType: 'text',
    keyLabel: 'Keyword',
    keyHint: 'Alphabetic word, columns sorted alphabetically by key letters',
  },

  encode(text, key) {
    if (!key) throw new Error('Key required');
    key = key.toUpperCase().replace(/[^A-Z]/g, '');
    const cols = key.length;
    const order = key.split('').map((ch, i) => ({ ch, i })).sort((a, b) => a.ch.localeCompare(b.ch)).map(o => o.i);
    const rows = Math.ceil(text.length / cols);
    const padded = text.padEnd(rows * cols, 'X');
    return order.map(c => {
      let col = '';
      for (let r = 0; r < rows; r++) col += padded[r * cols + c];
      return col;
    }).join('');
  },

  decode(text, key) {
    if (!key) throw new Error('Key required');
    key = key.toUpperCase().replace(/[^A-Z]/g, '');
    const cols = key.length;
    const rows = Math.ceil(text.length / cols);
    const order = key.split('').map((ch, i) => ({ ch, i })).sort((a, b) => a.ch.localeCompare(b.ch)).map(o => o.i);
    const colLen = rows;
    const grid = {};
    let pos = 0;
    for (const c of order) {
      grid[c] = text.slice(pos, pos + colLen);
      pos += colLen;
    }
    let result = '';
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) result += grid[c][r];
    }
    return result.trimEnd();
  },
};

// ── Substitution Cipher ───────────────────────────────────────
const Substitution = {
  info: {
    name: 'Simple Substitution',
    category: 'classic',
    description: 'Each alphabet letter maps to a unique letter in a 26-char key alphabet. Key must be all 26 unique letters.',
    keyRequired: true,
    keyType: 'text',
    keyLabel: 'Substitution Alphabet (26 chars)',
    keyHint: 'A-Z permutation, e.g. QWERTYUIOPASDFGHJKLZXCVBNM',
  },

  validate(key) {
    key = key.toUpperCase().replace(/[^A-Z]/g, '');
    if (key.length !== 26) throw new Error('Key must be exactly 26 alphabetic characters');
    if (new Set(key).size !== 26) throw new Error('Key must contain each letter exactly once');
    return key;
  },

  encode(text, key) {
    key = this.validate(key);
    return text.replace(/[a-zA-Z]/g, ch => {
      const base = ch >= 'a' ? 97 : 65;
      const result = key[ch.charCodeAt(0) - 65 < 0 ? ch.charCodeAt(0) - 97 : ch.charCodeAt(0) - 65];
      return ch >= 'a' ? result.toLowerCase() : result;
    });
  },

  decode(text, key) {
    key = this.validate(key);
    const reverse = new Array(26);
    for (let i = 0; i < 26; i++) reverse[key.charCodeAt(i) - 65] = String.fromCharCode(65 + i);
    return text.replace(/[a-zA-Z]/g, ch => {
      const idx = ch.toUpperCase().charCodeAt(0) - 65;
      return ch >= 'a' ? reverse[idx].toLowerCase() : reverse[idx];
    });
  },
};


/* ============================================================
   ENCODING SCHEMES
   ============================================================ */

// ── Base64 ────────────────────────────────────────────────────
const Base64 = {
  info: {
    name: 'Base64',
    category: 'encoding',
    description: 'Binary-to-text encoding using 64-character alphabet (A-Z, a-z, 0-9, +, /). Used widely in email (MIME) and data URIs.',
    keyRequired: false,
  },
  encode(text) { return btoa(unescape(encodeURIComponent(text))); },
  decode(text) {
    try {
      return decodeURIComponent(escape(atob(text.replace(/\s/g, ''))));
    } catch {
      throw new Error('Invalid Base64 string');
    }
  },
};

// ── Base64 URL-safe ───────────────────────────────────────────
const Base64URL = {
  info: {
    name: 'Base64 URL-safe',
    category: 'encoding',
    description: 'Base64 variant replacing + with - and / with _ for use in URLs. No padding optional.',
    keyRequired: false,
  },
  encode(text) {
    return btoa(unescape(encodeURIComponent(text)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  },
  decode(text) {
    let b64 = text.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    try {
      return decodeURIComponent(escape(atob(b64)));
    } catch {
      throw new Error('Invalid Base64 URL string');
    }
  },
};

// ── Base32 ────────────────────────────────────────────────────
const Base32 = {
  info: {
    name: 'Base32',
    category: 'encoding',
    description: 'Encodes binary data using 32-character alphabet (A-Z, 2-7). Used in TOTP/OTP and DNS encoding.',
    keyRequired: false,
  },
  ALPHABET: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',

  encode(text) {
    const bytes = Utils.strToBytes(text);
    let bits = 0, value = 0, output = '';
    for (const byte of bytes) {
      value = (value << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        output += this.ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) output += this.ALPHABET[(value << (5 - bits)) & 31];
    while (output.length % 8) output += '=';
    return output;
  },

  decode(text) {
    text = text.replace(/=+$/, '').toUpperCase();
    let bits = 0, value = 0;
    const output = [];
    for (const ch of text) {
      const idx = this.ALPHABET.indexOf(ch);
      if (idx === -1) throw new Error(`Invalid Base32 character: ${ch}`);
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        output.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }
    return Utils.bytesToStr(new Uint8Array(output));
  },
};

// ── Base58 ────────────────────────────────────────────────────
const Base58 = {
  info: {
    name: 'Base58',
    category: 'encoding',
    description: 'Bitcoin-style encoding. Removes ambiguous chars (0, O, I, l). Common in crypto addresses.',
    keyRequired: false,
  },
  ALPHABET: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',

  encode(text) {
    const bytes = Utils.strToBytes(text);
    let num = BigInt('0x' + Utils.bytesToHex(bytes));
    let result = '';
    const base = BigInt(58);
    while (num > 0n) {
      result = this.ALPHABET[Number(num % base)] + result;
      num /= base;
    }
    for (const b of bytes) {
      if (b !== 0) break;
      result = '1' + result;
    }
    return result;
  },

  decode(text) {
    let num = 0n;
    const base = BigInt(58);
    for (const ch of text) {
      const idx = this.ALPHABET.indexOf(ch);
      if (idx === -1) throw new Error(`Invalid Base58 character: ${ch}`);
      num = num * base + BigInt(idx);
    }
    const hex = num.toString(16).padStart(2, '0');
    const padded = hex.length % 2 ? '0' + hex : hex;
    const bytes = Utils.hexToBytes(padded);
    const leadingOnes = text.match(/^1*/)[0].length;
    const leading = new Uint8Array(leadingOnes);
    return Utils.bytesToStr(new Uint8Array([...leading, ...bytes]));
  },
};

// ── Hex Encoding ──────────────────────────────────────────────
const HexEncode = {
  info: {
    name: 'Hexadecimal',
    category: 'encoding',
    description: 'Encodes text as hexadecimal byte values. Each character becomes 2 hex digits.',
    keyRequired: false,
  },
  encode(text) { return Utils.bytesToHex(Utils.strToBytes(text)); },
  decode(text) {
    try { return Utils.bytesToStr(Utils.hexToBytes(text)); }
    catch { throw new Error('Invalid hexadecimal string'); }
  },
};

// ── Binary Encoding ───────────────────────────────────────────
const BinaryEncode = {
  info: {
    name: 'Binary (ASCII)',
    category: 'encoding',
    description: 'Encodes each character as its 8-bit binary ASCII/UTF representation.',
    keyRequired: false,
  },
  encode(text) {
    return Array.from(Utils.strToBytes(text))
      .map(b => b.toString(2).padStart(8, '0'))
      .join(' ');
  },
  decode(text) {
    const groups = text.trim().replace(/\s+/g, ' ').split(' ');
    try {
      const bytes = groups.map(g => parseInt(g, 2));
      if (bytes.some(isNaN)) throw new Error();
      return Utils.bytesToStr(new Uint8Array(bytes));
    } catch {
      throw new Error('Invalid binary string');
    }
  },
};

// ── Octal Encoding ────────────────────────────────────────────
const OctalEncode = {
  info: {
    name: 'Octal',
    category: 'encoding',
    description: 'Encodes text as octal byte values.',
    keyRequired: false,
  },
  encode(text) {
    return Array.from(Utils.strToBytes(text)).map(b => b.toString(8).padStart(3, '0')).join(' ');
  },
  decode(text) {
    const groups = text.trim().split(/\s+/);
    try {
      return Utils.bytesToStr(new Uint8Array(groups.map(g => parseInt(g, 8))));
    } catch {
      throw new Error('Invalid octal string');
    }
  },
};

// ── URL Encoding ──────────────────────────────────────────────
const URLEncode = {
  info: {
    name: 'URL Encoding',
    category: 'encoding',
    description: 'Percent-encodes special characters for use in URLs (RFC 3986).',
    keyRequired: false,
  },
  encode: (text) => encodeURIComponent(text),
  decode(text) {
    try { return decodeURIComponent(text); }
    catch { throw new Error('Invalid URL-encoded string'); }
  },
};

// ── HTML Entities ─────────────────────────────────────────────
const HTMLEntities = {
  info: {
    name: 'HTML Entities',
    category: 'encoding',
    description: 'Encodes/decodes HTML special characters (&, <, >, ", \') using named or numeric entities.',
    keyRequired: false,
  },
  encode(text) {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  },
  decode(text) {
    const el = document.createElement('textarea');
    el.innerHTML = text;
    return el.value;
  },
};

// ── Unicode Escape ────────────────────────────────────────────
const UnicodeEscape = {
  info: {
    name: 'Unicode Escape',
    category: 'encoding',
    description: 'Converts characters to \\uXXXX escape sequences and back.',
    keyRequired: false,
  },
  encode(text) {
    return Array.from(text).map(ch => {
      const code = ch.codePointAt(0);
      return code > 127 ? `\\u${code.toString(16).padStart(4, '0')}` : ch;
    }).join('');
  },
  decode(text) {
    return text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) =>
      String.fromCodePoint(parseInt(hex, 16))
    );
  },
};

// ── Morse Code ────────────────────────────────────────────────
const Morse = {
  info: {
    name: 'Morse Code',
    category: 'encoding',
    description: 'Encodes text as dots (.) and dashes (-). Letters separated by space, words by /.',
    keyRequired: false,
  },
  TABLE: {
    A:'.-', B:'-...', C:'-.-.', D:'-..', E:'.', F:'..-.', G:'--.', H:'....', I:'..', J:'.---',
    K:'-.-', L:'.-..', M:'--', N:'-.', O:'---', P:'.--.', Q:'--.-', R:'.-.', S:'...', T:'-',
    U:'..-', V:'...-', W:'.--', X:'-..-', Y:'-.--', Z:'--..',
    '0':'-----', '1':'.----', '2':'..---', '3':'...--', '4':'....-', '5':'.....', '6':'-....', '7':'--...', '8':'---..', '9':'----.',
    '.':'.-.-.-', ',':'--..--', '?':'..--..', "'":'.----.', '!':'-.-.--', '/':'-..-.', '(':'-.--.', ')':'-.--.-',
    '&':'.-...', ':':'---...', ';':'-.-.-.', '=':'-...-', '+':'.-.-.', '-':'-....-', '_':'..--.-',
    '"':'.-..-.', '$':'...-..-', '@':'.--.-.', ' ':'/'
  },

  encode(text) {
    const reverseTable = {};
    for (const [k, v] of Object.entries(this.TABLE)) reverseTable[v] = k;
    return text.toUpperCase().split('').map(ch => this.TABLE[ch] || '?').join(' ');
  },

  decode(text) {
    const reverseTable = {};
    for (const [k, v] of Object.entries(this.TABLE)) reverseTable[v] = k;
    return text.trim().split(' / ').map(word =>
      word.split(' ').map(code => reverseTable[code] || '?').join('')
    ).join(' ');
  },
};

// ── NATO Phonetic ─────────────────────────────────────────────
const NATO = {
  info: {
    name: 'NATO Phonetic',
    category: 'encoding',
    description: 'Converts letters to NATO phonetic alphabet (Alpha, Bravo, Charlie...).',
    keyRequired: false,
  },
  TABLE: {
    A:'Alpha', B:'Bravo', C:'Charlie', D:'Delta', E:'Echo', F:'Foxtrot', G:'Golf', H:'Hotel',
    I:'India', J:'Juliet', K:'Kilo', L:'Lima', M:'Mike', N:'November', O:'Oscar', P:'Papa',
    Q:'Quebec', R:'Romeo', S:'Sierra', T:'Tango', U:'Uniform', V:'Victor', W:'Whiskey',
    X:'X-ray', Y:'Yankee', Z:'Zulu',
    '0':'Zero', '1':'One', '2':'Two', '3':'Three', '4':'Four', '5':'Five',
    '6':'Six', '7':'Seven', '8':'Eight', '9':'Nine'
  },
  encode(text) {
    return text.toUpperCase().split('').map(ch => this.TABLE[ch] || ch).join(' ');
  },
  decode(text) {
    const rev = {};
    for (const [k, v] of Object.entries(this.TABLE)) rev[v.toUpperCase()] = k;
    return text.split(/\s+/).map(w => rev[w.toUpperCase()] || w).join('');
  },
};


/* ============================================================
   MODERN / SYMMETRIC (Client-side via Web Crypto API)
   ============================================================ */

// ── XOR Cipher ────────────────────────────────────────────────
const XOR = {
  info: {
    name: 'XOR Cipher',
    category: 'modern',
    description: 'Bitwise XOR of each byte with the key (repeating). Self-inverse. Common in obfuscation and stream cipher building blocks.',
    keyRequired: true,
    keyType: 'text',
    keyLabel: 'Key (any string)',
    keyHint: 'Key repeats over plaintext',
  },
  encode(text, key) {
    if (!key) throw new Error('Key required');
    const textBytes = Utils.strToBytes(text);
    const keyBytes = Utils.strToBytes(key);
    const result = textBytes.map((b, i) => b ^ keyBytes[i % keyBytes.length]);
    return Utils.bytesToHex(result);
  },
  decode(hex, key) {
    if (!key) throw new Error('Key required');
    const bytes = Utils.hexToBytes(hex);
    const keyBytes = Utils.strToBytes(key);
    const result = bytes.map((b, i) => b ^ keyBytes[i % keyBytes.length]);
    return Utils.bytesToStr(result);
  },
};

// ── AES-GCM (Web Crypto) ──────────────────────────────────────
const AES_GCM = {
  info: {
    name: 'AES-256-GCM',
    category: 'modern',
    description: 'Advanced Encryption Standard with GCM (Galois/Counter Mode). Authenticated encryption. Key is derived from password via PBKDF2.',
    keyRequired: true,
    keyType: 'password',
    keyLabel: 'Password',
    keyHint: 'Any password; key is derived via PBKDF2-SHA256',
    async: true,
  },

  async deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async encode(text, password) {
    if (!password) throw new Error('Password required');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.deriveKey(password, salt);
    const data = new TextEncoder().encode(text);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
    combined.set(salt, 0);
    combined.set(iv, 16);
    combined.set(new Uint8Array(ciphertext), 28);
    return btoa(String.fromCharCode(...combined));
  },

  async decode(b64, password) {
    if (!password) throw new Error('Password required');
    try {
      const combined = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      const salt = combined.slice(0, 16);
      const iv = combined.slice(16, 28);
      const ciphertext = combined.slice(28);
      const key = await this.deriveKey(password, salt);
      const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
      return new TextDecoder().decode(plaintext);
    } catch {
      throw new Error('Decryption failed. Wrong password or corrupted data.');
    }
  },
};

// ── AES-CBC (Web Crypto) ──────────────────────────────────────
const AES_CBC = {
  info: {
    name: 'AES-256-CBC',
    category: 'modern',
    description: 'AES in CBC mode. Output format: Base64(salt[16] + iv[16] + ciphertext). Key derived via PBKDF2.',
    keyRequired: true,
    keyType: 'password',
    keyLabel: 'Password',
    keyHint: 'Any password; key derived via PBKDF2-SHA256',
    async: true,
  },

  async deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-CBC', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async encode(text, password) {
    if (!password) throw new Error('Password required');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const key = await this.deriveKey(password, salt);
    const data = new TextEncoder().encode(text);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, data);
    const combined = new Uint8Array(32 + ciphertext.byteLength);
    combined.set(salt); combined.set(iv, 16);
    combined.set(new Uint8Array(ciphertext), 32);
    return btoa(String.fromCharCode(...combined));
  },

  async decode(b64, password) {
    if (!password) throw new Error('Password required');
    try {
      const combined = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
      const salt = combined.slice(0, 16), iv = combined.slice(16, 32), ct = combined.slice(32);
      const key = await this.deriveKey(password, salt);
      const pt = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, ct);
      return new TextDecoder().decode(pt);
    } catch {
      throw new Error('Decryption failed. Wrong password or corrupted data.');
    }
  },
};


/* ============================================================
   HASH FUNCTIONS (one-way)
   ============================================================ */

const HashUtils = {
  async digest(algorithm, text) {
    const data = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest(algorithm, data);
    return Utils.bytesToHex(new Uint8Array(hashBuffer));
  },
};

const SHA1 = {
  info: { name: 'SHA-1', category: 'hash', description: 'Produces 160-bit (40 hex) digest. Cryptographically broken, avoid for security.', keyRequired: false, async: true },
  encode: (text) => HashUtils.digest('SHA-1', text),
  decode: () => { throw new Error('SHA-1 is a one-way hash function — it cannot be reversed.'); },
};

const SHA256 = {
  info: { name: 'SHA-256', category: 'hash', description: 'SHA-2 family. 256-bit secure hash. Standard for digital signatures and TLS.', keyRequired: false, async: true },
  encode: (text) => HashUtils.digest('SHA-256', text),
  decode: () => { throw new Error('SHA-256 is a one-way hash function — it cannot be reversed.'); },
};

const SHA384 = {
  info: { name: 'SHA-384', category: 'hash', description: 'SHA-2 family. 384-bit hash. More collision-resistant than SHA-256.', keyRequired: false, async: true },
  encode: (text) => HashUtils.digest('SHA-384', text),
  decode: () => { throw new Error('SHA-384 is a one-way hash function — it cannot be reversed.'); },
};

const SHA512 = {
  info: { name: 'SHA-512', category: 'hash', description: 'SHA-2 family. 512-bit hash. Strongest in SHA-2. Common in HMAC and key derivation.', keyRequired: false, async: true },
  encode: (text) => HashUtils.digest('SHA-512', text),
  decode: () => { throw new Error('SHA-512 is a one-way hash function — it cannot be reversed.'); },
};

// ── MD5 (pure JS, not in Web Crypto) ─────────────────────────
const MD5 = {
  info: { name: 'MD5', category: 'hash', description: 'Produces 128-bit (32 hex) digest. Cryptographically broken. Still used for checksums and legacy systems.', keyRequired: false },

  hash(str) {
    // Pure JS MD5 implementation
    function safeAdd(x, y) { const lsw = (x & 0xffff) + (y & 0xffff); return (((x >> 16) + (y >> 16) + (lsw >> 16)) << 16) | (lsw & 0xffff); }
    function bitRotateLeft(num, cnt) { return (num << cnt) | (num >>> (32 - cnt)); }
    function md5cmn(q, a, b, x, s, t) { return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b); }
    function md5ff(a,b,c,d,x,s,t){return md5cmn((b&c)|((~b)&d),a,b,x,s,t);}
    function md5gg(a,b,c,d,x,s,t){return md5cmn((b&d)|(c&(~d)),a,b,x,s,t);}
    function md5hh(a,b,c,d,x,s,t){return md5cmn(b^c^d,a,b,x,s,t);}
    function md5ii(a,b,c,d,x,s,t){return md5cmn(c^(b|(~d)),a,b,x,s,t);}

    const binaryStr = unescape(encodeURIComponent(str));
    const l = binaryStr.length;
    const words = [];
    for (let i = 0; i < l * 8; i += 8) words[i >> 5] |= (binaryStr.charCodeAt(i / 8) & 0xff) << (i % 32);
    words[l * 8 >> 5] |= 0x80 << l * 8 % 32;
    words[(((l + 8) >>> 6) << 4) + 14] = l * 8;

    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
    for (let i = 0; i < words.length; i += 16) {
      const [oa, ob, oc, od] = [a, b, c, d];
      a=md5ff(a,b,c,d,words[i+0],7,-680876936);d=md5ff(d,a,b,c,words[i+1],12,-389564586);
      c=md5ff(c,d,a,b,words[i+2],17,606105819);b=md5ff(b,c,d,a,words[i+3],22,-1044525330);
      a=md5ff(a,b,c,d,words[i+4],7,-176418897);d=md5ff(d,a,b,c,words[i+5],12,1200080426);
      c=md5ff(c,d,a,b,words[i+6],17,-1473231341);b=md5ff(b,c,d,a,words[i+7],22,-45705983);
      a=md5ff(a,b,c,d,words[i+8],7,1770035416);d=md5ff(d,a,b,c,words[i+9],12,-1958414417);
      c=md5ff(c,d,a,b,words[i+10],17,-42063);b=md5ff(b,c,d,a,words[i+11],22,-1990404162);
      a=md5ff(a,b,c,d,words[i+12],7,1804603682);d=md5ff(d,a,b,c,words[i+13],12,-40341101);
      c=md5ff(c,d,a,b,words[i+14],17,-1502002290);b=md5ff(b,c,d,a,words[i+15],22,1236535329);
      a=md5gg(a,b,c,d,words[i+1],5,-165796510);d=md5gg(d,a,b,c,words[i+6],9,-1069501632);
      c=md5gg(c,d,a,b,words[i+11],14,643717713);b=md5gg(b,c,d,a,words[i+0],20,-373897302);
      a=md5gg(a,b,c,d,words[i+5],5,-701558691);d=md5gg(d,a,b,c,words[i+10],9,38016083);
      c=md5gg(c,d,a,b,words[i+15],14,-660478335);b=md5gg(b,c,d,a,words[i+4],20,-405537848);
      a=md5gg(a,b,c,d,words[i+9],5,568446438);d=md5gg(d,a,b,c,words[i+14],9,-1019803690);
      c=md5gg(c,d,a,b,words[i+3],14,-187363961);b=md5gg(b,c,d,a,words[i+8],20,1163531501);
      a=md5gg(a,b,c,d,words[i+13],5,-1444681467);d=md5gg(d,a,b,c,words[i+2],9,-51403784);
      c=md5gg(c,d,a,b,words[i+7],14,1735328473);b=md5gg(b,c,d,a,words[i+12],20,-1926607734);
      a=md5hh(a,b,c,d,words[i+5],4,-378558);d=md5hh(d,a,b,c,words[i+8],11,-2022574463);
      c=md5hh(c,d,a,b,words[i+11],16,1839030562);b=md5hh(b,c,d,a,words[i+14],23,-35309556);
      a=md5hh(a,b,c,d,words[i+1],4,-1530992060);d=md5hh(d,a,b,c,words[i+4],11,1272893353);
      c=md5hh(c,d,a,b,words[i+7],16,-155497632);b=md5hh(b,c,d,a,words[i+10],23,-1094730640);
      a=md5hh(a,b,c,d,words[i+13],4,681279174);d=md5hh(d,a,b,c,words[i+0],11,-358537222);
      c=md5hh(c,d,a,b,words[i+3],16,-722521979);b=md5hh(b,c,d,a,words[i+6],23,76029189);
      a=md5hh(a,b,c,d,words[i+9],4,-640364487);d=md5hh(d,a,b,c,words[i+12],11,-421815835);
      c=md5hh(c,d,a,b,words[i+15],16,530742520);b=md5hh(b,c,d,a,words[i+2],23,-995338651);
      a=md5ii(a,b,c,d,words[i+0],6,-198630844);d=md5ii(d,a,b,c,words[i+7],10,1126891415);
      c=md5ii(c,d,a,b,words[i+14],15,-1416354905);b=md5ii(b,c,d,a,words[i+5],21,-57434055);
      a=md5ii(a,b,c,d,words[i+12],6,1700485571);d=md5ii(d,a,b,c,words[i+3],10,-1894986606);
      c=md5ii(c,d,a,b,words[i+10],15,-1051523);b=md5ii(b,c,d,a,words[i+1],21,-2054922799);
      a=md5ii(a,b,c,d,words[i+8],6,1873313359);d=md5ii(d,a,b,c,words[i+15],10,-30611744);
      c=md5ii(c,d,a,b,words[i+6],15,-1560198380);b=md5ii(b,c,d,a,words[i+13],21,1309151649);
      a=md5ii(a,b,c,d,words[i+4],6,-145523070);d=md5ii(d,a,b,c,words[i+11],10,-1120210379);
      c=md5ii(c,d,a,b,words[i+2],15,718787259);b=md5ii(b,c,d,a,words[i+9],21,-343485551);
      a=safeAdd(a,oa);b=safeAdd(b,ob);c=safeAdd(c,oc);d=safeAdd(d,od);
    }
    return [a,b,c,d].map(n => {
      let s = '';
      for (let j = 0; j < 4; j++) s += ('0' + ((n >> (j*8)) & 0xff).toString(16)).slice(-2);
      return s;
    }).join('');
  },

  encode(text) { return this.hash(text); },
  decode() { throw new Error('MD5 is a one-way hash function — it cannot be reversed.'); },
};

// ── CRC32 ─────────────────────────────────────────────────────
const CRC32 = {
  info: { name: 'CRC-32', category: 'hash', description: 'Cyclic Redundancy Check, 32-bit. Used for error detection in files and network protocols.', keyRequired: false },

  table: (() => {
    const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
      t[n] = c;
    }
    return t;
  })(),

  encode(text) {
    const bytes = Utils.strToBytes(text);
    let crc = 0xffffffff;
    for (const b of bytes) crc = (crc >>> 8) ^ this.table[(crc ^ b) & 0xff];
    return ((crc ^ 0xffffffff) >>> 0).toString(16).padStart(8, '0');
  },
  decode() { throw new Error('CRC-32 is a checksum — it cannot be reversed.'); },
};


/* ============================================================
   AUTO-DETECT ENGINE
   ============================================================ */

const AutoDetect = {
  /** Heuristic scoring for each cipher type */
  analyze(text) {
    const candidates = [];
    const t = text.trim();

    // Base64
    if (/^[A-Za-z0-9+/]+=*$/.test(t) && t.length % 4 === 0) {
      candidates.push({ id: 'base64', name: 'Base64', confidence: 90 });
    }

    // Base64 URL
    if (/^[A-Za-z0-9\-_]+=*$/.test(t)) {
      candidates.push({ id: 'base64url', name: 'Base64 URL-safe', confidence: 75 });
    }

    // Hex
    if (/^[0-9a-fA-F\s]+$/.test(t) && t.replace(/\s/g,'').length % 2 === 0) {
      candidates.push({ id: 'hex', name: 'Hexadecimal', confidence: 85 });
    }

    // Binary
    if (/^[01\s]+$/.test(t) && t.replace(/\s/g,'').length % 8 === 0) {
      candidates.push({ id: 'binary', name: 'Binary', confidence: 88 });
    }

    // Morse
    if (/^[.\-/ ]+$/.test(t)) {
      candidates.push({ id: 'morse', name: 'Morse Code', confidence: 92 });
    }

    // URL encoded
    if (/%[0-9A-Fa-f]{2}/.test(t)) {
      candidates.push({ id: 'url', name: 'URL Encoding', confidence: 95 });
    }

    // HTML entities
    if (/&[a-zA-Z#][^;]+;/.test(t)) {
      candidates.push({ id: 'html', name: 'HTML Entities', confidence: 95 });
    }

    // Unicode escape
    if (/\\u[0-9a-fA-F]{4}/.test(t)) {
      candidates.push({ id: 'unicode', name: 'Unicode Escape', confidence: 95 });
    }

    // ROT13 heuristic: all alpha, looks like words but scrambled
    if (/^[A-Za-z\s.,!?]+$/.test(t) && t.length > 5) {
      candidates.push({ id: 'rot13', name: 'ROT13', confidence: 40 });
      candidates.push({ id: 'caesar', name: 'Caesar Cipher', confidence: 35 });
    }

    // Base32
    if (/^[A-Z2-7]+=*$/.test(t) && t.length % 8 === 0) {
      candidates.push({ id: 'base32', name: 'Base32', confidence: 80 });
    }

    // MD5 hash (32 hex)
    if (/^[0-9a-f]{32}$/i.test(t)) {
      candidates.push({ id: 'md5', name: 'MD5 Hash', confidence: 97 });
    }

    // SHA-1 (40 hex)
    if (/^[0-9a-f]{40}$/i.test(t)) {
      candidates.push({ id: 'sha1', name: 'SHA-1 Hash', confidence: 97 });
    }

    // SHA-256 (64 hex)
    if (/^[0-9a-f]{64}$/i.test(t)) {
      candidates.push({ id: 'sha256', name: 'SHA-256 Hash', confidence: 97 });
    }

    // SHA-512 (128 hex)
    if (/^[0-9a-f]{128}$/i.test(t)) {
      candidates.push({ id: 'sha512', name: 'SHA-512 Hash', confidence: 97 });
    }

    return candidates.sort((a, b) => b.confidence - a.confidence).slice(0, 5);
  },

  /** Text entropy (Shannon) - higher = more random = likely encrypted */
  entropy(text) {
    const freq = {};
    for (const ch of text) freq[ch] = (freq[ch] || 0) + 1;
    const n = text.length;
    return -Object.values(freq).reduce((sum, f) => {
      const p = f / n;
      return sum + p * Math.log2(p);
    }, 0);
  },

  /** Basic stats */
  stats(text) {
    const chars = text.length;
    const words = text.trim().split(/\s+/).filter(Boolean).length;
    const lines = text.split('\n').length;
    const unique = new Set(text).size;
    const entropy = this.entropy(text).toFixed(3);
    return { chars, words, lines, unique, entropy };
  },
};


/* ============================================================
   ALGORITHM REGISTRY
   Exported as window.ALGOS for use by ui.js
   ============================================================ */

window.ALGOS = {
  caesar:       Caesar,
  rot13:        ROT13,
  rot47:        ROT47,
  atbash:       Atbash,
  vigenere:     Vigenere,
  beaufort:     Beaufort,
  playfair:     Playfair,
  affine:       Affine,
  railfence:    RailFence,
  columnar:     Columnar,
  substitution: Substitution,
  base64:       Base64,
  base64url:    Base64URL,
  base32:       Base32,
  base58:       Base58,
  hex:          HexEncode,
  binary:       BinaryEncode,
  octal:        OctalEncode,
  url:          URLEncode,
  html:         HTMLEntities,
  unicode:      UnicodeEscape,
  morse:        Morse,
  nato:         NATO,
  xor:          XOR,
  'aes-gcm':    AES_GCM,
  'aes-cbc':    AES_CBC,
  sha1:         SHA1,
  sha256:       SHA256,
  sha384:       SHA384,
  sha512:       SHA512,
  md5:          MD5,
  crc32:        CRC32,
};

window.AutoDetect = AutoDetect;
window.Utils = Utils;

/*
 * ============================================================
 * CONTRIBUTING — Adding New Algorithms
 * ============================================================
 * 1. Create your algorithm object with:
 *    - info: { name, category, description, keyRequired, keyType?, keyLabel?, keyHint?, async? }
 *    - encode(text, key?) → string | Promise<string>
 *    - decode(text, key?) → string | Promise<string>
 *
 * 2. Register it in the ALGOS map above with a unique slug key.
 *
 * 3. Categories: 'classic' | 'encoding' | 'modern' | 'hash'
 *
 * 4. Async algorithms: set info.async = true and return Promises.
 *    The UI handles async transparently.
 *
 * 5. Hash-only algorithms: decode() should throw a descriptive error.
 * ============================================================
 */
