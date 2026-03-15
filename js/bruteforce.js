/**
 * UMBRA - Brute Force Engine + Image Analysis
 * js/bruteforce.js v2.0.0
 *
 * BruteForce: tries ALL supported algorithms on any input
 *   and scores results by "readability" heuristics (English IC,
 *   dictionary word density, printable ratio, entropy).
 *
 * ImageAnalysis: OCR via Tesseract.js CDN, then passes
 *   extracted text through the full auto-detect + brute-force
 *   pipeline.
 */

'use strict';

/* ============================================================
   ENGLISH LANGUAGE SCORING
   ============================================================ */
const Scorer = {
  // English letter frequencies
  EN_FREQ: {
    a:0.082,b:0.015,c:0.028,d:0.043,e:0.127,f:0.022,g:0.020,h:0.061,i:0.070,j:0.002,
    k:0.008,l:0.040,m:0.024,n:0.067,o:0.075,p:0.019,q:0.001,r:0.060,s:0.063,t:0.091,
    u:0.028,v:0.010,w:0.023,x:0.002,y:0.020,z:0.001
  },

  // Common English words (short set for fast scoring)
  COMMON_WORDS: new Set([
    'the','be','to','of','and','a','in','that','have','it','for','not','on','with','he',
    'as','you','do','at','this','but','his','by','from','they','we','say','her','she','or',
    'an','will','my','one','all','would','there','their','what','so','up','out','if','about',
    'who','get','which','go','me','when','make','can','like','time','no','just','him','know',
    'take','people','into','year','your','good','some','could','them','see','other','than',
    'then','now','look','only','come','its','over','think','also','back','after','use','two',
    'how','our','work','first','well','way','even','new','want','because','any','these','give',
    'day','most','us','is','was','are','were','has','had','been','said','hello','world','key',
    'flag','secret','password','cipher','decode','message','text'
  ]),

  /**
   * Score 0-100 how likely a string is human-readable English/text.
   * Higher = more likely to be the correct decryption.
   */
  score(text) {
    if (!text || text.length < 2) return 0;

    const lower = text.toLowerCase();
    const chars = lower.split('');
    const n = chars.length;

    // 1. Printable ratio (non-printable chars tank the score)
    const printable = chars.filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) < 127).length;
    const printRatio = printable / n;
    if (printRatio < 0.7) return Math.round(printRatio * 10);

    // 2. Letter frequency correlation (Index of Coincidence)
    const freq = {};
    let letterCount = 0;
    for (const c of lower) {
      if (c >= 'a' && c <= 'z') { freq[c] = (freq[c] || 0) + 1; letterCount++; }
    }
    if (letterCount === 0) return Math.round(printRatio * 20);

    // Chi-squared against English frequencies
    let chi = 0;
    for (const [ch, expected] of Object.entries(this.EN_FREQ)) {
      const observed = (freq[ch] || 0) / letterCount;
      chi += Math.pow(observed - expected, 2) / expected;
    }
    // Lower chi = more English-like. Map to 0-50 score.
    const freqScore = Math.max(0, 50 - chi * 80);

    // 3. Word density
    const words = lower.split(/[\s\W]+/).filter(w => w.length >= 2);
    let dictHits = 0;
    for (const w of words) { if (this.COMMON_WORDS.has(w)) dictHits++; }
    const wordScore = words.length > 0
      ? Math.min(40, (dictHits / words.length) * 80)
      : 0;

    // 4. Space ratio (English text ~15-20% spaces)
    const spaces = (text.match(/\s/g) || []).length;
    const spaceRatio = spaces / n;
    const spaceScore = (spaceRatio > 0.05 && spaceRatio < 0.35) ? 10 : 0;

    const total = freqScore + wordScore + spaceScore;
    return Math.min(100, Math.round(total * printRatio));
  },

  grade(score) {
    if (score >= 60) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
  },
};


/* ============================================================
   BRUTE FORCE ENGINE
   ============================================================ */
const BruteForce = {

  /**
   * Run every applicable algorithm (no-key ones + common keys)
   * on `input` and return sorted results.
   * @param {string} input
   * @param {function} onProgress  (pct 0-100, label)
   * @returns {Promise<Array>} sorted by score desc
   */
  async run(input, onProgress = () => {}) {
    const results = [];
    const algos = window.ALGOS;
    const tasks = this._buildTaskList(input);
    let done = 0;

    for (const task of tasks) {
      done++;
      onProgress(Math.round((done / tasks.length) * 100), task.label);

      try {
        const algo = algos[task.algoId];
        if (!algo) continue;

        let result;
        if (algo.info.async) {
          result = await algo.decode(input, task.key);
        } else {
          result = algo.decode(input, task.key);
        }

        const score = Scorer.score(result);
        results.push({
          algoId:   task.algoId,
          algoName: algo.info.name,
          key:      task.key,
          keyLabel: task.keyLabel,
          result,
          score,
          grade:    Scorer.grade(score),
        });
      } catch (_) {
        // Skip failed decodings silently
      }
    }

    // Sort by score descending
    results.sort((a, b) => b.score - a.score);
    return results;
  },

  /**
   * Build the list of (algoId, key) tasks to try.
   * No-key algos run once. Key algos run with a set of common/likely keys.
   */
  _buildTaskList(input) {
    const tasks = [];

    // No-key decodings
    const noKeyAlgos = [
      'base64','base64url','base32','base58','hex','binary','octal',
      'url','html','unicode','morse','nato','rot13','rot47','atbash',
    ];
    for (const id of noKeyAlgos) {
      tasks.push({ algoId: id, key: '', label: id, keyLabel: '' });
    }

    // Caesar: all 26 shifts
    for (let s = 0; s < 26; s++) {
      tasks.push({ algoId: 'caesar', key: String(s), label: `caesar-${s}`, keyLabel: `shift ${s}` });
    }

    // Vigenère: common short keys
    const vigenereKeys = [
      'key','secret','password','cipher','crypto','umbra','flag','hack',
      'admin','love','hello','world','abc','abcd','test','code','pass',
      'alpha','delta','omega','sigma','matrix','shadow','ghost','dark',
    ];
    for (const k of vigenereKeys) {
      tasks.push({ algoId: 'vigenere', key: k, label: `vigenere-${k}`, keyLabel: `key:"${k}"` });
    }

    // Affine: common (a,b) pairs
    const validA = [1,3,5,7,9,11,15,17,19,21,23,25];
    for (const a of validA) {
      for (const b of [0,1,3,5,7,13]) {
        tasks.push({ algoId: 'affine', key: `${a},${b}`, label: `affine-${a},${b}`, keyLabel: `(${a},${b})` });
      }
    }

    // Rail fence: 2-10 rails
    for (let r = 2; r <= 10; r++) {
      tasks.push({ algoId: 'railfence', key: String(r), label: `railfence-${r}`, keyLabel: `${r} rails` });
    }

    // XOR: common single-char XOR keys
    for (let i = 1; i < 128; i++) {
      const hexInput = /^[0-9a-fA-F\s]+$/.test(input) && input.replace(/\s/g,'').length % 2 === 0;
      if (hexInput) {
        tasks.push({ algoId: 'xor', key: String.fromCharCode(i), label: `xor-${i}`, keyLabel: `key 0x${i.toString(16).padStart(2,'0')}` });
      }
    }

    return tasks;
  },
};


/* ============================================================
   IMAGE ANALYSIS MODULE
   ============================================================ */
const ImageAnalysis = {
  tesseractLoaded: false,
  tesseractWorker: null,

  /**
   * Load Tesseract.js from CDN (lazy)
   */
  async loadTesseract() {
    if (this.tesseractLoaded) return;
    return new Promise((resolve, reject) => {
      if (window.Tesseract) { this.tesseractLoaded = true; resolve(); return; }
      const script = document.createElement('script');
      script.src = 'https://unpkg.com/tesseract.js@5/dist/tesseract.min.js';
      script.onload = () => { this.tesseractLoaded = true; resolve(); };
      script.onerror = () => reject(new Error('Failed to load Tesseract.js OCR engine'));
      document.head.appendChild(script);
    });
  },

  /**
   * Perform OCR on an image file/dataURL.
   * Returns the extracted text.
   * @param {File|string} imageSource  File object or data URL
   * @param {function} onProgress  (pct, status)
   */
  async extractText(imageSource, onProgress = () => {}) {
    await this.loadTesseract();
    onProgress(5, 'Initializing OCR engine...');

    const { createWorker } = window.Tesseract;
    const worker = await createWorker('eng', 1, {
      logger: m => {
        if (m.status === 'recognizing text') {
          onProgress(20 + Math.round(m.progress * 60), 'Recognizing text...');
        }
      }
    });

    onProgress(15, 'Loading language data...');
    const { data } = await worker.recognize(imageSource);
    await worker.terminate();

    onProgress(85, 'Analyzing extracted text...');
    return data.text.trim();
  },

  /**
   * Analyze an image: OCR → auto-detect → brute-force
   * Returns { rawText, detections, bruteResults }
   */
  async analyze(imageSource, onProgress = () => {}) {
    const rawText = await this.extractText(imageSource, onProgress);
    if (!rawText) return { rawText: '', detections: [], bruteResults: [] };

    onProgress(88, 'Running cipher detection...');
    const detections = window.AutoDetect.analyze(rawText);

    onProgress(92, 'Attempting decryption...');
    const quickTasks = this._quickTasksFromDetections(rawText, detections);
    const bruteResults = [];

    for (const task of quickTasks) {
      const algo = window.ALGOS[task.algoId];
      if (!algo) continue;
      try {
        const result = algo.info.async
          ? await algo.decode(rawText, task.key)
          : algo.decode(rawText, task.key);
        const score = Scorer.score(result);
        bruteResults.push({
          algoId: task.algoId,
          algoName: algo.info.name,
          key: task.key,
          result,
          score,
          grade: Scorer.grade(score),
          howTo: this._howToDecrypt(task.algoId, task.key),
        });
      } catch (_) {}
    }

    bruteResults.sort((a, b) => b.score - a.score);
    onProgress(100, 'Done');
    return { rawText, detections, bruteResults: bruteResults.slice(0, 8) };
  },

  _quickTasksFromDetections(text, detections) {
    const tasks = [];
    // Add top detected types
    for (const d of detections) {
      tasks.push({ algoId: d.id, key: '' });
    }
    // Also try Caesar all shifts and ROT13/47 always
    tasks.push({ algoId: 'rot13', key: '' });
    tasks.push({ algoId: 'rot47', key: '' });
    tasks.push({ algoId: 'atbash', key: '' });
    for (let s = 0; s < 26; s++) tasks.push({ algoId: 'caesar', key: String(s) });
    return tasks;
  },

  _howToDecrypt(algoId, key) {
    const algo = window.ALGOS[algoId];
    if (!algo) return '';
    const name = algo.info.name;
    const guides = {
      base64:    'Decode with Base64. Tooling: Python `base64.b64decode()`, CyberChef, or this tool.',
      base64url: 'Decode with URL-safe Base64 (replace - with +, _ with /).',
      base32:    'Decode with Base32. Python: `base64.b32decode()`.',
      hex:       'Convert hex pairs to ASCII bytes. Python: `bytes.fromhex(text)`.',
      binary:    'Convert 8-bit groups from binary to ASCII.',
      octal:     'Convert octal groups to ASCII bytes.',
      url:       'URL-decode percent-encoded characters.',
      html:      'Decode HTML entities (&amp; → &, &lt; → <).',
      unicode:   'Replace \\uXXXX escape sequences with the actual Unicode characters.',
      morse:     'Decode Morse Code: . = dot, - = dash, space = letter sep, / = word sep.',
      rot13:     'Apply ROT13: each letter rotated 13 positions. Self-inverse.',
      rot47:     'Apply ROT47: all printable ASCII rotated by 47. Self-inverse.',
      atbash:    'Apply Atbash: each letter mapped to its reverse (A↔Z).',
      nato:      'Reverse NATO phonetic alphabet back to letters.',
      caesar:    `Apply Caesar cipher with shift=${key}. Rotate each letter back by ${key}.`,
      vigenere:  `Apply Vigenère with key="${key}". Use the key to reverse each shift.`,
      affine:    `Apply Affine inverse: C = a⁻¹(P - b) mod 26 with key=(${key}).`,
      railfence: `Read the Rail Fence pattern with ${key} rails.`,
      xor:       `XOR each byte with key byte 0x${key ? key.charCodeAt(0).toString(16).padStart(2,'0') : '??'}.`,
      sha256:    'This is a SHA-256 hash. It cannot be reversed — only verified by hashing a known value.',
      sha512:    'This is a SHA-512 hash. Hashes are one-way — compare against known hashes.',
      md5:       'This is an MD5 hash. Try rainbow tables (CrackStation) for common passwords.',
      sha1:      'This is a SHA-1 hash. Compare against known values or use rainbow tables.',
    };
    return guides[algoId] || `Use ${name} decryption.`;
  },
};

// Export globals
window.BruteForce = BruteForce;
window.ImageAnalysis = ImageAnalysis;
window.Scorer = Scorer;
