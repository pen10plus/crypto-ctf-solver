function caesarSolve(text, shift) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz';
  const results = [];
  
  if (/^\d+$/.test(text)) {
    const decoded = text.split(/\d+/).slice(1).map(n => {
      const idx = (parseInt(n) - 1) % 26;
      return alphabet[idx] || '';
    }).join('');
    results.push({ text: decoded, method: 'numeric' });
  }
  
  const maxShift = shift !== null ? shift + 1 : 26;
  const minShift = shift !== null ? shift : 0;
  
  for (let s = minShift; s < maxShift; s++) {
    const shifted = text.toLowerCase().split('').map(c => {
      const idx = alphabet.indexOf(c);
      return idx >= 0 ? alphabet[(idx - s + 26) % 26] : c;
    }).join('');
    results.push({ text: shifted, shift: s, method: 'caesar' });
  }
  
  return results;
}

function vigenereSolve(text, key) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz';
  const results = [];
  const cleanText = text.toLowerCase().replace(/[^a-z]/g, '');
  
  function kasiski(text) {
    const ngrams = {};
    for (let i = 0; i < text.length - 3; i++) {
      const ngram = text.slice(i, i + 4);
      ngrams[ngram] = ngrams[ngram] || [];
      ngrams[ngram].push(i);
    }
    const distances = [];
    for (const ngram of Object.values(ngrams)) {
      if (ngram.length > 1) {
        for (let i = 1; i < ngram.length; i++) {
          distances.push(ngram[i] - ngram[i-1]);
        }
      }
    }
    if (distances.length === 0) return 3;
    const gcd = (a, b) => b === 0 ? a : gcd(b, a % b);
    return distances.reduce(gcd);
  }
  
  const keyLen = key ? key.length : kasiski(cleanText);
  const commonKeys = key ? [key] : ['the', 'and', 'for', 'key', 'flag', 'secret'];
  
  for (const k of commonKeys) {
    const expanded = k.repeat(Math.ceil(cleanText.length / k.length));
    const decrypted = cleanText.split('').map((c, i) => {
      const tIdx = alphabet.indexOf(c);
      const kIdx = alphabet.indexOf(expanded[i]);
      return tIdx >= 0 ? alphabet[(tIdx - kIdx + 26) % 26] : c;
    }).join('');
    results.push({ text: decrypted, key: k, method: 'vigenere' });
  }
  
  return results;
}

function railfenceSolve(text, rails) {
  const results = [];
  const maxRails = rails ? rails + 1 : 10;
  const minRails = rails ? rails : 2;
  
  for (let r = minRails; r < maxRails; r++) {
    const fence = Array(r).fill().map(() => []);
    let dir = 1, row = 0;
    
    for (const char of text.toLowerCase()) {
      fence[row].push(char);
      row += dir;
      if (row === 0 || row === r - 1) dir *= -1;
    }
    
    const decrypted = fence.flat().join('');
    results.push({ text: decrypted, rails: r, method: 'railfence' });
  }
  
  return results;
}

function baconianSolve(text) {
  const alphabet = 'ABCDEFGHIZKLMNOPQRSTUZWYX';
  const A = 'AAAAA', B = 'AAAAB';
  const results = [];
  const cleaned = text.toUpperCase().replace(/[^AB]/g, '');
  
  if (cleaned.length % 5 !== 0) return [];
  
  let decoded = '';
  for (let i = 0; i < cleaned.length; i += 5) {
    const chunk = cleaned.slice(i, i + 5);
    let idx = alphabet.indexOf(chunk[0]);
    if (chunk === B) idx = 1;
    if (idx >= 0 && idx < 26) decoded += alphabet[idx];
  }
  
  results.push({ text: decoded, method: 'baconian' });
  return results;
}

function atbashSolve(text) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz';
  const reversed = alphabet.split('').reverse().join('');
  const result = text.toLowerCase().split('').map(c => {
    const idx = alphabet.indexOf(c);
    return idx >= 0 ? reversed[idx] : c;
  }).join('');
  return [{ text: result, method: 'atbash' }];
}

module.exports = { caesarSolve, vigenereSolve, railfenceSolve, baconianSolve, atbashSolve, solve: caesarSolve };
