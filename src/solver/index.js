const Detection = {
  patterns: {
    base16: /^[0-9a-fA-F]+$/,
    base32: /^[A-Z2-7]+=*$/i,
    base64: /^[A-Za-z0-9+\/]+=*$/,
    base58: /^[A-HJ-NP-Za-km-z1-9]+$/,
  },
  hashes: {
    md5: /^[a-f0-9]{32}$/i,
    sha1: /^[a-f0-9]{40}$/i,
    sha256: /^[a-f0-9]{64}$/i,
    sha512: /^[a-f0-9]{128}$/i,
  }
};

class CryptoSolver {
  constructor(opts={}) {
    this.timeout = opts.timeout || 30000;
    this.debug = opts.debug || false;
  }

  detect(input) {
    const results = [];
    const text = String(input).replace(/\s/g, "");
    
    for (const [enc, pattern] of Object.entries(Detection.patterns)) {
      if (pattern.test(text)) results.push({type:"encoding", subtype:enc, confidence:0.9});
    }
    for (const [algo, pattern] of Object.entries(Detection.hashes)) {
      if (pattern.test(text)) results.push({type:"hash", subtype:algo, confidence:0.95});
    }
    if (/^\d{50,}$/.test(text)) results.push({type:"rsa", subtype:"large_int", confidence:0.85});
    if (/^[01\s]{8,}$/.test(text)) results.push({type:"binary", confidence:0.8});
    
    return results.sort((a,b)=>b.confidence-a.confidence);
  }

  solve(ciphertext, options={}) {
    const detections = this.detect(ciphertext);
    const results = [];
    
    for (const d of detections) {
      if (d.type === "encoding") results.push(...this.decodeAll(ciphertext, d.subtype));
      if (d.type === "hash") results.push({type:"hash_check", algo:d.subtype, value:ciphertext});
    }
    
    return {detections, results};
  }

  decodeAll(text, fromEncoding) {
    const results = [];
    const encodings = ["base64","base32","hex","base16","base58","ascii85","base85"];
    for (const enc of encodings) {
      try {
        const decoded = Buffer.from(text, enc).toString("utf8");
        if (/^[\x20-\x7E]+$/.test(decoded)) {
          results.push({from:enc, to:"utf8", result:decoded});
        }
      } catch(e) {}
    }
    return results;
  }
}

module.exports = {CryptoSolver};