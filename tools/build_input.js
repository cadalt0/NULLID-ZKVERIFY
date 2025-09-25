// Build input.json for eml_receiver.circom
// Usage: node tools/build_input.js /path/to/email.eml

const fs = require('fs');
const circomlibjs = require('circomlibjs');

const MAX = 8192; // must match main template size in circuit

function pack31LE(bytes) {
  let acc = 0n, mul = 1n;
  for (let i = 0; i < 31; i++) {
    const b = BigInt(bytes[i] || 0);
    acc += b * mul;
    mul *= 256n;
  }
  return acc;
}

function strBytesAscii(s) {
  return Array.from(Buffer.from(s, 'ascii'));
}

function oneHot(length, pos) {
  const arr = new Array(length).fill(0);
  if (pos >= 0 && pos < length) arr[pos] = 1;
  return arr;
}

(async () => {
  const emlPath = process.argv[2];
  if (!emlPath) {
    console.error('usage: node tools/build_input.js /path/to/email.eml');
    process.exit(1);
  }

  const raw = fs.readFileSync(emlPath);
  const eml = Array.from(raw.slice(0, MAX));
  while (eml.length < MAX) eml.push(0);

  const buf = Buffer.from(eml);
  // Literals required by current circuit: From:, To:, and @gmail.com
  const fromStr = 'From:';
  const toStr = 'To:';
  const atgStr = '@gmail.com';
  const idx_from = buf.indexOf(Buffer.from(fromStr, 'ascii'));
  const idx_to = buf.indexOf(Buffer.from(toStr, 'ascii'));
  const idx_atg = buf.indexOf(Buffer.from(atgStr, 'ascii'));
  if (idx_from < 0 || idx_to < 0 || idx_atg < 0) {
    console.error('Required literals not found in .eml (need From:, To:, and @gmail.com)');
    process.exit(2);
  }

  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;
  let h = 0n;
  for (let off = 0; off < MAX; off += 31) {
    const chunk = pack31LE(eml.slice(off, off + 31));
    const out = poseidon([F.e(h), F.e(chunk)]);
    h = BigInt(F.toString(out));
  }

  const input = {
    eml_commitment: h.toString(),
    eml: eml.map(n => n.toString()),
    from_bytes: strBytesAscii(fromStr).map(n => n.toString()),
    to_bytes: strBytesAscii(toStr).map(n => n.toString()),
    atg_bytes: strBytesAscii(atgStr).map(n => n.toString()),
    sel_from: oneHot(MAX, idx_from).map(n => n.toString()),
    sel_to: oneHot(MAX, idx_to).map(n => n.toString()),
    sel_atg: oneHot(MAX, idx_atg).map(n => n.toString())
  };

  fs.writeFileSync('input.json', JSON.stringify(input));
  console.log('input.json written');
})().catch(err => {
  console.error(err);
  process.exit(3);
});


