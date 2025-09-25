// Offchain Circom circuit to attest that an .eml contains:
//   - "Authentication-Results:" and
//   - "receiver=gmail.com"
// anywhere in the byte buffer.
//
// What it proves (offchain):
// - Poseidon commitment of the padded .eml bytes equals a public input.
// - There exists a position where the literal "Authentication-Results:" occurs.
// - There exists a position where the literal "receiver=gmail.com" occurs.
//
// Important: This is content attestation only (no claim of real delivery).
//
// Public input:
//   - eml_commitment: rolling Poseidon over fixed-size buffer (padding with zeros)
// Private input (witness):
//   - eml[MAX_EML_LEN]: raw .eml bytes, padded with zeros to MAX_EML_LEN
//
// Hash definition (fixed-size rolling Poseidon):
//   h_0 = 0; For each 31-byte chunk c_i (little-endian packed): h_{i+1} = Poseidon2(h_i, c_i);
//   eml_commitment = h_last over all chunks (including zero-padded tail).

pragma circom 2.1.6;

include "poseidon.circom";
include "bitify.circom";

template Bits1() {
	signal input in;
	signal output out;
	out <== in;
	out * (out - 1) === 0;
}

template ByteIsUint8() {
	signal input b; // expect 0..255
	signal output ok;
	component n2b = Num2Bits(8);
	n2b.in <== b;
	ok <== 1;
}

template Pack31BytesLittleEndian() {
	// Packs up to 31 bytes (b[0] is least significant) into a single field element
	signal input bytes[31];
	signal output out;

	// Enforce all inputs are bytes
	component isByte[31];
	for (var i = 0; i < 31; i++) {
		isByte[i] = ByteIsUint8();
		isByte[i].b <== bytes[i];
	}

	var accCalc = 0;
	var mulCalc = 1;
	for (var j = 0; j < 31; j++) {
		accCalc += bytes[j] * mulCalc;
		mulCalc = mulCalc * 256;
	}
	out <== accCalc;
}

template RollingPoseidon(maxLen, numChunks) {
	// Hash eml[0:eml_len] in 31-byte chunks using Poseidon(2)
	signal input eml[maxLen];
	signal output commitment;

	// Build chunks
	component packers[numChunks];
	for (var c = 0; c < numChunks; c++) {
		packers[c] = Pack31BytesLittleEndian();
		// feed 31 bytes
		for (var k = 0; k < 31; k++) {
			var idx = c * 31 + k;
			if (idx < maxLen) {
				packers[c].bytes[k] <== eml[idx];
			} else {
				packers[c].bytes[k] <== 0;
			}
		}
	}

	// Rolling hash: h = 0; for each chunk: h = Poseidon(h, chunk)
	component H[numChunks];
	for (var i2 = 0; i2 < numChunks; i2++) {
		H[i2] = Poseidon(2);
		H[i2].inputs[0] <== (i2 == 0 ? 0 : H[i2-1].out);
		H[i2].inputs[1] <== packers[i2].out;
	}
	commitment <== H[numChunks - 1].out;
}

template LiteralAtIndex(MAX_EML_LEN, LIT_LEN) {
	// Quadratic-safe check using a one-hot selector vector over positions.
	// Prover supplies sel[0..MAX_EML_LEN-1] with exactly one '1' within the valid window [0..MAX_EML_LEN-LIT_LEN]
	// For each byte offset i in the literal, enforce sum_t sel[t]*(eml[t+i] - lit[i]) == 0
	signal input eml[MAX_EML_LEN];
	signal input lit[LIT_LEN];
	signal input sel[MAX_EML_LEN];
	signal output ok;

	var POSITIONS = MAX_EML_LEN - LIT_LEN + 1;

	// Enforce sel is boolean and one-hot within the valid window; and zero outside
	var sumSel = 0;
	for (var t = 0; t < POSITIONS; t++) {
		// boolean
		sel[t] * (sel[t] - 1) === 0;
		sumSel += sel[t];
	}
	sumSel === 1;
	for (var u = POSITIONS; u < MAX_EML_LEN; u++) {
		// must be zero outside window
		sel[u] === 0;
	}

	// Literal match via dot-products
	for (var i = 0; i < LIT_LEN; i++) {
		for (var t2 = 0; t2 < POSITIONS; t2++) {
			// Enforce individually: sel[t2] * (eml[t2+i] - lit[i]) == 0
			// This keeps each constraint quadratic
			sel[t2] * (eml[t2 + i] - lit[i]) === 0;
		}
	}

	ok <== 1;
}

template EmlHasHeadersSimple(MAX_EML_LEN) {
	// Public
	signal input eml_commitment;
	// Private
	signal input eml[MAX_EML_LEN];
	signal input from_bytes[5]; // "From:" bytes
	signal input to_bytes[3];   // "To:" bytes
	signal input atg_bytes[10]; // "@gmail.com" bytes
	signal input sel_from[MAX_EML_LEN];
	signal input sel_to[MAX_EML_LEN];
	signal input sel_atg[MAX_EML_LEN];

	// 1) Hash commitment
	// With MAX_EML_LEN=8192, NUM_CHUNKS = ceil(8192/31) = 265
	component RH = RollingPoseidon(MAX_EML_LEN, 265);
	for (var i = 0; i < MAX_EML_LEN; i++) {
		RH.eml[i] <== eml[i];
	}
	RH.commitment === eml_commitment;

	// 2) Literal at index: "From:" (5 bytes)
	component HAS_FROM = LiteralAtIndex(MAX_EML_LEN, 5);
	for (var e1 = 0; e1 < MAX_EML_LEN; e1++) {
		HAS_FROM.eml[e1] <== eml[e1];
	}
	for (var a = 0; a < 5; a++) {
		HAS_FROM.lit[a] <== from_bytes[a];
	}
	for (var sf = 0; sf < MAX_EML_LEN; sf++) {
		HAS_FROM.sel[sf] <== sel_from[sf];
	}
	HAS_FROM.ok === 1;

	// 3) Literal at index: "To:" (3 bytes)
	component HAS_TO = LiteralAtIndex(MAX_EML_LEN, 3);
	for (var e2 = 0; e2 < MAX_EML_LEN; e2++) {
		HAS_TO.eml[e2] <== eml[e2];
	}
	for (var t = 0; t < 3; t++) {
		HAS_TO.lit[t] <== to_bytes[t];
	}
	for (var st = 0; st < MAX_EML_LEN; st++) {
		HAS_TO.sel[st] <== sel_to[st];
	}
	HAS_TO.ok === 1;

	// 4) Literal at index: "@gmail.com" (10 bytes)
	component HAS_ATG = LiteralAtIndex(MAX_EML_LEN, 10);
	for (var e3 = 0; e3 < MAX_EML_LEN; e3++) {
		HAS_ATG.eml[e3] <== eml[e3];
	}
	for (var g = 0; g < 10; g++) {
		HAS_ATG.lit[g] <== atg_bytes[g];
	}
	for (var sg = 0; sg < MAX_EML_LEN; sg++) {
		HAS_ATG.sel[sg] <== sel_atg[sg];
	}
	HAS_ATG.ok === 1;
}

// Default capacity: 8192 bytes; adjust as needed.
component main { public [ eml_commitment ] } = EmlHasHeadersSimple(8192);


