// Submit snarkjs Groth16 proof to zkVerify Relayer and poll status
// Ref: https://docs.zkverify.io/overview/getting-started/relayer

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const ethersLib = require('ethers');

const API_URL = 'https://relayer-api.horizenlabs.io/api/v1';
const API_KEY = process.env.API_KEY || '';

function readJSON(p) {
  return JSON.parse(fs.readFileSync(p));
}

function toBeHex32(bn) {
  let hex = bn.toString(16);
  if (hex.length > 64) throw new Error('public input > 256 bits');
  return '0x' + hex.padStart(64, '0');
}

function keccak256Hex(hex) {
  // Support ethers v5/v6
  try {
    const ethersLib = require('ethers');
    if (ethersLib.utils && ethersLib.utils.keccak256) {
      return ethersLib.utils.keccak256(hex);
    }
    if (ethersLib.keccak256) {
      return ethersLib.keccak256(hex);
    }
  } catch (_) {}
  // Fallback to keccak module
  const Keccak = require('keccak');
  return '0x' + Keccak('keccak256').update(Buffer.from(hex.slice(2), 'hex')).digest('hex');
}

function reverse32(hex) {
  const b = Buffer.from(hex.slice(2), 'hex');
  return '0x' + Buffer.from(b.reverse()).toString('hex');
}

async function main() {
  const root = process.cwd();
  const proof = readJSON(path.join(root, 'proof.json'));
  const publicInputs = readJSON(path.join(root, 'public.json'));
  const vkey = readJSON(path.join(root, 'build', 'vkey.json'));

  // 1) Register verification key (idempotent caching to file)
  const cachePath = path.join(root, 'relayer', 'circom-vkey.json');
  let vkReg;
  if (!fs.existsSync(cachePath)) {
    if (!fs.existsSync(path.dirname(cachePath))) {
      fs.mkdirSync(path.dirname(cachePath), { recursive: true });
    }
    const regParams = {
      proofType: 'groth16',
      proofOptions: { library: 'snarkjs', curve: 'bn128' },
      vk: vkey,
    };
    const regRes = await axios.post(`${API_URL}/register-vk/${API_KEY}`, regParams);
    fs.writeFileSync(cachePath, JSON.stringify(regRes.data));
    vkReg = regRes.data;
    console.log('VK registered:', vkReg);
  } else {
    vkReg = readJSON(cachePath);
    console.log('Using cached VK registration');
  }

  const vkHash = vkReg.vkHash || (vkReg.meta && vkReg.meta.vkHash);
  if (!vkHash) throw new Error('vkHash missing from VK registration response');

  // 2) Submit proof
  const submitParams = {
    proofType: 'groth16',
    vkRegistered: true,
    chainId: 845320009,
    proofOptions: { library: 'snarkjs', curve: 'bn128' },
    proofData: { proof, publicSignals: publicInputs, vk: vkHash },
  };
  const submitRes = await axios.post(`${API_URL}/submit-proof/${API_KEY}`, submitParams);
  console.log('Submitted:', submitRes.data);

  const jobId = submitRes.data.jobId;
  if (!jobId) throw new Error('No jobId returned');
  let last;
  for (;;) {
    const st = await axios.get(`${API_URL}/job-status/${API_KEY}/${jobId}`);
    last = st.data;
    console.log('Job status:', last.status);
    if (last.status === 'Aggregated') break;
    await new Promise(r => setTimeout(r, 5000));
  }
  // Grace wait after aggregation becomes available
  await new Promise(r => setTimeout(r, 15000));

  const RPC_URL = process.env.RPC_URL || 'https://horizen-rpc-testnet.appchain.base.org';
  const PRIVATE_KEY = process.env.PRIVATE_KEY || '';
  const REGISTRY_ADDR = process.env.REGISTRY_ADDR || '0xbc9bc0e9d12c4d22ba1d7e0330ef822a8da2f7db';
  const REGISTRY_ABI = [
    'function recordAfterAggregation(uint256,uint256,uint256,bytes32[],uint256,uint256,bytes32) external'
  ];
  const ZKVERIFY_ADDR = process.env.ZKVERIFY_ADDR || '0x201B6ba8EA862d83AAA03CFbaC962890c7a4d195';
  const ZKVERIFY_ABI = [
    'function verifyProofAggregation(uint256,uint256,bytes32,bytes32[],uint256,uint256) external view returns (bool)'
  ];

  if (last.status === 'Aggregated' && PRIVATE_KEY) {
    const agg = last.aggregationDetails || {};
    const aggregationId = last.aggregationId;
    const domainId = 113; // forced per request
    const merklePath = agg.merkleProof || [];
    const leafCount = agg.numberOfLeaves;
    const index = agg.leafIndex;
    const relayerTxHash = last.txHash;

    console.log('Aggregation debug:', {
      aggregationId,
      domainId,
      leaf: agg.leaf,
      merklePath,
      merklePathLen: merklePath.length,
      leafCount,
      index
    });

    const beWords = publicInputs.map((d) => toBeHex32(BigInt(d)));
    const concatHex = '0x' + beWords.map(h => h.slice(2)).join('');
    const publicInputsHash = keccak256Hex(concatHex);
    // Offchain leaf recompute to sanity-check with aggregator leaf
    const inner = keccak256Hex(reverse32(publicInputsHash));
    const ethersUtils = ethersLib.utils || ethersLib;
    const provingId = ethersUtils.keccak256(ethersUtils.toUtf8Bytes('groth16'));
    const versionHash = ethersUtils.sha256 ? ethersUtils.sha256(ethersUtils.toUtf8Bytes('')) : ethersUtils.keccak256('0x');
    const vkHashHex = readJSON(path.join(root, 'relayer', 'circom-vkey.json')).vkHash;
    const leafComputed = ethersUtils.solidityKeccak256(
      ['bytes32','bytes32','bytes32','bytes32'],
      [provingId, vkHashHex, versionHash, inner]
    );
    // If mismatch, call contract using aggregator-provided leaf directly

    const ProviderCtor = (ethersLib.providers && ethersLib.providers.JsonRpcProvider) || ethersLib.JsonRpcProvider;
    const provider = new ProviderCtor(RPC_URL);
    const signer = new ethersLib.Wallet(PRIVATE_KEY, provider);
    const registry = new ethersLib.Contract(REGISTRY_ADDR, REGISTRY_ABI, signer);
    const registryLeaf = new ethersLib.Contract(REGISTRY_ADDR, ['function recordWithLeaf(bytes32,uint256,uint256,bytes32[],uint256,uint256,bytes32) external'], signer);
    const zkverify = new ethersLib.Contract(ZKVERIFY_ADDR, ZKVERIFY_ABI, signer);

    // Precheck on zkVerify
    try {
      const ok = await zkverify.verifyProofAggregation(domainId, aggregationId, (agg.leaf || leafComputed), merklePath, leafCount, index);
      if (!ok) {
        console.log('zkVerify view returned false. Aborting send. Params:', { domainId, aggregationId, leaf: agg.leaf || leafComputed, leafCount, index, merklePathLen: merklePath.length });
        return;
      }
    } catch (e) {
      console.log('zkVerify view call failed. Aborting send. Error:', e.message);
      return;
    }

    console.log('Recording aggregation to contract...');
    let tx;
    if (agg.leaf && agg.leaf.length === 66 && agg.leaf.toLowerCase() !== leafComputed.toLowerCase()) {
      console.log('Using aggregator leaf directly');
      tx = await registryLeaf.recordWithLeaf(
        agg.leaf,
        aggregationId,
        domainId,
        merklePath,
        leafCount,
        index,
        relayerTxHash,
        { gasLimit: 850000 }
      );
    } else {
      tx = await registry.recordAfterAggregation(
        publicInputsHash,
        aggregationId,
        domainId,
        merklePath,
        leafCount,
        index,
        relayerTxHash,
        { gasLimit: 850000 }
      );
    }
    console.log('record tx:', tx.hash);
    await tx.wait();
    console.log('recorded.');
  } else {
    if (PRIVATE_KEY) {
      console.log('Waiting up to ~15 minutes for Aggregated status...');
      let aggregated = last.status === 'Aggregated';
      for (let i = 0; i < 180 && !aggregated; i++) {
        await new Promise(r => setTimeout(r, 5000));
        const st2 = await axios.get(`${API_URL}/job-status/${API_KEY}/${jobId}`);
        last = st2.data;
        if (i % 6 === 0) console.log('Job status:', last.status);
        if (last.status === 'Aggregated') aggregated = true;
      }
      if (aggregated) {
        // Grace wait after aggregation becomes available
        await new Promise(r => setTimeout(r, 15000));
        const agg = last.aggregationDetails || {};
        const aggregationId = last.aggregationId;
        const domainId = 113; // forced per request
        const merklePath = agg.merkleProof || [];
        const leafCount = agg.numberOfLeaves;
        const index = agg.leafIndex;
        const relayerTxHash = last.txHash;

        const beWords2 = publicInputs.map((d) => toBeHex32(BigInt(d)));
        const concatHex = '0x' + beWords2.map(h => h.slice(2)).join('');
        const publicInputsHash = keccak256Hex(concatHex);

        const ProviderCtor2 = (ethersLib.providers && ethersLib.providers.JsonRpcProvider) || ethersLib.JsonRpcProvider;
        const provider2 = new ProviderCtor2(RPC_URL);
        const signer2 = new ethersLib.Wallet(PRIVATE_KEY, provider2);
        const registry2 = new ethersLib.Contract(REGISTRY_ADDR, REGISTRY_ABI, signer2);

        console.log('Recording aggregation to contract...');
        const tx = await registry2.recordAfterAggregation(
          publicInputsHash,
          aggregationId,
          domainId,
          merklePath,
          leafCount,
          index,
          relayerTxHash
        );
        console.log('record tx:', tx.hash);
        await tx.wait();
        console.log('recorded.');
      } else {
        console.log('Aggregation still not available after extended wait; skipping on-chain record.');
      }
    } else {
      console.log('Wallet env not set; skipping on-chain record.');
    }
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});


