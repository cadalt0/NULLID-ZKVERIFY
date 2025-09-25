// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// zkVerify Aggregation Verifier interface (per docs)
// https://docs.zkverify.io/overview/getting-started/smart-contract
interface IVerifyProofAggregation {
    function verifyProofAggregation(
        uint256 _domainId,
        uint256 _aggregationId,
        bytes32 _leaf,
        bytes32[] calldata _merklePath,
        uint256 _leafCount,
        uint256 _index
    ) external view returns (bool);
}

// Records a statement (leaf) after verifying zkVerify aggregation.
// Tailored for Circom/Groth16 proofs produced with snarkjs.
contract EmlProofRecorder {
    // Proving system and version (per zkVerify docs for Groth16)
    bytes32 public constant PROVING_SYSTEM_ID = keccak256(abi.encodePacked("groth16"));
    bytes32 public constant VERSION_HASH = sha256(abi.encodePacked(""));

    // zkVerify contract address and circuit vkey (as bytes32 hash expected by zkVerify)
    address public immutable zkVerify;
    bytes32 public immutable vkey;

    // statement => relayer tx hash (set once)
    mapping(bytes32 => bytes32) public statementToTxHash;

    event ProofRecorded(bytes32 indexed statement, bytes32 relayerTxHash, address indexed sender, uint64 recordedAt);

    constructor(address _zkVerify, bytes32 _vkey) {
        require(_zkVerify != address(0), "zkVerify addr");
        zkVerify = _zkVerify;
        vkey = _vkey;
    }

    // Groth16 public inputs hash endianness fix (EVM vs zkVerify pallet)
    // https://docs.zkverify.io/overview/getting-started/smart-contract
    function _changeEndianess(uint256 input) internal pure returns (uint256 v) {
        v = input;
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
          | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
          | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
          | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
          | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        v = (v >> 128) | (v << 128);
    }

    // Verify the aggregation on zkVerify, then record the statement and relayer tx hash.
    // Params:
    // - publicInputsHash: keccak over public inputs as required by zkVerify (snarkjs Groth16) supplied as uint256
    // - aggregation and merkle data: from relayer aggregation result
    // - relayerTxHash: transaction hash (bytes32) that included the proof on-chain
    function recordAfterAggregation(
        uint256 publicInputsHash,
        uint256 aggregationId,
        uint256 domainId,
        bytes32[] calldata merklePath,
        uint256 leafCount,
        uint256 index,
        bytes32 relayerTxHash
    ) external {
        require(relayerTxHash != bytes32(0), "txHash");

        // Compose leaf per zkVerify spec for Groth16
        bytes32 leaf = keccak256(
            abi.encodePacked(
                PROVING_SYSTEM_ID,
                vkey,
                VERSION_HASH,
                keccak256(abi.encodePacked(_changeEndianess(publicInputsHash)))
            )
        );

        bool ok = IVerifyProofAggregation(zkVerify).verifyProofAggregation(
            domainId,
            aggregationId,
            leaf,
            merklePath,
            leafCount,
            index
        );
        require(ok, "Invalid aggregation");

        require(statementToTxHash[leaf] == bytes32(0), "already recorded");
        statementToTxHash[leaf] = relayerTxHash;
        emit ProofRecorded(leaf, relayerTxHash, msg.sender, uint64(block.timestamp));
    }

    function isRecorded(bytes32 statement) external view returns (bool) {
        return statementToTxHash[statement] != bytes32(0);
    }

    // Variant: accept leaf directly from aggregator output to avoid offchain recomputation mismatches
    function recordWithLeaf(
        bytes32 leaf,
        uint256 aggregationId,
        uint256 domainId,
        bytes32[] calldata merklePath,
        uint256 leafCount,
        uint256 index,
        bytes32 relayerTxHash
    ) external {
        require(relayerTxHash != bytes32(0), "txHash");

        bool ok = IVerifyProofAggregation(zkVerify).verifyProofAggregation(
            domainId,
            aggregationId,
            leaf,
            merklePath,
            leafCount,
            index
        );
        require(ok, "Invalid aggregation");

        require(statementToTxHash[leaf] == bytes32(0), "already recorded");
        statementToTxHash[leaf] = relayerTxHash;
        emit ProofRecorded(leaf, relayerTxHash, msg.sender, uint64(block.timestamp));
    }
}


