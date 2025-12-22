// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title StateSetAnchor
 * @notice Anchors StateSet sequencer commitments on-chain for verifiability
 * @dev Stores Merkle roots of event batches for cryptographic verification
 */
contract StateSetAnchor {
    /// @notice Emitted when a new commitment is anchored
    event CommitmentAnchored(
        bytes32 indexed batchId,
        bytes32 indexed tenantId,
        bytes32 storeId,
        bytes32 eventsRoot,
        bytes32 stateRoot,
        uint64 sequenceStart,
        uint64 sequenceEnd,
        uint32 eventCount,
        uint256 timestamp
    );

    /// @notice Emitted when a batch of commitments is anchored
    event BatchAnchored(
        bytes32 indexed batchRoot,
        uint256 commitmentCount,
        uint256 timestamp
    );

    /// @notice Commitment data structure
    struct Commitment {
        bytes32 batchId;
        bytes32 tenantId;
        bytes32 storeId;
        bytes32 eventsRoot;
        bytes32 stateRoot;
        uint64 sequenceStart;
        uint64 sequenceEnd;
        uint32 eventCount;
        uint256 anchoredAt;
        address anchoredBy;
    }

    /// @notice Mapping from batch ID to commitment
    mapping(bytes32 => Commitment) public commitments;

    /// @notice Mapping from tenant+store to their latest anchored sequence
    mapping(bytes32 => uint64) public latestSequence;

    /// @notice Array of all anchored batch IDs for enumeration
    bytes32[] public anchoredBatches;

    /// @notice Owner address (can be set to address(0) for permissionless)
    address public owner;

    /// @notice Whether anchoring is permissionless
    bool public permissionless;

    modifier onlyAuthorized() {
        require(permissionless || msg.sender == owner, "Not authorized");
        _;
    }

    constructor(bool _permissionless) {
        owner = msg.sender;
        permissionless = _permissionless;
    }

    /**
     * @notice Anchor a single commitment
     * @param batchId Unique batch identifier
     * @param tenantId Tenant identifier
     * @param storeId Store identifier
     * @param eventsRoot Merkle root of events in batch
     * @param stateRoot State root after applying batch
     * @param sequenceStart First sequence number in batch
     * @param sequenceEnd Last sequence number in batch
     * @param eventCount Number of events in batch
     */
    function anchor(
        bytes32 batchId,
        bytes32 tenantId,
        bytes32 storeId,
        bytes32 eventsRoot,
        bytes32 stateRoot,
        uint64 sequenceStart,
        uint64 sequenceEnd,
        uint32 eventCount
    ) external onlyAuthorized {
        require(commitments[batchId].anchoredAt == 0, "Already anchored");
        require(sequenceEnd >= sequenceStart, "Invalid sequence range");
        require(eventCount > 0, "Empty batch");

        // Store commitment
        commitments[batchId] = Commitment({
            batchId: batchId,
            tenantId: tenantId,
            storeId: storeId,
            eventsRoot: eventsRoot,
            stateRoot: stateRoot,
            sequenceStart: sequenceStart,
            sequenceEnd: sequenceEnd,
            eventCount: eventCount,
            anchoredAt: block.timestamp,
            anchoredBy: msg.sender
        });

        // Update latest sequence for tenant+store
        bytes32 tenantStoreKey = keccak256(abi.encodePacked(tenantId, storeId));
        if (sequenceEnd > latestSequence[tenantStoreKey]) {
            latestSequence[tenantStoreKey] = sequenceEnd;
        }

        anchoredBatches.push(batchId);

        emit CommitmentAnchored(
            batchId,
            tenantId,
            storeId,
            eventsRoot,
            stateRoot,
            sequenceStart,
            sequenceEnd,
            eventCount,
            block.timestamp
        );
    }

    /**
     * @notice Anchor multiple commitments in a single transaction
     * @param batchIds Array of batch identifiers
     * @param tenantIds Array of tenant identifiers
     * @param storeIds Array of store identifiers
     * @param eventsRoots Array of events Merkle roots
     * @param stateRoots Array of state roots
     * @param sequenceStarts Array of sequence starts
     * @param sequenceEnds Array of sequence ends
     * @param eventCounts Array of event counts
     */
    function anchorBatch(
        bytes32[] calldata batchIds,
        bytes32[] calldata tenantIds,
        bytes32[] calldata storeIds,
        bytes32[] calldata eventsRoots,
        bytes32[] calldata stateRoots,
        uint64[] calldata sequenceStarts,
        uint64[] calldata sequenceEnds,
        uint32[] calldata eventCounts
    ) external onlyAuthorized {
        uint256 len = batchIds.length;
        require(
            tenantIds.length == len &&
            storeIds.length == len &&
            eventsRoots.length == len &&
            stateRoots.length == len &&
            sequenceStarts.length == len &&
            sequenceEnds.length == len &&
            eventCounts.length == len,
            "Array length mismatch"
        );

        // Compute batch root for the batch anchor event
        bytes32 batchRoot = keccak256(abi.encodePacked(batchIds));

        for (uint256 i = 0; i < len; i++) {
            require(commitments[batchIds[i]].anchoredAt == 0, "Already anchored");
            require(sequenceEnds[i] >= sequenceStarts[i], "Invalid sequence range");

            commitments[batchIds[i]] = Commitment({
                batchId: batchIds[i],
                tenantId: tenantIds[i],
                storeId: storeIds[i],
                eventsRoot: eventsRoots[i],
                stateRoot: stateRoots[i],
                sequenceStart: sequenceStarts[i],
                sequenceEnd: sequenceEnds[i],
                eventCount: eventCounts[i],
                anchoredAt: block.timestamp,
                anchoredBy: msg.sender
            });

            bytes32 tenantStoreKey = keccak256(abi.encodePacked(tenantIds[i], storeIds[i]));
            if (sequenceEnds[i] > latestSequence[tenantStoreKey]) {
                latestSequence[tenantStoreKey] = sequenceEnds[i];
            }

            anchoredBatches.push(batchIds[i]);

            emit CommitmentAnchored(
                batchIds[i],
                tenantIds[i],
                storeIds[i],
                eventsRoots[i],
                stateRoots[i],
                sequenceStarts[i],
                sequenceEnds[i],
                eventCounts[i],
                block.timestamp
            );
        }

        emit BatchAnchored(batchRoot, len, block.timestamp);
    }

    /**
     * @notice Verify an events root is anchored
     * @param batchId The batch to verify
     * @param eventsRoot The expected events root
     * @return valid Whether the events root matches
     */
    function verifyEventsRoot(bytes32 batchId, bytes32 eventsRoot) external view returns (bool valid) {
        Commitment storage c = commitments[batchId];
        return c.anchoredAt > 0 && c.eventsRoot == eventsRoot;
    }

    /**
     * @notice Get commitment details
     * @param batchId The batch to query
     */
    function getCommitment(bytes32 batchId) external view returns (
        bytes32 tenantId,
        bytes32 storeId,
        bytes32 eventsRoot,
        bytes32 stateRoot,
        uint64 sequenceStart,
        uint64 sequenceEnd,
        uint32 eventCount,
        uint256 anchoredAt,
        address anchoredBy
    ) {
        Commitment storage c = commitments[batchId];
        require(c.anchoredAt > 0, "Not anchored");
        return (
            c.tenantId,
            c.storeId,
            c.eventsRoot,
            c.stateRoot,
            c.sequenceStart,
            c.sequenceEnd,
            c.eventCount,
            c.anchoredAt,
            c.anchoredBy
        );
    }

    /**
     * @notice Get the latest anchored sequence for a tenant+store
     * @param tenantId Tenant identifier
     * @param storeId Store identifier
     */
    function getLatestSequence(bytes32 tenantId, bytes32 storeId) external view returns (uint64) {
        bytes32 key = keccak256(abi.encodePacked(tenantId, storeId));
        return latestSequence[key];
    }

    /**
     * @notice Get total number of anchored batches
     */
    function getAnchoredCount() external view returns (uint256) {
        return anchoredBatches.length;
    }

    /**
     * @notice Check if a batch is anchored
     * @param batchId The batch to check
     */
    function isAnchored(bytes32 batchId) external view returns (bool) {
        return commitments[batchId].anchoredAt > 0;
    }

    /**
     * @notice Transfer ownership
     * @param newOwner New owner address
     */
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }

    /**
     * @notice Set permissionless mode
     * @param _permissionless Whether to allow anyone to anchor
     */
    function setPermissionless(bool _permissionless) external {
        require(msg.sender == owner, "Not owner");
        permissionless = _permissionless;
    }
}
