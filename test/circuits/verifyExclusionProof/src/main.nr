use dep::indexed_merkle;

fn main(
    leafIdx: u32,
    leafKey: u64,
    leafNextIdx: u32,
    leafNextKey: u64,
    leafValue: Field,
    root: pub Field,
    siblings: [Field; indexed_merkle::MAX_DEPTH],
    excludedKey: u64
) {
    indexed_merkle::verifyExclusionProof(
        leafIdx,
        leafKey,
        leafNextIdx,
        leafNextKey,
        leafValue,
        root,
        siblings,
        excludedKey
    );
}
