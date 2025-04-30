use dep::indexed_merkle;

fn main(
    ogLeafIdx: u32,
    ogLeafKey: u64,
    ogLeafNextIdx: u32,
    ogLeafNextKey: u64,
    ogLeafValue: Field,
    newLeafIdx: u32,
    newLeafKey: u64,
    newLeafValue: Field,
    rootBefore: pub Field,
    rootAfter: pub Field,
    siblingsBefore: [Field; indexed_merkle::MAX_DEPTH],
    siblingsAfterOg: [Field; indexed_merkle::MAX_DEPTH],
    siblingsAfterNew: [Field; indexed_merkle::MAX_DEPTH]
) {
    indexed_merkle::verifyInsertionProof(
        ogLeafIdx,
        ogLeafKey,
        ogLeafNextIdx,
        ogLeafNextKey,
        ogLeafValue,
        newLeafIdx,
        newLeafKey,
        newLeafValue,
        rootBefore,
        rootAfter,
        siblingsBefore,
        siblingsAfterOg,
        siblingsAfterNew
    );
}
