global MAX_DEPTH : u32 = 32;

fn verifyProof(
    leafIdx: u32,
    leafKey: u64,
    leafNextIdx: u32,
    leafNextKey: u64,
    leafValue: Field,
    root: Field,
    siblings: [Field]
) {
    let mut hash = std::hash::poseidon::bn254::hash_4([
        leafKey as Field, leafNextIdx as Field, leafNextKey as Field, leafValue
    ]);
    let mut idx = leafIdx;
    for i in 0..MAX_DEPTH {
        if i < siblings.len() {
            let is_right = ((idx & 1) == 0) as bool;
            let (hash_left, hash_right) = if is_right {
                (hash, siblings[i])
            } else {
                (siblings[i], hash)
            };
            hash = std::hash::poseidon::bn254::hash_2([hash_left, hash_right]);
            idx >>= 1;
        }
    };
    assert(hash == root);
}

fn verifyExclusionProof(
    leafIdx: u32,
    leafKey: u64,
    leafNextIdx: u32,
    leafNextKey: u64,
    leafValue: Field,
    root: Field,
    siblings: [Field],
    excludedKey: u64
) {
    verifyProof(leafIdx, leafKey, leafNextIdx, leafNextKey, leafValue, root, siblings);
    assert(excludedKey > leafKey);
    if leafNextIdx > 0 {
        assert(excludedKey < leafNextKey);
    }
}

fn verifyInsertionProof(
    ogLeafIdx: u32,
    ogLeafKey: u64,
    ogLeafNextIdx: u32,
    ogLeafNextKey: u64,
    ogLeafValue: Field,
    newLeafIdx: u32,
    newLeafKey: u64,
    newLeafValue: Field,
    rootBefore: Field,
    rootAfter: Field,
    siblingsBefore: [Field],
    siblingsAfterOg: [Field],
    siblingsAfterNew: [Field]
) {
    // 1) All three proofs must be individually valid
    verifyProof(ogLeafIdx, ogLeafKey, ogLeafNextIdx, ogLeafNextKey, ogLeafValue, rootBefore, siblingsBefore);
    verifyProof(ogLeafIdx, ogLeafKey, newLeafIdx, newLeafKey, ogLeafValue, rootAfter, siblingsAfterOg);
    verifyProof(newLeafIdx, newLeafKey, ogLeafNextIdx, ogLeafNextKey, newLeafValue, rootAfter, siblingsAfterNew);

    // 2) After insertion, both "new-item" and "updated-prev" must land on the same root
    // non-op here since it's the same input signal

    // 3) The "after" proofs must have equal length
    assert(siblingsAfterOg.len() == siblingsAfterNew.len());
    //    And the "before" proof's length must be either the same (no height change)
    //    or exactly one less (height grew by 1, e.g. first insertion or crossing a power-of-two).
    assert((siblingsBefore.len() == siblingsAfterNew.len())
        | (siblingsBefore.len() + 1 == siblingsAfterNew.len()));

    // 4) Find the first level at which the predecessor's proof changed
    let mut diffIdx = 0;
    for i in 0..MAX_DEPTH {
        if i < siblingsBefore.len() {
            if (diffIdx == 0) & (siblingsBefore[i] != siblingsAfterOg[i]) {
                diffIdx = i;
            }
        }
    }
    // XXX: Added this since can't lazily evaluate array index above
    // TODO test that this works for all combinations of leaf indices (especially first insert)
    if diffIdx == 0 {
        diffIdx = siblingsBefore.len();
    }
    // We must see exactly one "first" change
    assert(diffIdx > 0);
    // And ensure nothing *before* that level changed
    for i in 0..MAX_DEPTH {
        if i < siblingsBefore.len() {
            assert(siblingsBefore[i] == siblingsAfterOg[i]);
        }
    }
    // 5) Now recompute the "sub-root" of the new leaf up to diffIdx, and
    //    check it matches the sibling that was injected into the prev-proof.
    let mut hash = std::hash::poseidon::bn254::hash_4([
        newLeafKey as Field, ogLeafNextIdx as Field, ogLeafNextKey as Field, newLeafValue
    ]);
    let mut idx = newLeafIdx;
    for i in 0..MAX_DEPTH {
        if i < diffIdx {
            let is_right = ((idx & 1) == 0) as bool;
            let (hash_left, hash_right) = if is_right {
                (hash, siblingsAfterNew[i])
            } else {
                (siblingsAfterNew[i], hash)
            };
            hash = std::hash::poseidon::bn254::hash_2([hash_left, hash_right]);
            idx >>= 1;
        }
    };
    assert(hash == siblingsAfterOg[diffIdx]);

}

#[test]
fn test_verifyProof() {
    // Values from javascript test case
    verifyProof(
        2, 20, 1, 30, 234,
        6668943297883148265098278873555187520846124753710152977795611422562477639299,
        [
            20759673891506207694606256884301953054087839119850062912178024809139786256525,
            13570217411213457836903525328870830571019970122567943123711413970257955169666
        ]
    );
}

#[test]
fn test_verifyExclusionProof() {
    // Values from javascript test case
    verifyExclusionProof(
        3, 10, 2, 20, 345,
        6668943297883148265098278873555187520846124753710152977795611422562477639299,
        [
            11135396582441045199900643499438439681601330703827922539252138484042051185631,
            13570217411213457836903525328870830571019970122567943123711413970257955169666
        ],
        13
    );
}

#[test]
fn test_verifyExclusionProofPastEnd() {
    // Values from javascript test case
    verifyExclusionProof(
        1, 30, 0, 0, 123,
        6668943297883148265098278873555187520846124753710152977795611422562477639299,
        [
            6267760970832874298001165242953505942071048916205419224198468699938087185580,
            21006214261944761893288216955619891277091894074878556242157792523868647089882
        ],
        33
    );
}

#[test]
fn test_verifyInsertionProof() {
    // Values from javascript test case
    verifyInsertionProof(
        3, 30, 0, 0, 369, 4, 40, 492,
        2571980431646512226537973716044286349345455446077442026376592565776796645988,
        2963872233248354362054425041526741667834940426492725195869776079054072427609,
        [
            21811187948234496653038156303271104363293342331973867763419216898445358052835,
            19105469470815259923778736722894778945358156111821148490927046754068671364855
        ],
        [
            21811187948234496653038156303271104363293342331973867763419216898445358052835,
            19105469470815259923778736722894778945358156111821148490927046754068671364855,
            21456886111827427998357836449341111815053179374366685590435429032039554303766
        ],
        [
            2351654555892372227640888372176282444150254868378439619268573230312091195718,
            5723720832300544730179969191054372086051633243972178196193101286943139171509,
            14016517550536154496576705664688405808854048460765765188269560158066581900513
        ]
    );
}
