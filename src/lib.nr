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
