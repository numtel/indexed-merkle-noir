import {poseidon2, poseidon4} from 'poseidon-lite';

export class IndexedMerkleTree {
  constructor() {
    // Always initialize with a zero item for exclusion proofs below the first item
    this.items = [{ key: 0n, nextIdx: 0, nextKey: 0n, value: 0n }];
  }

  insertItem(key, value) {
    const {items} = this;
    if(typeof key !== 'bigint' || key < 1n) throw new Error('invalid_key');
    if(typeof value !== 'bigint' || value < 0n) throw new Error('invalid_value');
    if(items.find(x => x.key === key)) throw new Error('duplicate_key');

    // Find previous key
    let prevKey = 0n;
    let prevIdx = 0;
    for(let i = 1; i < items.length; i++) {
      if(items[i].key < key && items[i].key > prevKey) {
        prevKey = items[i].key;
        prevIdx = i;
        // Doesn't get any closer
        if(items[i].key + 1n === key) break;
      }
    }

    const exProof = this.generateProof(prevKey);

    items.push({
      key,
      nextIdx: items[prevIdx].nextIdx,
      nextKey: items[prevIdx].nextKey,
      value,
    });
    items[prevIdx].nextKey = key;
    items[prevIdx].nextIdx = items.length - 1;

    const newItemProof = this.generateProof(key);
    const updatedPrevProof = this.generateProof(prevKey);

    return {
      ogLeafIdx: exProof.leafIdx,
      ogLeafKey: exProof.leaf.key,
      ogLeafNextIdx: exProof.leaf.nextIdx,
      ogLeafNextKey: exProof.leaf.nextKey,
      ogLeafValue: exProof.leaf.value,
      newLeafIdx: newItemProof.leafIdx,
      newLeafKey: newItemProof.leaf.key,
      newLeafValue: newItemProof.leaf.value,
      rootBefore: exProof.root,
      rootAfter: newItemProof.root,
      siblingsBefore: exProof.siblings,
      siblingsAfterOg: updatedPrevProof.siblings,
      siblingsAfterNew: newItemProof.siblings,
    };
  }

  generateProof(key) {
    const {items} = this;
    const idx = items.findIndex(x => x.key === key)
    if(idx < 0) throw new Error('invalid_key');

    const leaves = items.map(x => poseidon4([ x.key, x.nextIdx, x.nextKey, x.value ]));

    // Pad to the next power-of-two with an explicit zero-leaf
    const ZERO_LEAF = poseidon4([0n, 0n, 0n, 0n]);
    const size = 1 << Math.ceil(Math.log2(leaves.length));
    while(leaves.length < size) leaves.push(ZERO_LEAF);

    const siblings = [];
    let idxAtLevel = idx;
    let level = leaves;

    while(level.length > 1) {
      // flip the low bit instead of calculating left or right side of pair
      const sibIdx = idxAtLevel ^ 1;
      if(sibIdx < level.length) siblings.push(level[sibIdx]);

      const nextLevel = [];
      for(let i = 0; i < level.length; i += 2) {
        nextLevel.push(poseidon2([level[i], level[i + 1]]));
      }

      idxAtLevel >>= 1; // parent index
      level = nextLevel; // ascend one level
    }

    return {
      leafIdx: idx,
      leaf: {...items[idx]}, // copy the leaf instead of passing reference
      root: level[0],
      siblings,
    }
  }

  generateExclusionProof(key) {
    const {items} = this;
    if(typeof key !== 'bigint' || key < 1n) throw new Error('invalid_key');
    for(let i = 0; i < items.length; i++) {
      if(items[i].key === key) {
        throw new Error('key_exists');
      } else if(items[i].key < key && (items[i].nextKey > key || items[i].nextKey === 0n)) {
        return this.generateProof(items[i].key);
      }
    }
  }

  verifyProof(proof) {
    let hash = poseidon4([
      proof.leaf.key,
      proof.leaf.nextIdx,
      proof.leaf.nextKey,
      proof.leaf.value
    ]);
    let idx = proof.leafIdx;

    for (const sib of proof.siblings) {
      hash = poseidon2((idx & 1) === 0 ? [hash, sib] : [sib, hash]);
      idx >>= 1;
    }

    return hash === proof.root;
  }

  verifyInsertionProof({
      ogLeafIdx, ogLeafKey, ogLeafNextIdx, ogLeafNextKey, ogLeafValue,
      newLeafIdx, newLeafKey, newLeafValue, rootBefore, rootAfter,
      siblingsBefore, siblingsAfterOg, siblingsAfterNew,
    }) {
    // 1) All three proofs must be individually valid
    if (
      !this.verifyProof({
        leafIdx: ogLeafIdx,
        leaf: {
          key: ogLeafKey,
          nextIdx: ogLeafNextIdx,
          nextKey: ogLeafNextKey,
          value: ogLeafValue,
        },
        root: rootBefore,
        siblings: siblingsBefore,
      }) ||
      !this.verifyProof({
        leafIdx: newLeafIdx,
        leaf: {
          key: newLeafKey,
          nextIdx: ogLeafNextIdx,
          nextKey: ogLeafNextKey,
          value: newLeafValue,
        },
        root: rootAfter,
        siblings: siblingsAfterNew,
      }) ||
      !this.verifyProof({
        leafIdx: ogLeafIdx,
        leaf: {
          key: ogLeafKey,
          nextIdx: newLeafIdx,
          nextKey: newLeafKey,
          value: ogLeafValue,
        },
        root: rootAfter,
        siblings: siblingsAfterOg,
      })
    ) {
      return false;
    }

    // 2) The "after" proofs must have equal length
    if (siblingsAfterNew.length !== siblingsAfterOg.length) {
      return false;
    }
    //    And the "before" proof’s length must be either the same (no height change)
    //    or exactly one less (height grew by 1, e.g. first insertion or crossing a power‐of‐two).
    if (
      !(
        siblingsBefore.length === siblingsAfterNew.length ||
        siblingsBefore.length + 1 === siblingsAfterNew.length
      )
    ) {
      return false;
    }

    // 3) Find the first level at which the predecessor’s proof changed
    let diffIdx = -1;
    for (let i = 0; i < siblingsAfterNew.length; i++) {
      const before = siblingsBefore[i];
      const after  = siblingsAfterOg[i];
      if (before !== after) {
        diffIdx = i;
        break;
      }
    }
    // We must see exactly one "first" change
    if (diffIdx < 0) {
      return false;
    }
    // And ensure nothing *before* that level changed
    for (let i = 0; i < diffIdx; i++) {
      if (siblingsBefore[i] !== siblingsAfterOg[i]) {
        return false;
      }
    }

    // 4) Now recompute the "sub‐root" of the new leaf up to diffIdx, and
    //    check it matches the sibling that was injected into the prev-proof.
    let hash = poseidon4([
      newLeafKey,
      ogLeafNextIdx,
      ogLeafNextKey,
      newLeafValue
    ]);
    let idx  = newLeafIdx;

    for (let lvl = 0; lvl < diffIdx; lvl++) {
      const sib = siblingsAfterNew[lvl];
      if ((idx & 1) === 0) {
        hash = poseidon2([hash, sib]);
      } else {
        hash = poseidon2([sib, hash]);
      }
      idx >>= 1;
    }

    // That must be exactly the "new" sibling in the updated-prev proof
    return hash === siblingsAfterOg[diffIdx];
  }

}

