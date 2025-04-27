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

    items.push({
      key,
      nextIdx: items[prevIdx].nextIdx,
      nextKey: items[prevIdx].nextKey,
      value,
    });
    items[prevIdx].nextKey = key;
    items[prevIdx].nextIdx = items.length - 1;
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
}

