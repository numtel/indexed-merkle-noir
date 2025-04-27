import {ok} from 'node:assert';

import {IndexedMerkleTree} from '../index.js';

describe('IndexedMerkleTree', () => {
  it('should generate and verify exclusion proof on empty tree', () => {
    const tree = new IndexedMerkleTree;

    const exProof = tree.generateExclusionProof(13n);
    ok(tree.verifyProof(exProof));
  });

  for(let size = 2; size <= (process.env.TEST_SIZE || 10); size++) {
    it(`should generate and verify proof of ${size} items correctly matrix`, () => {
      const tree = new IndexedMerkleTree;
      for(let i = 1; i < size; i++) {
        tree.insertItem(10n * BigInt(i), 123n * BigInt(i));
      }

      for(let i = 1; i < size; i++) {
        // Test that each item can be successfully proved for inclusion
        const proof = tree.generateProof(10n * BigInt(i));
        ok(tree.verifyProof(proof));

        // Test that a missing item doesn't exist slightly beyond each item
        const exProof = tree.generateExclusionProof(10n * BigInt(i) + 3n);
        ok(tree.verifyProof(exProof));
      }
    });
  }

  it('should generate a proof of inserting a new item (state transition)', () => {
    const tree = new IndexedMerkleTree;
    tree.insertItem(20n, 234n);

    const exProof = tree.generateExclusionProof(30n);
    ok(tree.verifyProof(exProof));

    // Perform the state change
    tree.insertItem(30n, 123n);

    const proof = tree.generateProof(30n);
    ok(tree.verifyProof(proof));

    // TODO How to verify this transition without recreating the tree in the circuit?
    console.log('EXCLUSION', exProof)
    console.log('INCLUSION', proof);

  });
});

