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
        const transition = tree.insertItem(10n * BigInt(i), 123n * BigInt(i));
        ok(tree.verifyInsertionProof(transition));
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

  it('should generate and verify insertion proof from further leaves', () => {
    const tree = new IndexedMerkleTree;

    // Insert items such that the test item won't be neigbor to its previous item
    tree.insertItem(20n, 234n);
    tree.insertItem(22n, 234n);
    tree.insertItem(23n, 234n);
    tree.insertItem(24n, 234n);
    tree.insertItem(25n, 234n);
    tree.insertItem(26n, 234n);
    tree.insertItem(27n, 234n);
    tree.insertItem(28n, 234n);

    const transition = tree.insertItem(21n, 123n);

    ok(tree.verifyInsertionProof(transition))
  });
});

