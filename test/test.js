import {ok} from 'node:assert';

import {IndexedMerkleTree} from '../index.js';

describe('IndexedMerkleTree', () => {
  it('should generate and verify proof of 4 items correctly', () => {
    const tree = new IndexedMerkleTree;
    tree.insertItem(30n, 123n);
    tree.insertItem(20n, 234n);
    tree.insertItem(10n, 345n);

    const proof = tree.generateProof(20n);
    ok(tree.verifyProof(proof));

    const exProof = tree.generateExclusionProof(13n);
    ok(tree.verifyProof(exProof));
  });

  it('should generate and verify proof of 5 items correctly', () => {
    const tree = new IndexedMerkleTree;
    tree.insertItem(30n, 123n);
    tree.insertItem(20n, 234n);
    tree.insertItem(10n, 345n);
    tree.insertItem(40n, 456n);

    const proof = tree.generateProof(20n);
    ok(tree.verifyProof(proof));

    const exProof = tree.generateExclusionProof(33n);
    ok(tree.verifyProof(exProof));
  });

  it('should generate and verify proof of 6 items correctly', () => {
    const tree = new IndexedMerkleTree;
    tree.insertItem(30n, 123n);
    tree.insertItem(20n, 234n);
    tree.insertItem(10n, 345n);
    tree.insertItem(40n, 456n);
    tree.insertItem(50n, 567n);

    const proof = tree.generateProof(20n);
    ok(tree.verifyProof(proof));

    const exProof = tree.generateExclusionProof(33n);
    ok(tree.verifyProof(exProof));
  });
});

