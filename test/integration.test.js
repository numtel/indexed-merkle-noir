import {ok} from 'node:assert';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { compile, createFileManager } from '@noir-lang/noir_wasm';
import { UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';

import {IndexedMerkleTree} from '../index.js';

const MAX_DEPTH = 32;

describe('Integration Tests', () => {
  it('should generate and verify inclusion proof', async () => {
    const compiledCircuit = await compile(createFileManager(resolve(
      dirname(fileURLToPath(import.meta.url)),
      'circuits/verifyProof'
    )));
    const noir = new Noir(compiledCircuit.program);
    const backend = new UltraHonkBackend(compiledCircuit.program.bytecode, { threads: os.cpus().length });

    const tree = new IndexedMerkleTree;
    tree.insertItem(10n, 123n);
    tree.insertItem(12n, 123n);
    tree.insertItem(14n, 123n);
    tree.insertItem(16n, 123n);
    tree.insertItem(18n, 123n);
    tree.insertItem(20n, 123n);
    const merkleProof = tree.generateProof(16n);

    const inputs = {
      leafIdx: merkleProof.leafIdx,
      leafKey: merkleProof.leaf.key.toString(10),
      leafNextIdx: merkleProof.leaf.nextIdx,
      leafNextKey: merkleProof.leaf.nextKey.toString(10),
      leafValue: merkleProof.leaf.value.toString(10),
      root: merkleProof.root.toString(10),
      siblings: expandArray(merkleProof.siblings.map(x => x.toString(10)), MAX_DEPTH, 0)
    };

    const { witness } = await noir.execute(inputs);
    const { proof, publicInputs } = await backend.generateProof(witness);

    ok(await backend.verifyProof({ proof, publicInputs }));

  });

  it('should generate and verify exclusion proof', async () => {
    const compiledCircuit = await compile(createFileManager(resolve(
      dirname(fileURLToPath(import.meta.url)),
      'circuits/verifyExclusionProof'
    )));
    const noir = new Noir(compiledCircuit.program);
    const backend = new UltraHonkBackend(compiledCircuit.program.bytecode, { threads: os.cpus().length });

    const tree = new IndexedMerkleTree;
    const excludedKey = 16n;
    tree.insertItem(10n, 123n);
    const merkleProof = tree.generateExclusionProof(excludedKey);

    const inputs = {
      leafIdx: merkleProof.leafIdx,
      leafKey: merkleProof.leaf.key.toString(10),
      leafNextIdx: merkleProof.leaf.nextIdx,
      leafNextKey: merkleProof.leaf.nextKey.toString(10),
      leafValue: merkleProof.leaf.value.toString(10),
      root: merkleProof.root.toString(10),
      siblings: expandArray(merkleProof.siblings.map(x => x.toString(10)), MAX_DEPTH, 0),
      excludedKey: excludedKey.toString(10)
    };

    const { witness } = await noir.execute(inputs);
    const { proof, publicInputs } = await backend.generateProof(witness);

    ok(await backend.verifyProof({ proof, publicInputs }));

  });

  it('should generate and verify insertion proof', async () => {
    const compiledCircuit = await compile(createFileManager(resolve(
      dirname(fileURLToPath(import.meta.url)),
      'circuits/verifyInsertionProof'
    )));
    const noir = new Noir(compiledCircuit.program);
    const backend = new UltraHonkBackend(compiledCircuit.program.bytecode, { threads: os.cpus().length });

    const tree = new IndexedMerkleTree;
    tree.insertItem(10n, 123n);
    tree.insertItem(15n, 123n);
    tree.insertItem(40n, 123n);
    tree.insertItem(45n, 123n);
    const insertionProof = tree.insertItem(20n, 123n);
    const inputs = membersToStrings(insertionProof);

    const { witness } = await noir.execute(inputs);
    const { proof, publicInputs } = await backend.generateProof(witness);

    ok(await backend.verifyProof({ proof, publicInputs }));

  });

  it('should generate and verify insertion proof of first item', async () => {
    const compiledCircuit = await compile(createFileManager(resolve(
      dirname(fileURLToPath(import.meta.url)),
      'circuits/verifyInsertionProof'
    )));
    const noir = new Noir(compiledCircuit.program);
    const backend = new UltraHonkBackend(compiledCircuit.program.bytecode, { threads: os.cpus().length });

    const tree = new IndexedMerkleTree;
    const insertionProof = tree.insertItem(20n, 123n);
    const inputs = membersToStrings(insertionProof);

    const { witness } = await noir.execute(inputs);
    const { proof, publicInputs } = await backend.generateProof(witness);

    ok(await backend.verifyProof({ proof, publicInputs }));

  });
});

function expandArray(arr, len, fill) {
  return [...arr, ...Array(len - arr.length).fill(fill)];
}

function membersToStrings(obj) {
  const out = {};
  for(let key of Object.keys(obj)) {
    if(obj[key] instanceof Array) {
      out[key] = expandArray(obj[key].map(x => x.toString(10)), MAX_DEPTH, '0');
    } else {
      out[key] = obj[key].toString(10);
    }
  }
  return out;
}
