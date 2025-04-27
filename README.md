# indexed-merkle-noir

[Indexed Merkle Tree](https://docs.aztec.network/aztec/concepts/advanced/storage/indexed_merkle_tree) implementation in Javascript and Noir

* Keys can be max 64-bit uints
* Values can be any field element
* Max tree size: 2^32 items

## Installation

```
$ git clone https://github.com/numtel/indexed-merkle-noir
$ cd indexed-merkle-noir
$ npm install

# Test javascript implementation
$ npm test

# Test noir implementation
$ nargo test
```

## License

MIT
