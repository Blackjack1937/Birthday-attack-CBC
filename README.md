# Birthday Attack on CBC Mode (SPECK)

This project implements CBC encryption using SPECK block cipher variants and demonstrates a birthday attack on CBC mode.

## 🔧 Compilation

To compile the tests, use the `Makefile` with a specified block size:

```bash
make BLOCKSIZE=32   # Options: 32, 48, or 64
```

This compiles:

- test_speck – for testing standalone SPECK encryption/decryption.
- test_cbc – for testing CBC encryption/decryption.
- test_attack – for testing the birthday attack.

## Running the Tests

1. Test SPECK encryption/decryption:

```bash
./test_speck
```

2. Test CBC encryption/decryption:

```bash
./test_cbc
```

3. Run the birthday attack:

```bash
./test_attack
```

The attack tries to find two ciphertext blocks that collide and reveals the XOR of their corresponding plaintext blocks.

## Cleaning Up

To remove compiled files:

```bash
make clean
```

Note: Default block size is 32. It's possible to change it at any time by rerunning make with a new BLOCKSIZE value.