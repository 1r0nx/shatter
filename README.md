# shatter v2.2 — RSA CTF Attack Toolkit

A comprehensive RSA attack toolkit for CTF challenges.
**17 attacks** in a clean CLI — more powerful than X-RSA, better structured than the original shatter.

---

## Disclaimer
This have been write with x-rsa as an inspiration and with the use of claude AI

---

## Installation

```bash
pip install -r requirements.txt
```

**Dependencies:** `pycryptodome`, `gmpy2`, `tqdm`, `sympy`, `owiener`, `requests`, `rich`  
**For Boneh-Durfee:** `pip install fpylll cysignals` (optional)

---

## Usage

```bash
# From the src/ directory
python shatter.py <attack> [options]
python shatter.py <attack>     # print help for that specific attack
python shatter.py --help       # list all attacks
```

All integer arguments accept **decimal or hex** (with or without `0x` prefix):

```bash
python shatter.py p_and_q -p 61 -q 53 -e 17 -c 2790          # decimal
python shatter.py p_and_q -p 0x3d -q 0x35 -e 0x11 -c 0xae6   # hex with 0x
python shatter.py p_and_q -p 3d -q 35 -e 11 -c ae6            # hex without prefix
```

---

## Attack Reference

| Sub-command      | Required arguments                       | Description                                              |
|------------------|------------------------------------------|----------------------------------------------------------|
| `p_and_q`        | `-p -q -e -c`                            | Known p and q -> compute d, decrypt                     |
| `known_p`        | `-n -p -e -c`                            | One prime factor known -> recover the other, decrypt     |
| `n_easy_factor`  | `-n -e -c [--no-ecm]`                    | Auto-factorise n (Fermat -> ECM -> SymPy -> FactorDB)   |
| `factordb`       | `-n -e -c`                               | Query FactorDB online directly -> decrypt                |
| `small_e`        | `-n -e -c`                               | Coppersmith / small exponent attack (e.g. e=3)           |
| `cube_root`      | `-c`                                     | Pure cube-root attack (c = m^3 exactly, no mod reduction)|
| `wiener`         | `-n -e -c`                               | Wiener's attack (owiener library then manual fallback)  |
| `common_modulus` | `-n -e1 -e2 -ct1 -ct2`                  | Same n, same plaintext, two different exponents          |
| `broadcast`      | `-cs c1,c2,.. -ns n1,n2,.. -e`          | Hastad's broadcast attack via CRT                      |
| `crt_decrypt`    | `-c -p -q -dp -dq`                       | CRT decryption when dp and dq are known                  |
| `dp_leak`        | `-n -e -c -dp`                           | dp-leak: recover p from dp = d mod (p-1)                 |
| `partial_d`      | `-n -e -c -d`                            | Partial private key recovery (lower bits of d known)     |
| `common_factor`  | `-n1 -n2 -e -ct1 -ct2`                  | Two moduli share a prime -> GCD attack, decrypt both     |
| `multi_prime`    | `-n -e -c`                               | Multi-prime RSA (n=p*q*r*...) via ECM/Pollard-Brent      |
| `with_d`         | `-n -d -c`                               | Direct decryption when d is already known                |
| `with_phi`       | `-n -e -c --phi`                         | Direct decryption when phi(n) is already known           |
| `boneh_durfee`   | `-n -e -c [--bd-delta] [--bd-m]`        | Boneh-Durfee LLL lattice attack (d < N^0.292)            |

---

## Examples

```bash
# Known p and q
python shatter.py p_and_q -p <p> -q <q> -e 65537 -c <c>

# One prime factor known (leaked, etc.)
python shatter.py known_p -n <n> -p <p> -e 65537 -c <c>

# Automatic factorisation (Fermat -> ECM -> SymPy -> FactorDB as last resort)
python shatter.py n_easy_factor -n <n> -e 65537 -c <c>

# Query FactorDB directly (requires internet)
python shatter.py factordb -n <n> -e 65537 -c <c>

# Wiener's attack (small d)
python shatter.py wiener -n <n> -e <large_e> -c <c>

# Hastad broadcast attack (e=3, three pairs)
python shatter.py broadcast -cs c1,c2,c3 -ns n1,n2,n3 -e 3

# CRT decryption with dp and dq
python shatter.py crt_decrypt -c <c> -p <p> -q <q> -dp <dp> -dq <dq>

# dp leak only (p and q unknown)
python shatter.py dp_leak -n <n> -e <e> -dp <dp> -c <c>

# Two moduli sharing a prime factor
python shatter.py common_factor -n1 <n1> -n2 <n2> -e <e> -ct1 <c1> -ct2 <c2>

# Multi-prime RSA (n = p*q*r)
python shatter.py multi_prime -n <n> -e <e> -c <c>

# Known phi(n)
python shatter.py with_phi -n <n> -e <e> -c <c> --phi <phi>

# Boneh-Durfee (d < N^0.26, default settings)
python shatter.py boneh_durfee -n <n> -e <e> -c <c>

# Boneh-Durfee with tuned parameters
python shatter.py boneh_durfee -n <n> -e <e> -c <c> --bd-delta 0.28 --bd-m 6
```

---

## Running the Tests

```bash
cd src/
python test_shatter.py           # run all tests
python test_shatter.py -v        # verbose output
python test_shatter.py TestAttackWiener   # run a single test class
```

**70 tests** covering all attacks, math helpers, factorisation methods, hex input parsing, and the CLI.

---

## Project Structure

```
shatter_v2/
├── requirements.txt
├── README.md
└── src/
    ├── shatter.py          — main CLI (argparse + rich)
    ├── rsa.py              — RSA primitives, factorisation, 17 attacks
    ├── boneh_durfee.py     — Boneh-Durfee attack (LLL via fpylll, no SageMath)
    └── test_shatter.py     — test suite (70 tests)
```

---

## What's New vs Original Shatter

| Feature                   | v1  | v2.2    |
|---------------------------|-----|---------|
| Attacks                   | 5   | **17**  |
| FactorDB online           | x   | yes     |
| ECM / Pollard-Brent       | x   | yes     |
| CRT decryption (dp/dq)    | x   | yes     |
| dp-leak attack            | x   | yes     |
| Common factor (GCD)       | x   | yes     |
| Multi-prime RSA           | x   | yes     |
| Partial d recovery        | x   | yes     |
| Pure cube-root            | x   | yes     |
| Known one factor          | x   | yes     |
| Wiener (unified)          | x   | yes     |
| Known d / known phi       | x   | yes     |
| Boneh-Durfee (LLL)        | x   | yes     |
| Hex input (0x / raw)      | x   | yes     |
| Automated tests           | x   | **70**  |
| Multi-result display      | x   | yes     |

---

## Boneh-Durfee Tuning

The `boneh_durfee` attack uses LLL lattice reduction to recover `d` when `d < N^delta`.

| Parameter     | Default | Effect                                                     |
|---------------|---------|------------------------------------------------------------|
| `--bd-delta`  | `0.26`  | Upper bound for d: `d < N^delta`. Theoretical max ~0.292  |
| `--bd-m`      | `4`     | Lattice dimension. Higher = stronger but slower.           |

**Recommended approach:**
1. Try defaults first: `--bd-delta 0.26 --bd-m 4`
2. If it fails, increment `--bd-m` (5, 6, 7...)
3. If d is very close to N^0.292, try `--bd-delta 0.28` or `0.29`

Requires: `pip install fpylll cysignals`

