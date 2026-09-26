# shatter v2.2 — RSA CTF Attack Toolkit

A comprehensive RSA attack toolkit for CTF challenges: **17 attacks** behind a
single, colourful CLI. Point it at whatever you leaked — factors, a small `d`, a
shared modulus, `dp`/`dq`, partial keys — and it recovers the plaintext.

---

## ✨ Features

- 17 classical and modern RSA attacks in one command
- Colourful output via `rich` (with a plain-text fallback when `rich` is absent)
- Flexible integer input: **decimal by default**, `--hex` for hex, `0x…` always forced hex
- Automatic factorisation cascade (Fermat → ECM/Pollard-Brent → SymPy → FactorDB)
- Test suite and CI covering every attack

| Attack | Scenario |
|--------|----------|
| `p_and_q` | Both prime factors `p` and `q` are known |
| `known_p` | One prime factor is known — recover the other |
| `n_easy_factor` | Factor `n` automatically (Fermat / ECM / SymPy / FactorDB) |
| `factordb` | Factor `n` via the FactorDB online database |
| `small_e` | Small exponent / Coppersmith (e.g. `e=3`, unpadded) |
| `cube_root` | `e=3` and `m^3 < n`, so `c = m^3` exactly |
| `wiener` | Small private exponent `d < n^0.25 / 3` |
| `common_modulus` | Same `n`, same plaintext, two coprime exponents |
| `broadcast` | Håstad broadcast — same plaintext under `e` moduli |
| `crt_decrypt` | `dp` and `dq` are known (Garner CRT) |
| `dp_leak` | `dp = d mod (p-1)` leaked — recover `p` |
| `partial_d` | Lower half of `d` known (Boneh partial-key recovery) |
| `common_factor` | Two moduli share a prime — GCD attack |
| `multi_prime` | `n = p·q·r·…` (three or more primes) |
| `with_d` | The private exponent `d` is already known |
| `with_phi` | `phi(n)` is already known |
| `boneh_durfee` | Lattice attack for `d < N^0.292` (needs `fpylll`) |

---

## 🧱 Requirements

- **Python 3.10+** (uses `match` statements and PEP 585 generics)
- Dependencies: `pycryptodome`, `gmpy2`, `tqdm`, `sympy`, `owiener`, `requests`, `rich`
- For the Boneh-Durfee attack only: `pip install fpylll cysignals` (optional)

---

## 📦 Installation

```bash
git clone https://github.com/1r0nx/shatter.git
cd shatter
pip install -r requirements.txt
```

Run it from the `src/` directory:

```bash
cd src
python shatter.py <attack> [options]
python shatter.py <attack>     # help for that specific attack
python shatter.py --help       # list all attacks
```

---

## 🚀 Usage & Hex Mode

All integer arguments are **decimal** by default. Pass `--hex` (before the
sub-command) to interpret every integer as hexadecimal. An explicit `0x` prefix
always forces hex regardless of mode.

```bash
# decimal (default)
python shatter.py p_and_q -p 61 -q 53 -e 17 -c 2790

# hex mode — --hex goes before the attack name
python shatter.py --hex p_and_q -p 3d -q 35 -e 11 -c ae6
[*] Hex mode enabled — all integer inputs are interpreted as hexadecimal.
[*] Computing d from p and q…
✔ A

# 0x prefix forces hex even in decimal mode
python shatter.py p_and_q -p 0x3d -q 0x35 -e 0x11 -c 0xae6
```

Every run prints a banner and, on success, a green **Flag recovered** panel. In
the examples below the banner is trimmed and the recovered plaintext is shown as
`✔ <plaintext>`. All example commands are real and were run against `flag{demo}`.

---

## 📖 Attack Reference

| Sub-command      | Required arguments               | Description                                             |
|------------------|----------------------------------|---------------------------------------------------------|
| `p_and_q`        | `-p -q -e -c`                    | Known p and q → compute d, decrypt                      |
| `known_p`        | `-n -p -e -c`                    | One prime known → recover the other, decrypt            |
| `n_easy_factor`  | `-n -e -c [--no-ecm]`            | Auto-factorise n (Fermat → ECM → SymPy → FactorDB)      |
| `factordb`       | `-n -e -c`                       | Query FactorDB online → decrypt                         |
| `small_e`        | `-n -e -c`                       | Coppersmith / small-exponent attack                     |
| `cube_root`      | `-c`                             | Pure cube-root attack (c = m^3 exactly)                 |
| `wiener`         | `-n -e -c`                       | Wiener's attack (owiener then manual fallback)          |
| `common_modulus` | `-n -e1 -e2 -ct1 -ct2`           | Same n, same plaintext, two exponents                   |
| `broadcast`      | `-cs c1,c2,… -ns n1,n2,… -e`     | Håstad broadcast via CRT                                |
| `crt_decrypt`    | `-c -p -q -dp -dq`               | Garner CRT decryption when dp, dq are known             |
| `dp_leak`        | `-n -e -c -dp`                   | Recover p from dp = d mod (p-1)                         |
| `partial_d`      | `-n -e -c -d`                    | Partial private-key recovery (lower bits of d)          |
| `common_factor`  | `-n1 -n2 -e -ct1 -ct2`           | Two moduli share a prime → GCD attack, decrypt both     |
| `multi_prime`    | `-n -e -c`                       | Multi-prime RSA (n = p·q·r·…)                            |
| `with_d`         | `-n -d -c`                       | Direct decryption when d is known                       |
| `with_phi`       | `-n -e -c --phi`                 | Direct decryption when phi(n) is known                  |
| `boneh_durfee`   | `-n -e -c [--bd-delta] [--bd-m]` | Boneh-Durfee LLL lattice attack (d < N^0.292)           |

---

## 🔓 Worked Examples

### p_and_q — both factors known

```bash
python shatter.py p_and_q -p 204388393158487 -q 275539187709493 -e 65537 \
    -c 8588700201302142106390453939
[*] Computing d from p and q…
✔ flag{demo}
```

### known_p — one factor known

```bash
python shatter.py known_p -n 56317011828138004357263417091 -p 204388393158487 \
    -e 65537 -c 8588700201302142106390453939
[*] Recovering q from n / p…
✔ flag{demo}
```

### n_easy_factor — automatic factorisation

```bash
python shatter.py n_easy_factor -n 51031543659074410064875972819 -e 65537 \
    -c 51009689251824723521516516124
[*] Factorising n (Fermat → ECM → SymPy → FactorDB)…
[*] Found 2 factor(s):
    p1 = 225901623852221
    p2 = 225901623852239
✔ flag{demo}
```

### cube_root — e=3, m^3 < n

```bash
python shatter.py cube_root \
    -c 113155621913748575717230208182590225545024904959353396050706258235785829
[*] Running pure cube-root attack (e=3, c = m^3)…
✔ flag{demo}
```

### small_e — Coppersmith / short plaintext

```bash
python shatter.py small_e -n <n> -e 3 -c <c>
[*] Running Coppersmith / small-e attack (e=3)…
[*] c < n → possible small-exponent or short-plaintext attack.
✔ flag{demo}
```

### wiener — small private exponent

```bash
python shatter.py wiener -n <n> -e <large_e> -c <c>
[*] Running Wiener's attack (owiener → manual fallback)…
[*] d = 1029957427142612423426033
✔ flag{demo}
```

### common_modulus — same n, two exponents

```bash
python shatter.py common_modulus -n 220905638989996818020745112914383618221 \
    -e1 17 -e2 65537 \
    -ct1 31364589631794394330167068363419172069 \
    -ct2 170208369756201322152774717748316534443
[*] Running common-modulus attack…
✔ flag{demo}
```

### broadcast — Håstad (e=3, three pairs)

```bash
python shatter.py broadcast -e 3 \
    -cs c1,c2,c3 \
    -ns n1,n2,n3
[*] Running Håstad broadcast attack (e=3, 3 pairs)…
✔ flag{demo}
```

### crt_decrypt — dp and dq known

```bash
python shatter.py crt_decrypt -c 91916724361591422450181213292989240405 \
    -p 11275160485880705443 -q 15578587254480790871 \
    -dp 8983724159661239861 -dq 12091191529768221133
[*] Running CRT decryption (dp, dq known)…
✔ flag{demo}
```

### dp_leak — recover p from a leaked dp

```bash
python shatter.py dp_leak -n 175651071437566599009519591094034410853 \
    -e 65537 -c 91916724361591422450181213292989240405 \
    -dp 8983724159661239861
[*] Running dp-leak attack…
✔ flag{demo}
```

### common_factor — two moduli share a prime

```bash
python shatter.py common_factor -n1 <n1> -n2 <n2> -e 65537 -ct1 <c1> -ct2 <c2>
[*] Running common-factor (GCD) attack on n1, n2…
✔ flag{demo}   (from ct1)
✔ flag{demo}   (from ct2)
```

### multi_prime — n = p·q·r

```bash
python shatter.py multi_prime -n 11592513039338118027183247077160755430519747 \
    -e 65537 -c 2465779238201253643547985654295887079835232
[*] Running multi-prime factorisation attack (ECM/Pollard-Brent)…
✔ flag{demo}
```

### with_d / with_phi — direct decryption

```bash
python shatter.py with_d   -n <n> -d <d> -c <c>
python shatter.py with_phi -n <n> -e <e> -c <c> --phi <phi>
```

### factordb — factor online (requires internet)

```bash
python shatter.py factordb -n <n> -e <e> -c <c>
```

### boneh_durfee — lattice attack (requires fpylll)

```bash
# defaults: d < N^0.26, lattice size m=4
python shatter.py boneh_durfee -n <n> -e <e> -c <c>

# tuned: push delta up and enlarge the lattice
python shatter.py boneh_durfee -n <n> -e <e> -c <c> --bd-delta 0.28 --bd-m 6
```

---

## 🧪 Tests

The test suite lives in `src/test_shatter.py` and covers every attack, the math
helpers, factorisation methods, hex-input parsing, and the CLI.

```bash
cd src
python test_shatter.py            # run everything (unittest runner)
python test_shatter.py -v         # verbose
python test_shatter.py TestAttackWiener   # a single class
pytest                            # or via pytest
```

**74 tests.** They also run automatically on every push and pull request via
GitHub Actions (`.github/workflows/tests.yml`) across Python 3.10, 3.11 and 3.12.

---

## 🗂 Project Structure

```
shatter/
├── requirements.txt
├── README.md
├── .github/workflows/tests.yml   — CI: runs the suite on push / PR
└── src/
    ├── shatter.py          — CLI (argparse + rich)
    ├── rsa.py              — RSA primitives, factorisation, attacks
    ├── boneh_durfee.py     — Boneh-Durfee attack (LLL via fpylll, no SageMath)
    └── test_shatter.py     — test suite
```

---

## 🆕 What's New vs Original Shatter

| Feature                | v1  | v2.2   |
|------------------------|-----|--------|
| Attacks                | 5   | **17** |
| FactorDB online        | ✗   | ✓      |
| ECM / Pollard-Brent    | ✗   | ✓      |
| CRT decryption (dp/dq) | ✗   | ✓      |
| dp-leak attack         | ✗   | ✓      |
| Common factor (GCD)    | ✗   | ✓      |
| Multi-prime RSA        | ✗   | ✓      |
| Partial-d recovery     | ✗   | ✓      |
| Pure cube-root         | ✗   | ✓      |
| Wiener (unified)       | ✗   | ✓      |
| Known d / known phi    | ✗   | ✓      |
| Boneh-Durfee (LLL)     | ✗   | ✓      |
| Hex input (0x / raw)   | ✗   | ✓      |
| Automated tests + CI   | ✗   | ✓      |

---

## 🎯 Boneh-Durfee Tuning

The `boneh_durfee` attack uses LLL lattice reduction to recover `d` when
`d < N^delta`.

| Parameter    | Default | Effect                                            |
|--------------|---------|---------------------------------------------------|
| `--bd-delta` | `0.26`  | Bound `d < N^delta`. Theoretical max ≈ 0.292      |
| `--bd-m`     | `4`     | Lattice dimension. Higher = stronger but slower.  |

**Recommended approach:**
1. Try defaults: `--bd-delta 0.26 --bd-m 4`
2. If it fails, increase `--bd-m` (5, 6, 7, …)
3. If `d` is very close to `N^0.292`, try `--bd-delta 0.28` or `0.29`

Requires `pip install fpylll cysignals`.

---

## 📜 License

MIT License.

---

## 🤝 Contributing

Contributions and suggestions are welcome — open an issue or a pull request.
