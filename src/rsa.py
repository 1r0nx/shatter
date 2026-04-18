"""
rsa.py — Core RSA math, factorisation, and attack primitives for shatter.
Integrates all attacks from X-RSA plus original shatter functionality.
"""

from gmpy2 import iroot
from tqdm import tqdm
from Crypto.Util.number import long_to_bytes
import itertools
import gmpy2
import math
import sympy
import owiener
import sys
import requests
import random


# ── Parsing ───────────────────────────────────────────────────────────────────

# Global flag set by the CLI when --hex is passed.
# When True, all integer arguments are interpreted as hexadecimal.
HEX_MODE: bool = False


def parse_int(s: str) -> int:
    """
    Parse an integer string as decimal (default) or hex (when --hex is active).

    Decimal mode (default):
        "12345"    -> 12345

    Hex mode (--hex flag):
        "1a2b"     -> 6699
        "deadbeef" -> 3735928559

    An explicit 0x/0X prefix always forces hex regardless of mode:
        "0x1a2b"   -> 6699
    """
    s = s.strip()
    # Explicit 0x prefix always means hex
    if s.lower().startswith("0x"):
        return int(s, 16)
    # Otherwise defer to the active mode
    base = 16 if HEX_MODE else 10
    try:
        return int(s, base)
    except ValueError:
        mode = "hex" if HEX_MODE else "decimal"
        raise ValueError(
            f"Cannot parse {s!r} as a {mode} integer. "
            + ("Expected hex digits (e.g. 1a2b, deadbeef)." if HEX_MODE
               else "Expected decimal digits (e.g. 12345). Use --hex for hex input.")
        )


def parse_list(s: str) -> list[int]:
    """Parse a comma-separated string of integers (decimal or hex per active mode)."""
    return [parse_int(tok.strip()) for tok in s.split(",")]


# ── Math helpers ──────────────────────────────────────────────────────────────

def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm. Returns (gcd, x, y) s.t. a*x + b*y = gcd."""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m using pow(a, -1, m). Raises ValueError if it doesn't exist."""
    try:
        return pow(a, -1, m)
    except ValueError:
        raise ValueError(f"Modular inverse does not exist for a={a}, m={m}")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def int_to_bytes(i: int) -> bytes:
    if i == 0:
        return b"\x00"
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder="big")


def nth_root_gmp(x: int, n: int) -> int:
    return int(gmpy2.iroot(x, n)[0])


def isqrt_exact(n: int) -> int | None:
    """Return integer square root of n if n is a perfect square, else None."""
    r = math.isqrt(n)
    return r if r * r == n else None


def floorSqrt(n: int) -> int:
    """Integer square root (floor)."""
    return math.isqrt(n)


# ── Core RSA operations ───────────────────────────────────────────────────────

def compute_d(p: int, q: int, e: int) -> int:
    """Compute private exponent d from primes p, q and public exponent e."""
    return pow(e, -1, (p - 1) * (q - 1))


def compute_d_multi(primes: list[int], e: int) -> int:
    """Compute d for multi-prime RSA (any number of prime factors)."""
    phi = 1
    for p in primes:
        phi *= (p - 1)
    return pow(e, -1, phi)


def decode_rsa(c: int, d: int, n: int) -> str:
    """Decrypt ciphertext c with private key (d, n) and decode as UTF-8."""
    raw = int_to_bytes(pow(c, d, n))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def decode_raw(m: int) -> str:
    """Convert integer plaintext to string, trying UTF-8 then latin-1."""
    raw = long_to_bytes(m)
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return raw.decode("latin-1").strip()


# ── Factorisation ─────────────────────────────────────────────────────────────

def factor_fermat(n: int, max_iter: int = 1_000_000) -> list[int] | None:
    """
    Fermat's factorisation method. Fast when p ≈ q.
    Returns [p, q] or None if not found within max_iter.
    """
    a = math.isqrt(n)
    if a * a == n:
        return [a, a]
    a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p * q == n and p > 1 and q > 1:
                return [p, q]
        a += 1
    return None


def factor_factordb(n: int) -> list[int]:
    """
    Query factordb.com for the factorisation of n.
    Returns list of prime factors (with repetition) or empty list on failure.
    """
    try:
        endpoint = "http://factordb.com/api"
        result = requests.get(endpoint, params={"query": str(n)}, timeout=10)
        data = result.json()
        factors_raw = data.get("factors", [])
        if not factors_raw:
            return []
        expanded = []
        for factor, exp in factors_raw:
            expanded.extend([int(factor)] * exp)
        return expanded
    except Exception:
        return []


def factor_pollard_brent(n: int) -> int | None:
    """Pollard-Brent rho factorisation. Returns one non-trivial factor or None."""
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    y, c, m = random.randint(1, n - 1), random.randint(1, n - 1), random.randint(1, n - 1)
    g, r, q = 1, 1, 1
    x = ys = 0
    while g == 1:
        x = y
        for _ in range(r):
            y = (pow(y, 2, n) + c) % n
        k = 0
        while k < r and g == 1:
            ys = y
            for _ in range(min(m, r - k)):
                y = (pow(y, 2, n) + c) % n
                q = q * abs(x - y) % n
            g = math.gcd(q, n)
            k += m
        r *= 2
    if g == n:
        while True:
            ys = (pow(ys, 2, n) + c) % n
            g = math.gcd(abs(x - ys), n)
            if g > 1:
                break
    return g if g != n else None


def factor_ecm_primefactors(n: int) -> list[int]:
    """
    Factorisation via Pollard-Brent (ECM-like). Returns list of prime factors.
    Works well for semi-primes with medium-sized factors.
    """
    if n <= 1:
        return []
    if sympy.isprime(n):
        return [n]

    factors = []
    # Trial division for small primes
    for p in sympy.primerange(2, 10000):
        while n % p == 0:
            factors.append(p)
            n //= p
        if n == 1:
            return factors
        if sympy.isprime(n):
            factors.append(n)
            return factors

    # Pollard-Brent for larger factors
    stack = [n]
    while stack:
        num = stack.pop()
        if num == 1:
            continue
        if sympy.isprime(num):
            factors.append(num)
            continue
        f = None
        for _ in range(50):
            f = factor_pollard_brent(num)
            if f and f != num:
                break
        if f and f != num:
            stack.append(f)
            stack.append(num // f)
        else:
            # Fallback to sympy
            fs = sympy.factorint(num)
            for prime, exp in fs.items():
                factors.extend([prime] * exp)

    return sorted(factors)


def factor_rsa(n: int, use_factordb: bool = True, use_ecm: bool = True,
               max_fermat_iter: int = 1_000_000) -> list[int]:
    """
    Comprehensive factorisation cascade:
      1. Trivial even / perfect-square check
      2. Fermat's method       (fast when p approx q)
      3. Pollard-Brent / ECM   (medium factors, optional)
      4. SymPy general         (general fallback)
      5. FactorDB online       (last resort - requires internet, optional)
    Returns [p, q] (or more factors for multi-prime RSA).
    """
    if n % 2 == 0:
        return [2, n // 2]

    sq = isqrt_exact(n)
    if sq is not None:
        return [sq, sq]

    # 1. Fermat
    result = factor_fermat(n, max_fermat_iter)
    if result:
        return result

    # 2. ECM / Pollard-Brent
    if use_ecm:
        try:
            ecm_factors = factor_ecm_primefactors(n)
            if len(ecm_factors) >= 2:
                return ecm_factors
        except Exception:
            pass

    # 3. SymPy general
    try:
        sym_factors = sympy.factorint(n)
        result = []
        for prime, exp in sym_factors.items():
            result.extend([prime] * exp)
        if len(result) >= 2:
            return result
    except Exception:
        pass

    # 4. FactorDB - last resort (needs internet)
    if use_factordb:
        try:
            db_factors = factor_factordb(n)
            if len(db_factors) >= 2:
                return db_factors
        except Exception:
            pass

    print("[!] No factorisation found.", file=sys.stderr)
    sys.exit(1)


# ── Attacks ───────────────────────────────────────────────────────────────────

def coppersmiths_attack(n: int, e: int, c: int) -> str:
    """
    Small-exponent / short-plaintext attack.
    Iterates c + k*n until a perfect e-th root is found.
    """
    if c < n:
        print("[*] c < n → possible small-exponent or short-plaintext attack.")

    for k in tqdm(itertools.count(), desc="Coppersmith", unit=" iter"):
        candidate = c + n * k
        root, exact = iroot(candidate, e)
        if exact:
            break
    try:
        return long_to_bytes(int(root)).decode().strip()
    except Exception as exc:
        print(f"[!] Cannot decode plaintext: {exc}", file=sys.stderr)
        sys.exit(1)


def wiener_attack(e: int, n: int) -> int:
    """
    Wiener's attack: recover d when d < n^0.25 / 3.

    Tries two implementations in order:
      1. owiener library  (fast, algebraically proven)
      2. Manual continued-fraction implementation (pure Python fallback)

    Returns d (int). Raises ValueError if both methods fail.
    """
    # --- Method 1: owiener library ---
    try:
        d = owiener.attack(e, n)
        if d is not None:
            return d
    except Exception:
        pass

    # --- Method 2: manual continued fractions ---
    def continued_fraction(num, den):
        cf = []
        while den:
            cf.append(num // den)
            num, den = den, num % den
        return cf

    def convergents(cf):
        convs = []
        for i in range(len(cf)):
            if i == 0:
                convs.append((cf[0], 1))
            elif i == 1:
                convs.append((cf[1] * cf[0] + 1, cf[1]))
            else:
                h_prev, k_prev = convs[-1]
                h_prev2, k_prev2 = convs[-2]
                convs.append((cf[i] * h_prev + h_prev2, cf[i] * k_prev + k_prev2))
        return convs

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        b = n - phi + 1
        discriminant = b * b - 4 * n
        if discriminant >= 0:
            sq = math.isqrt(discriminant)
            if sq * sq == discriminant:
                return d

    raise ValueError(
        "Wiener attack failed — d may not be small enough (d must be < n^0.25 / 3).\n"
        "If d is slightly larger, consider the Boneh-Durfee attack instead."
    )


def chinese_remainder_theorem(cs: list[int], ns: list[int]) -> int:
    """CRT: given residues cs and moduli ns, return unique X mod ∏ns."""
    if len(cs) != len(ns):
        raise ValueError("cs and ns must have the same length")
    N = math.prod(ns)
    X = sum(
        ai * (N // ni) * pow(N // ni, -1, ni)
        for ai, ni in zip(cs, ns)
    )
    return X % N


def crt_decrypt(c: int, p: int, q: int, dp: int, dq: int) -> str:
    """
    Garner's CRT decryption using pre-computed dp, dq.
    Faster alternative when dp = d mod (p-1) and dq = d mod (q-1) are known.
    """
    q_inv = pow(p, -1, q)
    m1 = pow(c, dp, p)
    m2 = pow(c, dq, q)
    h = (q_inv * (m1 - m2)) % p
    m = m2 + h * q
    return decode_raw(m)


def common_modulus(n: int, c1: int, c2: int, e1: int, e2: int) -> str:
    """
    Common-modulus attack: same n, same plaintext, different coprime (e1, e2).
    Works even when Bezout coefficients are negative.
    """
    g, a, b = egcd(e1, e2)
    if g != 1:
        # Try with g-th root
        pass

    def _pow_maybe_neg(base: int, exp: int, mod: int) -> int:
        if exp < 0:
            return pow(pow(base, -1, mod), -exp, mod)
        return pow(base, exp, mod)

    recovered = (_pow_maybe_neg(c1, a, n) * _pow_maybe_neg(c2, b, n)) % n
    if g > 1:
        root, exact = iroot(recovered, g)
        if exact:
            recovered = int(root)
    return decode_raw(recovered)


def common_factor_attack(n1: int, n2: int, c1: int, c2: int, e: int) -> tuple[str, str]:
    """
    Common prime factor attack: two moduli sharing a prime factor.
    gcd(n1, n2) reveals p, then q1 = n1/p, q2 = n2/p.
    Returns (plaintext1, plaintext2).
    """
    p = math.gcd(n1, n2)
    if p == 1:
        raise ValueError("gcd(n1, n2) = 1 — no common factor found")
    q1, q2 = n1 // p, n2 // p
    d1 = compute_d(p, q1, e)
    d2 = compute_d(p, q2, e)
    m1 = decode_raw(pow(c1, d1, n1))
    m2 = decode_raw(pow(c2, d2, n2))
    return m1, m2


def dp_leak_attack(n: int, e: int, dp: int, c: int) -> str:
    """
    dp-leak attack: recover p from dp = d mod (p-1).
    Searches for p by iterating k in (e*dp - 1) = k*(p-1).
    """
    mp = (dp * e) - 1
    for k in range(2, 1_000_000):
        if mp % k == 0:
            p_candidate = (mp // k) + 1
            if n % p_candidate == 0 and p_candidate > 1:
                p = p_candidate
                q = n // p
                d = compute_d(p, q, e)
                return decode_raw(pow(c, d, n))
    raise ValueError("dp-leak attack failed: no valid p found within search bound")


def partial_d_attack(n: int, e: int, d_partial: int, c: int) -> str:
    """
    Partial private key recovery (Boneh-Durfee half-d attack).
    Works when the lower half of d is known, for standard key sizes (2048/4096 bit).
    """
    import sympy as sp

    bit_len_d0 = 2048
    n_bits = int(sp.floor(sp.log(n) / sp.log(2)) + 1)

    test1 = pow(3, e, n)
    test2 = pow(5, e, n)

    for k in range(1, e):
        d = ((k * n + 1) // e)
        d >>= bit_len_d0
        d <<= bit_len_d0
        d |= d_partial
        if (e * d) % k == 1:
            if pow(test1, d, n) == 3:
                if pow(test2, d, n) == 5:
                    return decode_raw(pow(c, d, n))
    raise ValueError("Partial-d attack failed — no valid d found")


def decrypt_with_d(c: int, d: int, n: int) -> str:
    """Straightforward RSA decryption when d is already known."""
    return decode_raw(pow(c, d, n))


def decrypt_with_known_phi(c: int, n: int, e: int, phi: int) -> str:
    """Decrypt when phi(n) is directly known."""
    d = pow(e, -1, phi)
    return decode_raw(pow(c, d, n))


def multi_prime_attack(c: int, n: int, e: int, use_ecm: bool = True) -> str:
    """
    Multi-prime RSA attack: factor n (possibly into 3+ primes) via ECM/Pollard-Brent,
    then reconstruct phi and decrypt.
    """
    primes = factor_ecm_primefactors(n)
    if not primes:
        raise ValueError("Could not factorise n for multi-prime attack")
    phi = 1
    for p in primes:
        phi *= (p - 1)
    d = pow(e, -1, phi)
    return decode_raw(pow(c, d, n))


def cube_root_attack(c: int) -> str:
    """
    Pure cube-root attack (e=3, no padding, m^3 < n so c = m^3 exactly).
    """
    root, exact = gmpy2.iroot(c, 3)
    if not exact:
        raise ValueError("c is not a perfect cube — use small_e attack instead")
    return decode_raw(int(root))


def factordb_attack(c: int, n: int, e: int) -> str:
    """
    Attack using FactorDB to factor n online, then decrypt.
    """
    factors = factor_factordb(n)
    if len(factors) < 2:
        raise ValueError("FactorDB could not factor n")
    if len(factors) == 2:
        p, q = factors
        d = compute_d(p, q, e)
    else:
        phi = 1
        for p in factors:
            phi *= (p - 1)
        d = pow(e, -1, phi)
        n_check = 1
        for p in factors:
            n_check *= p
        n = n_check
    return decode_raw(pow(c, d, n))


def known_p_attack(c: int, n: int, e: int, p: int) -> str:
    """
    Attack when one prime factor p (or q) is known.
    Recovers the other factor by division.
    """
    if n % p != 0:
        raise ValueError("p does not divide n — incorrect prime provided")
    q = n // p
    d = compute_d(p, q, e)
    return decode_raw(pow(c, d, n))
