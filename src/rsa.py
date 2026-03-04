from gmpy2 import iroot
from tqdm import tqdm
from Crypto.Util.number import long_to_bytes
import itertools
import gmpy2
import math
import sympy
import owiener
import sys


# ── Parsing ───────────────────────────────────────────────────────────────────

def parse_list(s: str) -> list[int]:
    """Parse a comma-separated string into a list of integers."""
    return list(map(int, s.split(",")))


# ── Math helpers ──────────────────────────────────────────────────────────────

def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm. Returns (gcd, x, y) s.t. a*x + b*y = gcd."""
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m. Raises ValueError if it doesn't exist."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist (gcd={g})")
    return x % m


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def int_to_bytes(i: int) -> bytes:
    if i == 0:
        return b"\x00"
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder="big")

def nth_root_gmp(x: int, n: int) -> int:
    return int(gmpy2.iroot(x, n)[0])


# ── Core RSA operations ───────────────────────────────────────────────────────

def compute_d(p: int, q: int, e: int) -> int:
    """Compute private exponent d from primes p, q and public exponent e."""
    return pow(e, -1, (p - 1) * (q - 1))

def decode_rsa(c: int, d: int, n: int) -> str:
    """Decrypt ciphertext c with private key (d, n) and decode as UTF-8."""
    return int_to_bytes(pow(c, d, n)).decode("utf-8")


# ── Factorisation ─────────────────────────────────────────────────────────────

def factor_rsa(n: int, max_fermat_iter: int = 1_000_000) -> list[int]:
    """
    Factor n using:
      1. Trivial even check
      2. Perfect-square check
      3. Fermat's method  (fast when p ≈ q)
      4. SymPy fallback   (general case)
    Returns [p, q].
    """
    if n % 2 == 0:
        return [2, n // 2]

    a = math.isqrt(n)
    if a * a == n:
        return [a, a]
    a += 1

    for _ in range(max_fermat_iter):
        b2 = a * a - n
        b  = math.isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p * q == n:
                return [p, q]
        a += 1

    factors = sympy.factorint(n)
    keys = list(factors.keys())
    if len(keys) == 2:
        return keys
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


def owiener_attack(e: int, n: int) -> int:
    """Wiener's attack: recover d when d is small relative to n."""
    d = owiener.attack(e, n)
    if d is None:
        print("[!] Wiener attack failed — d may not be small enough.", file=sys.stderr)
        sys.exit(1)
    return d


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


def common_modulus(n: int, c1: int, c2: int, e1: int, e2: int) -> str:
    """
    Common-modulus attack: same n, same plaintext, different coprime (e1, e2).
    """
    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError(f"gcd(e1, e2) = {g} ≠ 1 — attack requires coprime exponents")

    def _pow_maybe_neg(base: int, exp: int, mod: int) -> int:
        return pow(modinv(base, mod), -exp, mod) if exp < 0 else pow(base, exp, mod)

    recovered = (_pow_maybe_neg(c1, a, n) * _pow_maybe_neg(c2, b, n)) % n
    try:
        return int_to_bytes(recovered).decode()
    except Exception as exc:
        print(f"[!] Cannot decode plaintext: {exc}", file=sys.stderr)
        sys.exit(1)