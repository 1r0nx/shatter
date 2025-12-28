from gmpy2 import iroot
from tqdm import tqdm
from Crypto.Util.number import long_to_bytes, bytes_to_long
import itertools
import gmpy2
import json
import math
import sympy
import owiener
import sys


def parse_list(s):
    return list(map(int, s.split(",")))


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = egcd(b, a % b)
        return (g, y1, x1 - (a // b) * y1)


def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Inverse modular do not exist")
    return x % m


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def int_to_bytes(i: int) -> bytes:
    if i == 0:
        return b"\x00"
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder="big")


def compute_d(p, q, e):
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    return d


def decode_rsa(c, d, n):
    int_flag = pow(c, d, n)
    hex_flag = hex(int_flag)[2:]
    str_flag = bytes.fromhex(hex_flag).decode("utf-8")
    return str_flag


def factor_rsa(n, max_fermat_iter=1000000):
    """
    Try n with two methods :
    1. Fermat factorisation if numbers are close
    2. Else sympy factorization will be used
    """

    if n % 2 == 0:
        return [2, n // 2]

    a = math.isqrt(n)
    if a * a == n:
        return [a, a]
    a += 1

    for _ in range(max_fermat_iter):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            if p * q == n:
                return [p, q]
        a += 1

    # If Fermat is slow, we try SymPy
    factors = sympy.factorint(n)
    if len(factors) == 2:
        p = list(factors.keys())[0]
        q = list(factors.keys())[1]
        print(p, q)
        return [p, q]
    else:
        print("\nNo possible factorization!")
        sys.exit(0)


def coppersmiths_attack(n, e, c):
    if c < n:
        print("\npossible small exponent or short plain text attack\n")

    for k in tqdm(itertools.count()):
        c_before_mod = c + n * k
        if iroot(c_before_mod, e)[1]:
            break

    try:
        plaintext = long_to_bytes(iroot(c_before_mod, e)[0])
        return plaintext.decode().strip(" ")
    except:
        print("\nCannot decode in text!")
        sys.exit(0)


def owiener_attack(e, n):
    d = owiener.attack(e, n)
    return d


def nth_root_gmp(x, n):
    return int(gmpy2.iroot(x, n)[0])


def chinese_remainder_theorem(cs, ns):
    if len(cs) != len(ns):
        raise ValueError("cs et ns need to have the same size")

    N = 1
    for n in ns:
        N *= n

    X = 0
    for ai, ni in zip(cs, ns):
        Ni = N // ni  # N_i
        Mi = pow(Ni, -1, ni)
        X += ai * Ni * Mi

    return X % N


def common_modulus(n, c1, c2, e1, e2):
    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError("e1 and e2 are not prime together")

    if a < 0:
        inv_c1 = modinv(c1, n)
        part1 = pow(inv_c1, -a, n)
    else:
        part1 = pow(c1, a, n)

    if b < 0:
        inv_c2 = modinv(c2, n)
        part2 = pow(inv_c2, -b, n)
    else:
        part2 = pow(c2, b, n)

    recovered = (part1 * part2) % n
    try:
        recovered_text = int_to_bytes(recovered).decode()
        return recovered_text
    except:
        print("\nCannot decode as text!")
        sys.exit(0)
