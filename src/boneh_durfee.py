"""
boneh_durfee.py — Boneh-Durfee attack (pure Python, no SageMath required)

Recovers the private exponent d when d < N^delta (theoretical max delta ≈ 0.292).
Uses fpylll for LLL lattice reduction.

Based on:
  - D. Boneh, G. Durfee, "Cryptanalysis of RSA with private key d less than N^0.292"
  - M. Herrmann, A. May, "Maximizing Small Root Bounds by Linearization and Applications to…"
"""

from __future__ import annotations
import math
import sys

try:
    from fpylll import IntegerMatrix, LLL
    HAS_FPYLLL = True
except ImportError:
    HAS_FPYLLL = False


# ── Integer polynomial helpers ─────────────────────────────────────────────────

class Poly:
    """
    Minimal multivariate integer polynomial over variables x, y, u (u = x*y + 1).
    Stored as dict mapping (px, py) exponent tuples to integer coefficients.
    """

    def __init__(self, coeffs: dict | None = None):
        self.coeffs: dict[tuple[int, int], int] = coeffs or {}

    def __add__(self, other: "Poly") -> "Poly":
        res = dict(self.coeffs)
        for k, v in other.coeffs.items():
            res[k] = res.get(k, 0) + v
        return Poly({k: v for k, v in res.items() if v != 0})

    def __mul__(self, other: "Poly | int") -> "Poly":
        if isinstance(other, int):
            return Poly({k: v * other for k, v in self.coeffs.items()})
        res: dict[tuple[int, int], int] = {}
        for (px1, py1), v1 in self.coeffs.items():
            for (px2, py2), v2 in other.coeffs.items():
                k = (px1 + px2, py1 + py2)
                res[k] = res.get(k, 0) + v1 * v2
        return Poly({k: v for k, v in res.items() if v != 0})

    def __rmul__(self, other: int) -> "Poly":
        return self.__mul__(other)

    def __pow__(self, exp: int) -> "Poly":
        result = Poly({(0, 0): 1})
        base = self
        while exp > 0:
            if exp & 1:
                result = result * base
            base = base * base
            exp >>= 1
        return result

    def eval(self, x: int, y: int) -> int:
        total = 0
        for (px, py), coef in self.coeffs.items():
            total += coef * pow(x, px) * pow(y, py)
        return total

    def scale(self, X: int, Y: int) -> "Poly":
        """Scale monomial x^px * y^py by X^px * Y^py (for lattice construction)."""
        return Poly({
            (px, py): coef * pow(X, px) * pow(Y, py)
            for (px, py), coef in self.coeffs.items()
        })

    def monomials(self) -> list[tuple[int, int]]:
        return sorted(self.coeffs.keys())

    def coeff_at(self, mon: tuple[int, int]) -> int:
        return self.coeffs.get(mon, 0)

    @staticmethod
    def x() -> "Poly":
        return Poly({(1, 0): 1})

    @staticmethod
    def y() -> "Poly":
        return Poly({(0, 1): 1})

    @staticmethod
    def one() -> "Poly":
        return Poly({(0, 0): 1})


def _resultant_univariate(p1_coeffs: list[int], p2_coeffs: list[int]) -> list[int]:
    """
    Compute the resultant of two univariate polynomials via Sylvester matrix.
    Both are given as coefficient lists (index = degree).
    Returns coefficients of the resultant polynomial in y.
    """
    # This is a simplified approach — we solve for roots directly
    # via GCD on integer polynomials, used only when needed.
    raise NotImplementedError("Use _find_roots_univariate directly")


def _find_roots_univariate(coeffs: list[int], bound: int) -> list[int]:
    """
    Find integer roots of a univariate polynomial with integer coefficients.
    coeffs[i] = coefficient of x^i.
    Only returns roots |r| <= bound.
    """
    roots = []
    # rational root theorem: try divisors of constant term
    c0 = abs(coeffs[0]) if coeffs[0] != 0 else 0
    if c0 == 0:
        roots.append(0)
        # deflate
        while len(coeffs) > 1 and coeffs[0] == 0:
            coeffs = coeffs[1:]
        c0 = abs(coeffs[0]) if coeffs[0] != 0 else 1

    candidates: set[int] = set()
    # trial divisors up to min(c0, bound)
    limit = min(c0, bound)
    for d in range(1, int(limit**0.5) + 2):
        if c0 % d == 0:
            candidates.add(d)
            candidates.add(c0 // d)
    # also try small integers directly
    for v in range(-min(bound, 10**6), min(bound, 10**6) + 1):
        candidates.add(v)

    def poly_eval(coeffs, x):
        res = 0
        for i, c in enumerate(coeffs):
            res += c * pow(x, i)
        return res

    for r in sorted(candidates, key=abs):
        if abs(r) <= bound and poly_eval(coeffs, r) == 0:
            roots.append(r)

    return list(set(roots))


# ── LLL-based Boneh-Durfee ────────────────────────────────────────────────────

def boneh_durfee(N: int, e: int, delta: float = 0.26, m: int = 4) -> int | None:
    """
    Boneh-Durfee attack via LLL lattice reduction.

    Recovers d when d < N^delta. Theoretical limit is delta < 0.292.
    In practice, delta=0.26 works reliably; increase m for harder cases.

    Parameters
    ----------
    N     : RSA modulus
    e     : public exponent
    delta : upper bound exponent for d (d < N^delta), default 0.26
    m     : lattice parameter (bigger = stronger but slower), default 4

    Returns
    -------
    d (int) if found, None otherwise.
    """
    if not HAS_FPYLLL:
        raise ImportError(
            "fpylll is required for the Boneh-Durfee attack.\n"
            "Install it with: pip install fpylll cysignals"
        )

    # Herrmann-May parameterisation
    t = int((1 - 2 * delta) * m)
    X = int(2 * N**delta)
    Y = int(N**0.5)

    A = (N + 1) // 2  # ≈ (p+q)/2

    # The polynomial: f(x,y) = 1 + x*(A + y)   where x = k, y = (p+q)/2 - A
    # We search for small roots x0, y0 satisfying e*d = 1 + k*phi(N)
    # => pol(k, (p+q)/2 - A) = 0 mod e

    px = Poly.x()
    py = Poly.y()
    one = Poly.one()

    pol = one + px * (Poly({(0, 0): A}) + py)  # 1 + x*(A+y)

    # Build shift polynomials (Herrmann-May)
    g_polys: list[Poly] = []

    # x-shifts
    for k in range(m + 1):
        for i in range(m - k + 1):
            shift = (px**i) * (pol**k) * e**(m - k)
            g_polys.append(shift)

    # y-shifts
    for j in range(1, t + 1):
        for k in range(math.floor(m / t) * j, m + 1):
            shift = (py**j) * (pol**k) * e**(m - k)
            g_polys.append(shift)

    # Collect all monomials
    all_mons: set[tuple[int, int]] = set()
    for g in g_polys:
        all_mons.update(g.monomials())
    mons = sorted(all_mons)
    n_rows = len(g_polys)
    n_cols = len(mons)
    mon_idx = {mon: i for i, mon in enumerate(mons)}

    # Build the lattice matrix (scaled by X^px * Y^py)
    dim = min(n_rows, n_cols)
    B = IntegerMatrix(dim, dim)
    for row_i, g in enumerate(g_polys[:dim]):
        g_scaled = g.scale(X, Y)
        for mon, coef in g_scaled.coeffs.items():
            col_i = mon_idx.get(mon)
            if col_i is not None and col_i < dim:
                B[row_i, col_i] = int(coef)

    # LLL reduction
    LLL.reduction(B)

    # Extract two short vectors and form polynomials
    def row_to_poly(row_idx: int) -> Poly:
        p = Poly()
        for col_i, mon in enumerate(mons[:dim]):
            if col_i < dim:
                coef_scaled = B[row_idx, col_i]
                if coef_scaled != 0:
                    Xpx = pow(X, mon[0])
                    Ypy = pow(Y, mon[1])
                    denom = Xpx * Ypy
                    if denom != 0 and coef_scaled % denom == 0:
                        p.coeffs[mon] = coef_scaled // denom
                    else:
                        # approximate — keep as-is divided by gcd
                        g = math.gcd(abs(coef_scaled), denom) if denom else 1
                        p.coeffs[mon] = coef_scaled // g
        return p

    # Try pairs of LLL vectors to find resultant roots
    for i in range(min(dim - 1, 6)):
        for j in range(i + 1, min(dim, 8)):
            p1 = row_to_poly(i)
            p2 = row_to_poly(j)

            # Specialise to x only: substitute specific y values to find common root
            # Strategy: try small y values, find common x root
            for y_try in range(-min(Y, 1000), min(Y, 1000) + 1):
                # evaluate both polys at this y, get univariate in x
                def eval_at_y(poly: Poly, y_val: int) -> dict[int, int]:
                    coeffs_x: dict[int, int] = {}
                    for (px_exp, py_exp), c in poly.coeffs.items():
                        contrib = c * pow(y_val, py_exp)
                        coeffs_x[px_exp] = coeffs_x.get(px_exp, 0) + contrib
                    return coeffs_x

                c1 = eval_at_y(p1, y_try)
                c2 = eval_at_y(p2, y_try)

                max_deg = max((max(c1.keys(), default=0), max(c2.keys(), default=0)))
                uc1 = [c1.get(d, 0) for d in range(max_deg + 1)]
                uc2 = [c2.get(d, 0) for d in range(max_deg + 1)]

                # Find gcd of the two polynomials in x
                def poly_gcd(a: list[int], b: list[int]) -> list[int]:
                    while any(b):
                        # pseudo-division
                        while len(a) < len(b):
                            a.append(0)
                        while len(b) < len(a):
                            b.append(0)
                        if len(a) == 0:
                            break
                        # trim trailing zeros
                        while len(a) > 1 and a[-1] == 0:
                            a.pop()
                        while len(b) > 1 and b[-1] == 0:
                            b.pop()
                        if len(a) < len(b):
                            a, b = b, a
                        if len(b) == 1:
                            if b[0] == 0:
                                break
                            # remainder of a mod b[0]
                            g = math.gcd(*[abs(x) for x in a if x != 0] + [abs(b[0])])
                            a = [x // g for x in a]
                            b = [b[0] // g]
                            break
                        # one pseudo-division step
                        lc_b = b[-1]
                        deg_a, deg_b = len(a) - 1, len(b) - 1
                        if deg_a < deg_b:
                            a, b = b, a
                            deg_a, deg_b = deg_b, deg_a
                        # multiply a by lc_b^(deg_a-deg_b+1), then subtract
                        factor = pow(lc_b, deg_a - deg_b + 1)
                        a_new = [x * factor for x in a]
                        lc_a = a_new[-1]
                        shift = deg_a - deg_b
                        for k_i, bk in enumerate(b):
                            a_new[k_i + shift] -= bk * lc_a // lc_b if lc_b != 0 else 0
                        while len(a_new) > 1 and a_new[-1] == 0:
                            a_new.pop()
                        # content removal
                        gc = math.gcd(*[abs(x) for x in a_new if x != 0]) if any(a_new) else 1
                        a = b
                        b = [x // gc for x in a_new] if gc > 0 else a_new
                    return a

                # Try integer root search on each univariate
                for coeffs_dict in [c1, c2]:
                    if not coeffs_dict:
                        continue
                    max_d = max(coeffs_dict.keys(), default=0)
                    uni = [coeffs_dict.get(d, 0) for d in range(max_d + 1)]
                    if all(c == 0 for c in uni):
                        continue
                    # Search for small roots
                    for x_try in range(1, min(X, 500000) + 1):
                        val = sum(c * pow(x_try, deg) for deg, c in enumerate(uni))
                        if val == 0:
                            k_cand = x_try
                            # recover d from k and y_try
                            # e*d = 1 + k*phi(N), phi(N) = N - (p+q) + 1
                            # p+q = 2*(A + y_try)
                            pq_sum = 2 * (A + y_try)
                            phi_cand = N - pq_sum + 1
                            if phi_cand > 0 and (k_cand * phi_cand + 1) % e == 0:
                                d_cand = (k_cand * phi_cand + 1) // e
                                # verify
                                if pow(pow(2, e, N), d_cand, N) == 2:
                                    return d_cand

    return None


def boneh_durfee_attack(N: int, e: int, c: int,
                        delta: float = 0.26, m: int = 4) -> str:
    """
    Full Boneh-Durfee attack: recover d, then decrypt c.

    Parameters
    ----------
    N     : RSA modulus
    e     : public exponent
    c     : ciphertext
    delta : bound on d (d < N^delta), default 0.26
    m     : lattice size parameter, default 4

    Returns
    -------
    Decrypted plaintext as string.
    """
    from Crypto.Util.number import long_to_bytes

    d = boneh_durfee(N, e, delta=delta, m=m)
    if d is None:
        raise ValueError(
            f"Boneh-Durfee failed with delta={delta}, m={m}.\n"
            f"Try increasing m (e.g. --bd-m 6) or adjusting --bd-delta (max 0.292)."
        )
    m_int = pow(c, d, N)
    raw = long_to_bytes(m_int)
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return raw.decode("latin-1").strip()
