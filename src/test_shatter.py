#!/usr/bin/env python3
"""
test_shatter.py — Comprehensive test suite for shatter v2

Tests every attack with a known plaintext/key pair.
Run from the src/ directory:
    python test_shatter.py
    python test_shatter.py -v          # verbose
    python test_shatter.py TestName    # single test
"""

import sys
import math
import unittest

# ── Make sure we import from local src/
sys.path.insert(0, ".")
import rsa as r
import boneh_durfee as bd

# ── Helpers ───────────────────────────────────────────────────────────────────

def _msg(text: str) -> int:
    return int.from_bytes(text.encode(), "big")

def _enc(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


# ── Small toy primes for fast tests ───────────────────────────────────────────

# 512-bit-ish semi-prime for Wiener (needs large e, small d)
# We'll generate on the fly for the tests that need it.

import sympy


def gen_keypair(bits_p: int = 64) -> tuple[int, int, int, int]:
    """Generate (p, q, e, d) with e=65537."""
    p = sympy.randprime(2**(bits_p-1), 2**bits_p)
    q = sympy.randprime(2**(bits_p-1), 2**bits_p)
    while p == q:
        q = sympy.randprime(2**(bits_p-1), 2**bits_p)
    n = p * q
    e = 65537
    d = pow(e, -1, (p-1)*(q-1))
    return p, q, e, d


# ── Test cases ─────────────────────────────────────────────────────────────────

class TestMathHelpers(unittest.TestCase):

    def test_egcd(self):
        g, x, y = r.egcd(35, 15)
        self.assertEqual(g, 5)
        self.assertEqual(35*x + 15*y, g)

    def test_modinv(self):
        self.assertEqual(r.modinv(3, 7), 5)
        self.assertEqual((3 * r.modinv(3, 7)) % 7, 1)

    def test_modinv_no_inverse(self):
        with self.assertRaises(ValueError):
            r.modinv(4, 8)

    def test_int_bytes_roundtrip(self):
        for val in [0, 1, 255, 256, 2**64 - 1]:
            self.assertEqual(int.from_bytes(r.int_to_bytes(val), "big"), val)

    def test_nth_root_gmp(self):
        self.assertEqual(r.nth_root_gmp(27, 3), 3)
        self.assertEqual(r.nth_root_gmp(2**30, 10), 2**3)

    def test_isqrt_exact(self):
        self.assertEqual(r.isqrt_exact(16), 4)
        self.assertIsNone(r.isqrt_exact(15))


class TestParseInt(unittest.TestCase):
    """parse_int: decimal mode by default, hex mode via HEX_MODE flag."""

    def setUp(self):
        # Always start each test in decimal mode
        r.HEX_MODE = False

    def tearDown(self):
        # Reset after each test
        r.HEX_MODE = False

    # --- Decimal mode (default) ---

    def test_decimal(self):
        self.assertEqual(r.parse_int("12345"), 12345)

    def test_decimal_zero(self):
        self.assertEqual(r.parse_int("0"), 0)

    def test_decimal_large(self):
        n = 2**512 + 7
        self.assertEqual(r.parse_int(str(n)), n)

    def test_decimal_invalid_raises(self):
        with self.assertRaises(ValueError):
            r.parse_int("deadbeef")  # not decimal, no --hex

    def test_decimal_whitespace_stripped(self):
        self.assertEqual(r.parse_int("  255  "), 255)

    # --- 0x prefix always forces hex regardless of mode ---

    def test_0x_prefix_in_decimal_mode(self):
        self.assertEqual(r.parse_int("0x1a2b"), 0x1a2b)

    def test_0X_prefix_uppercase(self):
        self.assertEqual(r.parse_int("0X1A2B"), 0x1a2b)

    def test_0x_prefix_in_hex_mode(self):
        r.HEX_MODE = True
        self.assertEqual(r.parse_int("0xff"), 255)

    # --- Hex mode (HEX_MODE = True) ---

    def test_hex_mode_simple(self):
        r.HEX_MODE = True
        self.assertEqual(r.parse_int("ff"), 255)

    def test_hex_mode_deadbeef(self):
        r.HEX_MODE = True
        self.assertEqual(r.parse_int("deadbeef"), 0xdeadbeef)

    def test_hex_mode_uppercase(self):
        r.HEX_MODE = True
        self.assertEqual(r.parse_int("DEADBEEF"), 0xdeadbeef)

    def test_hex_mode_large(self):
        r.HEX_MODE = True
        n = 0xdeadbeefcafe1234567890abcdef
        self.assertEqual(r.parse_int(hex(n)[2:]), n)

    def test_hex_mode_invalid_raises(self):
        r.HEX_MODE = True
        with self.assertRaises(ValueError):
            r.parse_int("xyz_not_valid_hex")

    # --- parse_list ---

    def test_parse_list_decimal(self):
        self.assertEqual(r.parse_list("1,2,3"), [1, 2, 3])

    def test_parse_list_hex_mode(self):
        r.HEX_MODE = True
        self.assertEqual(r.parse_list("ff,1a,0b"), [255, 26, 11])

    def test_parse_list_0x_prefix_decimal_mode(self):
        self.assertEqual(r.parse_list("0x1,0x2,0x3"), [1, 2, 3])

    def test_chinese_remainder_theorem(self):
        cs = [2, 3, 2]
        ns = [3, 5, 7]
        result = r.chinese_remainder_theorem(cs, ns)
        for c_i, n_i in zip(cs, ns):
            self.assertEqual(result % n_i, c_i)

    def test_crt_length_mismatch(self):
        with self.assertRaises(ValueError):
            r.chinese_remainder_theorem([1, 2], [3])


class TestFactorisation(unittest.TestCase):

    def test_factor_fermat_close_primes(self):
        # p and q very close → Fermat fast
        p = sympy.nextprime(10**9)
        q = sympy.nextprime(p + 2)
        n = p * q
        result = r.factor_fermat(n)
        self.assertIsNotNone(result)
        self.assertEqual(set(result), {p, q})

    def test_factor_fermat_perfect_square(self):
        p = sympy.nextprime(10**6)
        n = p * p
        result = r.factor_fermat(n)
        self.assertIsNotNone(result)
        self.assertEqual(result, [p, p])

    def test_factor_fermat_no_result(self):
        # Random primes far apart → Fermat should fail quickly
        p = 1000000007
        q = 9999999999971
        n = p * q
        result = r.factor_fermat(n, max_iter=100)
        self.assertIsNone(result)

    def test_factor_pollard_brent(self):
        p = 1000000007
        q = 1000000009
        n = p * q
        f = r.factor_pollard_brent(n)
        self.assertIn(f, [p, q])

    def test_factor_ecm(self):
        p = sympy.randprime(2**20, 2**24)
        q = sympy.randprime(2**20, 2**24)
        n = p * q
        factors = r.factor_ecm_primefactors(n)
        self.assertEqual(sorted(factors), sorted([p, q]))

    def test_factor_rsa_cascade(self):
        p = sympy.randprime(2**32, 2**33)
        q = sympy.randprime(2**32, 2**33)
        n = p * q
        factors = r.factor_rsa(n, use_factordb=False)
        self.assertEqual(set(factors), {p, q})

    def test_factor_rsa_even(self):
        factors = r.factor_rsa(2 * 997)
        self.assertEqual(set(factors), {2, 997})


class TestCoreRSA(unittest.TestCase):

    def setUp(self):
        self.p = 61
        self.q = 53
        self.e = 17
        self.n = self.p * self.q
        self.d = r.compute_d(self.p, self.q, self.e)
        self.plaintext = "A"
        self.m = _msg(self.plaintext)
        self.c = _enc(self.m, self.e, self.n)

    def test_compute_d(self):
        self.assertEqual((self.e * self.d) % ((self.p-1)*(self.q-1)), 1)

    def test_decode_rsa(self):
        result = r.decode_rsa(self.c, self.d, self.n)
        self.assertEqual(result, self.plaintext)

    def test_decode_raw(self):
        result = r.decode_raw(self.m)
        self.assertEqual(result, self.plaintext)

    def test_compute_d_multi(self):
        # Pick primes where gcd(e, phi) = 1
        p, q, s = 61, 53, 47
        e = 7  # gcd(7, 60*52*46) must be 1
        import math as _math
        phi = (p-1)*(q-1)*(s-1)
        if _math.gcd(e, phi) != 1:
            self.skipTest("e not coprime to phi for these test primes")
        n = p * q * s
        d = r.compute_d_multi([p, q, s], e)
        m = 7
        c = pow(m, e, n)
        self.assertEqual(pow(c, d, n), m)


class TestAttackPAndQ(unittest.TestCase):

    def test_basic(self):
        p, q, e, d = gen_keypair(64)  # 64-bit primes → n is 128 bits, fits "flag{test}"
        n = p * q
        m = _msg("flag{test}")
        c = _enc(m, e, n)
        d_calc = r.compute_d(p, q, e)
        result = r.decode_raw(pow(c, d_calc, n))
        self.assertEqual(result, "flag{test}")


class TestAttackKnownP(unittest.TestCase):

    def test_known_p(self):
        p, q, e, d = gen_keypair(40)
        n = p * q
        m = _msg("secret")
        c = _enc(m, e, n)
        result = r.known_p_attack(c, n, e, p)
        self.assertEqual(result, "secret")

    def test_known_q(self):
        p, q, e, d = gen_keypair(40)
        n = p * q
        m = _msg("hello")
        c = _enc(m, e, n)
        # Pass q as the known factor
        result = r.known_p_attack(c, n, e, q)
        self.assertEqual(result, "hello")

    def test_wrong_factor_raises(self):
        p, q, e, d = gen_keypair(40)
        n = p * q
        m = _msg("x")
        c = _enc(m, e, n)
        with self.assertRaises(ValueError):
            r.known_p_attack(c, n, e, p + 1)


class TestAttackNEasyFactor(unittest.TestCase):

    def test_close_primes(self):
        # Fermat should work
        p = sympy.nextprime(10**9 + 7)
        q = sympy.nextprime(p + 2)
        n = p * q
        e = 65537
        d = r.compute_d(p, q, e)
        m = _msg("ctf")
        c = _enc(m, e, n)
        factors = r.factor_rsa(n, use_factordb=False, use_ecm=True)
        self.assertEqual(set(factors), {p, q})
        p2, q2 = factors[0], factors[1]
        d2 = r.compute_d(p2, q2, e)
        result = r.decode_raw(pow(c, d2, n))
        self.assertEqual(result, "ctf")


class TestAttackSmallE(unittest.TestCase):

    def test_e3_no_padding(self):
        # m^3 < n → Coppersmith at k=0
        m_bytes = b"hi"
        m = int.from_bytes(m_bytes, "big")
        # Use a very large n so m^3 < n
        p = sympy.nextprime(2**200)
        q = sympy.nextprime(2**201)
        n = p * q
        e = 3
        c = pow(m, e, n)  # m^3 < n, so c = m^3 exactly
        result = r.coppersmiths_attack(n, e, c)
        self.assertEqual(result.encode(), m_bytes)


class TestAttackCubeRoot(unittest.TestCase):

    def test_pure_cube(self):
        m = int.from_bytes(b"abc", "big")
        c = m ** 3  # no modular reduction
        result = r.decode_raw(int(r.nth_root_gmp(c, 3)))
        self.assertEqual(result, "abc")

    def test_cube_root_attack(self):
        m = int.from_bytes(b"xyz", "big")
        c = m ** 3
        result = r.decode_raw(r.nth_root_gmp(c, 3))
        self.assertEqual(result, "xyz")


class TestAttackWiener(unittest.TestCase):

    def _make_wiener_key(self):
        """Generate a key with small d (< n^0.24) for Wiener's attack."""
        import random as _random
        p = sympy.nextprime(_random.randint(2**128, 2**129))
        q = sympy.nextprime(_random.randint(2**128, 2**129))
        n = p * q
        phi = (p-1)*(q-1)
        d = sympy.randprime(2, int(n**0.24))
        e = pow(d, -1, phi)
        return n, e, d, p, q

    def test_wiener_unified_recovers_d(self):
        """wiener_attack() should recover d via owiener or manual fallback."""
        n, e, d, p, q = self._make_wiener_key()
        d_recovered = r.wiener_attack(e, n)
        self.assertEqual(d_recovered, d)

    def test_wiener_then_decrypt(self):
        """Full round-trip: generate vulnerable key, recover d, decrypt."""
        n, e, d, p, q = self._make_wiener_key()
        m = _msg("wiener")
        c = _enc(m, e, n)
        d_recovered = r.wiener_attack(e, n)
        result = r.decode_raw(pow(c, d_recovered, n))
        self.assertEqual(result, "wiener")

    def test_wiener_fails_on_large_d(self):
        """Normal key (large d) should raise ValueError."""
        p, q, e, d = gen_keypair(64)
        n = p * q
        with self.assertRaises(ValueError):
            r.wiener_attack(e, n)


class TestAttackCommonModulus(unittest.TestCase):

    def test_coprime_exponents(self):
        p, q, _, _ = gen_keypair(48)
        n = p * q
        e1, e2 = 3, 5
        m = _msg("common")
        c1 = _enc(m, e1, n)
        c2 = _enc(m, e2, n)
        result = r.common_modulus(n, c1, c2, e1, e2)
        self.assertEqual(result, "common")

    def test_large_exponents(self):
        p, q, _, _ = gen_keypair(48)
        n = p * q
        e1 = 65537
        e2 = 65539
        m = _msg("msg")
        c1 = _enc(m, e1, n)
        c2 = _enc(m, e2, n)
        result = r.common_modulus(n, c1, c2, e1, e2)
        self.assertEqual(result, "msg")


class TestAttackBroadcast(unittest.TestCase):

    def test_hastad_e3(self):
        e = 3
        m = _msg("hi!")
        ns, cs = [], []
        for _ in range(e):
            p = sympy.randprime(2**64, 2**65)
            q = sympy.randprime(2**64, 2**65)
            ns.append(p * q)
            cs.append(_enc(m, e, ns[-1]))
        # all moduli must be pairwise coprime — very likely for random primes
        combined = r.chinese_remainder_theorem(cs, ns)
        recovered = r.nth_root_gmp(combined, e)
        self.assertEqual(r.decode_raw(recovered), "hi!")


class TestAttackCRTDecrypt(unittest.TestCase):

    def test_crt_decrypt(self):
        p, q, e, d = gen_keypair(48)
        n = p * q
        dp = d % (p - 1)
        dq = d % (q - 1)
        m = _msg("garner")
        c = _enc(m, e, n)
        result = r.crt_decrypt(c, p, q, dp, dq)
        self.assertEqual(result, "garner")


class TestAttackDpLeak(unittest.TestCase):

    def test_dp_leak(self):
        p = sympy.nextprime(10**15)
        q = sympy.nextprime(p + 10**6)
        n = p * q
        e = 65537
        d = r.compute_d(p, q, e)
        dp = d % (p - 1)
        m = _msg("leak")
        c = _enc(m, e, n)
        result = r.dp_leak_attack(n, e, dp, c)
        self.assertEqual(result, "leak")


class TestAttackCommonFactor(unittest.TestCase):

    def _safe_prime_pair(self, base: int) -> tuple[int, int]:
        """Find p, q where gcd(65537, p-1)=1 and gcd(65537, q-1)=1."""
        e = 65537
        p = sympy.nextprime(base)
        while (p - 1) % e == 0:
            p = sympy.nextprime(p + 1)
        q = sympy.nextprime(p + 2)
        while (q - 1) % e == 0:
            q = sympy.nextprime(q + 1)
        return p, q

    def test_two_moduli_shared_prime(self):
        e = 65537
        p = sympy.nextprime(2**48)
        while (p - 1) % e == 0:
            p = sympy.nextprime(p + 1)
        q1, q2 = self._safe_prime_pair(2**48 + 100)
        n1 = p * q1
        n2 = p * q2
        m1 = _msg("alpha")
        m2 = _msg("beta")
        c1 = _enc(m1, e, n1)
        c2 = _enc(m2, e, n2)
        r1, r2 = r.common_factor_attack(n1, n2, c1, c2, e)
        self.assertEqual(r1, "alpha")
        self.assertEqual(r2, "beta")

    def test_no_common_factor_raises(self):
        p1 = sympy.nextprime(2**48)
        q1 = sympy.nextprime(2**48 + 100)
        p2 = sympy.nextprime(2**48 + 300)
        q2 = sympy.nextprime(2**48 + 400)
        n1, n2 = p1*q1, p2*q2
        e = 65537
        with self.assertRaises(ValueError):
            r.common_factor_attack(n1, n2, 1, 1, e)


class TestAttackMultiPrime(unittest.TestCase):

    def test_three_primes(self):
        p = sympy.randprime(2**30, 2**32)
        q = sympy.randprime(2**30, 2**32)
        s = sympy.randprime(2**30, 2**32)
        n = p * q * s
        e = 65537
        phi = (p-1)*(q-1)*(s-1)
        d = pow(e, -1, phi)
        m = _msg("tri")
        c = _enc(m, e, n)
        result = r.multi_prime_attack(c, n, e)
        self.assertEqual(result, "tri")


class TestAttackWithD(unittest.TestCase):

    def test_decrypt_with_d(self):
        p, q, e, d = gen_keypair(48)
        n = p * q
        m = _msg("knownD")
        c = _enc(m, e, n)
        result = r.decrypt_with_d(c, d, n)
        self.assertEqual(result, "knownD")


class TestAttackWithPhi(unittest.TestCase):

    def test_decrypt_with_phi(self):
        p, q, e, d = gen_keypair(48)
        n = p * q
        phi = (p-1)*(q-1)
        m = _msg("phi")
        c = _enc(m, e, n)
        result = r.decrypt_with_known_phi(c, n, e, phi)
        self.assertEqual(result, "phi")


class TestPolyBonehDurfee(unittest.TestCase):
    """Unit tests for the Poly helper class in boneh_durfee.py."""

    def test_add(self):
        px = bd.Poly.x()
        py = bd.Poly.y()
        p = px + py
        self.assertEqual(p.eval(2, 3), 5)

    def test_mul(self):
        px = bd.Poly.x()
        py = bd.Poly.y()
        p = px * py
        self.assertEqual(p.eval(2, 3), 6)

    def test_pow(self):
        px = bd.Poly.x()
        p = px ** 3
        self.assertEqual(p.eval(4, 0), 64)

    def test_eval_constant(self):
        one = bd.Poly.one()
        self.assertEqual(one.eval(99, 99), 1)

    def test_scale(self):
        px = bd.Poly.x()
        py = bd.Poly.y()
        p = px * py  # coeff {(1,1): 1}
        scaled = p.scale(X=10, Y=100)
        # scaled coeff for (1,1) = 1 * 10^1 * 100^1 = 1000
        self.assertEqual(scaled.coeffs.get((1, 1), 0), 1000)

    def test_monomials_sorted(self):
        px = bd.Poly.x()
        py = bd.Poly.y()
        p = py + px
        mons = p.monomials()
        self.assertEqual(mons, sorted(mons))


class TestCLI(unittest.TestCase):
    """Smoke-test the CLI via subprocess."""

    def _run(self, args: list[str]) -> tuple[int, str, str]:
        import subprocess
        res = subprocess.run(
            [sys.executable, "shatter.py"] + args,
            capture_output=True, text=True, cwd="."
        )
        return res.returncode, res.stdout, res.stderr

    def test_no_args_exit_0(self):
        rc, out, err = self._run([])
        self.assertEqual(rc, 0)
        self.assertIn("shatter", out.lower() + err.lower())

    def test_help(self):
        rc, out, err = self._run(["--help"])
        self.assertEqual(rc, 0)

    def test_p_and_q_cli(self):
        p, q = 61, 53
        e = 17
        n = p * q
        m = ord("A")
        c = pow(m, e, n)
        rc, out, err = self._run([
            "p_and_q",
            "-p", str(p), "-q", str(q), "-e", str(e), "-c", str(c)
        ])
        self.assertEqual(rc, 0)
        self.assertIn("A", out)

    def test_with_d_cli(self):
        p, q = 61, 53
        e, n = 17, 61*53
        d = pow(e, -1, (p-1)*(q-1))
        m = ord("B")
        c = pow(m, e, n)
        rc, out, err = self._run([
            "with_d",
            "-n", str(n), "-d", str(d), "-c", str(c)
        ])
        self.assertEqual(rc, 0)
        self.assertIn("B", out)

    def test_cube_root_cli(self):
        m = int.from_bytes(b"hi", "big")
        c = m ** 3
        rc, out, err = self._run(["cube_root", "-c", str(c)])
        self.assertEqual(rc, 0)
        self.assertIn("hi", out)

    def test_common_factor_cli(self):
        p = sympy.nextprime(2**32)
        q1 = sympy.nextprime(2**32 + 100)
        q2 = sympy.nextprime(2**32 + 200)
        n1, n2 = p*q1, p*q2
        e = 65537
        c1 = pow(_msg("AA"), e, n1)
        c2 = pow(_msg("BB"), e, n2)
        rc, out, err = self._run([
            "common_factor",
            "-n1", str(n1), "-n2", str(n2),
            "-e", str(e),
            "-ct1", str(c1), "-ct2", str(c2)
        ])
        self.assertEqual(rc, 0)
        self.assertIn("AA", out)
        self.assertIn("BB", out)

    def test_boneh_durfee_subcommand_help(self):
        rc, out, err = self._run(["boneh_durfee"])
        self.assertEqual(rc, 0)
        self.assertIn("delta", out + err)

    def test_hex_flag_with_0x_prefix(self):
        """--hex flag: 0x-prefixed values are always parsed as hex."""
        p, q = 61, 53
        e = 17
        n = p * q
        m = ord("Z")
        c = pow(m, e, n)
        rc, out, err = self._run([
            "--hex", "p_and_q",
            "-p", hex(p), "-q", hex(q), "-e", hex(e), "-c", hex(c)
        ])
        self.assertEqual(rc, 0)
        self.assertIn("Z", out)

    def test_hex_flag_without_prefix(self):
        """--hex flag: bare hex strings (no 0x) are interpreted as hex."""
        p, q = 61, 53
        e = 17
        n = p * q
        m = ord("W")
        c = pow(m, e, n)
        rc, out, err = self._run([
            "--hex", "p_and_q",
            "-p", hex(p)[2:], "-q", hex(q)[2:],
            "-e", hex(e)[2:], "-c", hex(c)[2:]
        ])
        self.assertEqual(rc, 0)
        self.assertIn("W", out)

    def test_hex_flag_with_d(self):
        """--hex flag works with the with_d command."""
        p, q = 61, 53
        e, n = 17, 61*53
        d = pow(e, -1, (p-1)*(q-1))
        m = ord("X")
        c = pow(m, e, n)
        rc, out, err = self._run([
            "--hex", "with_d",
            "-n", hex(n)[2:], "-d", hex(d)[2:], "-c", hex(c)[2:]
        ])
        self.assertEqual(rc, 0)
        self.assertIn("X", out)

    def test_no_hex_flag_rejects_bare_hex(self):
        """Without --hex, bare hex strings should cause a parse error."""
        rc, out, err = self._run([
            "p_and_q",
            "-p", "3d", "-q", "35", "-e", "11", "-c", "ae6"
        ])
        self.assertNotEqual(rc, 0)  # should fail


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse as _ap
    ap = _ap.ArgumentParser(description="shatter v2 test suite")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("tests", nargs="*", help="specific test class names")
    parsed, remaining = ap.parse_known_args()

    verbosity = 2 if parsed.verbose else 1
    loader = unittest.TestLoader()

    if parsed.tests:
        suite = unittest.TestSuite()
        for name in parsed.tests:
            try:
                suite.addTests(loader.loadTestsFromName(name, sys.modules[__name__]))
            except AttributeError:
                suite.addTests(loader.loadTestsFromName(name))
    else:
        suite = loader.loadTestsFromModule(sys.modules[__name__])

    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
