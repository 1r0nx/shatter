#!/usr/bin/env python3
"""
shatter.py — RSA CTF attack toolkit (v2)

Attacks available:
  p_and_q          Known p and q → decrypt
  known_p          Known one factor (p or q) → recover other, decrypt
  n_easy_factor    Factorise n automatically (Fermat / ECM / SymPy / FactorDB)
  factordb         Factor n via FactorDB online → decrypt
  small_e          Small exponent / Coppersmith attack (e.g. e=3)
  cube_root        Pure cube-root attack (c = m^3 exactly, e=3)
  wiener           Wiener's attack (small d) — owiener then manual fallback
  common_modulus   Same n, same plaintext, two different exponents
  broadcast        Håstad CRT broadcast (same plaintext, e moduli)
  crt_decrypt      CRT decryption with dp, dq known
  dp_leak          dp-leak attack (dp = d mod (p-1) known)
  partial_d        Partial private-key recovery (lower half of d known)
  common_factor    Two moduli sharing a prime → GCD attack
  multi_prime      Multi-prime RSA (n = p*q*r*...) via ECM/Pollard
  with_d           Direct decryption when d is already known
  with_phi         Direct decryption when phi(n) is already known
  boneh_durfee     Boneh-Durfee lattice attack (d < N^0.292)
"""

import argparse
import sys

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import print as rprint
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

import rsa as _rsa
import boneh_durfee as _bd

console = Console() if HAS_RICH else None


# ── Display helpers ───────────────────────────────────────────────────────────

VERSION = "2.2.0"

BANNER_TEXT = f"""\
[bold cyan]shatter.py[/bold cyan] [dim]v{VERSION}[/dim]  [dim]— RSA CTF attack toolkit[/dim]
[dim]17 attacks · factordb · multi-prime · CRT · Wiener · Coppersmith · Boneh-Durfee[/dim]"""


def banner():
    if HAS_RICH:
        console.print(Panel.fit(BANNER_TEXT, border_style="cyan"))
    else:
        print("=" * 60)
        print(f"  shatter.py v{VERSION}  —  RSA CTF attack toolkit")
        print("  17 attacks: factordb, multi-prime, CRT, Wiener, Coppersmith...")
        print("=" * 60)


def success(flag: str):
    if HAS_RICH:
        console.print()
        console.print(Panel(
            f"[bold green]{flag}[/bold green]",
            title="[bold white]✔  Flag recovered[/bold white]",
            border_style="green"
        ))
    else:
        print(f"\n[+] Flag: {flag}")


def success_multi(results: dict[str, str]):
    """Display multiple recovered plaintexts (e.g. common_factor gives two)."""
    if HAS_RICH:
        console.print()
        for label, value in results.items():
            console.print(Panel(
                f"[bold green]{value}[/bold green]",
                title=f"[bold white]✔  {label}[/bold white]",
                border_style="green"
            ))
    else:
        for label, value in results.items():
            print(f"\n[+] {label}: {value}")


def fail(msg: str):
    if HAS_RICH:
        console.print(f"\n[bold red][!] {msg}[/bold red]")
    else:
        print(f"\n[!] {msg}", file=sys.stderr)
    sys.exit(1)


def info(msg: str):
    if HAS_RICH:
        console.print(f"[cyan][*][/cyan] {msg}")
    else:
        print(f"[*] {msg}")


def warn(msg: str):
    if HAS_RICH:
        console.print(f"[yellow][!][/yellow] {msg}")
    else:
        print(f"[!] {msg}")


def show_factors(factors: list[int]):
    if HAS_RICH:
        tbl = Table(show_header=True, header_style="bold magenta")
        tbl.add_column("Factor #", style="dim")
        tbl.add_column("Value", style="cyan")
        for i, f in enumerate(factors, 1):
            tbl.add_row(str(i), str(f))
        console.print(tbl)
    else:
        for i, f in enumerate(factors, 1):
            print(f"  p{i} = {f}")


# ── CLI definition ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shatter.py",
        description="RSA CTF attack toolkit — choose a sub-command for your scenario.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  shatter.py p_and_q        -p <p> -q <q> -e <e> -c <c>\n"
            "  shatter.py known_p        -n <n> -p <p> -e <e> -c <c>\n"
            "  shatter.py n_easy_factor  -n <n> -e <e> -c <c>\n"
            "  shatter.py factordb       -n <n> -e <e> -c <c>\n"
            "  shatter.py small_e        -n <n> -e 3   -c <c>\n"
            "  shatter.py cube_root      -c <c>\n"
            "  shatter.py wiener         -n <n> -e <e> -c <c>\n"
            "  shatter.py common_modulus -n <n> -e1 <e1> -e2 <e2> -ct1 <c1> -ct2 <c2>\n"
            "  shatter.py broadcast      -cs c1,c2,c3 -ns n1,n2,n3 -e 3\n"
            "  shatter.py crt_decrypt    -c <c> -p <p> -q <q> -dp <dp> -dq <dq>\n"
            "  shatter.py dp_leak        -n <n> -e <e> -c <c> -dp <dp>\n"
            "  shatter.py partial_d      -n <n> -e <e> -c <c> -d <d_low>\n"
            "  shatter.py common_factor  -n1 <n1> -n2 <n2> -e <e> -ct1 <c1> -ct2 <c2>\n"
            "  shatter.py multi_prime    -n <n> -e <e> -c <c>\n"
            "  shatter.py with_d         -n <n> -d <d> -c <c>\n"
            "  shatter.py with_phi       -n <n> -e <e> -c <c> --phi <phi>\n"
            "  shatter.py boneh_durfee   -n <n> -e <e> -c <c> [--bd-delta 0.26] [--bd-m 4]\n"
        ),
    )
    # --hex: interpret all integer inputs as hexadecimal
    parser.add_argument(
        "--hex",
        action="store_true",
        default=False,
        help="interpret all integer inputs as hexadecimal (e.g. 1a2b instead of 0x1a2b)",
    )

    sub = parser.add_subparsers(dest="attack", metavar="<attack>")

    # ── p_and_q ──────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "p_and_q",
        help="known p and q → decrypt",
        description="Decrypt when both prime factors p and q are known.",
    )
    p.add_argument("-p", type=_rsa.parse_int, required=True, metavar="P", help="first prime factor")
    p.add_argument("-q", type=_rsa.parse_int, required=True, metavar="Q", help="second prime factor")
    p.add_argument("-e", type=_rsa.parse_int, required=True, metavar="E", help="public exponent")
    p.add_argument("-c", type=_rsa.parse_int, required=True, metavar="C", help="ciphertext (integer)")

    # ── known_p ───────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "known_p",
        help="one prime factor known → recover other, decrypt",
        description=(
            "Attack when one prime (p or q) is leaked or known.\n"
            "Recovers the other factor by n/p, then decrypts."
        ),
    )
    p.add_argument("-n",  type=_rsa.parse_int, required=True, metavar="N", help="RSA modulus")
    p.add_argument("-p",  type=_rsa.parse_int, required=True, metavar="P", help="known prime factor")
    p.add_argument("-e",  type=_rsa.parse_int, required=True, metavar="E", help="public exponent")
    p.add_argument("-c",  type=_rsa.parse_int, required=True, metavar="C", help="ciphertext (integer)")

    # ── n_easy_factor ─────────────────────────────────────────────────────────
    p = sub.add_parser(
        "n_easy_factor",
        help="factorise n automatically (Fermat / ECM / SymPy)",
        description=(
            "Factorise n automatically using a cascade:\n"
            "  1. Fermat's method (fast when p ≈ q)\n"
            "  2. Pollard-Brent / ECM  (medium factors)\n"
            "  3. SymPy general factorisation\n"
            "Works well when p and q are close, or n is small."
        ),
    )
    p.add_argument("-n",  type=_rsa.parse_int, required=True, metavar="N", help="RSA modulus")
    p.add_argument("-e",  type=_rsa.parse_int, required=True, metavar="E", help="public exponent")
    p.add_argument("-c",  type=_rsa.parse_int, required=True, metavar="C", help="ciphertext (integer)")
    p.add_argument("--no-ecm", action="store_true", help="skip ECM/Pollard step")

    # ── factordb ──────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "factordb",
        help="factor n via FactorDB online database → decrypt",
        description=(
            "Queries factordb.com for a known factorisation of n.\n"
            "Requires internet access. Works for CTF moduli that are pre-factored in the DB."
        ),
    )
    p.add_argument("-n",  type=_rsa.parse_int, required=True, metavar="N", help="RSA modulus")
    p.add_argument("-e",  type=_rsa.parse_int, required=True, metavar="E", help="public exponent")
    p.add_argument("-c",  type=_rsa.parse_int, required=True, metavar="C", help="ciphertext (integer)")

    # ── small_e ───────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "small_e",
        help="small exponent / Coppersmith attack",
        description=(
            "Coppersmith / cube-root attack.\n"
            "Use when e is small (e.g. 3) and the plaintext was not padded,\n"
            "so m^e might be recoverable by iterating c + k*n."
        ),
    )
    p.add_argument("-n",  type=_rsa.parse_int, required=True, metavar="N", help="RSA modulus")
    p.add_argument("-e",  type=_rsa.parse_int, required=True, metavar="E", help="public exponent (small)")
    p.add_argument("-c",  type=_rsa.parse_int, required=True, metavar="C", help="ciphertext (integer)")

    # ── cube_root ─────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "cube_root",
        help="pure cube-root attack (c = m^3 exactly, no modular reduction)",
        description=(
            "Use when e=3 and the message is so short that m^3 < n,\n"
            "so the ciphertext is literally m^3 without any modular reduction.\n"
            "Simply takes the integer cube root of c."
        ),
    )
    p.add_argument("-c",  type=_rsa.parse_int, required=True, metavar="C", help="ciphertext (integer)")

    # ── wiener ────────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "wiener",
        help="Wiener's attack (small d < n^0.25 / 3) — auto-tries owiener then manual",
        description=(
            "Wiener's continued-fraction attack.\n"
            "Applies when d < n^0.25 / 3.\n\n"
            "Automatically tries two implementations in order:\n"
            "  1. owiener library  (fast C-backed implementation)\n"
            "  2. Manual continued fractions  (pure Python fallback)\n\n"
            "If both fail, d is likely too large — try boneh_durfee instead (d < n^0.292)."
        ),
    )
    p.add_argument("-n",  type=_rsa.parse_int, required=True, metavar="N", help="RSA modulus")
    p.add_argument("-e",  type=_rsa.parse_int, required=True, metavar="E", help="public exponent (large)")
    p.add_argument("-c",  type=_rsa.parse_int, required=True, metavar="C", help="ciphertext (integer)")

    # ── common_modulus ────────────────────────────────────────────────────────
    p = sub.add_parser(
        "common_modulus",
        help="same n, same plaintext, two different exponents",
        description=(
            "Common-modulus attack.\n"
            "Requires gcd(e1, e2) = 1 and the same plaintext encrypted\n"
            "under both (n, e1) and (n, e2).\n"
            "Also handles the case where gcd(e1,e2) > 1 by extracting a root."
        ),
    )
    p.add_argument("-n",   type=_rsa.parse_int, required=True, metavar="N",   help="shared modulus")
    p.add_argument("-e1",  type=_rsa.parse_int, required=True, metavar="E1",  help="first exponent")
    p.add_argument("-e2",  type=_rsa.parse_int, required=True, metavar="E2",  help="second exponent")
    p.add_argument("-ct1", type=_rsa.parse_int, required=True, metavar="CT1", help="first ciphertext")
    p.add_argument("-ct2", type=_rsa.parse_int, required=True, metavar="CT2", help="second ciphertext")

    # ── broadcast ─────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "broadcast",
        help="Håstad's broadcast attack (CRT) — same plaintext, e moduli",
        description=(
            "Håstad's broadcast attack via the Chinese Remainder Theorem.\n"
            "Provide at least e ciphertext/modulus pairs (comma-separated).\n\n"
            "example:\n"
            "  shatter.py broadcast -cs 2,3,2 -ns 3,5,7 -e 3"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-cs", type=_rsa.parse_list, required=True, metavar="C1,C2,...",
                   help="comma-separated ciphertexts")
    p.add_argument("-ns", type=_rsa.parse_list, required=True, metavar="N1,N2,...",
                   help="comma-separated moduli")
    p.add_argument("-e",  type=_rsa.parse_int, required=True, metavar="E",
                   help="shared public exponent")

    # ── crt_decrypt ───────────────────────────────────────────────────────────
    p = sub.add_parser(
        "crt_decrypt",
        help="CRT decryption — dp and dq are known",
        description=(
            "Garner's CRT decryption when dp = d mod (p-1) and dq = d mod (q-1) are known.\n"
            "Faster decryption path commonly seen in CTF challenges that leak dp/dq."
        ),
    )
    p.add_argument("-c",  type=_rsa.parse_int, required=True, metavar="C",  help="ciphertext (integer)")
    p.add_argument("-p",  type=_rsa.parse_int, required=True, metavar="P",  help="prime factor p")
    p.add_argument("-q",  type=_rsa.parse_int, required=True, metavar="Q",  help="prime factor q")
    p.add_argument("-dp", type=_rsa.parse_int, required=True, metavar="DP", help="dp = d mod (p-1)")
    p.add_argument("-dq", type=_rsa.parse_int, required=True, metavar="DQ", help="dq = d mod (q-1)")

    # ── dp_leak ───────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "dp_leak",
        help="dp-leak attack — dp = d mod (p-1) is known, recover p",
        description=(
            "dp-leak attack: when dp = d mod (p-1) is leaked,\n"
            "search for k such that (e*dp - 1) = k*(p-1), recovering p."
        ),
    )
    p.add_argument("-n",  type=_rsa.parse_int, required=True, metavar="N",  help="RSA modulus")
    p.add_argument("-e",  type=_rsa.parse_int, required=True, metavar="E",  help="public exponent")
    p.add_argument("-c",  type=_rsa.parse_int, required=True, metavar="C",  help="ciphertext (integer)")
    p.add_argument("-dp", type=_rsa.parse_int, required=True, metavar="DP", help="dp = d mod (p-1)")

    # ── partial_d ─────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "partial_d",
        help="partial private key recovery — lower bits of d known",
        description=(
            "Boneh's partial private key recovery attack.\n"
            "Works when the lower half of d is known (e.g., leaked from a side channel).\n"
            "Assumes 2048-bit key; iterates over possible k values."
        ),
    )
    p.add_argument("-n",  type=_rsa.parse_int, required=True, metavar="N", help="RSA modulus")
    p.add_argument("-e",  type=_rsa.parse_int, required=True, metavar="E", help="public exponent")
    p.add_argument("-c",  type=_rsa.parse_int, required=True, metavar="C", help="ciphertext (integer)")
    p.add_argument("-d",  type=_rsa.parse_int, required=True, metavar="D", help="lower bits of d (partial)")

    # ── common_factor ─────────────────────────────────────────────────────────
    p = sub.add_parser(
        "common_factor",
        help="two moduli share a prime factor → GCD attack",
        description=(
            "Common-factor attack: when two RSA moduli n1, n2 share a prime p,\n"
            "gcd(n1, n2) = p reveals both private keys immediately.\n"
            "Decrypts both ciphertexts."
        ),
    )
    p.add_argument("-n1",  type=_rsa.parse_int, required=True, metavar="N1",  help="first modulus")
    p.add_argument("-n2",  type=_rsa.parse_int, required=True, metavar="N2",  help="second modulus")
    p.add_argument("-e",   type=_rsa.parse_int, required=True, metavar="E",   help="public exponent")
    p.add_argument("-ct1", type=_rsa.parse_int, required=True, metavar="CT1", help="first ciphertext")
    p.add_argument("-ct2", type=_rsa.parse_int, required=True, metavar="CT2", help="second ciphertext")

    # ── multi_prime ───────────────────────────────────────────────────────────
    p = sub.add_parser(
        "multi_prime",
        help="multi-prime RSA (n = p*q*r*...) via ECM/Pollard factorisation",
        description=(
            "Multi-prime RSA attack: n is the product of 3 or more primes.\n"
            "Uses Pollard-Brent / ECM to fully factor n, then reconstructs\n"
            "phi = (p1-1)(p2-1)... and decrypts."
        ),
    )
    p.add_argument("-n",  type=_rsa.parse_int, required=True, metavar="N", help="RSA modulus")
    p.add_argument("-e",  type=_rsa.parse_int, required=True, metavar="E", help="public exponent")
    p.add_argument("-c",  type=_rsa.parse_int, required=True, metavar="C", help="ciphertext (integer)")

    # ── with_d ────────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "with_d",
        help="direct decryption — d is already known",
        description="Decrypt when the private exponent d is already known.",
    )
    p.add_argument("-n",  type=_rsa.parse_int, required=True, metavar="N", help="RSA modulus")
    p.add_argument("-d",  type=_rsa.parse_int, required=True, metavar="D", help="private exponent d")
    p.add_argument("-c",  type=_rsa.parse_int, required=True, metavar="C", help="ciphertext (integer)")

    # ── with_phi ──────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "with_phi",
        help="direct decryption — phi(n) is known",
        description=(
            "Decrypt when phi(n) is directly known.\n"
            "Computes d = e^-1 mod phi(n), then decrypts."
        ),
    )
    p.add_argument("-n",    type=_rsa.parse_int, required=True, metavar="N",   help="RSA modulus")
    p.add_argument("-e",    type=_rsa.parse_int, required=True, metavar="E",   help="public exponent")
    p.add_argument("-c",    type=_rsa.parse_int, required=True, metavar="C",   help="ciphertext (integer)")
    p.add_argument("--phi", type=_rsa.parse_int, required=True, metavar="PHI", help="Euler's totient phi(n)")

    # ── boneh_durfee ──────────────────────────────────────────────────────────
    p = sub.add_parser(
        "boneh_durfee",
        help="Boneh-Durfee lattice attack — d < N^0.292 (requires fpylll)",
        description=(
            "Boneh-Durfee attack via LLL lattice reduction.\n"
            "Recovers d when d < N^delta (theoretical max delta ≈ 0.292).\n\n"
            "Requires: pip install fpylll cysignals\n\n"
            "Tuning tips:\n"
            "  - Start with default delta=0.26 and m=4\n"
            "  - If it fails, try increasing --bd-m (e.g. 5, 6) — slower but stronger\n"
            "  - If d is close to N^0.292, try --bd-delta 0.28 or 0.29\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-n",           type=_rsa.parse_int,   required=True, metavar="N",  help="RSA modulus")
    p.add_argument("-e",           type=_rsa.parse_int,   required=True, metavar="E",  help="public exponent")
    p.add_argument("-c",           type=_rsa.parse_int,   required=True, metavar="C",  help="ciphertext (integer)")
    p.add_argument("--bd-delta",   type=float, default=0.26,  metavar="D",  help="bound: d < N^delta (default: 0.26, max ~0.292)")
    p.add_argument("--bd-m",       type=_rsa.parse_int,   default=4,     metavar="M",  help="lattice size (bigger = stronger/slower, default: 4)")

    return parser


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()

    if len(sys.argv) == 1:
        banner()
        parser.print_help()
        sys.exit(0)
    if len(sys.argv) == 2 and sys.argv[1] in parser._subparsers._group_actions[0].choices:
        banner()
        parser._subparsers._group_actions[0].choices[sys.argv[1]].print_help()
        sys.exit(0)

    # Pre-scan sys.argv for --hex BEFORE parse_args() runs.
    # This is necessary because argparse calls type=parse_int on each argument
    # as it parses them, so HEX_MODE must be set before that happens.
    if "--hex" in sys.argv:
        _rsa.HEX_MODE = True

    args = parser.parse_args()
    banner()
    if _rsa.HEX_MODE:
        info("Hex mode enabled — all integer inputs are interpreted as hexadecimal.")

    try:
        match args.attack:

            case "p_and_q":
                info("Computing d from p and q…")
                d = _rsa.compute_d(args.p, args.q, args.e)
                flag = _rsa.decode_raw(pow(args.c, d, args.p * args.q))

            case "known_p":
                info(f"Recovering q from n / p…")
                flag = _rsa.known_p_attack(args.c, args.n, args.e, args.p)

            case "n_easy_factor":
                info("Factorising n (Fermat → ECM → SymPy → FactorDB)…")
                use_ecm = not getattr(args, "no_ecm", False)
                factors = _rsa.factor_rsa(args.n, use_ecm=use_ecm)
                info(f"Found {len(factors)} factor(s):")
                show_factors(factors)
                if len(factors) == 2:
                    p, q = factors
                    d = _rsa.compute_d(p, q, args.e)
                else:
                    phi = 1
                    for f in factors:
                        phi *= (f - 1)
                    d = pow(args.e, -1, phi)
                flag = _rsa.decode_raw(pow(args.c, d, args.n))

            case "factordb":
                info("Querying FactorDB for n…")
                flag = _rsa.factordb_attack(args.c, args.n, args.e)

            case "small_e":
                info(f"Running Coppersmith / small-e attack (e={args.e})…")
                flag = _rsa.coppersmiths_attack(args.n, args.e, args.c)

            case "cube_root":
                info("Running pure cube-root attack (e=3, c = m^3)…")
                flag = _rsa.cube_root_attack(args.c)

            case "wiener":
                info("Running Wiener's attack (owiener → manual fallback)…")
                d = _rsa.wiener_attack(args.e, args.n)
                info(f"d = {d}")
                flag = _rsa.decode_raw(pow(args.c, d, args.n))

            case "common_modulus":
                info("Running common-modulus attack…")
                flag = _rsa.common_modulus(args.n, args.ct1, args.ct2, args.e1, args.e2)

            case "broadcast":
                info(f"Running Håstad broadcast attack (e={args.e}, {len(args.cs)} pairs)…")
                res  = _rsa.chinese_remainder_theorem(args.cs, args.ns)
                tmp  = _rsa.nth_root_gmp(res, args.e)
                flag = _rsa.decode_raw(tmp)

            case "crt_decrypt":
                info("Running CRT decryption (dp, dq known)…")
                flag = _rsa.crt_decrypt(args.c, args.p, args.q, args.dp, args.dq)

            case "dp_leak":
                info("Running dp-leak attack…")
                flag = _rsa.dp_leak_attack(args.n, args.e, args.dp, args.c)

            case "partial_d":
                info("Running partial private-key recovery (half-d)…")
                flag = _rsa.partial_d_attack(args.n, args.e, args.d, args.c)

            case "common_factor":
                info("Running common-factor (GCD) attack on n1, n2…")
                m1, m2 = _rsa.common_factor_attack(args.n1, args.n2, args.ct1, args.ct2, args.e)
                success_multi({"Plaintext from ct1": m1, "Plaintext from ct2": m2})
                return

            case "multi_prime":
                info("Running multi-prime factorisation attack (ECM/Pollard-Brent)…")
                flag = _rsa.multi_prime_attack(args.c, args.n, args.e)

            case "with_d":
                info("Decrypting with known d…")
                flag = _rsa.decrypt_with_d(args.c, args.d, args.n)

            case "with_phi":
                info("Decrypting with known phi(n)…")
                flag = _rsa.decrypt_with_known_phi(args.c, args.n, args.e, args.phi)

            case "boneh_durfee":
                delta = getattr(args, "bd_delta", 0.26)
                m_bd  = getattr(args, "bd_m", 4)
                info(f"Running Boneh-Durfee attack (delta={delta}, m={m_bd})…")
                info("This may take a while — LLL lattice reduction in progress.")
                flag = _bd.boneh_durfee_attack(args.n, args.e, args.c,
                                               delta=delta, m=m_bd)

            case _:
                parser.print_help()
                sys.exit(1)

        success(flag)

    except (ValueError, UnicodeDecodeError) as exc:
        fail(str(exc))
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        fail(f"Unexpected error: {exc}")


if __name__ == "__main__":
    main()
