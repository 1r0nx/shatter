#!/usr/bin/env python3
"""
shatter.py — RSA CTF attack toolkit
"""

import argparse
import sys

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich import print as rprint
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

import rsa as _rsa

console = Console() if HAS_RICH else None


# ── Display helpers ───────────────────────────────────────────────────────────

def banner():
    if HAS_RICH:
        console.print(Panel.fit(
            "[bold cyan]shatter.py[/bold cyan]  [dim]— RSA CTF attack toolkit[/dim]",
            border_style="cyan"
        ))
    else:
        print("=" * 50)
        print("  shatter.py  —  RSA CTF attack toolkit")
        print("=" * 50)


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


# ── CLI definition ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shatter.py",
        description="RSA CTF attack toolkit — choose a sub-command for your scenario.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  shatter.py p_and_q   -p <p> -q <q> -e <e> -c <c>\n"
            "  shatter.py small_e   -n <n> -e 3   -c <c>\n"
            "  shatter.py broadcast -cs c1,c2,c3 -ns n1,n2,n3 -e 3\n"
        ),
    )
    sub = parser.add_subparsers(dest="attack", metavar="<attack>")

    # ── p_and_q ──────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "p_and_q",
        help="you already know p and q",
        description="Decrypt when both prime factors p and q are known.",
    )
    p.add_argument("-p", type=int, required=True, metavar="P", help="first prime factor")
    p.add_argument("-q", type=int, required=True, metavar="Q", help="second prime factor")
    p.add_argument("-e", type=int, required=True, metavar="E", help="public exponent")
    p.add_argument("-c", type=int, required=True, metavar="C", help="ciphertext (integer)")

    # ── n_easy_factor ─────────────────────────────────────────────────────────
    p = sub.add_parser(
        "n_easy_factor",
        help="n is easily factorisable (Fermat / SymPy)",
        description=(
            "Factorise n automatically (Fermat's method then SymPy).\n"
            "Works well when p and q are close, or n is small."
        ),
    )
    p.add_argument("-n", type=int, required=True, metavar="N", help="RSA modulus")
    p.add_argument("-e", type=int, required=True, metavar="E", help="public exponent")
    p.add_argument("-c", type=int, required=True, metavar="C", help="ciphertext (integer)")

    # ── small_e ───────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "small_e",
        help="e is small or plaintext is short (Coppersmith)",
        description=(
            "Coppersmith / cube-root attack.\n"
            "Use when e is small (e.g. 3) and the plaintext was not padded,\n"
            "so m^e < n and the ciphertext is just m^e in ℤ."
        ),
    )
    p.add_argument("-n", type=int, required=True, metavar="N", help="RSA modulus")
    p.add_argument("-e", type=int, required=True, metavar="E", help="public exponent (small)")
    p.add_argument("-c", type=int, required=True, metavar="C", help="ciphertext (integer)")

    # ── owiener ───────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "owiener",
        help="d is small — Wiener's attack",
        description=(
            "Wiener's continued-fraction attack.\n"
            "Applies when d < n^0.25 / 3."
        ),
    )
    p.add_argument("-n", type=int, required=True, metavar="N", help="RSA modulus")
    p.add_argument("-e", type=int, required=True, metavar="E", help="public exponent (large)")
    p.add_argument("-c", type=int, required=True, metavar="C", help="ciphertext (integer)")

    # ── common_modulus ────────────────────────────────────────────────────────
    p = sub.add_parser(
        "common_modulus",
        help="same n, same plaintext, two different exponents",
        description=(
            "Common-modulus attack.\n"
            "Requires gcd(e1, e2) = 1 and the same plaintext encrypted\n"
            "under both (n, e1) and (n, e2)."
        ),
    )
    p.add_argument("-n",   type=int, required=True, metavar="N",   help="shared modulus")
    p.add_argument("-e1",  type=int, required=True, metavar="E1",  help="first exponent")
    p.add_argument("-e2",  type=int, required=True, metavar="E2",  help="second exponent")
    p.add_argument("-ct1", type=int, required=True, metavar="CT1", help="first ciphertext")
    p.add_argument("-ct2", type=int, required=True, metavar="CT2", help="second ciphertext")

    # ── broadcast ─────────────────────────────────────────────────────────────
    p = sub.add_parser(
        "broadcast",
        help="same plaintext, e different moduli — CRT broadcast attack",
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
    p.add_argument("-e",  type=int, required=True, metavar="E",
                   help="shared public exponent")

    return parser


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()

    # Print top-level help when called with no args or just the sub-command name
    if len(sys.argv) == 1:
        banner()
        parser.print_help()
        sys.exit(0)
    if len(sys.argv) == 2 and sys.argv[1] in parser._subparsers._group_actions[0].choices:
        banner()
        parser._subparsers._group_actions[0].choices[sys.argv[1]].print_help()
        sys.exit(0)

    args = parser.parse_args()
    banner()

    try:
        match args.attack:

            case "p_and_q":
                info(f"Computing d from p and q…")
                d = _rsa.compute_d(args.p, args.q, args.e)
                flag = _rsa.decode_rsa(args.c, d, args.p * args.q)

            case "n_easy_factor":
                info("Factorising n…")
                p, q = _rsa.factor_rsa(args.n)
                info(f"p = {p}\n    q = {q}")
                d = _rsa.compute_d(p, q, args.e)
                flag = _rsa.decode_rsa(args.c, d, args.n)

            case "small_e":
                info(f"Running Coppersmith / small-e attack (e={args.e})…")
                flag = _rsa.coppersmiths_attack(args.n, args.e, args.c)

            case "owiener":
                info("Running Wiener's attack…")
                d = _rsa.owiener_attack(args.e, args.n)
                info(f"d = {d}")
                flag = _rsa.decode_rsa(args.c, d, args.n)

            case "common_modulus":
                info("Running common-modulus attack…")
                flag = _rsa.common_modulus(args.n, args.ct1, args.ct2, args.e1, args.e2)

            case "broadcast":
                info(f"Running CRT broadcast attack (e={args.e}, {len(args.cs)} pairs)…")
                res  = _rsa.chinese_remainder_theorem(args.cs, args.ns)
                tmp  = _rsa.nth_root_gmp(res, args.e)
                flag = bytes.fromhex(hex(tmp)[2:]).decode("utf-8")

            case _:
                parser.print_help()
                sys.exit(1)

        success(flag)

    except (ValueError, UnicodeDecodeError) as exc:
        fail(str(exc))
    except Exception as exc:
        fail(f"Unexpected error: {exc}")


if __name__ == "__main__":
    main()