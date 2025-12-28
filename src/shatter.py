#!/usr/bin/env python3

import argparse
import sys
import rsa


parser = argparse.ArgumentParser(description="rsa problem solver!")
subparsers = parser.add_subparsers(dest="rsa_problem", required=True)

### p_and_q
p_and_q_parser = subparsers.add_parser(
    "p_and_q", help="when you have p and q", description="when you have p and q"
)
p_and_q_parser.add_argument("-p", "--prime1", type=int, metavar="prime1", required=True)
p_and_q_parser.add_argument("-q", "--prime2", type=int, metavar="prime2", required=True)
p_and_q_parser.add_argument(
    "-c", "--ciphertext", type=int, metavar="ciph", required=True
)
p_and_q_parser.add_argument("-e", "--exponent", type=int, metavar="exp", required=True)


### n_easy_factor
n_easy_factor_parser = subparsers.add_parser(
    "n_easy_factor",
    help="use when n is easly factorizable",
    description="use when n is easly factorizable",
)
n_easy_factor_parser.add_argument(
    "-n", "--modulus", type=int, metavar="mod", required=True
)
n_easy_factor_parser.add_argument(
    "-e", "--exponent", type=int, metavar="exp", required=True
)
n_easy_factor_parser.add_argument(
    "-c", "--ciphertext", type=int, metavar="ciph", required=True
)

### small_e
small_e_parser = subparsers.add_parser(
    "small_e",
    help="use when e is small or plaintext is short",
    description="use when e is small or plaintext is short",
)
small_e_parser.add_argument("-n", "--modulus", type=int, metavar="mod", required=True)
small_e_parser.add_argument("-e", "--exponent", type=int, metavar="exp", required=True)
small_e_parser.add_argument(
    "-c", "--ciphertext", type=int, metavar="ciph", required=True
)

### owiener
owiener_parser = subparsers.add_parser(
    "owiener", help="use when d is too small", description="use when d is too small"
)
owiener_parser.add_argument("-n", "--modulus", type=int, metavar="mod", required=True)
owiener_parser.add_argument("-e", "--exponent", type=int, metavar="exp", required=True)
owiener_parser.add_argument(
    "-c", "--ciphertext", type=int, metavar="ciph", required=True
)

###
common_modulus_parser = subparsers.add_parser(
    "common_modulus",
    help="when two users share the same n(modulus) but different e(exponent) value",
    description="when two users share the same n(modulus) but different e(exponent) value",
)
common_modulus_parser.add_argument(
    "-n", "--modulus", type=int, metavar="modulus", required=True
)
common_modulus_parser.add_argument(
    "-e1", "--exponent1", type=int, metavar="exp1", required=True
)
common_modulus_parser.add_argument(
    "-e2", "--exponent2", type=int, metavar="exp2", required=True
)
common_modulus_parser.add_argument(
    "-ct1", "--ciphertext1", type=int, metavar="ciph1", required=True
)
common_modulus_parser.add_argument(
    "-ct2", "--ciphertext2", type=int, metavar="ciph2", required=True
)

### broadcast attack
broadcast_attack_parser = subparsers.add_parser(
    "broadcast_attack",
    help="chinese reminder theorem.",
    description="chinese reminder theorem. \nex: t ≡ 2 mod 3, t ≡ 3 mod 5, t ≡ 2 mod 7\n"
    "broadcast_attack.py -xs 2,3,2 -ns 3,5,7 -e 3",
    formatter_class=argparse.RawTextHelpFormatter,
)
broadcast_attack_parser.add_argument(
    "-cs", "--ciphs", type=rsa.parse_list, metavar="ciphs", required=True
)
broadcast_attack_parser.add_argument(
    "-ns", "--mods", type=rsa.parse_list, metavar="mods", required=True
)
broadcast_attack_parser.add_argument(
    "-e", "--exponent", type=int, metavar="exp", required=True
)

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(0)

if len(sys.argv) == 2:
    cmd = sys.argv[1]
    if cmd in subparsers.choices:
        subparsers.choices[cmd].print_help()
        sys.exit(0)

args = parser.parse_args()

if args.rsa_problem == "p_and_q":
    d = rsa.compute_d(args.prime1, args.prime2, args.exponent)
    try:
        flag = rsa.decode_rsa(args.ciphertext, d, (args.prime1 * args.prime2))
    except:
        print("\nCannot decode in text!")
        sys.exit(0)

    print(f"\n{flag}")
    sys.exit(0)

if args.rsa_problem == "n_easy_factor":
    p, q = rsa.factor_rsa(args.modulus)
    d = rsa.compute_d(p, q, args.exponent)
    try:
        flag = rsa.decode_rsa(args.ciphertext, d, args.modulus)
    except:
        print("\nCannot decode in text!")
        sys.exit(0)

    print(f"\n{flag}")
    sys.exit(0)

if args.rsa_problem == "common_modulus":
    flag = rsa.common_modulus(
        args.modulus,
        args.ciphertext1,
        args.ciphertext2,
        args.exponent1,
        args.exponent2,
    )
    print(f"\n{flag}")
    sys.exit(0)

if args.rsa_problem == "small_e":
    try:
        flag = rsa.coppersmiths_attack(args.modulus, args.exponent, args.ciphertext)
    except:
        print("\nCannot decode in text!")
        sys.exit(0)

    print(f"\n{flag}")
    sys.exit(0)


if args.rsa_problem == "owiener":
    d = rsa.owiener_attack(args.exponent, args.modulus)
    try:
        flag = rsa.decode_rsa(args.ciphertext, d, args.modulus)
    except:
        print("\nCannot decode in text!")
        sys.exit(0)

    print(f"\n{flag}")
    sys.exit(0)

if args.rsa_problem == "broadcast_attack":
    res = rsa.chinese_remainder_theorem(args.ciphs, args.mods)
    tmp = rsa.nth_root_gmp(res, args.exponent)
    hex_flag = hex(tmp)[2:]
    try:
        flag = bytes.fromhex(hex_flag).decode("utf-8")
    except:
        print("\nCannot decode in text!")
        sys.exit(0)

    print(f"\n{flag}")
    sys.exit(0)
