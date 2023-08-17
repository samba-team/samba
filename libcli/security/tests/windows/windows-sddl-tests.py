# Test SDDL strings on Windows
#
#
# Copyright (c) 2023 Catalyst IT
#
# GPLv3+.
#
# This uses the Python win32 module to access
# ConvertStringSecurityDescriptorToSecurityDescriptor and the like. To
# install this, you need to go
#
# pip install pywin32
#
# or something like that.

import argparse
from difflib import SequenceMatcher
from collections import defaultdict
import sys
import json

try:
    import win32security as w
except ImportError:
    print("This test script is meant to be run on Windows using the pywin32 module.")
    print("To install this module, try:\n")
    print("pip install pywin32")
    sys.exit(1)


# This is necessary for ANSI colour escapes to work in Powershell.
import os
os.system('')

RED = "\033[1;31m"
GREEN = "\033[1;32m"
DARK_YELLOW = "\033[0;33m"
C_NORMAL = "\033[0m"

def c_RED(s):
    return f"{RED}{s}{C_NORMAL}"
def c_GREEN(s):
    return f"{GREEN}{s}{C_NORMAL}"
def c_DY(s):
    return f"{DARK_YELLOW}{s}{C_NORMAL}"


def read_strings(files):
    """Try to read as JSON a JSON dictionary first, then secondly in the bespoke
        sddl-in -> sddl-out
    format used by other Samba SDDL test programs on Windows.
    """
    pairs = []
    for filename in files:
        with open(filename) as f:
            try:
                data = json.load(f)
                print(f"loading {filename} as JSON")
                for k, v in data.items():
                    if not v or not isinstance(v, str):
                        v = k
                    pairs.append((k, v))
                continue
            except json.JSONDecodeError:
                pass

            print(f"loading {filename} as 'a -> b' style")
            for line in f:
                line = line.rstrip()
                if line.startswith('#') or line == '':
                    continue
                # note: if the line does not have ' -> ', we expect a
                # perfect round trip.
                o, _, c = line.partition(' -> ')
                if c == '':
                    c = o
                pairs.append((o, c))

    return pairs


def colourdiff(a, b):
    out = []
    a = a.replace(' ', '␠')
    b = b.replace(' ', '␠')

    s = SequenceMatcher(None, a, b)
    for op, al, ar, bl, br in s.get_opcodes():
        if op == 'equal':
            out.append(a[al: ar])
        elif op == 'delete':
            out.append(c_RED(a[al: ar]))
        elif op == 'insert':
            out.append(c_GREEN(b[bl: br]))
        elif op == 'replace':
            out.append(c_RED(a[al: ar]))
            out.append(c_GREEN(b[bl: br]))
        else:
            print(f'unknown op {op}!')

    return ''.join(out)


def no_print(*args, **kwargs):
    pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--export-bytes', const='sddl_bytes.json', nargs='?',
                        help='write JSON file containing SD bytes')
    parser.add_argument('--quiet', action='store_true',
                        help='avoid printing to sdtout')
    parser.add_argument('files', nargs='+', help='read these files')

    args = parser.parse_args()

    if args.quiet:
        global print
        print = no_print

    cases = read_strings(args.files)
    parseable_cases = []
    unparseable_cases = []
    unserializeable_cases = []
    round_trip_failures = []
    exceptions = defaultdict(list)
    bytes_json = {}

    print(f"{len(set(cases))}/{len(cases)} unique pairs, "
          f"{len(set(x[0] for x in cases))}/{len(cases)} unique strings")

    for a, b in sorted(set(cases)):
        try:
            sd = w.ConvertStringSecurityDescriptorToSecurityDescriptor(a, 1)
        except Exception as e:
            print(a)
            exceptions[f"{e} parse"].append(a)
            print(c_RED(e))
            unparseable_cases.append(a)
            continue

        parseable_cases.append(a)

        try:
            # maybe 0xffff is an incorrect guess -- it gives use v2 (NT), not v4 (AD)
            c = w.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, 1, 0xffff)
        except Exception as e:
            print(f"could sot serialize '{sd}': {e}")
            print(f" derived from       '{a}'")
            exceptions[f"{e} serialize"].append(a)
            unserializeable_cases.append(a)
            continue

        if args.export_bytes:
            bytes_json[c] = list(bytes(sd))

        if c != b:
            round_trip_failures.append((a, b, c))
            exceptions["mismatch"].append(a)
            #print(f"{c_GREEN(a)} -> {c_DY(c)}")
            print(colourdiff(b, c))
            print(c_DY(f"{b} -> {c}"))

    for k, v in exceptions.items():
        print(f"{k}: {len(v)}")

    print(f"{len(unparseable_cases)} failed to parsed")
    print(f"{len(parseable_cases)} successfully parsed")
    print(f"{len(unserializeable_cases)} of these failed to re-serialize")
    print(f"{len(round_trip_failures)} of these failed to round trip")
    #for p in parseable_cases:
    #    print(f"«{c_GREEN(p)}»")

    if args.export_bytes:
        with open(args.export_bytes, 'w') as f:
            json.dump(bytes_json, f)
        print(f"wrote bytes to {args.export_bytes}")

main()
