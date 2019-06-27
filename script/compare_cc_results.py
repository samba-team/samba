#!/usr/bin/env python3
"""Compare the results of native and cross-compiled configure tests

The compared files are called "default.cache.py" and are generated in
bin/c4che/.

USAGE: compare_cc_results.py CONFIG_1 CONFIG_2 [CONFIG_3 [CONFIG_4 ...]]
"""
from __future__ import print_function
import sys
import difflib

exceptions = [
    'BUILD_DIRECTORY', 'SELFTEST_PREFIX', 'defines',
    'CROSS_COMPILE', 'CROSS_ANSWERS', 'CROSS_EXECUTE',
    'LIBSOCKET_WRAPPER_SO_PATH',
    'LIBNSS_WRAPPER_SO_PATH',
    'LIBPAM_WRAPPER_SO_PATH',
    'PAM_SET_ITEMS_SO_PATH',
    'LIBUID_WRAPPER_SO_PATH',
    'LIBRESOLV_WRAPPER_SO_PATH',
]

if len(sys.argv) < 3:
    print(__doc__)
    sys.exit(1)

base_lines = list()
base_fname = ''

found_diff = False

for fname in sys.argv[1:]:
    lines = list()
    f = open(fname, 'r')
    for line in f:
        if line.startswith("cfg_files ="):
            # waf writes configuration files as absolute paths
            continue
        if len(line.split('=', 1)) == 2:
            key = line.split('=', 1)[0].strip()
            value = line.split('=', 1)[1].strip()
            if key in exceptions:
                continue
            # using waf with python 3.4 seems to randomly sort dict keys
            # we can't modify the waf code but we can fake a dict value
            # string representation as if it were sorted. python 3.6.5
            # doesn't seem to suffer from this behaviour
            if value.startswith('{'):
                import ast
                amap = ast.literal_eval(value)
                fakeline = ""
                for k in sorted(amap.keys()):
                    if not len(fakeline) == 0:
                        fakeline = fakeline + ", "
                    fakeline = fakeline + '\'' + k + '\': \'' + amap[k] + '\''
                line = key + ' = {' + fakeline + '}'
        lines.append(line)
    f.close()
    if base_fname:
        diff = list(difflib.unified_diff(base_lines, lines, base_fname, fname))
        if diff:
            print('configuration files %s and %s do not match' % (base_fname, fname))
            for l in diff:
                sys.stdout.write(l)
            found_diff = True
    else:
        base_fname = fname
        base_lines = lines

if found_diff:
    sys.exit(1)
