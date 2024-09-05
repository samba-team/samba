#!/usr/bin/env python3
# Unix SMB/CIFS implementation.
#
# Copyright (C) Catalyst.Net Ltd. 2021
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys

sys.path.insert(0, 'bin/python')
os.environ['PYTHONUNBUFFERED'] = '1'

import subprocess
from collections import Counter
from samba.colour import c_RED, c_GREEN, c_DARK_YELLOW, switch_colour_off
import re
import unicodedata as u
from samba.tests import TestCase, SkipTest

if not sys.stdout.isatty():
    switch_colour_off()


def _find_root():
    try:
        p = subprocess.run(['git', 'rev-parse', '--show-toplevel'],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           timeout=10)
    except subprocess.CalledProcessError as err:
        print(c_RED("Error running git (is this a git tree?): %s" % (err)))

        SkipTest("This test is only useful in a git working tree")
        sys.exit(0)

    if p.returncode != 0:
        raise SkipTest("This test is only useful in a git working tree")
        sys.exit(0)

    root = p.stdout.decode().strip()

    should_be_roots = (
        os.path.abspath(os.path.join(os.path.dirname(__file__),
                                     "../../..")),
        os.path.abspath(os.path.join(os.path.dirname(__file__),
                                     "../../../..")),
    )
    if root not in should_be_roots:
        print(c_RED("It looks like we have found the wrong git tree!"))
        sys.exit(1)
    return root


ROOT = None

IGNORED_FILES = (
    'source3/selftest/ktest-krb5_ccache-2',
    'source3/selftest/ktest-krb5_ccache-3',
    'testdata/source-chars-bad.c',
)

IGNORED_RE = (
    r'^third_party/heimdal/lib/hcrypto/passwd_dialog',
    r'^third_party/heimdal/lib/hx509/data/',
    r'^third_party/heimdal/po',
    r'^third_party/heimdal/tests/kdc/hdb-mitdb',
    r'^testdata/compression/',
    r'^third_party/heimdal/lib/asn1/fuzz-inputs/',
)

IGNORED_EXTENSIONS = {
    'bmp',
    'cer',
    'corrupt',
    'crl',
    'crt',
    'dat',
    'der',
    'dump',
    'gpg',
    'gz',
    'ico',
    'keytab',
    'ldb',
    'p12',
    'pdf',
    'pem',
    'png',
    'SAMBABACKUP',
    'sxd',
    'tdb',
    'tif',
    'reg',
    'req'
}


# This list is by no means exhaustive -- these are just the format
# characters we actually use.
SAFE_FORMAT_CHARS = {
    '\u200b',
    '\ufeff'
}

# These files legitimately mix left-to-right and right-to-left text.
# In the real world mixing directions would be normal in bilingual
# documents, but it is rare in Samba source code.
BIDI_FILES = {
    'third_party/heimdal/lib/base/test_base.c',
    'third_party/heimdal/lib/wind/NormalizationTest.txt',
    'testdata/source-chars-bidi.py',
}


def get_git_files():
    try:
        p = subprocess.run(['git',
                            '-C', ROOT,
                            'ls-files',
                            '-z'],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           timeout=10)
    except subprocess.SubprocessError as e:
        print(c_RED(f"Error running git (is this a git tree?): {e}"))
        print("This test is only useful in a git working tree")
        return []

    filenames = p.stdout.split(b'\x00')
    return [x.decode() for x in filenames[:-1]]


def iter_source_files():
    filenames = get_git_files()

    for name in filenames:
        ignore = False
        if name in IGNORED_FILES:
            print(c_DARK_YELLOW(f"ignoring (exact) {name}"))
            continue

        for ignored in IGNORED_RE:
            ignore = (re.match(ignored, name))
            if ignore:
                break

        if ignore:
            print(c_DARK_YELLOW(f"ignoring (via RE) {name}"))
            continue

        if '.' in name:
            ext = name.rsplit('.', 1)[1]
            if ext in IGNORED_EXTENSIONS:
                print(c_DARK_YELLOW(f"ignoring {name}"))
                continue

        yield name


def is_latin1_file(name):
    for pattern in (
            r'^source4/setup/ad-schema/\w+.ldf$',
            r'^source4/setup/display-specifiers/D[\w-]+.txt$',
            r'^third_party/heimdal/cf/pkg.m4$',
            r'^third_party/heimdal/doc/standardisation/',
    ):
        if re.match(pattern, name):
            return True
    return False


def is_bad_latin1_file(fullname):
    # In practice, the few latin-1 files we have have single non-ASCII
    # byte islands in a sea of ASCII. The utf-8 sequences we are
    # concerned about involve sequences of 3 high bytes. We can say a
    # file is safe latin-1 if it has only individual high bytes.
    with open(fullname, 'rb') as f:
        b = f.read()
    in_seq = False
    for c in b:
        if c > 0x7f:
            if in_seq:
                return True
            in_seq = True
        else:
            in_seq = False
    return False


def is_bad_char(c):
    if u.category(c) != 'Cf':
        return False
    if c in SAFE_FORMAT_CHARS:
        return False
    return True


class CharacterTests(TestCase):
    def setUp(self):
        global ROOT
        if not ROOT:
            ROOT = _find_root()

    def test_no_unexpected_format_chars(self):
        """This test tries to ensure that no source file has unicode control
        characters that can change the apparent order of other
        characters. These characters could make code appear to have
        different semantic meaning it really does.

        This issue is sometimes called "Trojan Source", "CVE-2021-42574",
        or "CVE-2021-42694".
        """
        for name in iter_source_files():
            fullname = os.path.join(ROOT, name)
            try:
                with open(fullname) as f:
                    s = f.read()
            except UnicodeDecodeError as e:
                # probably a latin-1 encoding, which we tolerate in a few
                # files for historical reasons, though we check that there
                # are not long sequences of high bytes.
                if is_latin1_file(name):
                    if is_bad_latin1_file(fullname):
                        self.fail(f"latin-1 file {name} has long sequences "
                                  "of high bytes")
                else:
                    self.fail(f"could not decode {name}: {e}")

            dirs = set()
            for c in set(s):
                if is_bad_char(c):
                    self.fail(f"{name} has potentially bad format character {ord(c[0])}!")
                dirs.add(u.bidirectional(c))

            if 'L' in dirs and 'R' in dirs:
                if name not in BIDI_FILES:
                    self.fail(f"{name} has LTR and RTL text ({dirs})")

    def test_unexpected_format_chars_do_fail(self):
        """Test the test"""
        for name, n_bad in [
                ('testdata/source-chars-bad.c', 3)
        ]:
            fullname = os.path.join(ROOT, name)
            with open(fullname) as f:
                s = f.read()
            chars = set(s)
            bad_chars = [c for c in chars if is_bad_char(c)]
            self.assertEqual(len(bad_chars), n_bad)

    def test_unexpected_bidi_fails(self):
        """Test the test"""
        for name in [
                'testdata/source-chars-bidi.py'
        ]:
            fullname = os.path.join(ROOT, name)
            with open(fullname) as f:
                s = f.read()

            dirs = set()
            for c in set(s):
                dirs.add(u.bidirectional(c))
            self.assertIn('L', dirs)
            self.assertIn('R', dirs)


def check_file_text():
    """If called directly as a script, count the found characters."""
    global ROOT
    if not ROOT:
        ROOT = _find_root()

    counts = Counter()
    for name in iter_source_files():
        fullname = os.path.join(ROOT, name)
        try:
            with open(fullname) as f:
                s = f.read()
        except UnicodeDecodeError as e:
            if is_latin1_file(name):
                if is_bad_latin1_file(fullname):
                    print(c_RED(f"latin-1 file {name} has long sequences "
                                "of high bytes"))
                else:
                    print(c_GREEN(f"latin-1 file {name} is fine"))
            else:
                print(c_RED(f"can't read {name}: {e}"))

        counts.update(s)
        chars = set(s)
        for c in chars:
            if u.category(c) == 'Cf':
                print(c_GREEN(f"{name} has {u.name(c)}"))

    print(len(counts))
    controls = []
    formats = []
    others = []
    for x in counts:
        c = u.category(x)
        if c == 'Cc':
            controls.append(x)
        elif c == 'Cf':
            formats.append(x)
        elif c[0] == 'C':
            others.append(x)

    print(f"normal control characters {controls}")
    print(f"format characters {formats}")
    print(f"other control characters {others}")


if __name__ == '__main__':
    check_file_text()
