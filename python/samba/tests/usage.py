# Unix SMB/CIFS implementation.
# Copyright © Douglas Bagnall <douglas.bagnall@catalyst.net.nz>
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
import subprocess
from samba.tests import TestCase
from unittest import TestSuite
import re
import stat

if 'SRCDIR_ABS' in os.environ:
    BASEDIR = os.environ['SRCDIR_ABS']
else:
    BASEDIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                           '../../..'))

TEST_DIRS = [
    "bootstrap",
    "testdata",
    "ctdb",
    "dfs_server",
    "pidl",
    "auth",
    "packaging",
    "python",
    "include",
    "nsswitch",
    "libcli",
    "coverity",
    "release-scripts",
    "testprogs",
    "bin",
    "source3",
    "docs-xml",
    "buildtools",
    "file_server",
    "dynconfig",
    "source4",
    "tests",
    "libds",
    "selftest",
    "lib",
    "script",
    "traffic",
    "testsuite",
    "libgpo",
    "wintest",
    "librpc",
]


EXCLUDE_USAGE = {
    'script/autobuild.py',  # defaults to mount /memdisk/
    'script/bisect-test.py',
    'ctdb/utils/etcd/ctdb_etcd_lock',
    'selftest/filter-subunit',
    'selftest/format-subunit',
    'bin/gen_output.py',  # too much output!
    'source4/scripting/bin/gen_output.py',
    'lib/ldb/tests/python/index.py',
    'lib/ldb/tests/python/api.py',
    'source4/selftest/tests.py',
    'buildtools/bin/waf',
    'selftest/tap2subunit',
    'script/show_test_time',
    'source4/scripting/bin/subunitrun',
    'source3/selftest/tests.py',
    'selftest/tests.py',
    'python/samba/subunit/run.py',
    'bin/python/samba/subunit/run.py',
    'python/samba/tests/dcerpc/raw_protocol.py'
}


EXCLUDE_DIRS = {
    'source3/script/tests',
    'python/examples',
    'source4/dsdb/tests/python',
    'bin/ab',
    'bin/python/samba/tests',
    'bin/python/samba/tests/dcerpc',
}


def _init_git_file_finder():
    """Generate a function that quickly answers the question:
    'is this a git file?'
    """
    git_file_cache = set()
    p = subprocess.run(['git',
                        '-C', BASEDIR,
                        'ls-files',
                        '-z'],
                       stdout=subprocess.PIPE)
    if p.returncode == 0:
        for fn in p.stdout.split(b'\0'):
            git_file_cache.add(os.path.join(BASEDIR, fn.decode('utf-8')))
    return git_file_cache.__contains__


is_git_file = _init_git_file_finder()


def python_script_iterator(d=BASEDIR, _cache={}):
    """Generate an iterator over executable Python scripts. By default it
    walks the entire source tree.
    """
    if d not in _cache:
        cache = {}
        _cache[d] = cache
        pyshebang = re.compile(br'#!.+python').match
        safename = re.compile(r'\W+').sub
        for subdir in TEST_DIRS:
            sd = os.path.join(d, subdir)
            for root, dirs, files in os.walk(sd, followlinks=False):
                for fn in files:
                    if fn.endswith('~'):
                        continue
                    if fn.endswith('.inst'):
                        continue
                    ffn = os.path.join(root, fn)
                    if not (subdir == 'bin' or is_git_file(ffn)):
                        continue

                    try:
                        s = os.stat(ffn)
                    except FileNotFoundError:
                        continue
                    if not s.st_mode & stat.S_IXUSR:
                        continue
                    try:
                        f = open(ffn, 'rb')
                    except OSError as e:
                        print("could not open %s: %s" % (ffn, e))
                        continue
                    line = f.read(40)
                    f.close()
                    if not pyshebang(line):
                        continue
                    name = safename('_', fn)
                    while name in cache:
                        name += '_'
                    cache[name] = ffn

    return _cache[d].items()


class PythonScriptUsageTests(TestCase):
    """Python scripts run without arguments should print a usage string,
        not fail with a traceback.
        """

    @classmethod
    def initialise(cls):
        for name, filename in python_script_iterator():
            # We add the actual tests after the class definition so we
            # can give individual names to them, so we can have a
            # knownfail list.
            fn = filename.replace(BASEDIR, '').lstrip('/')

            if fn in EXCLUDE_USAGE:
                print("skipping %s (EXCLUDE_USAGE)" % filename)
                continue

            if os.path.dirname(fn) in EXCLUDE_DIRS:
                print("skipping %s (EXCLUDE_DIRS)" % filename)
                continue

            def _f(self, filename=filename):
                print(filename)
                try:
                    p = subprocess.Popen(['python3', filename],
                                         stderr=subprocess.PIPE,
                                         stdout=subprocess.PIPE)
                    out, err = p.communicate(timeout=5)
                except OSError as e:
                    self.fail("Error: %s" % e)
                except subprocess.SubprocessError as e:
                    self.fail("Subprocess error: %s" % e)

                err = err.decode('utf-8')
                out = out.decode('utf-8')
                self.assertNotIn('Traceback', err)

                self.assertIn('usage', out.lower() + err.lower(),
                              'stdout:\n%s\nstderr:\n%s' % (out, err))

            setattr(cls, 'test_%s' % name, _f)


PythonScriptUsageTests.initialise()
