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
from samba.tests import TestCase, check_help_consistency
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
    'bin/samba_downgrade_db',
    'source4/scripting/bin/samba_downgrade_db',
    'source3/selftest/tests.py',
    'selftest/tests.py',
    'python/samba/subunit/run.py',
    'bin/python/samba/subunit/run.py',
    'python/samba/tests/dcerpc/raw_protocol.py',
    'python/samba/tests/krb5/kcrypto.py',
    'python/samba/tests/krb5/simple_tests.py',
    'python/samba/tests/krb5/s4u_tests.py',
    'python/samba/tests/krb5/xrealm_tests.py',
    'python/samba/tests/krb5/as_canonicalization_tests.py',
    'python/samba/tests/krb5/compatability_tests.py',
    'python/samba/tests/krb5/rfc4120_constants.py',
    'python/samba/tests/krb5/kdc_tests.py',
    'python/samba/tests/krb5/kdc_base_test.py',
    'python/samba/tests/krb5/kdc_tgs_tests.py',
    'python/samba/tests/krb5/test_ccache.py',
    'python/samba/tests/krb5/test_ldap.py',
    'python/samba/tests/krb5/test_rpc.py',
    'python/samba/tests/krb5/test_smb.py',
    'python/samba/tests/krb5/ms_kile_client_principal_lookup_tests.py',
    'python/samba/tests/krb5/as_req_tests.py',
    'python/samba/tests/krb5/fast_tests.py',
    'python/samba/tests/krb5/rodc_tests.py',
    'python/samba/tests/krb5/salt_tests.py',
    'python/samba/tests/krb5/spn_tests.py',
}

EXCLUDE_HELP = {
    'selftest/tap2subunit',
    'wintest/test-s3.py',
    'wintest/test-s4-howto.py',
}


EXCLUDE_DIRS = {
    'source3/script/tests',
    'python/examples',
    'source4/dsdb/tests/python',
    'bin/ab',
    'bin/python/samba/tests',
    'bin/python/samba/tests/dcerpc',
    'bin/python/samba/tests/krb5',
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


def script_iterator(d=BASEDIR, cache=None,
                    shebang_filter=None,
                    filename_filter=None,
                    subdirs=TEST_DIRS):
    if not cache:
        safename = re.compile(r'\W+').sub
        for subdir in subdirs:
            sd = os.path.join(d, subdir)
            for root, dirs, files in os.walk(sd, followlinks=False):
                for fn in files:
                    if fn.endswith('~'):
                        continue
                    if fn.endswith('.inst'):
                        continue
                    ffn = os.path.join(root, fn)
                    try:
                        s = os.stat(ffn)
                    except FileNotFoundError:
                        continue
                    if not s.st_mode & stat.S_IXUSR:
                        continue
                    if not (subdir == 'bin' or is_git_file(ffn)):
                        continue

                    if filename_filter is not None:
                        if not filename_filter(ffn):
                            continue

                    if shebang_filter is not None:
                        try:
                            f = open(ffn, 'rb')
                        except OSError as e:
                            print("could not open %s: %s" % (ffn, e))
                            continue
                        line = f.read(40)
                        f.close()
                        if not shebang_filter(line):
                            continue

                    name = safename('_', fn)
                    while name in cache:
                        name += '_'
                    cache[name] = ffn

    return cache.items()

# For ELF we only look at /bin/* top level.
def elf_file_name(fn):
    fn = fn.partition('bin/')[2]
    return fn and '/' not in fn and 'test' not in fn and 'ldb' in fn

def elf_shebang(x):
    return x[:4] == b'\x7fELF'

elf_cache = {}
def elf_iterator():
    return script_iterator(BASEDIR, elf_cache,
                           shebang_filter=elf_shebang,
                           filename_filter=elf_file_name,
                           subdirs=['bin'])


perl_shebang = re.compile(br'#!.+perl').match

perl_script_cache = {}
def perl_script_iterator():
    return script_iterator(BASEDIR, perl_script_cache, perl_shebang)


python_shebang = re.compile(br'#!.+python').match

python_script_cache = {}
def python_script_iterator():
    return script_iterator(BASEDIR, python_script_cache, python_shebang)


class PerlScriptUsageTests(TestCase):
    """Perl scripts run without arguments should print a usage string,
        not fail with a traceback.
    """

    @classmethod
    def initialise(cls):
        for name, filename in perl_script_iterator():
            print(name, filename)


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


class HelpTestSuper(TestCase):
    """Python scripts run with -h or --help should print a help string,
    and exit with success.
    """
    check_return_code = True
    check_consistency = True
    check_contains_usage = True
    check_multiline = True
    check_merged_out_and_err = False

    interpreter = None

    options_start = None
    options_end = None
    def iterator(self):
        raise NotImplementedError("Subclass this "
                                  "and add an iterator function!")

    @classmethod
    def initialise(cls):
        for name, filename in cls.iterator():
            # We add the actual tests after the class definition so we
            # can give individual names to them, so we can have a
            # knownfail list.
            fn = filename.replace(BASEDIR, '').lstrip('/')

            if fn in EXCLUDE_HELP:
                print("skipping %s (EXCLUDE_HELP)" % filename)
                continue

            if os.path.dirname(fn) in EXCLUDE_DIRS:
                print("skipping %s (EXCLUDE_DIRS)" % filename)
                continue

            def _f(self, filename=filename):
                print(filename)
                for h in ('--help', '-h'):
                    cmd = [filename, h]
                    if self.interpreter:
                        cmd.insert(0, self.interpreter)
                    try:
                        p = subprocess.Popen(cmd,
                                             stderr=subprocess.PIPE,
                                             stdout=subprocess.PIPE)
                        out, err = p.communicate(timeout=5)
                    except OSError as e:
                        self.fail("Error: %s" % e)
                    except subprocess.SubprocessError as e:
                        self.fail("Subprocess error: %s" % e)

                    err = err.decode('utf-8')
                    out = out.decode('utf-8')
                    if self.check_merged_out_and_err:
                        out = "%s\n%s" % (out, err)

                    outl = out[:500].lower()
                    # NOTE:
                    # These assertions are heuristics, not policy.
                    # If your script fails this test when it shouldn't
                    # just add it to EXCLUDE_HELP above or change the
                    # heuristic.

                    # --help should produce:
                    #    * multiple lines of help on stdout (not stderr),
                    #    * including a "Usage:" string,
                    #    * not contradict itself or repeat options,
                    #    * and return success.
                    #print(out.encode('utf8'))
                    #print(err.encode('utf8'))
                    if self.check_consistency:
                        errors = check_help_consistency(out,
                                                        self.options_start,
                                                        self.options_end)
                        if errors is not None:
                            self.fail(errors)

                    if self.check_return_code:
                        self.assertEqual(p.returncode, 0,
                                         "%s %s\nreturncode should not be %d\n"
                                         "err:\n%s\nout:\n%s" %
                                         (filename, h, p.returncode, err, out))
                    if self.check_contains_usage:
                        self.assertIn('usage', outl, 'lacks "Usage:"\n')
                    if self.check_multiline:
                        self.assertIn('\n', out, 'expected multi-line output')

            setattr(cls, 'test_%s' % name, _f)


class PythonScriptHelpTests(HelpTestSuper):
    """Python scripts run with -h or --help should print a help string,
    and exit with success.
    """
    iterator = python_script_iterator
    interpreter = 'python3'


class ElfHelpTests(HelpTestSuper):
    """ELF binaries run with -h or --help should print a help string,
    and exit with success.
    """
    iterator = elf_iterator
    check_return_code = False
    check_merged_out_and_err = True


PerlScriptUsageTests.initialise()
PythonScriptUsageTests.initialise()
PythonScriptHelpTests.initialise()
ElfHelpTests.initialise()
