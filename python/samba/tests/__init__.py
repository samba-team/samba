# Unix SMB/CIFS implementation.
# Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007-2010
# Copyright (C) Stefan Metzmacher 2014,2015
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
#

"""Samba Python tests."""
import os
import tempfile
import traceback
import collections
import ldb
import samba
from samba import param
from samba import credentials
from samba.credentials import Credentials
import subprocess
import sys
import unittest
import re
from enum import IntEnum, unique
import samba.auth
import samba.gensec
import samba.dcerpc.base
from random import randint
from random import SystemRandom
from contextlib import contextmanager
import shutil
import string
try:
    from samba.samdb import SamDB
except ImportError:
    # We are built without samdb support,
    # imitate it so that connect_samdb() can recover
    def SamDB(*args, **kwargs):
        return None

import samba.ndr
import samba.dcerpc.dcerpc
import samba.dcerpc.epmapper

from unittest import SkipTest
from pathlib import Path

BINDIR = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                      "../../../../bin"))

# HEXDUMP_FILTER maps ASCII control characters to '.', printables to themselves
HEXDUMP_FILTER = bytearray(x if (x > 31 and x < 127) else 46 for x in range(256))

LDB_ERR_LUT = {v: k for k, v in vars(ldb).items() if k.startswith('ERR_')}

RE_CAMELCASE = re.compile(r"([_\-])+")


def source_tree_topdir():
    """Return the top level source directory if this seems to be a
    full source tree. Otherwise raise FileNotFoundError."""
    topdir = Path(__file__) / "../../../.."
    topdir = topdir.resolve()

    for dirpath in ('source4', 'docs-xml', 'python/samba/tests'):
        d = topdir / dirpath
        if not d.is_dir():
            raise FileNotFoundError(f"missing or not a directory: {d}")

    return topdir


def ldb_err(v):
    if isinstance(v, ldb.LdbError):
        v = v.args[0]

    if v in LDB_ERR_LUT:
        return LDB_ERR_LUT[v]

    try:
        return f"[{', '.join(LDB_ERR_LUT.get(x, x) for x in v)}]"
    except TypeError as e:
        print(e)
    return v


def DynamicTestCase(cls):
    cls.setUpDynamicTestCases()
    return cls


class TestCase(unittest.TestCase):
    """A Samba test case."""

    # Re-implement addClassCleanup to support Python versions older than 3.8.
    # Can be removed once these older Python versions are no longer needed.
    if sys.version_info.major == 3 and sys.version_info.minor < 8:
        _class_cleanups = []

        @classmethod
        def addClassCleanup(cls, function, *args, **kwargs):
            cls._class_cleanups.append((function, args, kwargs))

        @classmethod
        def tearDownClass(cls):
            teardown_exceptions = []

            while cls._class_cleanups:
                function, args, kwargs = cls._class_cleanups.pop()
                try:
                    function(*args, **kwargs)
                except Exception:
                    teardown_exceptions.append(traceback.format_exc())

            # ExceptionGroup would be better but requires Python 3.11
            if teardown_exceptions:
                raise ValueError("tearDownClass failed:\n\n" +
                                 "\n".join(teardown_exceptions))

        @classmethod
        def setUpClass(cls):
            """
            Call setUpTestData, ensure tearDownClass is called on exceptions.

            This is only required on Python versions older than 3.8.
            """
            try:
                cls.setUpTestData()
            except Exception:
                cls.tearDownClass()
                raise
    else:
        @classmethod
        def setUpClass(cls):
            """
            setUpClass only needs to call setUpTestData.

            On Python 3.8 and above unittest will always call tearDownClass,
            even if an exception was raised in setUpClass.
            """
            cls.setUpTestData()

    @classmethod
    def setUpTestData(cls):
        """Create class level test fixtures here."""
        pass

    @classmethod
    def generate_dynamic_test(cls, fnname, suffix, *args, doc=None):
        """
        fnname is something like "test_dynamic_sum"
        suffix is something like "1plus2"
        argstr could be (1, 2)

        This would generate a test case called
        "test_dynamic_sum_1plus2(self)" that
        calls
        self._test_dynamic_sum_with_args(1, 2)
        """
        def fn(self):
            getattr(self, "_%s_with_args" % fnname)(*args)
        fn.__doc__ = doc
        attr = "%s_%s" % (fnname, suffix)
        if hasattr(cls, attr):
            raise RuntimeError(f"Dynamic test {attr} already exists!")
        setattr(cls, attr, fn)

    @classmethod
    def setUpDynamicTestCases(cls):
        """This can be implemented in order to call cls.generate_dynamic_test()
        In order to implement autogenerated testcase permutations.
        """
        msg = "%s needs setUpDynamicTestCases() if @DynamicTestCase is used!" % (cls)
        raise NotImplementedError(msg)

    def unique_name(self):
        """Generate a unique name from within a test for creating objects.

        Used to ensure each test generates uniquely named objects that don't
        interfere with other tests.
        """
        # name of calling function
        name = self.id().rsplit(".", 1)[1]

        # remove test_ prefix
        if name.startswith("test_"):
            name = name[5:]

        # finally, convert to camelcase
        name = RE_CAMELCASE.sub(" ", name).title().replace(" ", "")
        return "".join([name[0].lower(), name[1:]])

    def setUp(self):
        super().setUp()
        test_debug_level = os.getenv("TEST_DEBUG_LEVEL")
        if test_debug_level is not None:
            test_debug_level = int(test_debug_level)
            self._old_debug_level = samba.get_debug_level()
            samba.set_debug_level(test_debug_level)
            self.addCleanup(samba.set_debug_level, test_debug_level)

    @classmethod
    def get_loadparm(cls, s3=False):
        return env_loadparm(s3=s3)

    def get_credentials(self):
        return cmdline_credentials

    @classmethod
    def get_env_credentials(cls, *, lp, env_username, env_password,
                            env_realm=None, env_domain=None):
        creds = credentials.Credentials()

        # guess Credentials parameters here. Otherwise, workstation
        # and domain fields are NULL and gencache code segfaults
        creds.guess(lp)
        creds.set_username(env_get_var_value(env_username))
        creds.set_password(env_get_var_value(env_password))

        if env_realm is not None:
            creds.set_realm(env_get_var_value(env_realm))

        if env_domain is not None:
            creds.set_domain(env_get_var_value(env_domain))

        return creds

    def get_creds_ccache_name(self):
        creds = self.get_credentials()
        ccache = creds.get_named_ccache(self.get_loadparm())
        ccache_name = ccache.get_name()

        return ccache_name

    def hexdump(self, src):
        N = 0
        result = ''
        is_string = isinstance(src, str)
        while src:
            ll = src[:8]
            lr = src[8:16]
            src = src[16:]
            if is_string:
                hl = ' '.join(["%02X" % ord(x) for x in ll])
                hr = ' '.join(["%02X" % ord(x) for x in lr])
                ll = ll.translate(HEXDUMP_FILTER)
                lr = lr.translate(HEXDUMP_FILTER)
            else:
                hl = ' '.join(["%02X" % x for x in ll])
                hr = ' '.join(["%02X" % x for x in lr])
                ll = ll.translate(HEXDUMP_FILTER).decode('utf8')
                lr = lr.translate(HEXDUMP_FILTER).decode('utf8')
            result += "[%04X] %-*s  %-*s  %s %s\n" % (N, 8 * 3, hl, 8 * 3, hr, ll, lr)
            N += 16
        return result

    def insta_creds(self, template=None, username=None, userpass=None, kerberos_state=None):

        if template is None:
            raise ValueError("you need to supply a Credentials template")

        if username is not None and userpass is None:
            raise ValueError(
                "you cannot set creds username without setting a password")

        if username is None:
            assert userpass is None

            username = template.get_username()
            userpass = template.get_password()

        simple_bind_dn = template.get_bind_dn()

        if kerberos_state is None:
            kerberos_state = template.get_kerberos_state()

        # get a copy of the global creds or the passed in creds
        c = Credentials()
        c.set_username(username)
        c.set_password(userpass)
        c.set_domain(template.get_domain())
        c.set_realm(template.get_realm())
        c.set_workstation(template.get_workstation())
        c.set_gensec_features(c.get_gensec_features()
                              | samba.gensec.FEATURE_SEAL)
        c.set_kerberos_state(kerberos_state)
        if simple_bind_dn:
            c.set_bind_dn(simple_bind_dn)
        return c

    def assertStringsEqual(self, a, b, msg=None, strip=False):
        """Assert equality between two strings and highlight any differences.
        If strip is true, leading and trailing whitespace is ignored."""
        if strip:
            a = a.strip()
            b = b.strip()

        if a != b:
            sys.stderr.write("The strings differ %s(lengths %d vs %d); "
                             "a diff follows\n"
                             % ('when stripped ' if strip else '',
                                len(a), len(b),
                                ))

            from difflib import unified_diff
            diff = unified_diff(a.splitlines(True),
                                b.splitlines(True),
                                'a', 'b')
            for line in diff:
                sys.stderr.write(line)

            self.fail(msg)

    def assertRaisesLdbError(self, errcode, message, f, *args, **kwargs):
        """Assert a function raises a particular LdbError."""
        if message is None:
            message = f"{f.__name__}(*{args}, **{kwargs})"
        try:
            f(*args, **kwargs)
        except ldb.LdbError as e:
            (num, msg) = e.args
            if isinstance(errcode, collections.abc.Container):
                found = num in errcode
            else:
                found = num == errcode
            if not found:
                lut = {v: k for k, v in vars(ldb).items()
                       if k.startswith('ERR_') and isinstance(v, int)}
                if isinstance(errcode, collections.abc.Container):
                    errcode_name = ' '.join(lut.get(x) for x in errcode)
                else:
                    errcode_name = lut.get(errcode)
                self.fail(f"{message}, expected "
                          f"LdbError {errcode_name}, {errcode} "
                          f"got {lut.get(num)} ({num}) "
                          f"{msg}")
        else:
            lut = {v: k for k, v in vars(ldb).items()
                   if k.startswith('ERR_') and isinstance(v, int)}
            if isinstance(errcode, collections.abc.Container):
                errcode_name = ' '.join(lut.get(x) for x in errcode)
            else:
                errcode_name = lut.get(errcode)
            self.fail("%s, expected "
                      "LdbError %s, (%s) "
                      "but we got success" % (message,
                                              errcode_name,
                                              errcode))


class LdbTestCase(TestCase):
    """Trivial test case for running tests against a LDB."""

    def setUp(self):
        super().setUp()
        self.tempfile = tempfile.NamedTemporaryFile(delete=False)
        self.filename = self.tempfile.name
        self.ldb = samba.Ldb(self.filename)

    def set_modules(self, modules=None):
        """Change the modules for this Ldb."""
        if modules is None:
            modules = []
        m = ldb.Message()
        m.dn = ldb.Dn(self.ldb, "@MODULES")
        m["@LIST"] = ",".join(modules)
        self.ldb.add(m)
        self.ldb = samba.Ldb(self.filename)


class TestCaseInTempDir(TestCase):

    def setUp(self):
        super().setUp()
        self.tempdir = tempfile.mkdtemp()
        self.addCleanup(self._remove_tempdir)

    def _remove_tempdir(self):
        # Note asserting here is treated as an error rather than a test failure
        self.assertEqual([], os.listdir(self.tempdir))
        os.rmdir(self.tempdir)
        self.tempdir = None

    @contextmanager
    def mktemp(self):
        """Yield a temporary filename in the tempdir."""
        try:
            fd, fn = tempfile.mkstemp(dir=self.tempdir)
            yield fn
        finally:
            try:
                os.close(fd)
                os.unlink(fn)
            except (OSError, IOError) as e:
                print("could not remove temporary file: %s" % e,
                      file=sys.stderr)

    def rm_files(self, *files, allow_missing=False, _rm=os.remove):
        """Remove listed files from the temp directory.

        The files must be true files in the directory itself, not in
        sub-directories.

        By default a non-existent file will cause a test failure (or
        error if used outside a test in e.g. tearDown), but if
        allow_missing is true, the absence will be ignored.
        """
        for f in files:
            path = os.path.join(self.tempdir, f)

            # os.path.join will happily step out of the tempdir,
            # so let's just check.
            if os.path.dirname(path) != self.tempdir:
                raise ValueError(f"{path} might be outside {self.tempdir}")

            try:
                _rm(path)
            except FileNotFoundError as e:
                if not allow_missing:
                    raise AssertionError(f"{f} not in {self.tempdir}: {e}")

                print(f"{f} not in {self.tempdir}")

    def rm_dirs(self, *dirs, allow_missing=False):
        """Remove listed directories from temp directory.

        This works like rm_files, but only removes directories,
        including their contents.
        """
        self.rm_files(*dirs, allow_missing=allow_missing, _rm=shutil.rmtree)


def env_loadparm(s3=False):
    if s3:
        from samba.samba3 import param as s3param
        lp = s3param.get_context()
    else:
        lp = param.LoadParm()

    try:
        lp.load(os.environ["SMB_CONF_PATH"])
    except KeyError:
        raise KeyError("SMB_CONF_PATH not set")
    return lp

def env_get_var_value(var_name, allow_missing=False):
    """Returns value for variable in os.environ

    Function throws AssertionError if variable is undefined.
    Unit-test based python tests require certain input params
    to be set in environment, otherwise they can't be run
    """
    if allow_missing:
        if var_name not in os.environ.keys():
            return None
    assert var_name in os.environ.keys(), "Please supply %s in environment" % var_name
    return os.environ[var_name]


cmdline_credentials = None


class RpcInterfaceTestCase(TestCase):
    """DCE/RPC Test case."""


class BlackboxProcessError(Exception):
    """This is raised when check_output() process returns a non-zero exit status

    Exception instance should contain the exact exit code (S.returncode),
    command line (S.cmd), process output (S.stdout) and process error stream
    (S.stderr)
    """

    def __init__(self, returncode, cmd, stdout, stderr, msg=None):
        self.returncode = returncode
        if isinstance(cmd, list):
            self.cmd = ' '.join(cmd)
            self.shell = False
        else:
            self.cmd = cmd
            self.shell = True
        self.stdout = stdout
        self.stderr = stderr
        self.msg = msg

    def __str__(self):
        s = ("Command '%s'; shell %s; exit status %d; "
             "stdout: '%s'; stderr: '%s'" %
             (self.cmd, self.shell, self.returncode, self.stdout, self.stderr))
        if self.msg is not None:
            s = "%s; message: %s" % (s, self.msg)

        return s


class BlackboxTestCase(TestCaseInTempDir):
    """Base test case for blackbox tests."""

    @staticmethod
    def _make_cmdline(line):
        """Expand the called script into a fully resolved path in the bin
        directory."""
        if isinstance(line, list):
            parts = line
        else:
            parts = line.split(" ", 1)
        cmd = parts[0]
        exe = os.path.join(BINDIR, cmd)

        python_cmds = ["samba-tool",
                       "samba_dnsupdate",
                       "samba_upgradedns",
                       "script/traffic_replay",
                       "script/traffic_learner"]

        if os.path.exists(exe):
            parts[0] = exe
        if cmd in python_cmds and os.getenv("PYTHON", False):
            parts.insert(0, os.environ["PYTHON"])

        if not isinstance(line, list):
            line = " ".join(parts)

        return line

    @classmethod
    def check_run(cls, line, msg=None):
        cls.check_exit_code(line, 0, msg=msg)

    @classmethod
    def check_exit_code(cls, line, expected, msg=None):
        line = cls._make_cmdline(line)
        use_shell = not isinstance(line, list)
        p = subprocess.Popen(line,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=use_shell)
        stdoutdata, stderrdata = p.communicate()
        retcode = p.returncode
        if retcode != expected:
            if msg is None:
                msg = "expected return code %s; got %s" % (expected, retcode)
            raise BlackboxProcessError(retcode,
                                       line,
                                       stdoutdata,
                                       stderrdata,
                                       msg)
        return stdoutdata

    @classmethod
    def check_output(cls, line, env=None):
        use_shell = not isinstance(line, list)
        line = cls._make_cmdline(line)
        p = subprocess.Popen(line, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             shell=use_shell, close_fds=True, env=env)
        stdoutdata, stderrdata = p.communicate()
        retcode = p.returncode
        if retcode:
            raise BlackboxProcessError(retcode, line, stdoutdata, stderrdata)
        return stdoutdata

    #
    # Run a command without checking the return code, returns the tuple
    # (ret, stdout, stderr)
    # where ret is the return code
    #       stdout is a string containing the commands stdout
    #       stderr is a string containing the commands stderr
    @classmethod
    def run_command(cls, line):
        line = cls._make_cmdline(line)
        use_shell = not isinstance(line, list)
        p = subprocess.Popen(line,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             shell=use_shell)
        stdoutdata, stderrdata = p.communicate()
        retcode = p.returncode
        return (retcode, stdoutdata.decode('UTF8'), stderrdata.decode('UTF8'))

    # Generate a random password that can be safely  passed on the command line
    # i.e. it does not contain any shell meta characters.
    def random_password(self, count=32):
        password = SystemRandom().choice(string.ascii_uppercase)
        password += SystemRandom().choice(string.digits)
        password += SystemRandom().choice(string.ascii_lowercase)
        password += ''.join(SystemRandom().choice(string.ascii_uppercase +
                            string.ascii_lowercase +
                            string.digits) for x in range(count - 3))
        return password


def connect_samdb(samdb_url, *, lp=None, session_info=None, credentials=None,
                  flags=0, ldb_options=None, ldap_only=False, global_schema=True):
    """Create SamDB instance and connects to samdb_url database.

    :param samdb_url: Url for database to connect to.
    :param lp: Optional loadparm object
    :param session_info: Optional session information
    :param credentials: Optional credentials, defaults to anonymous.
    :param flags: Optional LDB flags
    :param ldap_only: If set, only remote LDAP connection will be created.
    :param global_schema: Whether to use global schema.

    Added value for tests is that we have a shorthand function
    to make proper URL for ldb.connect() while using default
    parameters for connection based on test environment
    """
    if "://" not in samdb_url:
        if not ldap_only and os.path.isfile(samdb_url):
            samdb_url = "tdb://%s" % samdb_url
        else:
            samdb_url = "ldap://%s" % samdb_url
    # use 'paged_search' module when connecting remotely
    if samdb_url.startswith("ldap://"):
        ldb_options = ["modules:paged_searches"]
    elif ldap_only:
        raise AssertionError("Trying to connect to %s while remote "
                             "connection is required" % samdb_url)

    # set defaults for test environment
    if lp is None:
        lp = env_loadparm()
    if session_info is None:
        session_info = samba.auth.system_session(lp)
    if credentials is None:
        credentials = cmdline_credentials

    return SamDB(url=samdb_url,
                 lp=lp,
                 session_info=session_info,
                 credentials=credentials,
                 flags=flags,
                 options=ldb_options,
                 global_schema=global_schema)


def connect_samdb_ex(samdb_url, *, lp=None, session_info=None, credentials=None,
                     flags=0, ldb_options=None, ldap_only=False):
    """Connects to samdb_url database

    :param samdb_url: Url for database to connect to.
    :param lp: Optional loadparm object
    :param session_info: Optional session information
    :param credentials: Optional credentials, defaults to anonymous.
    :param flags: Optional LDB flags
    :param ldap_only: If set, only remote LDAP connection will be created.
    :return: (sam_db_connection, rootDse_record) tuple
    """
    sam_db = connect_samdb(samdb_url, lp=lp, session_info=session_info,
                           credentials=credentials, flags=flags,
                           ldb_options=ldb_options, ldap_only=ldap_only)
    # fetch RootDse
    res = sam_db.search(base="", expression="", scope=ldb.SCOPE_BASE,
                        attrs=["*"])
    return (sam_db, res[0])


def connect_samdb_env(env_url, env_username, env_password, lp=None):
    """Connect to SamDB by getting URL and Credentials from environment

    :param env_url: Environment variable name to get lsb url from
    :param env_username: Username environment variable
    :param env_password: Password environment variable
    :return: sam_db_connection
    """
    samdb_url = env_get_var_value(env_url)
    creds = credentials.Credentials()
    if lp is None:
        # guess Credentials parameters here. Otherwise workstation
        # and domain fields are NULL and gencache code segfaults
        lp = param.LoadParm()
        creds.guess(lp)
    creds.set_username(env_get_var_value(env_username))
    creds.set_password(env_get_var_value(env_password))
    return connect_samdb(samdb_url, credentials=creds, lp=lp)


def delete_force(samdb, dn, **kwargs):
    try:
        samdb.delete(dn, **kwargs)
    except ldb.LdbError as error:
        (num, errstr) = error.args
        assert num == ldb.ERR_NO_SUCH_OBJECT, "ldb.delete() failed: %s" % errstr


def create_test_ou(samdb, name):
    """Creates a unique OU for the test"""

    # Add some randomness to the test OU. Replication between the testenvs is
    # constantly happening in the background. Deletion of the last test's
    # objects can be slow to replicate out. So the OU created by a previous
    # testenv may still exist at the point that tests start on another testenv.
    rand = randint(1, 10000000)
    dn = ldb.Dn(samdb, "OU=%s%d,%s" % (name, rand, samdb.get_default_basedn()))
    samdb.add({"dn": dn, "objectclass": "organizationalUnit"})
    return dn


@unique
class OptState(IntEnum):
    NOOPT = 0
    HYPHEN1 = 1
    HYPHEN2 = 2
    NAME = 3


def parse_help_consistency(out,
                           options_start=None,
                           options_end=None,
                           optmap=None,
                           max_leading_spaces=10):
    if options_start is None:
        opt_lines = []
    else:
        opt_lines = None

    for raw_line in out.split('\n'):
        line = raw_line.lstrip()
        if line == '':
            continue
        if opt_lines is None:
            if line == options_start:
                opt_lines = []
            else:
                continue
        if len(line) < len(raw_line) - max_leading_spaces:
            # for the case where we have:
            #
            #  --foo        frobnicate or barlify depending on
            #               --bar option.
            #
            # where we want to ignore the --bar.
            continue
        if line[0] == '-':
            opt_lines.append(line)
        if line == options_end:
            break

    if opt_lines is None:
        # No --help options is not an error in *this* test.
        return

    is_longname_char = re.compile(r'^[\w-]$').match
    for line in opt_lines:
        state = OptState.NOOPT
        name = None
        prev = ' '
        for c in line:
            if state == OptState.NOOPT:
                if c == '-' and prev.isspace():
                    state = OptState.HYPHEN1
                prev = c
                continue
            if state == OptState.HYPHEN1:
                if c.isalnum():
                    name = '-' + c
                    state = OptState.NAME
                elif c == '-':
                    state = OptState.HYPHEN2
                continue
            if state == OptState.HYPHEN2:
                if c.isalnum():
                    name = '--' + c
                    state = OptState.NAME
                else:  # WTF, perhaps '--' ending option list.
                    state = OptState.NOOPT
                    prev = c
                continue
            if state == OptState.NAME:
                if is_longname_char(c):
                    name += c
                else:
                    optmap.setdefault(name, []).append(line)
                    state = OptState.NOOPT
                    prev = c

        if state == OptState.NAME:
            optmap.setdefault(name, []).append(line)


def check_help_consistency(out,
                           options_start=None,
                           options_end=None):
    """Ensure that options are not repeated and redefined in --help
    output.

    Returns None if everything is OK, otherwise a string indicating
    the problems.

    If options_start and/or options_end are provided, only the bit in
    the output between these two lines is considered. For example,
    with samba-tool,

    options_start='Options:', options_end='Available subcommands:'

    will prevent the test looking at the preamble which may contain
    examples using options.
    """
    # Silly test, you might think, but this happens
    optmap = {}
    parse_help_consistency(out,
                           options_start,
                           options_end,
                           optmap)

    errors = []
    for k, values in sorted(optmap.items()):
        if len(values) > 1:
            for v in values:
                errors.append("%s: %s" % (k, v))

    if errors:
        return "\n".join(errors)


def get_env_dir(key):
    """A helper to pull a directory name from the environment, used in
    some tests that optionally write e.g. fuzz seeds into a directory
    named in an environment variable.
    """
    dir = os.environ.get(key)
    if dir is None:
        return None

    if not os.path.isdir(dir):
        raise ValueError(
            f"{key} should name an existing directory (got '{dir}')")

    return dir
