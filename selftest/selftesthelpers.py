#!/usr/bin/python
# This script generates a list of testsuites that should be run as part of
# the Samba 4 test suite.

# The output of this script is parsed by selftest.pl, which then decides
# which of the tests to actually run. It will, for example, skip all tests
# listed in selftest/skip or only run a subset during "make quicktest".

# The idea is that this script outputs all of the tests of Samba 4, not
# just those that are known to pass, and list those that should be skipped
# or are known to fail in selftest/skip or selftest/knownfail. This makes it
# very easy to see what functionality is still missing in Samba 4 and makes
# it possible to run the testsuite against other servers, such as Samba 3 or
# Windows that have a different set of features.

# The syntax for a testsuite is "-- TEST --" on a single line, followed
# by the name of the test, the environment it needs and the command to run, all
# three separated by newlines. All other lines in the output are considered
# comments.
from __future__ import print_function

import os
import subprocess
import sys

def srcdir():
    return os.path.normpath(os.getenv("SRCDIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")))

def source4dir():
    return os.path.normpath(os.path.join(srcdir(), "source4"))

def source3dir():
    return os.path.normpath(os.path.join(srcdir(), "source3"))

def bindir():
    return os.path.normpath(os.getenv("BINDIR", "./bin"))

def binpath(name):
    return os.path.join(bindir(), name)

# Split perl variable to allow $PERL to be set to e.g. "perl -W"
perl = os.getenv("PERL", "perl").split()

if subprocess.call(perl + ["-e", "eval require Test::More;"]) == 0:
    has_perl_test_more = True
else:
    has_perl_test_more = False

python = os.getenv("PYTHON", "python")
extra_python = os.getenv("EXTRA_PYTHON", None)

tap2subunit = python + " " + os.path.join(srcdir(), "selftest", "tap2subunit")


def valgrindify(cmdline):
    """Run a command under valgrind, if $VALGRIND was set."""
    valgrind = os.getenv("VALGRIND")
    if valgrind is None:
        return cmdline
    return valgrind + " " + cmdline


def plantestsuite(name, env, cmdline):
    """Plan a test suite.

    :param name: Testsuite name
    :param env: Environment to run the testsuite in
    :param cmdline: Command line to run
    """
    print("-- TEST --")
    if env == "none":
        fullname = name
    else:
        fullname = "%s(%s)" % (name, env)
    print(fullname)
    print(env)
    if isinstance(cmdline, list):
        cmdline = " ".join(cmdline)
    if "$LISTOPT" in cmdline:
        raise AssertionError("test %s supports --list, but not --load-list" % name)
    print(cmdline + " 2>&1 " + " | " + add_prefix(name, env))


def add_prefix(prefix, env, support_list=False):
    if support_list:
        listopt = "$LISTOPT "
    else:
        listopt = ""
    return "%s/selftest/filter-subunit %s--fail-on-empty --prefix=\"%s.\" --suffix=\"(%s)\"" % (srcdir(), listopt, prefix, env)


def plantestsuite_loadlist(name, env, cmdline):
    print("-- TEST-LOADLIST --")
    if env == "none":
        fullname = name
    else:
        fullname = "%s(%s)" % (name, env)
    print(fullname)
    print(env)
    if isinstance(cmdline, list):
        cmdline = " ".join(cmdline)
    support_list = ("$LISTOPT" in cmdline)
    if not "$LISTOPT" in cmdline:
        raise AssertionError("loadlist test %s does not support not --list" % name)
    if not "$LOADLIST" in cmdline:
        raise AssertionError("loadlist test %s does not support --load-list" % name)
    print(("%s | %s" % (cmdline.replace("$LOADLIST", ""), add_prefix(name, env, support_list))).replace("$LISTOPT", "--list"))
    print(cmdline.replace("$LISTOPT", "") + " 2>&1 " + " | " + add_prefix(name, env, False))


def skiptestsuite(name, reason):
    """Indicate that a testsuite was skipped.

    :param name: Test suite name
    :param reason: Reason the test suite was skipped
    """
    # FIXME: Report this using subunit, but re-adjust the testsuite count somehow
    print("skipping %s (%s)" % (name, reason), file=sys.stderr)


def planperltestsuite(name, path):
    """Run a perl test suite.

    :param name: Name of the test suite
    :param path: Path to the test runner
    """
    if has_perl_test_more:
        plantestsuite(name, "none", "%s %s | %s" % (" ".join(perl), path, tap2subunit))
    else:
        skiptestsuite(name, "Test::More not available")


def planpythontestsuite(env, module, name=None, extra_path=[], py3_compatible=False):
    if name is None:
        name = module
    pypath = list(extra_path)
    args = [python, "-m", "samba.subunit.run", "$LISTOPT", "$LOADLIST", module]
    if pypath:
        args.insert(0, "PYTHONPATH=%s" % ":".join(["$PYTHONPATH"] + pypath))
    plantestsuite_loadlist(name, env, args)
    if py3_compatible and extra_python is not None:
        # Plan one more test for Python 3 compatible module
        args[0] = extra_python
        plantestsuite_loadlist(name + ".python3", env, args)


def get_env_torture_options():
    ret = []
    if not os.getenv("SELFTEST_VERBOSE"):
        ret.append("--option=torture:progress=no")
    if os.getenv("SELFTEST_QUICK"):
        ret.append("--option=torture:quick=yes")
    return ret


samba4srcdir = source4dir()
samba3srcdir = source3dir()
bbdir = os.path.join(srcdir(), "testprogs/blackbox")
configuration = "--configfile=$SMB_CONF_PATH"

smbtorture4 = binpath("smbtorture")
smbtorture4_testsuite_list = subprocess.Popen([smbtorture4, "--list-suites"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate("")[0].splitlines()

smbtorture4_options = [
    configuration,
    "--option=\'fss:sequence timeout=1\'",
    "--maximum-runtime=$SELFTEST_MAXTIME",
    "--basedir=$SELFTEST_TMPDIR",
    "--format=subunit"
    ] + get_env_torture_options()


def plansmbtorture4testsuite(name, env, options, target, modname=None):
    if modname is None:
        modname = "samba4.%s" % name
    if isinstance(options, list):
        options = " ".join(options)
    options = " ".join(smbtorture4_options + ["--target=%s" % target]) + " " + options
    cmdline = "%s $LISTOPT $LOADLIST %s %s" % (valgrindify(smbtorture4), options, name)
    plantestsuite_loadlist(modname, env, cmdline)


def smbtorture4_testsuites(prefix):
    return filter(lambda x: x.startswith(prefix), smbtorture4_testsuite_list)


smbclient3 = binpath('smbclient')
smbtorture3 = binpath('smbtorture3')
ntlm_auth3 = binpath('ntlm_auth')
net = binpath('net')
scriptdir = os.path.join(srcdir(), "script/tests")

wbinfo = binpath('wbinfo')
dbwrap_tool = binpath('dbwrap_tool')
vfstest = binpath('vfstest')
smbcquotas = binpath('smbcquotas')
smbget = binpath('smbget')
rpcclient = binpath('rpcclient')
smbcacls = binpath('smbcacls')
