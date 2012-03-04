#!/usr/bin/python -u
# Bootstrap Samba and run a number of tests against it.
# Copyright (C) 2005-2012 Jelmer Vernooij <jelmer@samba.org>
# Copyright (C) 2007-2009 Stefan Metzmacher <metze@samba.org>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import atexit
from cStringIO import StringIO
import datetime
import iso8601
import os
import sys
import signal
import shutil
import subprocess
import subunit
import tempfile
import traceback
import warnings

import optparse

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from selftest import (
    socket_wrapper,
    subunithelper,
    testlist,
    )
from selftest.target import (
    EnvironmentManager,
    NoneTarget,
    UnsupportedEnvironment,
    )

includes = ()
excludes = ()

def now():
    return datetime.datetime.utcnow().replace(tzinfo=iso8601.iso8601.Utc())

def read_excludes(fn):
    excludes.extend(testlist.read_test_regexes(fn))

def read_includes(fn):
    includes.extend(testlist.read_test_regexes(fn))

parser = optparse.OptionParser("TEST-REGEXES")
parser.add_option("--target", type="choice", choices=["samba", "samba3", "none"], default="samba", help="Samba version to target")
parser.add_option("--quick", help="run quick overall test", action="store_true", default=False)
parser.add_option("--verbose", help="be verbose", action="store_true", default=False)
parser.add_option("--list", help="list available tests", action="store_true", default=False)
parser.add_option("--socket-wrapper", help="enable socket wrapper", action="store_true", default=False)
parser.add_option("--socket-wrapper-pcap", help="save traffic to pcap directories", type="str")
parser.add_option("--socket-wrapper-keep-pcap", help="keep all pcap files, not just those for tests that failed", action="store_true", default=False)
parser.add_option("--one", help="abort when the first test fails", action="store_true", default=False)
parser.add_option("--exclude", action="callback", help="Add file to exclude files", callback=read_excludes)
parser.add_option("--include", action="callback", help="Add file to include files", callback=read_includes)
parser.add_option("--testenv", help="run a shell in the requested test environment", action="store_true", default=False)
parser.add_option("--resetup-environment", help="Re-setup environment", action="store_true", default=False)
parser.add_option("--binary-mapping", help="Map binaries to use", type=str)
parser.add_option("--load-list", help="Load list of tests to load from a file", type=str)
parser.add_option("--prefix", help="prefix to run tests in", type=str, default="./st")
parser.add_option("--srcdir", type=str, default=".", help="source directory")
parser.add_option("--bindir", type=str, default="./bin", help="binaries directory")
parser.add_option("--testlist", type=str, action="append", help="file to read available tests from")
parser.add_option("--ldap", help="back samba onto specified ldap server", choices=["openldap", "fedora-ds"], type="choice")

opts, args = parser.parse_args()

subunit_ops = subunithelper.SubunitOps(sys.stdout)

def pipe_handler(sig, frame):
    sys.stderr.write("Exiting early because of SIGPIPE.\n")
    sys.exit(1)

signal.signal(signal.SIGPIPE, pipe_handler)

def skip(name):
    return testlist.find_in_list(excludes, name)

def setup_pcap(name):
    if (not opts.socket_wrapper_pcap or
        not os.environ.get("SOCKET_WRAPPER_PCAP_DIR")):
        return

    fname = "".join([x for x in name if x.isalnum() or x == '-'])

    pcap_file = os.path.join(
        os.environ["SOCKET_WRAPPER_PCAP_DIR"], "%s.pcap" % fname)

    socket_wrapper.setup_pcap(pcap_file)
    return pcap_file


def cleanup_pcap(pcap_file, exit_code):
    if not opts.socket_wrapper_pcap:
        return
    if opts.socket_wrapper_keep_pcap:
        return
    if exitcode == 0:
        return
    if pcap_file is None:
        return

    os.unlink(pcap_file)


# expand strings from %ENV
def expand_environment_strings(s):
    # we use a reverse sort so we do the longer ones first
    for k in sorted(os.environ.keys(), reverse=True):
        v = os.environ[k]
        s = s.replace("$%s" % k, v)
    return s


def run_testsuite(envname, name, cmd, i, totalsuites):
    pcap_file = setup_pcap(name)

    subunit_ops.start_testsuite(name)
    subunit_ops.progress(None, subunit.PROGRESS_PUSH)
    subunit_ops.time(now())
    try:
        exitcode = subprocess.call(cmd, shell=True)
    except Exception, e:
        subunit_ops.time(now())
        subunit_ops.progress(None, subunit.PROGRESS_POP)
        subunit_ops.end_testsuite(name, "error", "Unable to run %r: %s" % (cmd, e))
        sys.exit(1)

    subunit_ops.time(now())
    subunit_ops.progress(None, subunit.PROGRESS_POP)

    envlog = env_manager.getlog_env(envname)
    if envlog != "":
        sys.stdout.write("envlog: %s\n" % envlog)

    sys.stdout.write("command: %s\n" % cmd)
    sys.stdout.write("expanded command: %s\n" % expand_environment_strings(cmd))

    if exitcode == 0:
        subunit_ops.end_testsuite(name, "success")
    else:
        subunit_ops.end_testsuite(name, "failure", "Exit code was %d" % exitcode)

    cleanup_pcap(pcap_file, exitcode)

    if not opts.socket_wrapper_keep_pcap and pcap_file is not None:
        sys.stdout.write("PCAP FILE: %s\n" % pcap_file)

    if exitcode != 0 and opts.one:
        sys.exit(1)

    return exitcode

if opts.list and opts.testenv:
    sys.stderr.write("--list and --testenv are mutually exclusive\n")
    sys.exit(1)

tests = args

# quick hack to disable rpc validation when using valgrind - its way too slow
if not os.environ.get("VALGRIND"):
    os.environ["VALIDATE"] = "validate"
    os.environ["MALLOC_CHECK_"] = "2"

# make all our python scripts unbuffered
os.environ["PYTHONUNBUFFERED"] = "1"

bindir_abs = os.path.abspath(opts.bindir)

# Backwards compatibility:
if os.environ.get("TEST_LDAP") == "yes":
    if os.environ.get("FEDORA_DS_ROOT"):
        ldap = "fedora-ds"
    else:
        ldap = "openldap"

torture_maxtime = int(os.getenv("TORTURE_MAXTIME", "1200"))
if opts.ldap:
    # LDAP is slow
    torture_maxtime *= 2

prefix = os.path.normpath(opts.prefix)

if prefix == "":
    raise Exception("using an empty prefix isn't allowed")

# Ensure we have the test prefix around.
#
# We need restrictive
# permissions on this as some subdirectories in this tree will have
# wider permissions (ie 0777) and this would allow other users on the
# host to subvert the test process.
if not os.path.isdir(prefix):
    os.mkdir(prefix, 0700)
else:
    os.chmod(prefix, 0700)

prefix_abs = os.path.abspath(prefix)
tmpdir_abs = os.path.abspath(os.path.join(prefix_abs, "tmp"))
if not os.path.isdir(tmpdir_abs):
    os.mkdir(tmpdir_abs, 0777)

srcdir_abs = os.path.abspath(opts.srcdir)

if prefix_abs == "":
    raise Exception("using an empty absolute prefix isn't allowed")
if prefix_abs == "/":
    raise Exception("using '/' as absolute prefix isn't allowed")

os.environ["PREFIX"] = prefix
os.environ["KRB5CCNAME"] = os.path.join(prefix, "krb5ticket")
os.environ["PREFIX_ABS"] = prefix_abs
os.environ["SRCDIR"] = opts.srcdir
os.environ["SRCDIR_ABS"] = srcdir_abs
os.environ["BINDIR"] = bindir_abs

tls_enabled = not opts.quick
if tls_enabled:
    os.environ["TLS_ENABLED"] = "yes"
else:
    os.environ["TLS_ENABLED"] = "no"

def prefix_pathvar(name, newpath):
    if name in os.environ:
        os.environ[name] = "%s:%s" % (newpath, os.environ[name])
    else:
        os.environ[name] = newpath
prefix_pathvar("PKG_CONFIG_PATH", os.path.join(bindir_abs, "pkgconfig"))
prefix_pathvar("PYTHONPATH", os.path.join(bindir_abs, "python"))

if opts.socket_wrapper_keep_pcap:
    # Socket wrapper keep pcap implies socket wrapper pcap
    opts.socket_wrapper_pcap = True

if opts.socket_wrapper_pcap:
    # Socket wrapper pcap implies socket wrapper
    opts.socket_wrapper = True

if opts.socket_wrapper:
    socket_wrapper_dir = socket_wrapper.setup_dir(os.path.join(prefix_abs, "w"), opts.socket_wrapper_pcap)
    sys.stdout.write("SOCKET_WRAPPER_DIR=%s\n" % socket_wrapper_dir)
elif not opts.list:
    if os.getuid() != 0:
        warnings.warn("not using socket wrapper, but also not running as root. Will not be able to listen on proper ports")

testenv_default = "none"

if opts.binary_mapping:
    binary_mapping = dict([l.split(":") for l in opts.binary_mapping.split(",")])
    os.environ["BINARY_MAPPING"] = opts.binary_mapping
else:
    binary_mapping = {}
    os.environ["BINARY_MAPPING"] = ""

# After this many seconds, the server will self-terminate.  All tests
# must terminate in this time, and testenv will only stay alive this
# long

server_maxtime = 7500
if os.environ.get("SMBD_MAXTIME", ""):
    server_maxtime = int(os.environ["SMBD_MAXTIME"])


def has_socket_wrapper(bindir):
    """Check if Samba has been built with socket wrapper support.
    """
    f = StringIO()
    subprocess.check_call([os.path.join(bindir, "smbd"), "-b"], stdout=f)
    for l in f.readlines():
        if "SOCKET_WRAPPER" in l:
            return True
    return False


if not opts.list:
    if opts.target == "samba":
        if opts.socket_wrapper and not has_socket_wrapper(opts.bindir):
            sys.stderr.write("You must include --enable-socket-wrapper when compiling Samba in order to execute 'make test'.  Exiting....\n")
            sys.exit(1)
        testenv_default = "dc"
        from selftest.target.samba import Samba
        target = Samba(opts.bindir, binary_mapping, ldap, opts.srcdir, server_maxtime)
    elif opts.target == "samba3":
        if opts.socket_wrapper and not has_socket_wrapper(opts.bindir):
            sys.stderr.write("You must include --enable-socket-wrapper when compiling Samba in order to execute 'make test'.  Exiting....\n")
            sys.exit(1)
        testenv_default = "member"
        from selftest.target.samba3 import Samba3
        target = Samba3(opts.bindir, binary_mapping, srcdir_abs, server_maxtime)
    elif opts.target == "none":
        testenv_default = "none"
        target = NoneTarget()

    env_manager = EnvironmentManager(target)
    atexit.register(env_manager.teardown_all)

interfaces = ",".join([
    "127.0.0.11/8",
    "127.0.0.12/8",
    "127.0.0.13/8",
    "127.0.0.14/8",
    "127.0.0.15/8",
    "127.0.0.16/8"])

clientdir = os.path.join(prefix_abs, "client")

conffile = os.path.join(clientdir, "client.conf")
os.environ["SMB_CONF_PATH"] = conffile

def write_clientconf(conffile, clientdir, vars):
    if not os.path.isdir(clientdir):
        os.mkdir(clientdir, 0777)

    for n in ["private", "lockdir", "statedir", "cachedir"]:
        p = os.path.join(clientdir, n)
        if os.path.isdir(p):
            shutil.rmtree(p)
        os.mkdir(p, 0777)

    # this is ugly, but the ncalrpcdir needs exactly 0755
    # otherwise tests fail.
    mask = os.umask(0022)

    for n in ["ncalrpcdir", "ncalrpcdir/np"]:
        p = os.path.join(clientdir, n)
        if os.path.isdir(p):
            shutil.rmtree(p)
        os.mkdir(p, 0777)
    os.umask(mask)

    settings = {
        "netbios name": "client",
        "private dir": os.path.join(clientdir, "private"),
        "lock dir": os.path.join(clientdir, "lockdir"),
        "state directory": os.path.join(clientdir, "statedir"),
        "cache directory": os.path.join(clientdir, "cachedir"),
        "ncalrpc dir": os.path.join(clientdir, "ncalrpcdir"),
        "name resolve order": "file bcast",
        "panic action": os.path.join(os.path.dirname(__file__), "gdb_backtrace \%d"),
        "max xmit": "32K",
        "notify:inotify": "false",
        "ldb:nosync": "true",
        "system:anonymous": "true",
        "client lanman auth": "Yes",
        "log level": "1",
        "torture:basedir": clientdir,
        # We don't want to pass our self-tests if the PAC code is wrong
        "gensec:require_pac": "true",
        "resolv:host file": os.path.join(prefix_abs, "dns_host_file"),
        # We don't want to run 'speed' tests for very long
        "torture:timelimit": "1",
        }

    if "DOMAIN" in vars:
        settings["workgroup"] = vars["DOMAIN"]
    if "REALM" in vars:
        settings["realm"] = vars["REALM"]
    if opts.socket_wrapper:
        settings["interfaces"] = interfaces

    f = open(conffile, 'w')
    try:
        f.write("[global]\n")
        for item in settings.iteritems():
            f.write("\t%s = %s\n" % item)
    finally:
        f.close()

todo = []

if not opts.testlist:
    sys.stderr.write("No testlists specified\n")
    sys.exit(1)

os.environ["SELFTEST_PREFIX"] = prefix_abs
os.environ["SELFTEST_TMPDIR"] = tmpdir_abs
os.environ["TEST_DATA_PREFIX"] = tmpdir_abs
if opts.socket_wrapper:
    os.environ["SELFTEST_INTERFACES"] = interfaces
else:
    os.environ["SELFTEST_INTERFACES"] = ""
if opts.verbose:
    os.environ["SELFTEST_VERBOSE"] = "1"
else:
    os.environ["SELFTEST_VERBOSE"] = ""
if opts.quick:
    os.environ["SELFTEST_QUICK"] = "1"
else:
    os.environ["SELFTEST_QUICK"] = ""
os.environ["SELFTEST_MAXTIME"] = str(torture_maxtime)


def open_file_or_pipe(path, mode):
    if path.endswith("|"):
        return os.popen(path[:-1], mode)
    return open(path, mode)

available = []
for fn in opts.testlist:
    inf = open_file_or_pipe(fn, 'r')
    try:
        for testsuite in testlist.read_testlist(inf, sys.stdout):
            if not testlist.should_run_test(tests, testsuite):
                continue
            name = testsuite[0]
            if includes is not None and testlist.find_in_list(includes, name) is not None:
                continue
            available.append(testsuite)
    finally:
        inf.close()

if opts.load_list:
    restricted_mgr = testlist.RestrictedTestManager.from_path(opts.load_list)
else:
    restricted_mgr = None


for testsuite in available:
    name = testsuite[0]
    skipreason = skip(name)
    if restricted_mgr is not None:
        match = restricted_mgr.should_run_testsuite(name)
        if match == []:
            continue
    else:
        match = None
    if skipreason is not None:
        if not opts.list:
            subunit_ops.skip_testsuite(name, skipreason)
    else:
        todo.append(testsuite + (match,))

if restricted_mgr is not None:
    for name in restricted_mgr.iter_unused():
        sys.stdout.write("No test or testsuite found matching %s\n" % name)
if todo == []:
    sys.stderr.write("No tests to run\n")
    sys.exit(1)

suitestotal = len(todo)

if not opts.list:
    subunit_ops.progress(suitestotal, subunit.PROGRESS_SET)
    subunit_ops.time(now())

i = 0

exported_envvars = [
    # domain stuff
    "DOMAIN",
    "REALM",

    # domain controller stuff
    "DC_SERVER",
    "DC_SERVER_IP",
    "DC_NETBIOSNAME",
    "DC_NETBIOSALIAS",

    # domain member
    "MEMBER_SERVER",
    "MEMBER_SERVER_IP",
    "MEMBER_NETBIOSNAME",
    "MEMBER_NETBIOSALIAS",

    # rpc proxy controller stuff
    "RPC_PROXY_SERVER",
    "RPC_PROXY_SERVER_IP",
    "RPC_PROXY_NETBIOSNAME",
    "RPC_PROXY_NETBIOSALIAS",

    # domain controller stuff for Vampired DC
    "VAMPIRE_DC_SERVER",
    "VAMPIRE_DC_SERVER_IP",
    "VAMPIRE_DC_NETBIOSNAME",
    "VAMPIRE_DC_NETBIOSALIAS",

    # server stuff
    "SERVER",
    "SERVER_IP",
    "NETBIOSNAME",
    "NETBIOSALIAS",

    # user stuff
    "USERNAME",
    "USERID",
    "PASSWORD",
    "DC_USERNAME",
    "DC_PASSWORD",

    # misc stuff
    "KRB5_CONFIG",
    "WINBINDD_SOCKET_DIR",
    "WINBINDD_PRIV_PIPE_DIR",
    "NMBD_SOCKET_DIR",
    "LOCAL_PATH"
]

def handle_sigdie(signame, frame):
    sys.stderr.write("Received signal %s" % signame)
    sys.exit(1)

signal.signal(signal.SIGINT, handle_sigdie)
signal.signal(signal.SIGQUIT, handle_sigdie)
signal.signal(signal.SIGTERM, handle_sigdie)

def exported_envvars_str(testenv_vars):
    out = ""

    for n in exported_envvars:
        if not n in testenv_vars:
            continue
        out += "%s=%s\n" % (n, testenv_vars[n])

    return out


def switch_env(name, prefix):
    if ":" in name:
        (envname, option) = name.split(":", 1)
    else:
        envname = name
        option = "client"

    env = env_manager.setup_env(envname, prefix)

    testenv_vars = env.get_vars()

    if option == "local":
        socket_wrapper.set_default_iface(testenv_vars["SOCKET_WRAPPER_DEFAULT_IFACE"])
        os.environ["SMB_CONF_PATH"] = testenv_vars["SERVERCONFFILE"]
    elif option == "client":
        socket_wrapper.set_default_iface(11)
        write_clientconf(conffile, clientdir, testenv_vars)
        os.environ["SMB_CONF_PATH"] = conffile
    else:
        raise Exception("Unknown option[%s] for envname[%s]" % (option,
            envname))

    for name in exported_envvars:
        if name in testenv_vars:
            os.environ[name] = testenv_vars[name]
        elif name in os.environ:
            del os.environ[name]

    return testenv_vars

# This 'global' file needs to be empty when we start
dns_host_file_path = os.path.join(prefix_abs, "dns_host_file")
if os.path.exists(dns_host_file_path):
    os.unlink(dns_host_file_path)

if opts.testenv:
    testenv_name = os.environ.get("SELFTEST_TESTENV", testenv_default)

    testenv_vars = switch_env(testenv_name, prefix)

    os.environ["PIDDIR"] = testenv_vars["PIDDIR"]
    os.environ["ENVNAME"] = testenv_name

    envvarstr = exported_envvars_str(testenv_vars)

    term = os.environ.get("TERMINAL", "xterm -e")
    cmd = """'echo -e "
Welcome to the Samba4 Test environment '%(testenv_name)'

This matches the client environment used in make test
server is pid `cat \$PIDDIR/samba.pid`

Some useful environment variables:
TORTURE_OPTIONS=\$TORTURE_OPTIONS
SMB_CONF_PATH=\$SMB_CONF_PATH

$envvarstr
\" && LD_LIBRARY_PATH=%(LD_LIBRARY_PATH)s $(SHELL)'""" % {
        "testenv_name": testenv_name,
        "LD_LIBRARY_PATH": os.environ["LD_LIBRARY_PATH"]}
    subprocess.call(term + ' ' + cmd, shell=True)
    env_manager.teardown_env(testenv_name)
elif opts.list:
    for (name, envname, cmd, supports_loadfile, supports_idlist, subtests) in todo:
        if not "$LISTOPT" in cmd:
            warnings.warn("Unable to list tests in %s" % name)
            continue

        cmd = cmd.replace("$LISTOPT", "--list")

        exitcode = subprocess.call(cmd, shell=True)

        if exitcode != 0:
            sys.stderr.write("%s exited with exit code %s\n" % (cmd, exitcode))
            sys.exit(1)
else:
    for (name, envname, cmd, supports_loadfile, supports_idlist, subtests) in todo:
        try:
            envvars = switch_env(envname, prefix)
        except UnsupportedEnvironment:
            subunit_ops.start_testsuite(name)
            subunit_ops.end_testsuite(name, "skip",
                "environment %s is unknown in this test backend - skipping" % envname)
            continue
        except Exception, e:
            subunit_ops.start_testsuite(name)
            traceback.print_exc()
            subunit_ops.end_testsuite(name, "error",
                "unable to set up environment %s: %s" % (envname, e))
            continue

        # Generate a file with the individual tests to run, if the
        # test runner for this test suite supports it.
        if subtests is not None:
            if supports_loadfile:
                (fd, listid_file) = tempfile.mkstemp()
                # FIXME: Remove tempfile afterwards
                f = os.fdopen(fd)
                try:
                    for test in subtests:
                        f.write(test+"\n")
                finally:
                    f.close()
                cmd = cmd.replace("$LOADLIST", "--load-list=%s" % listid_file)
            elif supports_idlist:
                cmd += " ".join(subtests)

        run_testsuite(envname, name, cmd, i, suitestotal)

        if opts.resetup_environment:
            env_manager.teardown_env(envname)

sys.stdout.write("\n")

if not opts.list:
    env_manager.teardown_all()

# if there were any valgrind failures, show them
for fn in os.listdir(prefix):
    if fn.startswith("valgrind.log"):
        sys.stdout.write("VALGRIND FAILURE\n")
        f = open(os.path.join(prefix, fn), 'r')
        try:
            sys.stdout.write(f.read())
        finally:
            f.close()

sys.exit(0)
