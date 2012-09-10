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

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../selftest"))
from selftesthelpers import *
import subprocess

samba4srcdir = source4dir()
samba4bindir = bindir()
smb4torture = binpath("smbtorture4")
smb4torture_testsuite_list = subprocess.Popen([smb4torture, "--list-suites"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate("")[0].splitlines()
validate = os.getenv("VALIDATE", "")
if validate:
    validate_list = [validate]
else:
    validate_list = []

nmblookup = binpath('nmblookup4')
smbclient = binpath('smbclient4')

def plansmbtorturetestsuite(name, env, options, modname=None):
    if modname is None:
        modname = "samba4.%s" % name
    if isinstance(options, list):
        options = " ".join(options)
    cmdline = "%s $LISTOPT %s %s" % (valgrindify(smb4torture), options, name)
    plantestsuite_loadlist(modname, env, cmdline)

def smb4torture_testsuites(prefix):
    return filter(lambda x: x.startswith(prefix), smb4torture_testsuite_list)

subprocess.call([smb4torture, "-V"], stdout=sys.stderr)

bbdir = os.path.join(srcdir(), "testprogs/blackbox")

configuration = "--configfile=$SMB_CONF_PATH"

torture_options = [configuration, "--maximum-runtime=$SELFTEST_MAXTIME", "--target=samba4", "--basedir=$SELFTEST_TMPDIR"]
if not os.getenv("SELFTEST_VERBOSE"):
    torture_options.append("--option=torture:progress=no")
torture_options.append("--format=subunit")
if os.getenv("SELFTEST_QUICK"):
    torture_options.append("--option=torture:quick=yes")
smb4torture += " " + " ".join(torture_options)

print >>sys.stderr, "OPTIONS %s" % " ".join(torture_options)

# Simple tests for LDAP and CLDAP
for options in ['-U"$USERNAME%$PASSWORD" --option=socket:testnonblock=true', '-U"$USERNAME%$PASSWORD"', '-U"$USERNAME%$PASSWORD" -k yes', '-U"$USERNAME%$PASSWORD" -k no', '-U"$USERNAME%$PASSWORD" -k no --sign', '-U"$USERNAME%$PASSWORD" -k no --encrypt', '-U"$USERNAME%$PASSWORD" -k yes --encrypt', '-U"$USERNAME%$PASSWORD" -k yes --sign']:
    plantestsuite("samba4.ldb.ldap with options %s(dc)" % options, "dc", "%s/test_ldb.sh ldap $SERVER %s" % (bbdir, options))

# see if we support ADS on the Samba3 side
try:
    config_h = os.environ["CONFIG_H"]
except KeyError:
    config_h = os.path.join(samba4bindir, "default/include/config.h")

# see if we support ldaps
f = open(config_h, 'r')
try:
    have_tls_support = ("ENABLE_GNUTLS 1" in f.read())
finally:
    f.close()

if have_tls_support:
    for options in ['-U"$USERNAME%$PASSWORD"']:
        plantestsuite("samba4.ldb.ldaps with options %s(dc)" % options, "dc",
                "%s/test_ldb.sh ldaps $SERVER_IP %s" % (bbdir, options))

for options in ['-U"$USERNAME%$PASSWORD"']:
    plantestsuite("samba4.ldb.ldapi with options %s(dc:local)" % options, "dc:local",
            "%s/test_ldb.sh ldapi $PREFIX_ABS/dc/private/ldapi %s" % (bbdir, options))

for t in smb4torture_testsuites("ldap."):
    plansmbtorturetestsuite(t, "dc", '-U"$USERNAME%$PASSWORD" //$SERVER_IP/_none_')

ldbdir = os.path.join(srcdir(), "lib/ldb")
# Don't run LDB tests when using system ldb, as we won't have ldbtest installed
if os.path.exists(os.path.join(samba4bindir, "ldbtest")):
    plantestsuite("ldb.base", "none", "%s/tests/test-tdb-subunit.sh %s" % (ldbdir, samba4bindir))
else:
    skiptestsuite("ldb.base", "Using system LDB, ldbtest not available")

# Tests for RPC

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests = ["rpc.schannel", "rpc.join", "rpc.lsa", "rpc.dssetup", "rpc.altercontext", "rpc.multibind", "rpc.netlogon", "rpc.handles", "rpc.samsync", "rpc.samba3-sessionkey", "rpc.samba3-getusername", "rpc.samba3-lsa", "rpc.samba3-bind", "rpc.samba3-netlogon", "rpc.asyncbind", "rpc.lsalookup", "rpc.lsa-getuser", "rpc.schannel2", "rpc.authcontext"]
ncalrpc_tests = ["rpc.schannel", "rpc.join", "rpc.lsa", "rpc.dssetup", "rpc.altercontext", "rpc.multibind", "rpc.netlogon", "rpc.drsuapi", "rpc.asyncbind", "rpc.lsalookup", "rpc.lsa-getuser", "rpc.schannel2", "rpc.authcontext"]
drs_rpc_tests = smb4torture_testsuites("drs.rpc")
ncacn_ip_tcp_tests = ["rpc.schannel", "rpc.join", "rpc.lsa", "rpc.dssetup", "rpc.multibind", "rpc.netlogon", "rpc.asyncbind", "rpc.lsalookup", "rpc.lsa-getuser", "rpc.schannel2", "rpc.authcontext"] + drs_rpc_tests
slow_ncacn_np_tests = ["rpc.samlogon", "rpc.samr.users", "rpc.samr.large-dc", "rpc.samr.users.privileges", "rpc.samr.passwords", "rpc.samr.passwords.pwdlastset"]
slow_ncacn_ip_tcp_tests = ["rpc.samr", "rpc.cracknames"]

all_rpc_tests = ncalrpc_tests + ncacn_np_tests + ncacn_ip_tcp_tests + slow_ncacn_np_tests + slow_ncacn_ip_tcp_tests + ["rpc.lsa.secrets", "rpc.pac", "rpc.samba3-sharesec", "rpc.countcalls"]

# Make sure all tests get run
rpc_tests = smb4torture_testsuites("rpc.")
auto_rpc_tests = filter(lambda t: t not in all_rpc_tests, rpc_tests)

for bindoptions in ["seal,padcheck"] + validate_list + ["bigendian"]:
    for transport in ["ncalrpc", "ncacn_np", "ncacn_ip_tcp"]:
        env = "dc"
        if transport == "ncalrpc":
            tests = ncalrpc_tests
            env = "dc:local"
        elif transport == "ncacn_np":
            tests = ncacn_np_tests
        elif transport == "ncacn_ip_tcp":
            tests = ncacn_ip_tcp_tests
        else:
            raise AssertionError("invalid transport %r"% transport)
        for t in tests:
            plansmbtorturetestsuite(t, env, ["%s:$SERVER[%s]" % (transport, bindoptions), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.%s on %s with %s" % (t, transport, bindoptions))
        plansmbtorturetestsuite('rpc.samba3-sharesec', env, ["%s:$SERVER[%s]" % (transport, bindoptions), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', '--option=torture:share=tmp'], "samba4.rpc.samba3.sharesec on %s with %s" % (transport, bindoptions))

#Plugin S4 DC tests (confirms named pipe auth forwarding).  This can be expanded once kerberos is supported in the plugin DC
#
for bindoptions in ["seal,padcheck"] + validate_list + ["bigendian"]:
    for t in ncacn_np_tests:
        env = "plugin_s4_dc"
        transport = "ncacn_np"
        plansmbtorturetestsuite(t, env, ["%s:$SERVER[%s]" % (transport, bindoptions), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.%s with %s" % (t, bindoptions))

for bindoptions in [""] + validate_list + ["bigendian"]:
    for t in auto_rpc_tests:
        plansmbtorturetestsuite(t, "dc", ["$SERVER[%s]" % bindoptions, '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.%s with %s" % (t, bindoptions))

t = "rpc.countcalls"
plansmbtorturetestsuite(t, "dc:local", ["$SERVER[%s]" % bindoptions, '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], modname="samba4.%s" % t)

for transport in ["ncacn_np", "ncacn_ip_tcp"]:
    env = "dc"
    if transport == "ncacn_np":
        tests = slow_ncacn_np_tests
    elif transport == "ncacn_ip_tcp":
        tests = slow_ncacn_ip_tcp_tests
    else:
        raise AssertionError("Invalid transport %r" % transport)
    for t in tests:
        plansmbtorturetestsuite(t, env, ["%s:$SERVER" % transport, '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.%s on %s" % (t, transport))

# Tests for the DFS referral calls implementation
for t in smb4torture_testsuites("dfs."):
    plansmbtorturetestsuite(t, "dc", '//$SERVER/ipc\$ -U$USERNAME%$PASSWORD')
    plansmbtorturetestsuite(t, "plugin_s4_dc", '//$SERVER/ipc\$ -U$USERNAME%$PASSWORD')

# Tests for the NET API (net.api.become.dc tested below against all the roles)
net_tests = filter(lambda x: "net.api.become.dc" not in x, smb4torture_testsuites("net."))
for t in net_tests:
    plansmbtorturetestsuite(t, "dc", '$SERVER[%s] -U$USERNAME%%$PASSWORD -W$DOMAIN' % validate)

# Tests for session keys and encryption of RPC pipes
# FIXME: Integrate these into a single smbtorture test

transport = "ncacn_np"
for env in ["dc", "s3dc"]:
    for ntlmoptions in [
        "-k no --option=usespnego=yes",
        "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no",
        "-k no --option=usespnego=yes --option=ntlmssp_client:56bit=yes",
        "-k no --option=usespnego=yes --option=ntlmssp_client:56bit=no",
        "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=yes",
        "-k no --option=usespnego=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=no",
        "-k no --option=usespnego=yes --option=clientntlmv2auth=yes",
        "-k no --option=usespnego=yes --option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no",
        "-k no --option=usespnego=yes --option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=yes",
        "-k no --option=usespnego=no --option=clientntlmv2auth=yes",
        "-k no --option=gensec:spnego=no --option=clientntlmv2auth=yes",
        "-k no --option=usespnego=no"]:
        name = "rpc.lsa.secrets on %s with with %s" % (transport, ntlmoptions)
        plansmbtorturetestsuite('rpc.lsa.secrets', env, ["%s:$SERVER[]" % (transport), ntlmoptions, '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', '--option=gensec:target_hostname=$NETBIOSNAME'], "samba4.%s" % name)
    plantestsuite("samba.blackbox.pdbtest", "%s:local" % env, [os.path.join(bbdir, "test_pdbtest.sh"), '$SERVER', "$PREFIX", smbclient, '$SMB_CONF_PATH', configuration])

transports = ["ncacn_np", "ncacn_ip_tcp"]

#Kerberos varies between functional levels, so it is important to check this on all of them
for env in ["dc", "fl2000dc", "fl2003dc", "fl2008r2dc", "plugin_s4_dc"]:
    transport = "ncacn_np"
    plansmbtorturetestsuite('rpc.pac', env, ["%s:$SERVER[]" % (transport, ), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.pac on %s" % (transport,))
    plansmbtorturetestsuite('rpc.lsa.secrets', env, ["%s:$SERVER[]" % (transport, ), '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', '--option=gensec:target_hostname=$NETBIOSNAME', 'rpc.lsa.secrets'], "samba4.rpc.lsa.secrets on %s with Kerberos" % (transport,))
    plansmbtorturetestsuite('rpc.lsa.secrets', env, ["%s:$SERVER[]" % (transport, ), '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', "--option=clientusespnegoprincipal=yes", '--option=gensec:target_hostname=$NETBIOSNAME'], "samba4.rpc.lsa.secrets on %s with Kerberos - use target principal" % (transport,))
    plansmbtorturetestsuite('rpc.lsa.secrets.none*', env, ["%s:$SERVER" % transport, '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', "--option=gensec:fake_gssapi_krb5=yes", '--option=gensec:gssapi_krb5=no', '--option=gensec:target_hostname=$NETBIOSNAME'], "samba4.rpc.lsa.secrets on %s with Kerberos - use Samba3 style login" % transport)
    plansmbtorturetestsuite('rpc.lsa.secrets.none*', env, ["%s:$SERVER" % transport, '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', "--option=clientusespnegoprincipal=yes", '--option=gensec:fake_gssapi_krb5=yes', '--option=gensec:gssapi_krb5=no', '--option=gensec:target_hostname=$NETBIOSNAME'], "samba4.rpc.lsa.secrets on %s with Kerberos - use Samba3 style login, use target principal" % transport)
    for transport in transports:
        plansmbtorturetestsuite('rpc.echo', env, ["%s:$SERVER[]" % (transport,), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.echo on %s" % (transport, ))

        # Echo tests test bulk Kerberos encryption of DCE/RPC
        for bindoptions in ["connect", "spnego", "spnego,sign", "spnego,seal"] + validate_list + ["padcheck", "bigendian", "bigendian,seal"]:
            echooptions = "--option=socket:testnonblock=True --option=torture:quick=yes -k yes"
            plansmbtorturetestsuite('rpc.echo', env, ["%s:$SERVER[%s]" % (transport, bindoptions), echooptions, '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.echo on %s with %s and %s" % (transport, bindoptions, echooptions))
    plansmbtorturetestsuite("net.api.become.dc", env, '$SERVER[%s] -U$USERNAME%%$PASSWORD -W$DOMAIN' % validate)

for bindoptions in ["sign", "seal"]:
    plansmbtorturetestsuite('rpc.backupkey', "dc", ["ncacn_np:$SERVER[%s]" % ( bindoptions), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.backupkey with %s" % (bindoptions))

for transport in transports:
    for bindoptions in ["sign", "seal"]:
        for ntlmoptions in [
        "--option=ntlmssp_client:ntlm2=yes --option=torture:quick=yes",
        "--option=ntlmssp_client:ntlm2=no --option=torture:quick=yes",
        "--option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:128bit=no --option=torture:quick=yes",
        "--option=ntlmssp_client:ntlm2=no --option=ntlmssp_client:128bit=no --option=torture:quick=yes",
        "--option=ntlmssp_client:ntlm2=yes --option=ntlmssp_client:keyexchange=no --option=torture:quick=yes",
        "--option=ntlmssp_client:ntlm2=no --option=ntlmssp_client:keyexchange=no --option=torture:quick=yes",
        "--option=clientntlmv2auth=yes --option=ntlmssp_client:keyexchange=no --option=torture:quick=yes",
        "--option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:keyexchange=yes --option=torture:quick=yes",
        "--option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:keyexchange=no --option=torture:quick=yes"]:
            if transport == "ncalrpc":
                env = "dc:local"
            else:
                env = "dc"
            plansmbtorturetestsuite('rpc.echo', env, ["%s:$SERVER[%s]" % (transport, bindoptions), ntlmoptions, '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.echo on %s with %s and %s" % (transport, bindoptions, ntlmoptions))

plansmbtorturetestsuite('rpc.echo', "dc", ['ncacn_np:$SERVER[smb2]', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.echo on ncacn_np over smb2")

plansmbtorturetestsuite('ntp.signd', "dc:local", ['ncacn_np:$SERVER', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.ntp.signd")

nbt_tests = smb4torture_testsuites("nbt.")
for t in nbt_tests:
    plansmbtorturetestsuite(t, "dc", "//$SERVER/_none_ -U\"$USERNAME%$PASSWORD\"")

# Tests against the NTVFS POSIX backend
ntvfsargs = ["--option=torture:sharedelay=10000", "--option=torture:oplocktimeout=3", "--option=torture:writetimeupdatedelay=50000"]

smb2 = smb4torture_testsuites("smb2.")
#The QFILEINFO-IPC test needs to be on ipc$
raw = filter(lambda x: "raw.qfileinfo.ipc" not in x, smb4torture_testsuites("raw."))
base = smb4torture_testsuites("base.")

netapi = smb4torture_testsuites("netapi.")

libsmbclient = smb4torture_testsuites("libsmbclient.")

for t in base + raw + smb2 + netapi + libsmbclient:
    plansmbtorturetestsuite(t, "dc", ['//$SERVER/tmp', '-U$USERNAME%$PASSWORD'] + ntvfsargs)

plansmbtorturetestsuite("raw.qfileinfo.ipc", "dc", '//$SERVER/ipc\$ -U$USERNAME%$PASSWORD')

for t in smb4torture_testsuites("rap."):
    plansmbtorturetestsuite(t, "dc", '//$SERVER/IPC\$ -U$USERNAME%$PASSWORD')

# Tests against the NTVFS CIFS backend
for t in base + raw:
    plansmbtorturetestsuite(t, "dc", ['//$NETBIOSNAME/cifs', '-U$USERNAME%$PASSWORD', '--kerberos=yes'] + ntvfsargs, modname="samba4.ntvfs.cifs.krb5.%s" % t)

# Test NTVFS CIFS backend with S4U2Self and S4U2Proxy
t = "base.unlink"
plansmbtorturetestsuite(t, "dc", ['//$NETBIOSNAME/cifs', '-U$USERNAME%$PASSWORD', '--kerberos=no'] + ntvfsargs, "samba4.ntvfs.cifs.ntlm.%s" % t)
plansmbtorturetestsuite(t, "rpc_proxy", ['//$NETBIOSNAME/cifs_to_dc', '-U$DC_USERNAME%$DC_PASSWORD', '--kerberos=yes'] + ntvfsargs, "samba4.ntvfs.cifs.krb5.%s" % t)
plansmbtorturetestsuite(t, "rpc_proxy", ['//$NETBIOSNAME/cifs_to_dc', '-U$DC_USERNAME%$DC_PASSWORD', '--kerberos=no'] + ntvfsargs, "samba4.ntvfs.cifs.ntlm.%s" % t)

plansmbtorturetestsuite('echo.udp', 'dc:local', '//$SERVER/whatever')

# Local tests
for t in smb4torture_testsuites("local."):
    #The local.resolve test needs a name to look up using real system (not emulated) name routines
    plansmbtorturetestsuite(t, "none", "ncalrpc:localhost")

# Confirm these tests with the system iconv too
for t in ["local.convert_string_handle", "local.convert_string", "local.ndr"]:
    options = "ncalrpc: --option='iconv:use_builtin_handlers=false'"
    plansmbtorturetestsuite(t, "none", options,
        modname="samba4.%s.system.iconv" % t)

tdbtorture4 = binpath("tdbtorture")
if os.path.exists(tdbtorture4):
    plantestsuite("tdb.stress", "none", valgrindify(tdbtorture4))
else:
    skiptestsuite("tdb.stress", "Using system TDB, tdbtorture not available")

plansmbtorturetestsuite("drs.unit", "none", "ncalrpc:")

# Pidl tests
for f in sorted(os.listdir(os.path.join(samba4srcdir, "../pidl/tests"))):
    if f.endswith(".pl"):
        planperltestsuite("pidl.%s" % f[:-3], os.path.normpath(os.path.join(samba4srcdir, "../pidl/tests", f)))

# DNS tests
planpythontestsuite("fl2003dc", "samba.tests.dns")

# Local tests
for t in smb4torture_testsuites("dlz_bind9."):
    #The dlz_bind9 tests needs to look at the DNS database
    plansmbtorturetestsuite(t, "chgdcpass:local", "ncalrpc:localhost")

planpythontestsuite("s3dc", "samba.tests.libsmb_samba_internal");

# Blackbox Tests:
# tests that interact directly with the command-line tools rather than using
# the API. These mainly test that the various command-line options of commands
# work correctly.

for env in ["s3member", "s4member", "dc", "chgdcpass"]:
    plantestsuite("samba4.blackbox.smbclient(%s:local)" % env, "%s:local" % env, [os.path.join(samba4srcdir, "utils/tests/test_smbclient.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$DOMAIN', smbclient])

planpythontestsuite("none", "samba.tests.blackbox.ndrdump")
planpythontestsuite("none", "samba.tests.source")
plantestsuite("samba4.blackbox.samba_tool(dc:local)", "dc:local", [os.path.join(samba4srcdir, "utils/tests/test_samba_tool.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$DOMAIN', smbclient])
plantestsuite("samba4.blackbox.pkinit(dc:local)", "dc:local", [os.path.join(bbdir, "test_pkinit.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX', "aes256-cts-hmac-sha1-96", smbclient, configuration])
plantestsuite("samba4.blackbox.kinit(dc:local)", "dc:local", [os.path.join(bbdir, "test_kinit.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX', "aes256-cts-hmac-sha1-96", smbclient, configuration])
plantestsuite("samba4.blackbox.kinit(fl2000dc:local)", "fl2000dc:local", [os.path.join(bbdir, "test_kinit.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX', "arcfour-hmac-md5", smbclient, configuration])
plantestsuite("samba4.blackbox.kinit(fl2008r2dc:local)", "fl2008r2dc:local", [os.path.join(bbdir, "test_kinit.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX', "aes256-cts-hmac-sha1-96", smbclient, configuration])
plantestsuite("samba4.blackbox.ktpass(dc)", "dc", [os.path.join(bbdir, "test_ktpass.sh"), '$PREFIX'])
plantestsuite("samba4.blackbox.passwords(dc:local)", "dc:local", [os.path.join(bbdir, "test_passwords.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', "$PREFIX", smbclient])
plantestsuite("samba4.blackbox.export.keytab(dc:local)", "dc:local", [os.path.join(bbdir, "test_export_keytab.sh"), '$SERVER', '$USERNAME', '$REALM', '$DOMAIN', "$PREFIX", smbclient])
plantestsuite("samba4.blackbox.cifsdd(dc)", "dc", [os.path.join(samba4srcdir, "client/tests/test_cifsdd.sh"), '$SERVER', '$USERNAME', '$PASSWORD', "$DOMAIN"])
plantestsuite("samba4.blackbox.nmblookup(dc)", "dc", [os.path.join(samba4srcdir, "utils/tests/test_nmblookup.sh"), '$NETBIOSNAME', '$NETBIOSALIAS', '$SERVER', '$SERVER_IP', nmblookup])
plantestsuite("samba4.blackbox.locktest(dc)", "dc", [os.path.join(samba4srcdir, "torture/tests/test_locktest.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$DOMAIN', '$PREFIX'])
plantestsuite("samba4.blackbox.masktest", "dc", [os.path.join(samba4srcdir, "torture/tests/test_masktest.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$DOMAIN', '$PREFIX'])
plantestsuite("samba4.blackbox.gentest(dc)", "dc", [os.path.join(samba4srcdir, "torture/tests/test_gentest.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$DOMAIN', "$PREFIX"])
plantestsuite("samba4.blackbox.wbinfo(dc:local)", "dc:local", [os.path.join(samba4srcdir, "../nsswitch/tests/test_wbinfo.sh"), '$DOMAIN', '$USERNAME', '$PASSWORD', "dc"])
plantestsuite("samba4.blackbox.wbinfo(s4member:local)", "s4member:local", [os.path.join(samba4srcdir, "../nsswitch/tests/test_wbinfo.sh"), '$DOMAIN', '$DC_USERNAME', '$DC_PASSWORD', "s4member"])
plantestsuite("samba4.blackbox.chgdcpass", "chgdcpass", [os.path.join(bbdir, "test_chgdcpass.sh"), '$SERVER', "CHGDCPASS\$", '$REALM', '$DOMAIN', '$PREFIX', "aes256-cts-hmac-sha1-96", '$SELFTEST_PREFIX/chgdcpass', smbclient])
plantestsuite_loadlist("samba4.rpc.echo against NetBIOS alias", "dc", [valgrindify(smb4torture), "$LISTOPT", 'ncacn_np:$NETBIOSALIAS', '-U$DOMAIN/$USERNAME%$PASSWORD', 'rpc.echo'])

# Tests using the "Simple" NTVFS backend
for t in ["base.rw1"]:
    plansmbtorturetestsuite(t, "dc", ["//$SERVER/simple", '-U$USERNAME%$PASSWORD'], modname="samba4.ntvfs.simple.%s" % t)

# Domain S4member Tests
plansmbtorturetestsuite('rpc.echo', "s4member", ['ncacn_np:$NETBIOSNAME', '-U$NETBIOSNAME/$USERNAME%$PASSWORD'], "samba4.rpc.echo against s4member server with local creds")
plansmbtorturetestsuite('rpc.echo', "s4member", ['ncacn_np:$NETBIOSNAME', '-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'], "samba4.rpc.echo against s4member server with domain creds")
plansmbtorturetestsuite('rpc.samr', "s4member", ['ncacn_np:$NETBIOSNAME', '-U$NETBIOSNAME/$USERNAME%$PASSWORD'], "samba4.rpc.samr against s4member server with local creds")
plansmbtorturetestsuite('rpc.samr.users', "s4member", ['ncacn_np:$NETBIOSNAME', '-U$NETBIOSNAME/$USERNAME%$PASSWORD'], "samba4.rpc.samr.users against s4member server with local creds",)
plansmbtorturetestsuite('rpc.samr.passwords', "s4member", ['ncacn_np:$NETBIOSNAME', '-U$NETBIOSNAME/$USERNAME%$PASSWORD'], "samba4.rpc.samr.passwords against s4member server with local creds")
plantestsuite("samba4.blackbox.smbclient against s4member server with local creds", "s4member", [os.path.join(samba4srcdir, "client/tests/test_smbclient.sh"), '$NETBIOSNAME', '$USERNAME', '$PASSWORD', '$NETBIOSNAME', '$PREFIX', smbclient])

# RPC Proxy
plansmbtorturetestsuite("rpc.echo", "rpc_proxy", ['ncacn_ip_tcp:$NETBIOSNAME', '-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'], modname="samba4.rpc.echo against rpc proxy with domain creds")

# Tests SMB signing
for mech in [
    "-k no",
    "-k no --option=usespnego=no",
    "-k no --option=gensec:spengo=no",
    "-k yes",
    "-k yes --option=gensec:fake_gssapi_krb5=yes --option=gensec:gssapi_krb5=no"]:
    for signing in ["--signing=on", "--signing=required"]:
        signoptions = "%s %s" % (mech, signing)
        name = "smb.signing on with %s" % signoptions
        plansmbtorturetestsuite('base.xcopy', "dc", ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$USERNAME%$PASSWORD'], modname="samba4.%s" % name)

for mech in [
    "-k no",
    "-k no --option=usespnego=no",
    "-k no --option=gensec:spengo=no",
    "-k yes"]:
    signoptions = "%s --signing=off" % mech
    name = "smb.signing disabled on with %s" % signoptions
    plansmbtorturetestsuite('base.xcopy', "s4member", ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$DC_USERNAME%$DC_PASSWORD'], "samba4.%s domain-creds" % name)
    plansmbtorturetestsuite('base.xcopy', "s3member", ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$DC_USERNAME%$DC_PASSWORD'], "samba4.%s domain-creds" % name)
    plansmbtorturetestsuite('base.xcopy', "plugin_s4_dc", ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$USERNAME%$PASSWORD'], "samba4.%s" % name)
    plansmbtorturetestsuite('base.xcopy', "plugin_s4_dc",
                            ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$DC_USERNAME%$DC_PASSWORD'], "samba4.%s administrator" % name)

plantestsuite("samba4.blackbox.bogusdomain", "s3member", ["testprogs/blackbox/bogus.sh", "$NETBIOSNAME", "xcopy_share", '$USERNAME', '$PASSWORD', '$DC_USERNAME', '$DC_PASSWORD', smbclient])
for mech in [
    "-k no",
    "-k no --option=usespnego=no",
    "-k no --option=gensec:spengo=no"]:
    signoptions = "%s --signing=off" % mech
    plansmbtorturetestsuite('base.xcopy', "s4member", ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$NETBIOSNAME/$USERNAME%$PASSWORD'], modname="samba4.smb.signing on with %s local-creds" % signoptions)

plansmbtorturetestsuite('base.xcopy', "dc", ['//$NETBIOSNAME/xcopy_share', '-k', 'no', '--signing=yes', '-U%'], modname="samba4.smb.signing --signing=yes anon")
plansmbtorturetestsuite('base.xcopy', "dc", ['//$NETBIOSNAME/xcopy_share', '-k', 'no', '--signing=required', '-U%'], modname="samba4.smb.signing --signing=required anon")
plansmbtorturetestsuite('base.xcopy', "s4member", ['//$NETBIOSNAME/xcopy_share', '-k', 'no', '--signing=no', '-U%'], modname="samba4.smb.signing --signing=no anon")


wb_opts = ["--option=\"torture:strict mode=no\"", "--option=\"torture:timelimit=1\"", "--option=\"torture:winbindd_separator=/\"", "--option=\"torture:winbindd_netbios_name=$SERVER\"", "--option=\"torture:winbindd_netbios_domain=$DOMAIN\""]

winbind_struct_tests = smb4torture_testsuites("winbind.struct")
winbind_ndr_tests = smb4torture_testsuites("winbind.ndr")
for env in ["plugin_s4_dc", "dc", "s4member"]:
    for t in winbind_struct_tests:
        plansmbtorturetestsuite(t, env, wb_opts + ['//_none_/_none_'])

    for t in winbind_ndr_tests:
        plansmbtorturetestsuite(t, env, wb_opts + ['//_none_/_none_'])

nsstest4 = binpath("nsstest")
for env in ["plugin_s4_dc", "dc", "s4member", "s3dc", "s3member", "member"]:
    if os.path.exists(nsstest4):
        plantestsuite("samba4.nss.test using winbind(%s)" % env, env, [os.path.join(bbdir, "nsstest.sh"), nsstest4, os.path.join(samba4bindir, "default/nsswitch/libnss-winbind.so")])
    else:
        skiptestsuite("samba4.nss.test using winbind(%s)" % env, "nsstest not available")

subunitrun = valgrindify(python) + " " + os.path.join(samba4srcdir, "scripting/bin/subunitrun")
def planoldpythontestsuite(env, module, name=None, extra_path=[], environ={}, extra_args=[]):
    environ = dict(environ)
    py_path = list(extra_path)
    if py_path:
        environ["PYTHONPATH"] = ":".join(["$PYTHONPATH"] + py_path)
    args = ["%s=%s" % item for item in environ.iteritems()]
    args += [subunitrun, "$LISTOPT", module]
    args += extra_args
    if name is None:
        name = module
    plantestsuite(name, env, args)

planpythontestsuite("none", "selftest.tests.test_suite", extra_path=[srcdir()])
planpythontestsuite("none", "api", name="ldb.python", extra_path=['lib/ldb/tests/python'])
planpythontestsuite("none", "samba.tests.credentials")
planoldpythontestsuite("dc:local", "samba.tests.gensec", extra_args=['-U"$USERNAME%$PASSWORD"'])
planpythontestsuite("none", "samba.tests.registry")
planoldpythontestsuite("none", "simple", extra_path=["%s/lib/tdb/python/tests" % srcdir()], name="tdb.python")
planpythontestsuite("none", "samba.tests.auth")
planpythontestsuite("none", "samba.tests.getopt")
planpythontestsuite("none", "samba.tests.security")
planpythontestsuite("none", "samba.tests.dcerpc.misc")
planpythontestsuite("none", "samba.tests.param")
planpythontestsuite("none", "samba.tests.upgrade")
planpythontestsuite("none", "samba.tests.core")
planpythontestsuite("none", "samba.tests.provision")
planpythontestsuite("none", "samba.tests.samba3")
planpythontestsuite("none", "samba.tests.strings")
planpythontestsuite("dc:local", "samba.tests.dcerpc.sam")
planpythontestsuite("dc:local", "samba.tests.dsdb")
planpythontestsuite("none", "samba.tests.netcmd")
planpythontestsuite("dc:local", "samba.tests.dcerpc.bare")
planpythontestsuite("dc:local", "samba.tests.dcerpc.unix")
planpythontestsuite("dc:local", "samba.tests.dcerpc.srvsvc")
planpythontestsuite("none", "samba.tests.dcerpc.rpc_talloc")
planpythontestsuite("none", "samba.tests.samdb")
planpythontestsuite("none", "samba.tests.hostconfig")
planpythontestsuite("none", "samba.tests.messaging")
planpythontestsuite("none", "samba.tests.samba3sam")

planpythontestsuite("dc:local", "samba.tests.samba_tool.timecmd")
planpythontestsuite("dc:local", "samba.tests.samba_tool.user")
planpythontestsuite("dc:local", "samba.tests.samba_tool.group")
planpythontestsuite("plugin_s4_dc:local", "samba.tests.samba_tool.ntacl")

planpythontestsuite("none", "subunit")
planpythontestsuite("dc:local", "samba.tests.dcerpc.rpcecho")
planpythontestsuite("none", "wafsamba.tests.test_suite", extra_path=[os.path.join(samba4srcdir, "..", "buildtools"), os.path.join(samba4srcdir, "..", "buildtools", "wafadmin")])
planoldpythontestsuite("dc:local", "samba.tests.dcerpc.registry", extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("dc", "samba.tests.dcerpc.dnsserver", extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("plugin_s4_dc", "samba.tests.dcerpc.dnsserver", extra_args=['-U"$USERNAME%$PASSWORD"'])
plantestsuite("samba4.ldap.python(dc)", "dc", [python, os.path.join(samba4srcdir, "dsdb/tests/python/ldap.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
plantestsuite("samba4.tokengroups.python(dc)", "dc:local", [python, os.path.join(samba4srcdir, "dsdb/tests/python/token_group.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
plantestsuite("samba4.sam.python(dc)", "dc", [python, os.path.join(samba4srcdir, "dsdb/tests/python/sam.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
planoldpythontestsuite("dc", "dsdb_schema_info",
        extra_path=[os.path.join(samba4srcdir, 'dsdb/tests/python')],
        name="samba4.schemaInfo.python(dc)",
        extra_args=['-U"$DOMAIN/$DC_USERNAME%$DC_PASSWORD"'])
plantestsuite("samba4.urgent_replication.python(dc)", "dc:local", [python, os.path.join(samba4srcdir, "dsdb/tests/python/urgent_replication.py"), '$PREFIX_ABS/dc/private/sam.ldb'], allow_empty_output=True)
plantestsuite("samba4.ldap.dirsync.python(dc)", "dc", [python, os.path.join(samba4srcdir, "dsdb/tests/python/dirsync.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
plantestsuite("samba4.ldap.sites.python(dc)", "dc", [python, os.path.join(samba4srcdir, "dsdb/tests/python/sites.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
for env in ["dc", "fl2000dc", "fl2003dc", "fl2008r2dc"]:
    plantestsuite("samba4.ldap_schema.python(%s)" % env, env, [python, os.path.join(samba4srcdir, "dsdb/tests/python/ldap_schema.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
    plantestsuite("samba4.ldap.possibleInferiors.python(%s)" % env, env, [python, os.path.join(samba4srcdir, "dsdb/samdb/ldb_modules/tests/possibleinferiors.py"), "ldap://$SERVER", '-U"$USERNAME%$PASSWORD"', "-W$DOMAIN"])
    plantestsuite("samba4.ldap.secdesc.python(%s)" % env, env, [python, os.path.join(samba4srcdir, "dsdb/tests/python/sec_descriptor.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
    plantestsuite("samba4.ldap.acl.python(%s)" % env, env, [python, os.path.join(samba4srcdir, "dsdb/tests/python/acl.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
    if env != "fl2000dc":
        # This test makes excessive use of the "userPassword" attribute which
        # isn't available on DCs with Windows 2000 domain function level -
        # therefore skip it in that configuration
        plantestsuite("samba4.ldap.passwords.python(%s)" % env, env, [python, os.path.join(samba4srcdir, "dsdb/tests/python/passwords.py"), "$SERVER", '-U"$USERNAME%$PASSWORD"', "-W$DOMAIN"])

plantestsuite("samba4.blackbox.dbcheck.alpha13", "none" , ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck-alpha13.sh"), '$PREFIX_ABS/provision', configuration])
planpythontestsuite("dc:local", "samba.tests.upgradeprovisionneeddc")
planpythontestsuite("none", "samba.tests.upgradeprovision")
planpythontestsuite("none", "samba.tests.xattr")
planpythontestsuite("none", "samba.tests.ntacls")
planpythontestsuite("plugin_s4_dc:local", "samba.tests.posixacl")
plantestsuite("samba4.deletetest.python(dc)", "dc", ['PYTHONPATH="$PYTHONPATH:%s/lib/subunit/python:%s/lib/testtools"' % (srcdir(), srcdir()),
                                                     python, os.path.join(samba4srcdir, "dsdb/tests/python/deletetest.py"),
                                                     '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
planpythontestsuite("none", "samba.tests.policy")
plantestsuite("samba4.blackbox.samba3dump", "none", [python, os.path.join(samba4srcdir, "scripting/bin/samba3dump"), os.path.join(samba4srcdir, "../testdata/samba3")], allow_empty_output=True)
plantestsuite("samba4.blackbox.upgrade", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_s3upgrade.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.provision.py", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_provision.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.upgradeprovision.py", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_upgradeprovision.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.setpassword.py", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_setpassword.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.newuser.py", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_newuser.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.group.py", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_group.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.spn.py(dc:local)", "dc:local", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_spn.sh"), '$PREFIX/dc'])
plantestsuite("samba4.ldap.bind(dc)", "dc", [python, os.path.join(srcdir(), "auth/credentials/tests/bind.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"'])

# DRS python tests
planoldpythontestsuite("vampire_dc", "samba.tests.blackbox.samba_tool_drs",
        environ={'DC1': '$DC_SERVER', 'DC2': '$VAMPIRE_DC_SERVER'},
        extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
planoldpythontestsuite("vampire_dc:local", "replica_sync",
        extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
        name="samba4.drs.replica_sync.python(vampire_dc)",
        environ={'DC1': '$DC_SERVER', 'DC2': '$VAMPIRE_DC_SERVER'},
        extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
planoldpythontestsuite("vampire_dc", "delete_object",
        extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
        name="samba4.drs.delete_object.python(vampire_dc)",
        environ={'DC1': '$DC_SERVER', 'DC2': '$VAMPIRE_DC_SERVER'},
        extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
planoldpythontestsuite("vampire_dc", "fsmo",
        name="samba4.drs.fsmo.python(vampire_dc)",
        extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
        environ={'DC1': "$DC_SERVER", 'DC2': "$VAMPIRE_DC_SERVER"},
        extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
planoldpythontestsuite("vampire_dc", "repl_schema",
        extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
        name="samba4.drs.repl_schema.python(vampire_dc)",
        environ={'DC1': "$DC_SERVER", 'DC2': '$VAMPIRE_DC_SERVER'},
        extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

# This makes sure we test the rid allocation code
t = "rpc.samr.large-dc"
plansmbtorturetestsuite(t, "vampire_dc", ['$SERVER', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], modname=("samba4.%s.one" % t))
plansmbtorturetestsuite(t, "vampire_dc", ['$SERVER', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], modname="samba4.%s.two" % t)

# some RODC testing
for env in ['rodc']:
    plansmbtorturetestsuite('rpc.echo', env, ['ncacn_np:$SERVER', "-k", "yes", '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], modname="samba4.rpc.echo")
    plansmbtorturetestsuite('rpc.echo', "%s:local" % env, ['ncacn_np:$SERVER', "-k", "yes", '-P', '--workgroup=$DOMAIN'], modname="samba4.rpc.echo")
plantestsuite("samba4.blackbox.provision-backend", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_provision-backend.sh"), '$PREFIX/provision'])

# Test renaming the DC
plantestsuite("samba4.blackbox.renamedc.sh", "none", ["PYTHON=%s" % python, os.path.join(bbdir, "renamedc.sh"), '$PREFIX/provision'])

# Demote the vampire DC, it must be the last test on the VAMPIRE DC
for env in ['vampire_dc', 'promoted_vampire_dc']:
    plantestsuite("samba4.blackbox.samba_tool_demote(%s)" % env, env, [os.path.join(samba4srcdir, "utils/tests/test_demote.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$DOMAIN', '$DC_SERVER', '$PREFIX/%s' % env, smbclient])
# check the databases are all OK. PLEASE LEAVE THIS AS THE LAST TEST
for env in ["dc", "fl2000dc", "fl2003dc", "fl2008r2dc", 'vampire_dc', 'promoted_vampire_dc']:
    plantestsuite("samba4.blackbox.dbcheck(%s)" % env, env + ":local" , ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck.sh"), '$PREFIX/provision', configuration])
