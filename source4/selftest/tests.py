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
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../selftest"))
import selftesthelpers
from selftesthelpers import bindir, srcdir, binpath, python
from selftesthelpers import configuration, plantestsuite
from selftesthelpers import planpythontestsuite, planperltestsuite
from selftesthelpers import plantestsuite_loadlist
from selftesthelpers import skiptestsuite, source4dir, valgrindify
from selftesthelpers import smbtorture4_options, smbtorture4_testsuites
from selftesthelpers import smbtorture4, ntlm_auth3, samba3srcdir


print("OPTIONS %s" % " ".join(smbtorture4_options), file=sys.stderr)


def plansmbtorture4testsuite(name, env, options, modname=None):
    return selftesthelpers.plansmbtorture4testsuite(name, env, options,
                                                    target='samba4', modname=modname)


samba4srcdir = source4dir()
DSDB_PYTEST_DIR = os.path.join(samba4srcdir, "dsdb/tests/python/")

samba4bindir = bindir()
validate = os.getenv("VALIDATE", "")
if validate:
    validate_list = [validate]
else:
    validate_list = []

nmblookup4 = binpath('nmblookup4')
smbclient4 = binpath('smbclient4')
smbclient3 = binpath('smbclient')

bbdir = os.path.join(srcdir(), "testprogs/blackbox")

# alias to highlight what tests we want to run against a DC with SMBv1 disabled
smbv1_disabled_testenv = "restoredc"

all_fl_envs = ["fl2000dc", "fl2003dc", "fl2008dc", "fl2008r2dc"]

# Simple tests for LDAP and CLDAP
for auth_type in ['', '-k no', '-k yes']:
    for auth_level in ['--option=clientldapsaslwrapping=plain', '--sign', '--encrypt']:
        creds = '-U"$USERNAME%$PASSWORD"'
        options = creds + ' ' + auth_type + ' ' + auth_level
        plantestsuite("samba4.ldb.ldap with options %r(ad_dc_default)" % options, "ad_dc_default", "%s/test_ldb.sh ldap $SERVER %s" % (bbdir, options))

# see if we support ADS on the Samba3 side
try:
    config_h = os.environ["CONFIG_H"]
except KeyError:
    config_h = os.path.join(samba4bindir, "default/include/config.h")

# check available features
config_hash = dict()
f = open(config_h, 'r')
try:
    lines = f.readlines()
    config_hash = dict((x[0], ' '.join(x[1:]))
                       for x in map(lambda line: line.strip().split(' ')[1:],
                                    list(filter(lambda line: (line[0:7] == '#define') and (len(line.split(' ')) > 2), lines))))
finally:
    f.close()

have_heimdal_support = ("SAMBA4_USES_HEIMDAL" in config_hash)
have_gnutls_crypto_policies = ("HAVE_GNUTLS_CRYPTO_POLICIES" in config_hash)

for options in ['-U"$USERNAME%$PASSWORD"']:
    plantestsuite("samba4.ldb.ldaps with options %s(ad_dc_ntvfs)" % options, "ad_dc_ntvfs",
                  "%s/test_ldb.sh ldaps $SERVER_IP %s" % (bbdir, options))

creds_options = [
    '--simple-bind-dn=$USERNAME@$REALM --password=$PASSWORD',
]
peer_options = {
    'SERVER_IP': '$SERVER_IP',
    'SERVER_NAME': '$SERVER',
    'SERVER.REALM': '$SERVER.$REALM',
}
tls_verify_options = [
    '--option="tlsverifypeer=no_check"',
    '--option="tlsverifypeer=ca_only"',
    '--option="tlsverifypeer=ca_and_name_if_available"',
    '--option="tlsverifypeer=ca_and_name"',
    '--option="tlsverifypeer=as_strict_as_possible"',
]

# we use :local for fl2008r2dc because of the self-signed certificate
for env in ["ad_dc_ntvfs", "fl2008r2dc:local"]:
    for peer_key in peer_options.keys():
        peer_val = peer_options[peer_key]
        for creds in creds_options:
            for tls_verify in tls_verify_options:
                options = creds + ' ' + tls_verify
                plantestsuite("samba4.ldb.simple.ldaps with options %s %s(%s)" % (
                              peer_key, options, env), env,
                              "%s/test_ldb_simple.sh ldaps %s %s" % (bbdir, peer_val, options))

# test all "ldap server require strong auth" combinations
for env in ["ad_dc_ntvfs", "fl2008r2dc", "fl2003dc"]:
    options = '--simple-bind-dn="$USERNAME@$REALM" --password="$PASSWORD"'
    plantestsuite("samba4.ldb.simple.ldap with SIMPLE-BIND %s(%s)" % (options, env),
                  env, "%s/test_ldb_simple.sh ldap $SERVER %s" % (bbdir, options))
    options += ' --option="tlsverifypeer=no_check"'
    plantestsuite("samba4.ldb.simple.ldaps with SIMPLE-BIND %s(%s)" % (options, env),
                  env, "%s/test_ldb_simple.sh ldaps $SERVER %s" % (bbdir, options))

    auth_options = [
        '--option=clientldapsaslwrapping=plain',
        '--sign',
        '--encrypt',
        '-k yes --option=clientldapsaslwrapping=plain',
        '-k yes --sign',
        '-k yes --encrypt',
        '-k no --option=clientldapsaslwrapping=plain',
        '-k no --sign --option=ntlmssp_client:ldap_style_send_seal=no',
        '-k no --sign',
        '-k no --encrypt',
    ]

    for auth_option in auth_options:
        options = '-U"$USERNAME%$PASSWORD"' + ' ' + auth_option
        plantestsuite("samba4.ldb.simple.ldap with SASL-BIND %s(%s)" % (options, env),
                      env, "%s/test_ldb_simple.sh ldap $SERVER %s" % (bbdir, options))
    options = '-U"$USERNAME%$PASSWORD" --option="tlsverifypeer=no_check"'
    plantestsuite("samba4.ldb.simple.ldaps with SASL-BIND %s(%s)" % (options, env),
                  env, "%s/test_ldb_simple.sh ldaps $SERVER %s" % (bbdir, options))

for options in ['-U"$USERNAME%$PASSWORD"']:
    plantestsuite("samba4.ldb.ldapi with options %s(ad_dc_ntvfs:local)" % options, "ad_dc_ntvfs:local",
                  "%s/test_ldb.sh ldapi $PREFIX_ABS/ad_dc_ntvfs/private/ldapi %s" % (bbdir, options))

for t in smbtorture4_testsuites("ldap."):
    if t == "ldap.nested-search":
        plansmbtorture4testsuite(t, "ad_dc_default_smb1", '-U"$USERNAME%$PASSWORD" //$SERVER_IP/_none_')
    elif t == "ldap.session-expiry":
        # This requires kerberos and thus the server name
        plansmbtorture4testsuite(
            t, "ad_dc_default", '-U"$USERNAME%$PASSWORD" //$DC_SERVER/_none_')
    else:
        plansmbtorture4testsuite(t, "ad_dc_default", '-U"$USERNAME%$PASSWORD" //$SERVER_IP/_none_')

for t in smbtorture4_testsuites("dsdb."):
    plansmbtorture4testsuite(t, "ad_dc:local", "localhost")

ldbdir = os.path.join(srcdir(), "lib/ldb")
# Don't run LDB tests when using system ldb, as we won't have ldbtest installed
if os.path.exists(os.path.join(samba4bindir, "ldbtest")):
    plantestsuite("ldb.base", "none", "%s/tests/test-tdb-subunit.sh %s" % (ldbdir, samba4bindir))
else:
    skiptestsuite("ldb.base", "Using system LDB, ldbtest not available")

plantestsuite_loadlist("samba4.tests.attr_from_server.python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs:local",
                       [python, os.path.join(DSDB_PYTEST_DIR, "attr_from_server.py"),
                        '$PREFIX_ABS/ad_dc_ntvfs/private/sam.ldb', '$LOADLIST', '$LISTOPT'])

# Tests for RPC

# add tests to this list as they start passing, so we test
# that they stay passing
ncacn_np_tests = ["rpc.schannel", "rpc.join", "rpc.lsa", "rpc.dssetup", "rpc.altercontext", "rpc.netlogon", "rpc.netlogon.admin", "rpc.handles", "rpc.samsync", "rpc.samba3-sessionkey", "rpc.samba3-getusername", "rpc.samba3-lsa", "rpc.samba3-bind", "rpc.samba3-netlogon", "rpc.asyncbind", "rpc.lsalookup", "rpc.lsa-getuser", "rpc.schannel2", "rpc.authcontext"]
ncalrpc_tests = ["rpc.schannel", "rpc.join", "rpc.lsa", "rpc.dssetup", "rpc.altercontext", "rpc.netlogon", "rpc.netlogon.admin", "rpc.asyncbind", "rpc.lsalookup", "rpc.lsa-getuser", "rpc.schannel2", "rpc.authcontext"]
drs_rpc_tests = smbtorture4_testsuites("drs.rpc")
ncacn_ip_tcp_tests = ["rpc.schannel", "rpc.join", "rpc.lsa", "rpc.dssetup", "rpc.drsuapi", "rpc.drsuapi_w2k8", "rpc.netlogon", "rpc.netlogon.admin", "rpc.asyncbind", "rpc.lsalookup", "rpc.lsa-getuser", "rpc.schannel2", "rpc.authcontext", "rpc.samr.passwords.validate"] + drs_rpc_tests
slow_ncacn_np_tests = ["rpc.samlogon", "rpc.samr", "rpc.samr.users", "rpc.samr.large-dc", "rpc.samr.users.privileges", "rpc.samr.passwords", "rpc.samr.passwords.pwdlastset", "rpc.samr.passwords.lockout", "rpc.samr.passwords.badpwdcount"]
slow_ncacn_ip_tcp_tests = ["rpc.cracknames"]

all_rpc_tests = ncalrpc_tests + ncacn_np_tests + ncacn_ip_tcp_tests + slow_ncacn_np_tests + slow_ncacn_ip_tcp_tests + ["rpc.lsa.secrets", "rpc.pac", "rpc.samba3-sharesec", "rpc.countcalls"]

# Filter RPC tests that should not run against ad_dc_ntvfs
rpc_s3only = [
    "rpc.mdssvc",
]
rpc_tests = [x for x in smbtorture4_testsuites("rpc.") if x not in rpc_s3only]
auto_rpc_tests = list(filter(lambda t: t not in all_rpc_tests, rpc_tests))

for bindoptions in ["seal,padcheck"] + validate_list + ["bigendian"]:
    for transport in ["ncalrpc", "ncacn_np", "ncacn_ip_tcp"]:
        env = "ad_dc_default"
        local = ""
        if transport == "ncalrpc":
            tests = ncalrpc_tests
            local = ":local"
        elif transport == "ncacn_np":
            tests = ncacn_np_tests
        elif transport == "ncacn_ip_tcp":
            tests = ncacn_ip_tcp_tests
        else:
            raise AssertionError("invalid transport %r" % transport)
        for t in tests:
            if t == "rpc.netlogon":
                env = "ad_dc_ntvfs"
            elif t == "rpc.join":
                env = "ad_dc_default_smb1"
            plansmbtorture4testsuite(t, env + local, ["%s:$SERVER[%s]" % (transport, bindoptions), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.%s on %s with %s" % (t, transport, bindoptions))
        plansmbtorture4testsuite('rpc.samba3-sharesec', env + local, ["%s:$SERVER[%s]" % (transport, bindoptions), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', '--option=torture:share=tmp'], "samba4.rpc.samba3.sharesec on %s with %s" % (transport, bindoptions))

# Plugin S4 DC tests (confirms named pipe auth forwarding).  This can be expanded once kerberos is supported in the plugin DC
#
for bindoptions in ["seal,padcheck"] + validate_list + ["bigendian"]:
    for t in ncacn_np_tests:
        env = "ad_dc"
        transport = "ncacn_np"
        if t in ["rpc.authcontext", "rpc.join"]:
            env = "ad_dc_smb1"
        plansmbtorture4testsuite(t, env, ["%s:$SERVER[%s]" % (transport, bindoptions), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.%s with %s" % (t, bindoptions))

for bindoptions in [""] + validate_list + ["bigendian"]:
    for t in auto_rpc_tests:
        env = "ad_dc_default"
        if t in ["rpc.srvsvc", "rpc.mgmt"]:
            env = "ad_dc_ntvfs"
        elif t == "rpc.join":
            env = "ad_dc_default_smb1"
        plansmbtorture4testsuite(t, env, ["$SERVER[%s]" % bindoptions, '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.%s with %s" % (t, bindoptions))

t = "rpc.countcalls"
plansmbtorture4testsuite(t, "ad_dc_default:local", ["$SERVER[%s]" % bindoptions, '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], modname="samba4.%s" % t)

for transport in ["ncacn_np", "ncacn_ip_tcp"]:
    env = "ad_dc_slowtests"
    if transport == "ncacn_np":
        tests = slow_ncacn_np_tests
    elif transport == "ncacn_ip_tcp":
        tests = slow_ncacn_ip_tcp_tests
    else:
        raise AssertionError("Invalid transport %r" % transport)
    for t in tests:
        bindoptions = ''
        if t == 'rpc.cracknames':
            bindoptions = 'seal'
        plansmbtorture4testsuite(t, env, ["%s:$SERVER[%s]" % (transport, bindoptions), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.%s on %s with %s" % (t, transport, bindoptions))

# Tests for the DFS referral calls implementation
for t in smbtorture4_testsuites("dfs."):
    plansmbtorture4testsuite(t, "ad_dc_ntvfs", '//$SERVER/ipc\$ -U$USERNAME%$PASSWORD')
    plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER/ipc\$ -U$USERNAME%$PASSWORD')

# Tests for the NET API (net.api.become.dc tested below against all the roles)
net_tests = list(filter(lambda x: "net.api.become.dc" not in x, smbtorture4_testsuites("net.")))
for t in net_tests:
    plansmbtorture4testsuite(t, "ad_dc_default", '$SERVER[%s] -U$USERNAME%%$PASSWORD -W$DOMAIN' % validate)

# Tests for session keys and encryption of RPC pipes
# FIXME: Integrate these into a single smbtorture test

transport = "ncacn_np"
for env in ["ad_dc_default", "nt4_dc"]:
    for ntlmoptions in [
        "-k no --option=clientusespnego=yes",
        "-k no --option=clientusespnego=yes --option=ntlmssp_client:128bit=no",
        "-k no --option=clientusespnego=yes --option=ntlmssp_client:56bit=yes",
        "-k no --option=clientusespnego=yes --option=ntlmssp_client:56bit=no",
        "-k no --option=clientusespnego=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=yes",
        "-k no --option=clientusespnego=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=no",
        "-k no --option=clientusespnego=yes --option=clientntlmv2auth=yes",
        "-k no --option=clientusespnego=yes --option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no",
        "-k no --option=clientusespnego=yes --option=clientntlmv2auth=yes --option=ntlmssp_client:128bit=no --option=ntlmssp_client:56bit=yes",
        "-k no --option=clientusespnego=no --option=clientntlmv2auth=yes",
        "-k no --option=gensec:spnego=no --option=clientntlmv2auth=yes",
        "-k no --option=clientusespnego=no"]:
        name = "rpc.lsa.secrets on %s with with %s" % (transport, ntlmoptions)
        plansmbtorture4testsuite('rpc.lsa.secrets', env, ["%s:$SERVER[]" % (transport), ntlmoptions, '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', '--option=gensec:target_hostname=$NETBIOSNAME'], "samba4.%s" % name)
    plantestsuite("samba.blackbox.pdbtest(%s)" % env, "%s:local" % env, [os.path.join(bbdir, "test_pdbtest.sh"), '$SERVER', "$PREFIX", "pdbtest", smbclient3, '$SMB_CONF_PATH', configuration])

gpo = smbtorture4_testsuites("gpo.")
for t in gpo:
    plansmbtorture4testsuite(t, 'ad_dc:local', ['//$SERVER/sysvol', '-U$USERNAME%$PASSWORD'])

transports = ["ncacn_np", "ncacn_ip_tcp"]

# Kerberos varies between functional levels, so it is important to check this on all of them
for env in all_fl_envs:
    transport = "ncacn_np"
    plansmbtorture4testsuite('rpc.pac', env, ["%s:$SERVER[]" % (transport, ), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.pac on %s" % (transport,))
    plansmbtorture4testsuite('rpc.lsa.secrets', env, ["%s:$SERVER[]" % (transport, ), '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', '--option=gensec:target_hostname=$NETBIOSNAME', 'rpc.lsa.secrets'], "samba4.rpc.lsa.secrets on %s with Kerberos" % (transport,))
    plansmbtorture4testsuite('rpc.lsa.secrets', env, ["%s:$SERVER[]" % (transport, ), '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', "--option=clientusespnegoprincipal=yes", '--option=gensec:target_hostname=$NETBIOSNAME'], "samba4.rpc.lsa.secrets on %s with Kerberos - use target principal" % (transport,))
    plansmbtorture4testsuite('rpc.lsa.secrets', env, ["%s:$SERVER[target_principal=dcom/$NETBIOSNAME]" % (transport, ), '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.lsa.secrets on %s with Kerberos - netbios name principal dcom" % (transport,))
    plansmbtorture4testsuite('rpc.lsa.secrets', env, ["%s:$SERVER[target_principal=$NETBIOSNAME\$]" % (transport, ), '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.lsa.secrets on %s with Kerberos - netbios name principal dollar" % (transport,))
    plansmbtorture4testsuite('rpc.lsa.secrets', env, ["%s:$SERVER[target_principal=$NETBIOSNAME]" % (transport, ), '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.lsa.secrets on %s with Kerberos - netbios name principal" % (transport,))
    plansmbtorture4testsuite('rpc.lsa.secrets.none*', env, ["%s:$SERVER" % transport, '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', "--option=gensec:fake_gssapi_krb5=yes", '--option=gensec:gssapi_krb5=no', '--option=gensec:target_hostname=$NETBIOSNAME'], "samba4.rpc.lsa.secrets on %s with Kerberos - use Samba3 style login" % transport)
    plansmbtorture4testsuite('rpc.lsa.secrets.none*', env, ["%s:$SERVER" % transport, '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', "--option=gensec:fake_gssapi_krb5=yes", '--option=gensec:gssapi_krb5=no', '--option=gensec:target_hostname=$NETBIOSNAME', '--option=gensec_krb5:send_authenticator_checksum=false'], "samba4.rpc.lsa.secrets on %s with Kerberos - use raw-krb5-no-authenticator-checksum style login" % transport)
    plansmbtorture4testsuite('rpc.lsa.secrets.none*', env, ["%s:$SERVER" % transport, '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', "--option=clientusespnegoprincipal=yes", '--option=gensec:fake_gssapi_krb5=yes', '--option=gensec:gssapi_krb5=no', '--option=gensec:target_hostname=$NETBIOSNAME'], "samba4.rpc.lsa.secrets on %s with Kerberos - use Samba3 style login, use target principal" % transport)

    # Winreg tests test bulk Kerberos encryption of DCE/RPC
    # We test rpc.winreg here too, because the winreg interface if
    # handled by the source3/rpc_server code.
    for bindoptions in ["connect", "packet", "krb5", "krb5,packet", "krb5,sign", "krb5,seal", "spnego", "spnego,packet", "spnego,sign", "spnego,seal"]:
        plansmbtorture4testsuite('rpc.winreg', env, ["%s:$SERVER[%s]" % (transport, bindoptions), '-k', 'yes', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.winreg on %s with %s" % (transport, bindoptions))

    for transport in transports:
        plansmbtorture4testsuite('rpc.echo', env, ["%s:$SERVER[]" % (transport,), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.echo on %s" % (transport, ))

        # Echo tests test bulk Kerberos encryption of DCE/RPC
        for bindoptions in ["connect", "krb5", "krb5,sign", "krb5,seal", "spnego", "spnego,sign", "spnego,seal"] + validate_list + ["padcheck", "bigendian", "bigendian,seal"]:
            echooptions = "--option=socket:testnonblock=True --option=torture:quick=yes -k yes"
            plansmbtorture4testsuite('rpc.echo', env, ["%s:$SERVER[%s]" % (transport, bindoptions), echooptions, '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.echo on %s with %s and %s" % (transport, bindoptions, echooptions))

for env in ["fl2000dc", "fl2008r2dc"]:
    plansmbtorture4testsuite("net.api.become.dc", env, '$SERVER[%s] -U$USERNAME%%$PASSWORD -W$DOMAIN' % validate)

for bindoptions in ["sign", "seal"]:
    plansmbtorture4testsuite('rpc.backupkey', "ad_dc_default", ["ncacn_np:$SERVER[%s]" % (bindoptions), '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.backupkey with %s" % (bindoptions))

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
                env = "ad_dc_default:local"
            else:
                env = "ad_dc_default"
            plansmbtorture4testsuite('rpc.echo', env, ["%s:$SERVER[%s]" % (transport, bindoptions), ntlmoptions, '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.echo on %s with %s and %s" % (transport, bindoptions, ntlmoptions))

plansmbtorture4testsuite('rpc.echo', "ad_dc_default", ['ncacn_np:$SERVER[smb2]', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.rpc.echo on ncacn_np over smb2")
for env in ["ad_dc", "nt4_dc"]:
    plansmbtorture4testsuite('rpc.echo', env, ['60a15ec5-4de8-11d7-a637-005056a20182@ncacn_np:$SERVER[]', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', '--option=torture:quick=yes'], "samba4.rpc.echo on ncacn_np with object")
    plansmbtorture4testsuite('rpc.echo', env, ['60a15ec5-4de8-11d7-a637-005056a20182@ncacn_ip_tcp:$SERVER[]', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', '--option=torture:quick=yes'], "samba4.rpc.echo on ncacn_ip_tcp with object")

plansmbtorture4testsuite('ntp.signd', "ad_dc_default:local", ['ncacn_np:$SERVER', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], "samba4.ntp.signd")

nbt_tests = smbtorture4_testsuites("nbt.")
for t in nbt_tests:
    plansmbtorture4testsuite(t, "ad_dc_ntvfs", "//$SERVER/_none_ -U\"$USERNAME%$PASSWORD\"")

# Tests against the NTVFS POSIX backend
ntvfsargs = ["--option=torture:sharedelay=100000", "--option=torture:oplocktimeout=3", "--option=torture:writetimeupdatedelay=500000"]

# Filter smb2 tests that should not run against ad_dc_ntvfs
smb2_s3only = [
    "smb2.change_notify_disabled",
    "smb2.dosmode",
    "smb2.credits",
    "smb2.kernel-oplocks",
    "smb2.durable-v2-delay",
    "smb2.aio_delay",
    "smb2.fileid",
    "smb2.timestamps",
]
smb2 = [x for x in smbtorture4_testsuites("smb2.") if x not in smb2_s3only]

# The QFILEINFO-IPC test needs to be on ipc$
raw = list(filter(lambda x: "raw.qfileinfo.ipc" not in x, smbtorture4_testsuites("raw.")))
base = smbtorture4_testsuites("base.")

netapi = smbtorture4_testsuites("netapi.")

for t in base + raw + smb2 + netapi:
    plansmbtorture4testsuite(t, "ad_dc_ntvfs", ['//$SERVER/tmp', '-U$USERNAME%$PASSWORD'] + ntvfsargs)

libsmbclient = smbtorture4_testsuites("libsmbclient.")
protocols = [ 'NT1', 'SMB3' ]
for t in libsmbclient:
    url = "smb://$USERNAME:$PASSWORD@$SERVER/tmp"
    if t == "libsmbclient.list_shares":
        url = "smb://$USERNAME:$PASSWORD@$SERVER"
    if t == "libsmbclient.utimes":
        url += "/utimes.txt"

    libsmbclient_testargs = [
        '//$SERVER/tmp',
        '-U$USERNAME%$PASSWORD',
        "--option=torture:smburl=" + url,
        "--option=torture:replace_smbconf="
        "%s/testdata/samba3/smb_new.conf" % srcdir()
        ]

    for proto in protocols:
        plansmbtorture4testsuite(
            t,
            "nt4_dc" if proto == "SMB3" else "nt4_dc_smb1_done",
            libsmbclient_testargs +
            [ "--option=torture:clientprotocol=%s" % proto],
            "samba4.%s.%s" % (t, proto))

plansmbtorture4testsuite("raw.qfileinfo.ipc", "ad_dc_ntvfs", '//$SERVER/ipc\$ -U$USERNAME%$PASSWORD')

for t in smbtorture4_testsuites("rap."):
    plansmbtorture4testsuite(t, "ad_dc_ntvfs", '//$SERVER/IPC\$ -U$USERNAME%$PASSWORD')

# Tests against the NTVFS CIFS backend
for t in base + raw:
    plansmbtorture4testsuite(t, "ad_dc_ntvfs", ['//$NETBIOSNAME/cifs', '-U$USERNAME%$PASSWORD', '--kerberos=yes'] + ntvfsargs, modname="samba4.ntvfs.cifs.krb5.%s" % t)

# Test NTVFS CIFS backend with S4U2Self and S4U2Proxy
t = "base.unlink"
plansmbtorture4testsuite(t, "ad_dc_ntvfs", ['//$NETBIOSNAME/cifs', '-U$USERNAME%$PASSWORD', '--kerberos=no'] + ntvfsargs, "samba4.ntvfs.cifs.ntlm.%s" % t)
plansmbtorture4testsuite(t, "rpc_proxy", ['//$NETBIOSNAME/cifs_to_dc', '-U$DC_USERNAME%$DC_PASSWORD', '--kerberos=yes'] + ntvfsargs, "samba4.ntvfs.cifs.krb5.%s" % t)
plansmbtorture4testsuite(t, "rpc_proxy", ['//$NETBIOSNAME/cifs_to_dc', '-U$DC_USERNAME%$DC_PASSWORD', '--kerberos=no'] + ntvfsargs, "samba4.ntvfs.cifs.ntlm.%s" % t)

plansmbtorture4testsuite('echo.udp', 'ad_dc_ntvfs:local', '//$SERVER/whatever')

# Local tests
for t in smbtorture4_testsuites("local."):
    # The local.resolve test needs a name to look up using real system (not emulated) name routines
    plansmbtorture4testsuite(t, "none", "ncalrpc:localhost")

# Confirm these tests with the system iconv too
for t in ["local.convert_string_handle", "local.convert_string", "local.ndr"]:
    options = "ncalrpc: --option='iconv:use_builtin_handlers=false'"
    plansmbtorture4testsuite(t, "none", options,
                             modname="samba4.%s.system.iconv" % t)

tdbtorture4 = binpath("tdbtorture")
if os.path.exists(tdbtorture4):
    plantestsuite("tdb.stress", "none", valgrindify(tdbtorture4))
else:
    skiptestsuite("tdb.stress", "Using system TDB, tdbtorture not available")

plansmbtorture4testsuite("drs.unit", "none", "ncalrpc:")

# Pidl tests
for f in sorted(os.listdir(os.path.join(samba4srcdir, "../pidl/tests"))):
    if f.endswith(".pl"):
        planperltestsuite("pidl.%s" % f[:-3], os.path.normpath(os.path.join(samba4srcdir, "../pidl/tests", f)))

# DNS tests
plantestsuite_loadlist("samba.tests.dns", "fl2003dc:local", [python, os.path.join(srcdir(), "python/samba/tests/dns.py"), '$SERVER', '$SERVER_IP', '--machine-pass', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
plantestsuite_loadlist("samba.tests.dns", "rodc:local", [python, os.path.join(srcdir(), "python/samba/tests/dns.py"), '$SERVER', '$SERVER_IP', '--machine-pass', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
plantestsuite_loadlist("samba.tests.dns", "vampire_dc:local", [python, os.path.join(srcdir(), "python/samba/tests/dns.py"), '$SERVER', '$SERVER_IP', '--machine-pass', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba.tests.dns_forwarder", "fl2003dc:local", [python, os.path.join(srcdir(), "python/samba/tests/dns_forwarder.py"), '$SERVER', '$SERVER_IP', '$DNS_FORWARDER1', '$DNS_FORWARDER2', '--machine-pass', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba.tests.dns_tkey", "fl2008r2dc", [python, os.path.join(srcdir(), "python/samba/tests/dns_tkey.py"), '$SERVER', '$SERVER_IP', '--machine-pass', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
plantestsuite_loadlist("samba.tests.dns_wildcard", "ad_dc", [python, os.path.join(srcdir(), "python/samba/tests/dns_wildcard.py"), '$SERVER', '$SERVER_IP', '--machine-pass', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba.tests.dns_invalid", "ad_dc", [python, os.path.join(srcdir(), "python/samba/tests/dns_invalid.py"), '$SERVER_IP', '--machine-pass', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba.tests.dns_packet",
                       "ad_dc",
                       [python,
                        '-msamba.subunit.run',
                        '$LOADLIST',
                        "$LISTOPT"
                        "samba.tests.dns_packet"
                       ])


for t in smbtorture4_testsuites("dns_internal."):
    plansmbtorture4testsuite(t, "ad_dc_default:local", '//$SERVER/whavever')

# Local tests
for t in smbtorture4_testsuites("dlz_bind9."):
    # The dlz_bind9 tests needs to look at the DNS database
    plansmbtorture4testsuite(t, "chgdcpass:local", ["ncalrpc:$SERVER", '-U$USERNAME%$PASSWORD'])

planpythontestsuite("nt4_dc_smb1", "samba.tests.libsmb")

# Blackbox Tests:
# tests that interact directly with the command-line tools rather than using
# the API. These mainly test that the various command-line options of commands
# work correctly.

# smbtorture --fullname parameter test
plantestsuite("samba4.blackbox.smbtorture_subunit_names", "none",
              [
                 os.path.join(bbdir, "test_smbtorture_test_names.sh"),
                 smbtorture4
              ])

for env in ["ad_member", "s4member", "ad_dc_ntvfs", "chgdcpass"]:
    plantestsuite("samba4.blackbox.smbclient(%s:local)" % env, "%s:local" % env, [os.path.join(samba4srcdir, "utils/tests/test_smbclient.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$DOMAIN', smbclient4])

plantestsuite("samba4.blackbox.samba_tool(ad_dc_default:local)", "ad_dc_default:local", [os.path.join(samba4srcdir, "utils/tests/test_samba_tool.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$DOMAIN', smbclient3])
plantestsuite("samba4.blackbox.net_rpc_user(ad_dc)", "ad_dc", [os.path.join(bbdir, "test_net_rpc_user.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$DOMAIN'])

plantestsuite("samba4.blackbox.test_primary_group", "ad_dc:local", [os.path.join(bbdir, "test_primary_group.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$DOMAIN', '$PREFIX_ABS'])

plantestsuite("samba4.blackbox.test_old_enctypes", "fl2003dc:local", [os.path.join(bbdir, "test_old_enctypes.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$NETBIOSNAME', '$PREFIX_ABS'])

if have_heimdal_support:
    for env in ["ad_dc_ntvfs", "ad_dc"]:
        plantestsuite("samba4.blackbox.pkinit", "%s:local" % env, [os.path.join(bbdir, "test_pkinit_heimdal.sh"), '$SERVER', 'pkinit', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX/%s' % env, "aes256-cts-hmac-sha1-96", smbclient3, configuration])
        plantestsuite("samba4.blackbox.pkinit_pac", "%s:local" % env, [os.path.join(bbdir, "test_pkinit_pac_heimdal.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX/%s' % env, "aes256-cts-hmac-sha1-96", configuration])
    plantestsuite("samba4.blackbox.kinit", "ad_dc_ntvfs:local", [os.path.join(bbdir, "test_kinit_heimdal.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX', "aes256-cts-hmac-sha1-96", smbclient4, configuration])
    plantestsuite("samba4.blackbox.kinit", "fl2000dc:local", [os.path.join(bbdir, "test_kinit_heimdal.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX', "arcfour-hmac-md5", smbclient3, configuration])
    plantestsuite("samba4.blackbox.kinit", "fl2008r2dc:local", [os.path.join(bbdir, "test_kinit_heimdal.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX', "aes256-cts-hmac-sha1-96", smbclient3, configuration])
    plantestsuite("samba4.blackbox.kinit_trust", "fl2008r2dc:local", [os.path.join(bbdir, "test_kinit_trusts_heimdal.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$TRUST_SERVER', '$TRUST_USERNAME', '$TRUST_PASSWORD', '$TRUST_REALM', '$TRUST_DOMAIN', '$PREFIX', "forest", "aes256-cts-hmac-sha1-96"])
    plantestsuite("samba4.blackbox.kinit_trust", "fl2003dc:local", [os.path.join(bbdir, "test_kinit_trusts_heimdal.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$TRUST_SERVER', '$TRUST_USERNAME', '$TRUST_PASSWORD', '$TRUST_REALM', '$TRUST_DOMAIN', '$PREFIX', "external", "arcfour-hmac-md5"])
    plantestsuite("samba4.blackbox.export.keytab", "ad_dc_ntvfs:local", [os.path.join(bbdir, "test_export_keytab_heimdal.sh"), '$SERVER', '$USERNAME', '$REALM', '$DOMAIN', "$PREFIX", smbclient4])
    plantestsuite("samba4.blackbox.kpasswd", "ad_dc_ntvfs:local", [os.path.join(bbdir, "test_kpasswd_heimdal.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', "$PREFIX/ad_dc_ntvfs"])
    plantestsuite("samba4.blackbox.krb5.s4u", "fl2008r2dc:local", [os.path.join(bbdir, "test_s4u_heimdal.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$TRUST_SERVER', '$TRUST_USERNAME', '$TRUST_PASSWORD', '$TRUST_REALM', '$TRUST_DOMAIN', '$PREFIX', configuration])
else:
    plantestsuite("samba4.blackbox.kinit", "ad_dc_ntvfs:local", [os.path.join(bbdir, "test_kinit_mit.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX', smbclient4, configuration])
    plantestsuite("samba4.blackbox.kinit", "fl2000dc:local", [os.path.join(bbdir, "test_kinit_mit.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX', smbclient3, configuration])
    plantestsuite("samba4.blackbox.kinit", "fl2008r2dc:local", [os.path.join(bbdir, "test_kinit_mit.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$PREFIX', smbclient3, configuration])
    plantestsuite("samba4.blackbox.kinit_trust", "fl2008r2dc:local", [os.path.join(bbdir, "test_kinit_trusts_mit.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$TRUST_SERVER', '$TRUST_USERNAME', '$TRUST_PASSWORD', '$TRUST_REALM', '$TRUST_DOMAIN', '$PREFIX', "forest"])
    plantestsuite("samba4.blackbox.kinit_trust", "fl2003dc:local", [os.path.join(bbdir, "test_kinit_trusts_mit.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$TRUST_SERVER', '$TRUST_USERNAME', '$TRUST_PASSWORD', '$TRUST_REALM', '$TRUST_DOMAIN', '$PREFIX', "external"])
    plantestsuite("samba4.blackbox.export.keytab", "ad_dc_ntvfs:local", [os.path.join(bbdir, "test_export_keytab_mit.sh"), '$SERVER', '$USERNAME', '$REALM', '$DOMAIN', "$PREFIX", smbclient4])
    plantestsuite("samba4.blackbox.kpasswd", "ad_dc_ntvfs:local", [os.path.join(bbdir, "test_kpasswd_mit.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', "$PREFIX/ad_dc_ntvfs"])

plantestsuite("samba.blackbox.client_kerberos", "ad_dc", [os.path.join(bbdir, "test_client_kerberos.sh"), '$DOMAIN', '$REALM', '$USERNAME', '$PASSWORD', '$SERVER', '$PREFIX_ABS', '$SMB_CONF_PATH'])

plantestsuite("samba4.blackbox.trust_ntlm", "fl2008r2dc:local", [os.path.join(bbdir, "test_trust_ntlm.sh"), '$SERVER_IP', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$TRUST_USERNAME', '$TRUST_PASSWORD', '$TRUST_REALM', '$TRUST_DOMAIN', 'forest', 'auto', 'NT_STATUS_LOGON_FAILURE'])
plantestsuite("samba4.blackbox.trust_ntlm", "fl2003dc:local", [os.path.join(bbdir, "test_trust_ntlm.sh"), '$SERVER_IP', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$TRUST_USERNAME', '$TRUST_PASSWORD', '$TRUST_REALM', '$TRUST_DOMAIN', 'external', 'auto', 'NT_STATUS_LOGON_FAILURE'])
plantestsuite("samba4.blackbox.trust_ntlm", "ad_member:local", [os.path.join(bbdir, "test_trust_ntlm.sh"), '$SERVER_IP', '$USERNAME', '$PASSWORD', '$SERVER', '$SERVER', '$DC_USERNAME', '$DC_PASSWORD', '$REALM', '$DOMAIN', 'member', 'auto', 'NT_STATUS_LOGON_FAILURE'])
plantestsuite("samba4.blackbox.trust_ntlm", "nt4_member:local", [os.path.join(bbdir, "test_trust_ntlm.sh"), '$SERVER_IP', '$USERNAME', '$PASSWORD', '$SERVER', '$SERVER', '$DC_USERNAME', '$DC_PASSWORD', '$DOMAIN', '$DOMAIN', 'member', 'auto', 'NT_STATUS_LOGON_FAILURE'])

plantestsuite("samba4.blackbox.trust_utils(fl2008r2dc:local)", "fl2008r2dc:local", [os.path.join(bbdir, "test_trust_utils.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$TRUST_SERVER', '$TRUST_USERNAME', '$TRUST_PASSWORD', '$TRUST_REALM', '$TRUST_DOMAIN', '$PREFIX', "forest"])
plantestsuite("samba4.blackbox.trust_utils(fl2003dc:local)", "fl2003dc:local", [os.path.join(bbdir, "test_trust_utils.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$TRUST_SERVER', '$TRUST_USERNAME', '$TRUST_PASSWORD', '$TRUST_REALM', '$TRUST_DOMAIN', '$PREFIX', "external"])
plantestsuite("samba4.blackbox.trust_token", "fl2008r2dc", [os.path.join(bbdir, "test_trust_token.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$DOMSID', '$TRUST_USERNAME', '$TRUST_PASSWORD', '$TRUST_REALM', '$TRUST_DOMAIN', '$TRUST_DOMSID', 'forest'])
plantestsuite("samba4.blackbox.trust_token", "fl2003dc", [os.path.join(bbdir, "test_trust_token.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', '$DOMSID', '$TRUST_USERNAME', '$TRUST_PASSWORD', '$TRUST_REALM', '$TRUST_DOMAIN', '$TRUST_DOMSID', 'external'])
plantestsuite("samba4.blackbox.ktpass(ad_dc_ntvfs)", "ad_dc_ntvfs", [os.path.join(bbdir, "test_ktpass.sh"), '$PREFIX/ad_dc_ntvfs'])
plantestsuite("samba4.blackbox.password_settings(ad_dc_ntvfs:local)", "ad_dc_ntvfs:local", [os.path.join(bbdir, "test_password_settings.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', "$PREFIX/ad_dc_ntvfs"])
plantestsuite("samba4.blackbox.trust_user_account", "fl2008r2dc:local", [os.path.join(bbdir, "test_trust_user_account.sh"), '$PREFIX', '$REALM', '$DOMAIN', '$TRUST_REALM', '$TRUST_DOMAIN'])
plantestsuite("samba4.blackbox.cifsdd(ad_dc_ntvfs)", "ad_dc_ntvfs", [os.path.join(samba4srcdir, "client/tests/test_cifsdd.sh"), '$SERVER', '$USERNAME', '$PASSWORD', "$DOMAIN"])
plantestsuite("samba4.blackbox.nmblookup(ad_dc_ntvfs)", "ad_dc_ntvfs", [os.path.join(samba4srcdir, "utils/tests/test_nmblookup.sh"), '$NETBIOSNAME', '$NETBIOSALIAS', '$SERVER', '$SERVER_IP', nmblookup4])
plantestsuite("samba4.blackbox.locktest(ad_dc_ntvfs)", "ad_dc_ntvfs", [os.path.join(samba4srcdir, "torture/tests/test_locktest.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$DOMAIN', '$PREFIX'])
plantestsuite("samba4.blackbox.masktest", "ad_dc_ntvfs", [os.path.join(samba4srcdir, "torture/tests/test_masktest.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$DOMAIN', '$PREFIX'])
plantestsuite("samba4.blackbox.gentest(ad_dc_ntvfs)", "ad_dc_ntvfs", [os.path.join(samba4srcdir, "torture/tests/test_gentest.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$DOMAIN', "$PREFIX"])
plantestsuite("samba4.blackbox.rfc2307_mapping(ad_dc_ntvfs:local)", "ad_dc_ntvfs:local", [os.path.join(samba4srcdir, "../nsswitch/tests/test_rfc2307_mapping.sh"), '$DOMAIN', '$USERNAME', '$PASSWORD', "$SERVER", "$UID_RFC2307TEST", "$GID_RFC2307TEST", configuration])
plantestsuite("samba4.blackbox.chgdcpass", "chgdcpass", [os.path.join(bbdir, "test_chgdcpass.sh"), '$SERVER', "CHGDCPASS\$", '$REALM', '$DOMAIN', '$PREFIX/chgdcpass', "aes256-cts-hmac-sha1-96", '$PREFIX/chgdcpass', smbclient3])
plantestsuite("samba4.blackbox.samba_upgradedns(chgdcpass:local)", "chgdcpass:local", [os.path.join(bbdir, "test_samba_upgradedns.sh"), '$SERVER', '$REALM', '$PREFIX', '$SELFTEST_PREFIX/chgdcpass'])
plantestsuite("samba4.blackbox.net_ads", "ad_dc:client", [os.path.join(bbdir, "test_net_ads.sh"), '$DC_SERVER', '$DC_USERNAME', '$DC_PASSWORD', '$PREFIX_ABS'])
plantestsuite("samba4.blackbox.client_etypes_all(ad_dc:client)", "ad_dc:client", [os.path.join(bbdir, "test_client_etypes.sh"), '$DC_SERVER', '$DC_USERNAME', '$DC_PASSWORD', '$PREFIX_ABS', 'all', '17_18_23'])
plantestsuite("samba4.blackbox.client_etypes_legacy(ad_dc:client)", "ad_dc:client", [os.path.join(bbdir, "test_client_etypes.sh"), '$DC_SERVER', '$DC_USERNAME', '$DC_PASSWORD', '$PREFIX_ABS', 'legacy', '23'])
plantestsuite("samba4.blackbox.client_etypes_strong(ad_dc:client)", "ad_dc:client", [os.path.join(bbdir, "test_client_etypes.sh"), '$DC_SERVER', '$DC_USERNAME', '$DC_PASSWORD', '$PREFIX_ABS', 'strong', '17_18'])
plantestsuite("samba4.blackbox.net_ads_dns(ad_member:local)", "ad_member:local", [os.path.join(bbdir, "test_net_ads_dns.sh"), '$DC_SERVER', '$DC_USERNAME', '$DC_PASSWORD', '$REALM', '$USERNAME', '$PASSWORD'])
plantestsuite("samba4.blackbox.samba-tool_ntacl(ad_member:local)", "ad_member:local", [os.path.join(bbdir, "test_samba-tool_ntacl.sh"), '$PREFIX', '$DOMSID'])

if have_gnutls_crypto_policies:
    plantestsuite("samba4.blackbox.weak_crypto.client", "ad_dc", [os.path.join(bbdir, "test_weak_crypto.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', "$PREFIX/ad_dc"])

    for env in ["ad_dc_fips", "ad_member_fips"]:
        plantestsuite("samba4.blackbox.weak_crypto.server", env, [os.path.join(bbdir, "test_weak_crypto_server.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$REALM', '$DOMAIN', "$PREFIX/ad_dc_fips", configuration])
    plantestsuite("samba4.blackbox.net_ads_fips", "ad_dc_fips:client", [os.path.join(bbdir, "test_net_ads_fips.sh"), '$DC_SERVER', '$DC_USERNAME', '$DC_PASSWORD', '$PREFIX_ABS'])

    t = "--krb5auth=$DOMAIN/$DC_USERNAME%$DC_PASSWORD"
    plantestsuite("samba3.wbinfo_simple.fips.%s" % t, "ad_member_fips:local", [os.path.join(srcdir(), "nsswitch/tests/test_wbinfo_simple.sh"), t])
    plantestsuite("samba4.wbinfo_name_lookup.fips", "ad_member_fips", [os.path.join(srcdir(), "nsswitch/tests/test_wbinfo_name_lookup.sh"), '$DOMAIN', '$REALM', '$DC_USERNAME'])

plansmbtorture4testsuite('rpc.echo', "ad_dc_ntvfs", ['ncacn_np:$NETBIOSALIAS', '-U$DOMAIN/$USERNAME%$PASSWORD'], "samba4.rpc.echo against NetBIOS alias")

# json tests hook into ``chgdcpass'' to make them run in contributor CI on
# gitlab
planpythontestsuite("chgdcpass", "samba.tests.blackbox.netads_json")

# Tests using the "Simple" NTVFS backend
for t in ["base.rw1"]:
    plansmbtorture4testsuite(t, "ad_dc_ntvfs", ["//$SERVER/simple", '-U$USERNAME%$PASSWORD'], modname="samba4.ntvfs.simple.%s" % t)

# Domain S4member Tests
plansmbtorture4testsuite('rpc.echo', "s4member", ['ncacn_np:$NETBIOSNAME', '-U$NETBIOSNAME/$USERNAME%$PASSWORD'], "samba4.rpc.echo against s4member server with local creds")
plansmbtorture4testsuite('rpc.echo', "s4member", ['ncacn_np:$NETBIOSNAME', '-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'], "samba4.rpc.echo against s4member server with domain creds")
plansmbtorture4testsuite('rpc.samr', "s4member", ['ncacn_np:$NETBIOSNAME', '-U$NETBIOSNAME/$USERNAME%$PASSWORD'], "samba4.rpc.samr against s4member server with local creds")
plansmbtorture4testsuite('rpc.samr.users', "s4member", ['ncacn_np:$NETBIOSNAME', '-U$NETBIOSNAME/$USERNAME%$PASSWORD'], "samba4.rpc.samr.users against s4member server with local creds",)
plansmbtorture4testsuite('rpc.samr.passwords', "s4member", ['ncacn_np:$NETBIOSNAME', '-U$NETBIOSNAME/$USERNAME%$PASSWORD'], "samba4.rpc.samr.passwords against s4member server with local creds")
plantestsuite("samba4.blackbox.smbclient against s4member server with local creds", "s4member", [os.path.join(samba4srcdir, "client/tests/test_smbclient.sh"), '$NETBIOSNAME', '$USERNAME', '$PASSWORD', '$NETBIOSNAME', '$PREFIX', smbclient4])

# RPC Proxy
plansmbtorture4testsuite("rpc.echo", "rpc_proxy", ['ncacn_ip_tcp:$NETBIOSNAME', '-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'], modname="samba4.rpc.echo against rpc proxy with domain creds")

# Tests SMB signing
for mech in [
    "-k no",
    "-k no --option=clientusespnego=no",
    "-k no --option=gensec:spengo=no",
    "-k yes",
    "-k yes --option=gensec:fake_gssapi_krb5=yes --option=gensec:gssapi_krb5=no"]:
    for signing in ["--signing=on", "--signing=required"]:
        signoptions = "%s %s" % (mech, signing)
        name = "smb.signing on with %s" % signoptions
        plansmbtorture4testsuite('base.xcopy', "ad_dc_ntvfs", ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$USERNAME%$PASSWORD'], modname="samba4.%s" % name)

for mech in [
    "-k no",
    "-k no --option=clientusespnego=no",
    "-k no --option=gensec:spengo=no",
    "-k yes"]:
    signoptions = "%s --signing=off" % mech
    name = "smb.signing disabled on with %s" % signoptions
    plansmbtorture4testsuite('base.xcopy', "s4member", ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$DC_USERNAME%$DC_PASSWORD'], "samba4.%s domain-creds" % name)
    plansmbtorture4testsuite('base.xcopy', "ad_member", ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$DC_USERNAME%$DC_PASSWORD'], "samba4.%s domain-creds" % name)
    plansmbtorture4testsuite('base.xcopy', "ad_dc", ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$USERNAME%$PASSWORD'], "samba4.%s" % name)
    plansmbtorture4testsuite('base.xcopy', "ad_dc",
                             ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$DC_USERNAME%$DC_PASSWORD'], "samba4.%s administrator" % name)

plantestsuite("samba4.blackbox.bogusdomain", "ad_member", ["testprogs/blackbox/bogus.sh", "$NETBIOSNAME", "xcopy_share", '$USERNAME', '$PASSWORD', '$DC_USERNAME', '$DC_PASSWORD', smbclient3])
for mech in [
    "-k no",
    "-k no --option=clientusespnego=no",
    "-k no --option=gensec:spengo=no"]:
    signoptions = "%s --signing=off" % mech
    plansmbtorture4testsuite('base.xcopy', "s4member", ['//$NETBIOSNAME/xcopy_share', signoptions, '-U$NETBIOSNAME/$USERNAME%$PASSWORD'], modname="samba4.smb.signing on with %s local-creds" % signoptions)

plansmbtorture4testsuite('base.xcopy', "ad_dc_ntvfs", ['//$NETBIOSNAME/xcopy_share', '-k', 'no', '--signing=yes', '-U%'], modname="samba4.smb.signing --signing=yes anon")
plansmbtorture4testsuite('base.xcopy', "ad_dc_ntvfs", ['//$NETBIOSNAME/xcopy_share', '-k', 'no', '--signing=required', '-U%'], modname="samba4.smb.signing --signing=required anon")
plansmbtorture4testsuite('base.xcopy', "s4member", ['//$NETBIOSNAME/xcopy_share', '-k', 'no', '--signing=no', '-U%'], modname="samba4.smb.signing --signing=no anon")

# Test SPNEGO without issuing an optimistic token
opt='--option=spnego:client_no_optimistic=yes'
plansmbtorture4testsuite('base.xcopy', "ad_dc_smb1", ['//$NETBIOSNAME/xcopy_share', '-U$USERNAME%$PASSWORD', opt, '-k', 'no'], modname="samba4.smb.spnego.ntlmssp.no_optimistic")
plansmbtorture4testsuite('base.xcopy', "ad_dc_smb1", ['//$NETBIOSNAME/xcopy_share', '-U$USERNAME%$PASSWORD', opt, '-k', 'yes'], modname="samba4.smb.spnego.krb5.no_optimistic")

wb_opts_default = ["--option=\"torture:strict mode=no\"", "--option=\"torture:timelimit=1\"", "--option=\"torture:winbindd_separator=/\"", "--option=\"torture:winbindd_netbios_name=$SERVER\"", "--option=\"torture:winbindd_netbios_domain=$DOMAIN\""]

winbind_ad_client_tests = smbtorture4_testsuites("winbind.struct") + smbtorture4_testsuites("winbind.pac")
winbind_wbclient_tests = smbtorture4_testsuites("winbind.wbclient")
for env in ["ad_dc", "s4member", "ad_member", "nt4_member"]:
    wb_opts = wb_opts_default[:]
    if env in ["ad_member"]:
        wb_opts += ["--option=\"torture:winbindd_domain_without_prefix=$DOMAIN\""]
    for t in winbind_ad_client_tests:
        plansmbtorture4testsuite(t, "%s:local" % env, wb_opts + ['//$SERVER/tmp', '--realm=$REALM', '--machine-pass', '--option=torture:addc=$DC_SERVER'])

for env in ["nt4_dc", "fl2003dc"]:
    for t in winbind_wbclient_tests:
        plansmbtorture4testsuite(t, "%s:local" % env, '//$SERVER/tmp -U$DC_USERNAME%$DC_PASSWORD')

for env in ["nt4_dc", "nt4_member", "ad_dc", "ad_member", "s4member", "chgdcpass", "rodc"]:
    tests = ["--ping", "--separator",
             "--own-domain",
             "--all-domains",
             "--trusted-domains",
             "--domain-info=BUILTIN",
             "--domain-info=$DOMAIN",
             "--online-status",
             "--online-status --domain=BUILTIN",
             "--online-status --domain=$DOMAIN",
             "--check-secret --domain=$DOMAIN",
             "--change-secret --domain=$DOMAIN",
             "--check-secret --domain=$DOMAIN",
             "--online-status --domain=$DOMAIN",
             "--domain-users",
             "--domain-groups",
             "--name-to-sid=$DC_USERNAME",
             "--name-to-sid=$DOMAIN/$DC_USERNAME",
             "--user-info=$DOMAIN/$DC_USERNAME",
             "--user-groups=$DOMAIN/$DC_USERNAME",
             "--authenticate=$DOMAIN/$DC_USERNAME%$DC_PASSWORD",
             "--allocate-uid",
             "--allocate-gid"]

    for t in tests:
        plantestsuite("samba.wbinfo_simple.%s" % (t.replace(" --", ".").replace("--", "")), "%s:local" % env, [os.path.join(srcdir(), "nsswitch/tests/test_wbinfo_simple.sh"), t])

    plantestsuite(
        "samba.wbinfo_sids2xids.(%s:local)" % env, "%s:local" % env,
        [os.path.join(samba3srcdir, "script/tests/test_wbinfo_sids2xids.sh")])

    planpythontestsuite(env + ":local", "samba.tests.ntlm_auth")

for env in ["ktest"]:
    planpythontestsuite(env + ":local", "samba.tests.ntlm_auth_krb5")

for env in ["s4member_dflt_domain", "s4member"]:
    for cmd in ["id", "getent"]:
        users = ["$DC_USERNAME", "$DC_USERNAME@$REALM"]
        if env == "s4member":
            users = ["$DOMAIN/$DC_USERNAME", "$DC_USERNAME@$REALM"]
        for usr in users:
            plantestsuite("samba4.winbind.dom_name_parse.cmd", env, "%s/dom_parse.sh %s %s" % (bbdir, cmd, usr))

nsstest4 = binpath("nsstest")
for env in ["ad_dc:local", "s4member:local", "nt4_dc:local", "ad_member:local", "nt4_member:local"]:
    if os.path.exists(nsstest4):
        plantestsuite("samba.nss.test using winbind(%s)" % env, env, [os.path.join(bbdir, "nsstest.sh"), nsstest4, os.path.join(samba4bindir, "shared/libnss_wrapper_winbind.so.2")])
    else:
        skiptestsuite("samba.nss.test using winbind(%s)" % env, "nsstest not available")

subunitrun = valgrindify(python) + " " + os.path.join(samba4srcdir, "scripting/bin/subunitrun")


def planoldpythontestsuite(env, module, name=None, extra_path=[], environ={}, extra_args=[]):
    environ = dict(environ)
    py_path = list(extra_path)
    if py_path:
        environ["PYTHONPATH"] = ":".join(["$PYTHONPATH"] + py_path)
    args = ["%s=%s" % item for item in environ.items()]
    args += [subunitrun, "$LISTOPT", "$LOADLIST", module]
    args += extra_args
    if name is None:
        name = module
    plantestsuite_loadlist(name, env, args)

# Run complex search expressions test once for each database backend.
# Right now ad_dc has mdb and ad_dc_ntvfs has tdb
mdb_testenv = "ad_dc"
tdb_testenv = "ad_dc_ntvfs"
for testenv in [mdb_testenv, tdb_testenv]:
    planoldpythontestsuite(testenv, "samba.tests.complex_expressions", extra_args=['-U"$USERNAME%$PASSWORD"'])

planoldpythontestsuite("ad_dc_default:local", "samba.tests.gensec", extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("none", "simple", extra_path=["%s/lib/tdb/python/tests" % srcdir()], name="tdb.python")
planpythontestsuite("ad_dc_default:local", "samba.tests.dcerpc.sam")
planpythontestsuite("ad_dc_default:local", "samba.tests.dsdb")
planpythontestsuite("none", "samba.tests.dsdb_lock")
planpythontestsuite("ad_dc_default:local", "samba.tests.dcerpc.bare")
planpythontestsuite("ad_dc_default:local", "samba.tests.dcerpc.lsa")
planpythontestsuite("ad_dc_default:local", "samba.tests.dcerpc.unix")
planpythontestsuite("ad_dc_ntvfs:local", "samba.tests.dcerpc.srvsvc")
planpythontestsuite("ad_dc_default:local", "samba.tests.samba_tool.timecmd")
planpythontestsuite("ad_dc_default:local", "samba.tests.samba_tool.join")
planpythontestsuite("ad_dc_default",
                    "samba.tests.samba_tool.join_lmdb_size")
planpythontestsuite("ad_dc_default",
                    "samba.tests.samba_tool.drs_clone_dc_data_lmdb_size")
planpythontestsuite("ad_dc_default",
                    "samba.tests.samba_tool.promote_dc_lmdb_size")

planpythontestsuite("none", "samba.tests.samba_tool.visualize")


# test fsmo show
for env in all_fl_envs:
    planpythontestsuite(env + ":local", "samba.tests.samba_tool.fsmo")

# test samba-tool user, group, contact and computer edit command
for env in all_fl_envs:
    env += ":local"
    plantestsuite("samba.tests.samba_tool.user_edit", env, [os.path.join(srcdir(), "python/samba/tests/samba_tool/user_edit.sh"), '$SERVER', '$USERNAME', '$PASSWORD'])
    plantestsuite("samba.tests.samba_tool.group_edit", env, [os.path.join(srcdir(), "python/samba/tests/samba_tool/group_edit.sh"), '$SERVER', '$USERNAME', '$PASSWORD'])
    plantestsuite("samba.tests.samba_tool.contact_edit", env, [os.path.join(srcdir(), "python/samba/tests/samba_tool/contact_edit.sh"), '$SERVER', '$USERNAME', '$PASSWORD'])
    plantestsuite("samba.tests.samba_tool.computer_edit", env, [os.path.join(srcdir(), "python/samba/tests/samba_tool/computer_edit.sh"), '$SERVER', '$USERNAME', '$PASSWORD'])

# We run this test against both AD DC implementations because it is
# the only test we have of GPO get/set behaviour, and this involves
# the file server as well as the LDAP server.
# It's also a good sanity-check that sysvol backup worked correctly.
for env in ["ad_dc_ntvfs", "ad_dc", "offlinebackupdc", "renamedc",
            smbv1_disabled_testenv]:
    planpythontestsuite(env + ":local", "samba.tests.samba_tool.gpo")

planpythontestsuite("ad_dc_default:local", "samba.tests.samba_tool.processes")
planpythontestsuite("ad_dc_ntvfs:local", "samba.tests.samba_tool.user")
planpythontestsuite("ad_dc_default:local", "samba.tests.samba_tool.user_wdigest")
planpythontestsuite("ad_dc:local", "samba.tests.samba_tool.user")
planpythontestsuite("ad_dc:local", "samba.tests.samba_tool.user_virtualCryptSHA_userPassword")
planpythontestsuite("ad_dc:local", "samba.tests.samba_tool.user_virtualCryptSHA_gpg")
planpythontestsuite("chgdcpass:local", "samba.tests.samba_tool.user_check_password_script")
planpythontestsuite("ad_dc_default:local", "samba.tests.samba_tool.group")
planpythontestsuite("ad_dc_default:local", "samba.tests.samba_tool.ou")
planpythontestsuite("ad_dc_default:local", "samba.tests.samba_tool.computer")
planpythontestsuite("ad_dc_default:local", "samba.tests.samba_tool.forest")
planpythontestsuite("ad_dc_default:local", "samba.tests.samba_tool.schema")
planpythontestsuite("schema_dc:local", "samba.tests.samba_tool.schema")
planpythontestsuite("ad_dc:local", "samba.tests.samba_tool.ntacl")
planpythontestsuite("none", "samba.tests.samba_tool.provision_password_check")
planpythontestsuite("none", "samba.tests.samba_tool.provision_lmdb_size")
planpythontestsuite("none", "samba.tests.samba_tool.help")
planpythontestsuite("ad_dc_default:local", "samba.tests.samba_tool.passwordsettings")
planpythontestsuite("ad_dc:local", "samba.tests.samba_tool.dsacl")

planpythontestsuite("none", "samba.tests.samba_upgradedns_lmdb")

# Run these against chgdcpass to share the runtime load
planpythontestsuite("chgdcpass:local", "samba.tests.samba_tool.sites")
planpythontestsuite("chgdcpass:local", "samba.tests.samba_tool.dnscmd")

# Run this against chgdcpass to ensure at least one python3 test
# against this autobuild target (samba-ad-dc-2)
planpythontestsuite("chgdcpass:local", "samba.tests.dcerpc.rpcecho")

planoldpythontestsuite("nt4_dc", "samba.tests.netbios", extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("ad_dc:local", "samba.tests.gpo", extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("ad_dc:local", "samba.tests.dckeytab", extra_args=['-U"$USERNAME%$PASSWORD"'])

have_fast_support = int('SAMBA_USES_MITKDC' in config_hash)
tkt_sig_support = int('SAMBA4_USES_HEIMDAL' in config_hash)
planoldpythontestsuite("none", "samba.tests.krb5.kcrypto")
planoldpythontestsuite("ad_dc_default", "samba.tests.krb5.simple_tests",
                       environ={'SERVICE_USERNAME':'$SERVER',
                                'FAST_SUPPORT': have_fast_support,
                                'TKT_SIG_SUPPORT': tkt_sig_support})
planoldpythontestsuite("ad_dc_default:local", "samba.tests.krb5.s4u_tests",
                       environ={'ADMIN_USERNAME':'$USERNAME',
                                'ADMIN_PASSWORD':'$PASSWORD',
                                'FOR_USER':'$USERNAME',
                                'STRICT_CHECKING':'0',
                                'FAST_SUPPORT': have_fast_support,
                                'TKT_SIG_SUPPORT': tkt_sig_support})
planoldpythontestsuite("rodc:local", "samba.tests.krb5.rodc_tests",
                       environ={'ADMIN_USERNAME':'$USERNAME',
                                'ADMIN_PASSWORD':'$PASSWORD',
                                'STRICT_CHECKING':'0',
                                'FAST_SUPPORT': have_fast_support,
                                'TKT_SIG_SUPPORT': tkt_sig_support})

planoldpythontestsuite("fl2008r2dc:local", "samba.tests.krb5.xrealm_tests",
                       environ={'FAST_SUPPORT': have_fast_support,
                                'TKT_SIG_SUPPORT': tkt_sig_support})

planoldpythontestsuite("ad_dc_default", "samba.tests.krb5.test_ccache",
                       environ={
                           'ADMIN_USERNAME': '$USERNAME',
                           'ADMIN_PASSWORD': '$PASSWORD',
                           'STRICT_CHECKING': '0',
                           'FAST_SUPPORT': have_fast_support,
                           'TKT_SIG_SUPPORT': tkt_sig_support
                       })
planoldpythontestsuite("ad_dc_default", "samba.tests.krb5.test_ldap",
                       environ={
                           'ADMIN_USERNAME': '$USERNAME',
                           'ADMIN_PASSWORD': '$PASSWORD',
                           'STRICT_CHECKING': '0',
                           'FAST_SUPPORT': have_fast_support,
                           'TKT_SIG_SUPPORT': tkt_sig_support
                       })
planoldpythontestsuite("ad_dc_default", "samba.tests.krb5.test_rpc",
                       environ={
                           'ADMIN_USERNAME': '$USERNAME',
                           'ADMIN_PASSWORD': '$PASSWORD',
                           'STRICT_CHECKING': '0',
                           'FAST_SUPPORT': have_fast_support,
                           'TKT_SIG_SUPPORT': tkt_sig_support
                       })
planoldpythontestsuite("ad_dc_smb1", "samba.tests.krb5.test_smb",
                       environ={
                           'ADMIN_USERNAME': '$USERNAME',
                           'ADMIN_PASSWORD': '$PASSWORD',
                           'STRICT_CHECKING': '0',
                           'FAST_SUPPORT': have_fast_support,
                           'TKT_SIG_SUPPORT': tkt_sig_support
                       })

for env in ["ad_dc", smbv1_disabled_testenv]:
    planoldpythontestsuite(env, "samba.tests.smb", extra_args=['-U"$USERNAME%$PASSWORD"'])
    planoldpythontestsuite(env + ":local", "samba.tests.ntacls_backup",
        extra_args=['-U"$USERNAME%$PASSWORD"'])

planoldpythontestsuite(
    "ad_dc_ntvfs:local", "samba.tests.dcerpc.registry",
    extra_args=['-U"$USERNAME%$PASSWORD"'])

planoldpythontestsuite("ad_dc_ntvfs", "samba.tests.dcerpc.dnsserver", extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("ad_dc", "samba.tests.dcerpc.dnsserver", extra_args=['-U"$USERNAME%$PASSWORD"'])

for env in ["chgdcpass", "ad_member"]:
    planoldpythontestsuite(env, "samba.tests.dcerpc.raw_protocol",
                           environ={"MAX_NUM_AUTH": "8",
                                    "USERNAME": "$DC_USERNAME",
                                    "PASSWORD": "$DC_PASSWORD"})

if have_heimdal_support:
    planoldpythontestsuite("ad_dc_smb1:local", "samba.tests.auth_log", extra_args=['-U"$USERNAME%$PASSWORD"'],
                           environ={'CLIENT_IP': '10.53.57.11',
                                    'SOCKET_WRAPPER_DEFAULT_IFACE': 11})
    planoldpythontestsuite("ad_dc_ntvfs:local", "samba.tests.auth_log", extra_args=['-U"$USERNAME%$PASSWORD"'],
                           environ={'CLIENT_IP': '10.53.57.11',
                                    'SOCKET_WRAPPER_DEFAULT_IFACE': 11})
    planoldpythontestsuite("ad_dc_smb1", "samba.tests.auth_log_pass_change",
                           extra_args=['-U"$USERNAME%$PASSWORD"'])
    planoldpythontestsuite("ad_dc_ntvfs", "samba.tests.auth_log_pass_change",
                           extra_args=['-U"$USERNAME%$PASSWORD"'])

    # these tests use a NCA local RPC connection, so always run on the
    # :local testenv, and so don't need to fake a client connection
    for env in ["ad_dc_ntvfs:local", "ad_dc:local"]:
        planoldpythontestsuite(env, "samba.tests.auth_log_ncalrpc", extra_args=['-U"$USERNAME%$PASSWORD"'])
        planoldpythontestsuite(env, "samba.tests.auth_log_samlogon",
                               extra_args=['-U"$USERNAME%$PASSWORD"'])
        planoldpythontestsuite(env, "samba.tests.auth_log_netlogon",
                               extra_args=['-U"$USERNAME%$PASSWORD"'])
        planoldpythontestsuite(env, "samba.tests.auth_log_netlogon_bad_creds",
                               extra_args=['-U"$USERNAME%$PASSWORD"'])

    planoldpythontestsuite("ad_member:local",
                           "samba.tests.auth_log_winbind",
                           extra_args=['-U"$DC_USERNAME%$DC_PASSWORD"'])
    planoldpythontestsuite("ad_dc", "samba.tests.audit_log_pass_change",
                           extra_args=['-U"$USERNAME%$PASSWORD"'])
    planoldpythontestsuite("ad_dc", "samba.tests.audit_log_dsdb",
                           extra_args=['-U"$USERNAME%$PASSWORD"'])
    planoldpythontestsuite("ad_dc", "samba.tests.group_audit",
                           extra_args=['-U"$USERNAME%$PASSWORD"'])

planoldpythontestsuite("fl2008r2dc:local",
                       "samba.tests.getdcname",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])

planoldpythontestsuite("ad_dc_smb1",
                       "samba.tests.net_join_no_spnego",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("ad_dc",
                       "samba.tests.net_join",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("ad_dc",
                       "samba.tests.segfault",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
# Need to test the password hashing in multiple environments to ensure that
# all the possible options are covered
#
# ad_dc:local functional_level >= 2008, gpg keys available
planoldpythontestsuite("ad_dc:local",
                       "samba.tests.password_hash_gpgme",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
# ad_dc_ntvfs:local functional level >= 2008, gpg keys not available
planoldpythontestsuite("ad_dc_ntvfs:local",
                       "samba.tests.password_hash_fl2008",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
# fl2003dc:local functional level < 2008, gpg keys not available
planoldpythontestsuite("fl2003dc:local",
                       "samba.tests.password_hash_fl2003",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
# ad_dc: wDigest values over ldap
planoldpythontestsuite("ad_dc",
                       "samba.tests.password_hash_ldap",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])

for env in ["ad_dc_backup", smbv1_disabled_testenv]:
    planoldpythontestsuite(env + ":local", "samba.tests.domain_backup",
                           extra_args=['-U"$USERNAME%$PASSWORD"'])

planoldpythontestsuite("ad_dc",
                       "samba.tests.domain_backup_offline")
# Encrypted secrets
# ensure default provision (ad_dc) and join (vampire_dc)
# encrypt secret values on disk.
planoldpythontestsuite("ad_dc:local",
                       "samba.tests.encrypted_secrets",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("vampire_dc:local",
                       "samba.tests.encrypted_secrets",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
# The fl2000dc environment is provisioned with the --plaintext_secrets option
# so this test will fail, which proves the secrets are not being encrypted.
# There is an entry in known_fail.d.
planoldpythontestsuite("fl2000dc:local",
                       "samba.tests.encrypted_secrets",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])

planpythontestsuite("none",
                    "samba.tests.lsa_string")

planoldpythontestsuite("ad_dc_ntvfs",
                       "samba.tests.krb5_credentials",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])

for env in ["ad_dc_ntvfs", "vampire_dc", "promoted_dc"]:
    planoldpythontestsuite(env,
                           "samba.tests.py_credentials",
                           extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("ad_dc_ntvfs",
                       "samba.tests.emulate.traffic",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("ad_dc_ntvfs",
                       "samba.tests.emulate.traffic_packet",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("ad_dc_ntvfs",
                       "samba.tests.blackbox.traffic_replay",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("ad_dc_ntvfs",
                       "samba.tests.blackbox.traffic_learner",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("ad_dc_ntvfs",
                       "samba.tests.blackbox.traffic_summary",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("none", "samba.tests.loadparm")
planoldpythontestsuite("fileserver",
                       "samba.tests.blackbox.mdfind",
                       extra_args=['-U"$USERNAME%$PASSWORD"'])
planoldpythontestsuite("fileserver",
                       "samba.tests.blackbox.smbcacls_basic")
planoldpythontestsuite("fileserver",
                       "samba.tests.blackbox.smbcacls_basic",
                       "samba.tests.blackbox.smbcacls_basic(DFS)",
                       environ={'SHARE': 'msdfs-share',
                                 'TESTDIR': 'smbcacls_sharedir_dfs'})

#
# Want a selection of environments across the process models
#
for env in ["ad_dc_ntvfs:local", "ad_dc:local",
            "fl2003dc:local", "fl2008r2dc:local",
            "promoted_dc:local"]:
    planoldpythontestsuite(env, "samba.tests.blackbox.smbcontrol")

planoldpythontestsuite("none", "samba.tests.blackbox.downgradedatabase")

plantestsuite_loadlist("samba4.ldap.python(ad_dc_default)", "ad_dc_default", [python, os.path.join(DSDB_PYTEST_DIR, "ldap.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba4.ldap_modify_order.python(ad_dc_default)",
                       "ad_dc_default",
                       [python, os.path.join(samba4srcdir,
                                             "dsdb/tests/python/"
                                             "ldap_modify_order.py"),
                        # add "-v" here to diagnose
                        '$SERVER',
                        '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN',
                        '$LOADLIST',
                        '$LISTOPT'])

plantestsuite_loadlist("samba4.ldap_modify_order.normal_user.python(ad_dc_default)",
                       "ad_dc_default",
                       [python, os.path.join(samba4srcdir,
                                             "dsdb/tests/python/"
                                             "ldap_modify_order.py"),
                        '--normal-user',
                        # add "-v" here to diagnose
                        '$SERVER',
                        '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN',
                        '$LOADLIST',
                        '$LISTOPT'])

planoldpythontestsuite("ad_dc",
                       "samba.tests.ldap_raw",
                       extra_args=['-U"$USERNAME%$PASSWORD"'],
                       environ={'TEST_ENV': 'ad_dc'})

plantestsuite_loadlist("samba4.tokengroups.krb5.python(ad_dc_default)", "ad_dc_default:local", [python, os.path.join(DSDB_PYTEST_DIR, "token_group.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '-k', 'yes', '$LOADLIST', '$LISTOPT'])
plantestsuite_loadlist("samba4.tokengroups.ntlm.python(ad_dc_default)", "ad_dc_default:local", [python, os.path.join(DSDB_PYTEST_DIR, "token_group.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '-k', 'no', '$LOADLIST', '$LISTOPT'])
plantestsuite("samba4.sam.python(fl2008r2dc)", "fl2008r2dc", [python, os.path.join(DSDB_PYTEST_DIR, "sam.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
plantestsuite("samba4.sam.python(ad_dc_default)", "ad_dc_default", [python, os.path.join(DSDB_PYTEST_DIR, "sam.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
plantestsuite("samba4.asq.python(ad_dc_default)", "ad_dc_default", [python, os.path.join(DSDB_PYTEST_DIR, "asq.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])
plantestsuite("samba4.user_account_control.python(ad_dc_default)", "ad_dc_default", [python, os.path.join(DSDB_PYTEST_DIR, "user_account_control.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])

for env in ['ad_dc_default:local', 'schema_dc:local']:
    planoldpythontestsuite(env, "dsdb_schema_info",
                           extra_path=[os.path.join(samba4srcdir, 'dsdb/tests/python')],
                           name="samba4.schemaInfo.python(%s)" % (env),
            extra_args=['-U"$DOMAIN/$DC_USERNAME%$DC_PASSWORD"'])

    planpythontestsuite(env, "samba.tests.dsdb_schema_attributes")

plantestsuite_loadlist("samba4.urgent_replication.python(ad_dc_ntvfs)", "ad_dc_ntvfs:local", [python, os.path.join(DSDB_PYTEST_DIR, "urgent_replication.py"), '$PREFIX_ABS/ad_dc_ntvfs/private/sam.ldb', '$LOADLIST', '$LISTOPT'])
plantestsuite_loadlist("samba4.ldap.dirsync.python(ad_dc_ntvfs)", "ad_dc_ntvfs", [python, os.path.join(DSDB_PYTEST_DIR, "dirsync.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
plantestsuite_loadlist("samba4.ldap.match_rules.python", "ad_dc_ntvfs", [python, os.path.join(srcdir(), "lib/ldb-samba/tests/match_rules.py"), '$PREFIX_ABS/ad_dc_ntvfs/private/sam.ldb', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
plantestsuite("samba4.ldap.index.python", "none", [python, os.path.join(srcdir(), "lib/ldb-samba/tests/index.py")])
plantestsuite_loadlist("samba4.ldap.notification.python(ad_dc_ntvfs)", "ad_dc_ntvfs", [python, os.path.join(DSDB_PYTEST_DIR, "notification.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
plantestsuite_loadlist("samba4.ldap.sites.python(ad_dc_default)", "ad_dc_default", [python, os.path.join(DSDB_PYTEST_DIR, "sites.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

env = 'vampire_dc'
# Test with LMDB (GSSAPI/SASL bind)
plantestsuite_loadlist("samba4.ldap.large_ldap.gssapi.python(%s)" % env, env, [python, os.path.join(DSDB_PYTEST_DIR, "large_ldap.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--kerberos=yes', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

env = 'ad_dc_default'
# Test with TDB (NTLMSSP bind)
plantestsuite_loadlist("samba4.ldap.large_ldap.ntlmssp.python(%s)" % env, env, [python, os.path.join(DSDB_PYTEST_DIR, "large_ldap.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--kerberos=no', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

env = 'ad_dc_ntvfs'
# Test with ldaps://
plantestsuite_loadlist("samba4.ldap.large_ldap.ldaps.python(%s)" % env, env, [python, os.path.join(DSDB_PYTEST_DIR, "large_ldap.py"), 'ldaps://$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

env = 'fl2008r2dc'
# Test with straight ldap
plantestsuite_loadlist("samba4.ldap.large_ldap.straight_ldap.python(%s)" % env, env, [python, os.path.join(DSDB_PYTEST_DIR, "large_ldap.py"), 'ldap://$SERVER',     '--simple-bind-dn=$USERNAME@$REALM', '--password=$PASSWORD', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

planoldpythontestsuite("ad_dc_default", "sort", environ={'SERVER' : '$SERVER', 'DATA_DIR' : os.path.join(samba4srcdir, 'dsdb/tests/python/testdata/')}, name="samba4.ldap.sort.python", extra_path=[os.path.join(samba4srcdir, 'dsdb/tests/python')], extra_args=['-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])

plantestsuite_loadlist("samba4.ldap.linked_attributes.python(ad_dc_ntvfs)", "ad_dc_ntvfs:local", [python, os.path.join(DSDB_PYTEST_DIR, "linked_attributes.py"), '$PREFIX_ABS/ad_dc_ntvfs/private/sam.ldb', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba4.ldap.subtree_rename.python(ad_dc_ntvfs)",
                       "ad_dc_ntvfs:local",
                       [python, os.path.join(samba4srcdir,
                                             "dsdb/tests/python/subtree_rename.py"),
                        '$PREFIX_ABS/ad_dc_ntvfs/private/sam.ldb',
                        '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN',
                        '$LOADLIST',
                        '$LISTOPT'])

planoldpythontestsuite(
    "ad_dc_ntvfs",
    "samba.tests.ldap_referrals",
    environ={
        'SERVER': '$SERVER',
    },
    name="samba.ldap.referrals",
    extra_args=['-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN'])

# These should be the first tests run against testenvs created by backup/restore
for env in ['offlinebackupdc', 'restoredc', 'renamedc', 'labdc']:
    # check that a restored DC matches the original DC (backupfromdc)
    plantestsuite("samba4.blackbox.ldapcmp_restore", env,
                  ["PYTHON=%s" % python,
                   os.path.join(bbdir, "ldapcmp_restoredc.sh"),
                   '$PREFIX_ABS/backupfromdc', '$PREFIX_ABS/%s' % env])

# we also test joining backupfromdc here, as it's a bit special in that it
# doesn't have Default-First-Site-Name
for env in ['backupfromdc', 'offlinebackupdc', 'restoredc', 'renamedc',
	    'labdc']:
    # basic test that we can join the testenv DC
    plantestsuite("samba4.blackbox.join_ldapcmp", env,
                  ["PYTHON=%s" % python, os.path.join(bbdir, "join_ldapcmp.sh")])

env = 'backupfromdc'
planoldpythontestsuite("%s:local" % env, "samba_tool_drs_no_dns",
                       extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                       name="samba4.drs.samba_tool_drs_no_dns.python(%s)" % env,
                       environ={'DC1': '$DC_SERVER', 'DC2': '$DC_SERVER'},
                       extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

plantestsuite_loadlist("samba4.ldap.rodc.python(rodc)", "rodc",
                       [python,
                        os.path.join(DSDB_PYTEST_DIR, "rodc.py"),
                        '$SERVER', '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

plantestsuite_loadlist("samba4.ldap.rodc_rwdc.python(rodc)", "rodc:local",
                       [python,
                        os.path.join(samba4srcdir,
                                     "dsdb/tests/python/rodc_rwdc.py"),
                        '$SERVER', '$DC_SERVER', '-U"$USERNAME%$PASSWORD"',
                        '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])

planoldpythontestsuite("rodc:local", "replica_sync_rodc",
                       extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                       name="samba4.drs.replica_sync_rodc.python(rodc)",
                       environ={'DC1': '$DC_SERVER', 'DC2': '$SERVER'},
		       extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

planoldpythontestsuite("ad_dc_default_smb1", "password_settings",
                       extra_path=[os.path.join(samba4srcdir, 'dsdb/tests/python')],
                       name="samba4.ldap.passwordsettings.python",
                       extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

for env in all_fl_envs + ["schema_dc"]:
    plantestsuite_loadlist("samba4.ldap_schema.python(%s)" % env, env, [python, os.path.join(DSDB_PYTEST_DIR, "ldap_schema.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
    plantestsuite("samba4.ldap.possibleInferiors.python(%s)" % env, env, [python, os.path.join(samba4srcdir, "dsdb/samdb/ldb_modules/tests/possibleinferiors.py"), "ldap://$SERVER", '-U"$USERNAME%$PASSWORD"', "-W$DOMAIN"])
    plantestsuite_loadlist("samba4.ldap.secdesc.python(%s)" % env, env, [python, os.path.join(DSDB_PYTEST_DIR, "sec_descriptor.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
    plantestsuite_loadlist("samba4.ldap.acl.python(%s)" % env, env, ["STRICT_CHECKING=0", python, os.path.join(DSDB_PYTEST_DIR, "acl.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
    if env != "fl2000dc":
        # This test makes excessive use of the "userPassword" attribute which
        # isn't available on DCs with Windows 2000 domain function level -
        # therefore skip it in that configuration
        plantestsuite_loadlist("samba4.ldap.passwords.python(%s)" % env, env, [python, os.path.join(DSDB_PYTEST_DIR, "passwords.py"), "$SERVER", '-U"$USERNAME%$PASSWORD"', "-W$DOMAIN", '$LOADLIST', '$LISTOPT'])

for env in ["ad_dc_slowtests"]:
    # This test takes a lot of time, so we run it against a minimum of
    # environments, please only add new ones if there's really a
    # difference we need to test
    plantestsuite_loadlist("samba4.ldap.vlv.python(%s)" % env, env, [python, os.path.join(DSDB_PYTEST_DIR, "vlv.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
    plantestsuite_loadlist("samba4.ldap.confidential_attr.python(%s)" % env, env, [python, os.path.join(DSDB_PYTEST_DIR, "confidential_attr.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
    plantestsuite_loadlist("samba4.ldap.password_lockout.python(%s)" % env, env, [python, os.path.join(DSDB_PYTEST_DIR, "password_lockout.py"), "$SERVER", '-U"$USERNAME%$PASSWORD"', "-W$DOMAIN", "--realm=$REALM", '$LOADLIST', '$LISTOPT'])
    planoldpythontestsuite(env, "tombstone_reanimation",
                           name="samba4.tombstone_reanimation.python",
                           environ={'TEST_SERVER': '$SERVER', 'TEST_USERNAME': '$USERNAME', 'TEST_PASSWORD': '$PASSWORD'},
                           extra_path=[os.path.join(samba4srcdir, 'dsdb/tests/python')]
                           )
    planoldpythontestsuite(env, "samba.tests.join",
                           name="samba.tests.join.python(%s)" % env,
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

# this is a basic sanity-check of Kerberos/NTLM user login
for env in ["offlinebackupdc", "restoredc", "renamedc", "labdc"]:
    plantestsuite_loadlist("samba4.ldap.login_basics.python(%s)" % env, env,
                           [python, os.path.join(DSDB_PYTEST_DIR, "login_basics.py"),
                            "$SERVER", '-U"$USERNAME%$PASSWORD"', "-W$DOMAIN", "--realm=$REALM",
                            '$LOADLIST', '$LISTOPT'])

planpythontestsuite("ad_dc_ntvfs:local", "samba.tests.upgradeprovisionneeddc")
planpythontestsuite("ad_dc:local", "samba.tests.posixacl")
planpythontestsuite("ad_dc_no_nss:local", "samba.tests.posixacl")
plantestsuite_loadlist("samba4.deletetest.python(ad_dc_default)", "ad_dc_default", [python, os.path.join(DSDB_PYTEST_DIR, "deletetest.py"),
                                                                                '$SERVER', '-U"$USERNAME%$PASSWORD"', '--workgroup=$DOMAIN', '$LOADLIST', '$LISTOPT'])
plantestsuite("samba4.blackbox.samba3dump", "none", [os.path.join(samba4srcdir, "selftest/test_samba3dump.sh")])
plantestsuite("samba4.blackbox.upgrade", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_s3upgrade.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.provision.py", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_provision.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.provision_fileperms", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/provision_fileperms.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.supported_features", "none",
              ["PYTHON=%s" % python,
               os.path.join(samba4srcdir,
                            "setup/tests/blackbox_supported_features.sh"),
               '$PREFIX/provision'])
plantestsuite("samba4.blackbox.start_backup", "none",
              ["PYTHON=%s" % python,
               os.path.join(samba4srcdir,
                            "setup/tests/blackbox_start_backup.sh"),
               '$PREFIX/provision'])
plantestsuite("samba4.blackbox.upgradeprovision.current", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_upgradeprovision.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.setpassword.py", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_setpassword.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.newuser.py", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_newuser.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.group.py", "none", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_group.sh"), '$PREFIX/provision'])
plantestsuite("samba4.blackbox.spn.py(ad_dc_ntvfs:local)", "ad_dc_ntvfs:local", ["PYTHON=%s" % python, os.path.join(samba4srcdir, "setup/tests/blackbox_spn.sh"), '$PREFIX/ad_dc_ntvfs'])
plantestsuite_loadlist("samba4.ldap.bind(fl2008r2dc)", "fl2008r2dc", [python, os.path.join(srcdir(), "auth/credentials/tests/bind.py"), '$SERVER', '-U"$USERNAME%$PASSWORD"', '$LOADLIST', '$LISTOPT'])

# This makes sure we test the rid allocation code
t = "rpc.samr.large-dc"
plansmbtorture4testsuite(t, "vampire_dc", ['$SERVER', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], modname=("samba4.%s.one" % t))
plansmbtorture4testsuite(t, "vampire_dc", ['$SERVER', '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], modname="samba4.%s.two" % t)

# RPC smoke-tests for testenvs of interest (RODC, etc)
for env in ['rodc', 'offlinebackupdc', 'restoredc', 'renamedc', 'labdc']:
    plansmbtorture4testsuite('rpc.echo', env, ['ncacn_np:$SERVER', "-k", "yes", '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN'], modname="samba4.rpc.echo")
    plansmbtorture4testsuite('rpc.echo', "%s:local" % env, ['ncacn_np:$SERVER', "-k", "yes", '-P', '--workgroup=$DOMAIN'], modname="samba4.rpc.echo")
    plansmbtorture4testsuite('rpc.echo', "%s:local" % env, ['ncacn_np:$SERVER', "-k", "no", '-Utestallowed\ account%$DC_PASSWORD', '--workgroup=$DOMAIN'], modname="samba4.rpc.echo.testallowed")
    plansmbtorture4testsuite('rpc.echo', "%s:local" % env, ['ncacn_np:$SERVER', "-k", "no", '-Utestdenied%$DC_PASSWORD', '--workgroup=$DOMAIN'], modname="samba4.rpc.echo.testdenied")
    plantestsuite("samba4.blackbox.smbclient(%s:local)" % env, "%s:local" % env, [os.path.join(samba4srcdir, "utils/tests/test_smbclient.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$DOMAIN', binpath('smbclient')])

planpythontestsuite("rodc:local", "samba.tests.samba_tool.rodc")

plantestsuite("samba.blackbox.rpcclient_samlogon", "rodc:local", [os.path.join(samba3srcdir, "script/tests/test_rpcclient_samlogon.sh"),
                                                                  "$DC_USERNAME", "$DC_PASSWORD", "ncacn_np:$SERVER", configuration])

plantestsuite("samba.blackbox.rpcclient_samlogon_testallowed", "rodc:local", [os.path.join(samba3srcdir, "script/tests/test_rpcclient_samlogon.sh"),
                                                                              "testallowed\ account", "$DC_PASSWORD", "ncacn_np:$SERVER", configuration])

plantestsuite("samba.blackbox.rpcclient_samlogon_testdenied", "rodc:local", [os.path.join(samba3srcdir, "script/tests/test_rpcclient_samlogon.sh"),
                                                                             "testdenied", "$DC_PASSWORD", "ncacn_np:$SERVER", configuration])


# Test renaming the DC
plantestsuite("samba4.blackbox.renamedc.sh", "none", ["PYTHON=%s" % python, os.path.join(bbdir, "renamedc.sh"), '$PREFIX/provision'])

# DRS python tests
# Note that $DC_SERVER is the PDC (e.g. ad_dc_ntvfs) and $SERVER is
# the 2nd DC (e.g. vampire_dc).

env = 'vampire_dc'
planoldpythontestsuite(env, "ridalloc_exop",
                       extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                       name="samba4.drs.ridalloc_exop.python(%s)" % env,
                       environ={'DC1': "$DC_SERVER", 'DC2': '$SERVER'},
                       extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

# This test can pollute the environment a little by creating and
# deleting DCs which can get into the replication state for a while.
#
# The setting of DC1 to $DC_SERVER means that it will join towards and
# operate on schema_dc.  This matters most when running
# test_samba_tool_replicate_local as this sets up a full temp DC and
# does new replication to it, which can show up in the replication
# topology.
#
# That is why this test is run on the isolated environment and not on
# those connected with ad_dc (vampiredc/promoteddc)

env = 'schema_pair_dc'
planoldpythontestsuite("%s:local" % env, "samba_tool_drs",
                       extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                       name="samba4.drs.samba_tool_drs.python(%s)" % env,
                       environ={'DC1': '$DC_SERVER', 'DC2': '$SERVER'},
                       extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
planoldpythontestsuite(env, "getnc_schema",
                       extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                       name="samba4.drs.getnc_schema.python(%s)" % env,
                       environ={'DC1': "$DC_SERVER", 'DC2': '$SERVER',
                                "PLEASE_BREAK_MY_WINDOWS": "1"},
                       extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

# This test can be sensitive to the DC joins and replications don in
# "samba_tool_drs" so run this is run against scheam_pair_dc/schema_dc
# not the set of environments connected with ad_dc.

# This will show the replication state of ad_dc
planoldpythontestsuite("promoted_dc:local", "samba_tool_drs_showrepl",
                       extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                       name="samba4.drs.samba_tool_drs_showrepl.python(%s)" % env,
                       environ={'DC1': '$DC_SERVER', 'DC2': '$SERVER'},
                       extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

for env in ['vampire_dc', 'promoted_dc']:
    planoldpythontestsuite("%s:local" % env, "replica_sync",
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           name="samba4.drs.replica_sync.python(%s)" % env,
                           environ={'DC1': '$DC_SERVER', 'DC2': '$SERVER'},
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
    planoldpythontestsuite(env, "delete_object",
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           name="samba4.drs.delete_object.python(%s)" % env,
                           environ={'DC1': '$DC_SERVER', 'DC2': '$SERVER'},
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
    planoldpythontestsuite(env, "fsmo",
                           name="samba4.drs.fsmo.python(%s)" % env,
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           environ={'DC1': "$DC_SERVER", 'DC2': '$SERVER'},
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
    planoldpythontestsuite(env, "repl_secdesc",
                           name="samba4.drs.repl_secdesc.python(%s)" % env,
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           environ={'DC1': "$DC_SERVER", 'DC2': '$SERVER'},
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
    planoldpythontestsuite(env, "repl_move",
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           name="samba4.drs.repl_move.python(%s)" % env,
                           environ={'DC1': "$DC_SERVER", 'DC2': '$SERVER'},
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
    planoldpythontestsuite(env, "getnc_exop",
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           name="samba4.drs.getnc_exop.python(%s)" % env,
                           environ={'DC1': "$DC_SERVER", 'DC2': '$SERVER'},
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
    planoldpythontestsuite(env, "getnc_unpriv",
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           name="samba4.drs.getnc_unpriv.python(%s)" % env,
                           environ={'DC1': "$DC_SERVER", 'DC2': '$SERVER'},
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
    planoldpythontestsuite(env, "linked_attributes_drs",
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           name="samba4.drs.linked_attributes_drs.python(%s)" % env,
                           environ={'DC1': "$DC_SERVER", 'DC2': '$SERVER'},
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
    planoldpythontestsuite(env, "link_conflicts",
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           name="samba4.drs.link_conflicts.python(%s)" % env,
                           environ={'DC1': "$DC_SERVER", 'DC2': '$SERVER'},
			   extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

for env in ['vampire_dc', 'promoted_dc', 'vampire_2000_dc']:
    planoldpythontestsuite(env, "repl_schema",
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           name="samba4.drs.repl_schema.python(%s)" % env,
                           environ={'DC1': "$DC_SERVER", 'DC2': '$SERVER'},
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

# A side-effect of the getncchanges tests is that they will create hundreds of
# tombstone objects, so run them last to avoid interferring with (and slowing
# down) the other DRS tests
for env in ['vampire_dc', 'promoted_dc']:
    planoldpythontestsuite(env, "getncchanges",
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           name="samba4.drs.getncchanges.python(%s)" % env,
                           environ={'DC1': "$DC_SERVER", 'DC2': '$SERVER'},
			   extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

for env in ['ad_dc_ntvfs']:
    planoldpythontestsuite(env, "repl_rodc",
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           name="samba4.drs.repl_rodc.python(%s)" % env,
                           environ={'DC1': "$DC_SERVER", 'DC2': '$DC_SERVER'},
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])
    planoldpythontestsuite(env, "cracknames",
                           extra_path=[os.path.join(samba4srcdir, 'torture/drs/python')],
                           name="samba4.drs.cracknames.python(%s)" % env,
                           environ={'DC1': "$DC_SERVER", 'DC2': '$DC_SERVER'},
                           extra_args=['-U$DOMAIN/$DC_USERNAME%$DC_PASSWORD'])

planoldpythontestsuite("chgdcpass:local", "samba.tests.blackbox.samba_dnsupdate",
                       environ={'DNS_SERVER_IP': '$SERVER_IP'})

for env in ["ad_dc_ntvfs", "s4member", "rodc", "promoted_dc", "ad_dc", "ad_member"]:
    plantestsuite("samba.blackbox.wbinfo(%s:local)" % env, "%s:local" % env, [os.path.join(samba4srcdir, "../nsswitch/tests/test_wbinfo.sh"), '$DOMAIN', '$DC_USERNAME', '$DC_PASSWORD', env])

#
# KDC Tests
#

# This test is for users cached at the RODC
plansmbtorture4testsuite('krb5.kdc', "rodc", ['ncacn_np:$SERVER_IP', "-k", "yes", '-Utestdenied%$PASSWORD',
                                              '--workgroup=$DOMAIN', '--realm=$REALM',
                                              '--option=torture:krb5-upn=testdenied_upn@$REALM.upn',
                                              '--option=torture:expect_rodc=true'],
                         "samba4.krb5.kdc with account DENIED permission to replicate to an RODC")
plansmbtorture4testsuite('krb5.kdc', "rodc", ['ncacn_np:$SERVER_IP', "-k", "yes", '-Utestallowed\ account%$PASSWORD',
                                              '--workgroup=$DOMAIN', '--realm=$REALM',
                                              '--option=torture:expect_machine_account=true',
                                              '--option=torture:krb5-upn=testallowed\ upn@$REALM',
                                              '--option=torture:krb5-hostname=testallowed',
                                              '--option=torture:expect_rodc=true',
                                              '--option=torture:expect_cached_at_rodc=true'],
                         "samba4.krb5.kdc with account ALLOWED permission to replicate to an RODC")

# This ensures we have correct behaviour on a server that is not not the PDC emulator
env = "promoted_dc"
plansmbtorture4testsuite('krb5.kdc', env, ['ncacn_np:$SERVER_IP', "-k", "yes", '-U$USERNAME%$PASSWORD', '--workgroup=$DOMAIN', '--realm=$REALM'],
                         "samba4.krb5.kdc with specified account")
plansmbtorture4testsuite('krb5.kdc', env, ['ncacn_np:$SERVER_IP', "-k", "yes", '-Utestupnspn%$PASSWORD', '--workgroup=$DOMAIN', '--realm=$REALM',
                                           '--option=torture:expect_machine_account=true',
                                           '--option=torture:krb5-upn=http/testupnspn.$DNSNAME@$REALM',
                                           '--option=torture:krb5-hostname=testupnspn.$DNSNAME',
                                           '--option=torture:krb5-service=http'],
                         "samba4.krb5.kdc with account having identical UPN and SPN")
for env in ["fl2008r2dc", "fl2003dc"]:
    planoldpythontestsuite(env, "samba.tests.krb5.as_req_tests",
                           environ={
                               'ADMIN_USERNAME': '$USERNAME',
                               'ADMIN_PASSWORD': '$PASSWORD',
                               'STRICT_CHECKING': '0',
                               'FAST_SUPPORT': have_fast_support,
                               'TKT_SIG_SUPPORT': tkt_sig_support
                           })

planoldpythontestsuite('fl2008r2dc', 'samba.tests.krb5.salt_tests',
                       environ={
                           'ADMIN_USERNAME': '$USERNAME',
                           'ADMIN_PASSWORD': '$PASSWORD',
                           'STRICT_CHECKING': '0',
                           'FAST_SUPPORT': have_fast_support,
                           'TKT_SIG_SUPPORT': tkt_sig_support
                       })

for env in ["rodc", "promoted_dc", "fl2000dc", "fl2008r2dc"]:
    if env == "rodc":
        # The machine account is cached at the RODC, as it is the local account
        extra_options = ['--option=torture:expect_rodc=true', '--option=torture:expect_cached_at_rodc=true']
    else:
        extra_options = []

    plansmbtorture4testsuite('krb5.kdc', "%s:local" % env, ['ncacn_np:$SERVER_IP', "-k", "yes", '-P',
                                                            '--workgroup=$DOMAIN', '--realm=$REALM',
                                                            '--option=torture:krb5-hostname=$SERVER',
                                                            '--option=torture:run_removedollar_test=true',
                                                            '--option=torture:expect_machine_account=true'] + extra_options,
                             "samba4.krb5.kdc with machine account")

planpythontestsuite("ad_dc", "samba.tests.krb5.as_canonicalization_tests",
                       environ={
                           'ADMIN_USERNAME': '$USERNAME',
                           'ADMIN_PASSWORD': '$PASSWORD',
                           'FAST_SUPPORT': have_fast_support,
                           'TKT_SIG_SUPPORT': tkt_sig_support
                       })
planpythontestsuite("ad_dc", "samba.tests.krb5.compatability_tests",
                    environ={
                        'ADMIN_USERNAME': '$USERNAME',
                        'ADMIN_PASSWORD': '$PASSWORD',
                        'STRICT_CHECKING': '0',
                        'FAST_SUPPORT': have_fast_support,
                        'TKT_SIG_SUPPORT': tkt_sig_support
                    })
planpythontestsuite("ad_dc", "samba.tests.krb5.kdc_tests",
                    environ={'FAST_SUPPORT': have_fast_support,
                             'TKT_SIG_SUPPORT': tkt_sig_support})
planpythontestsuite(
    "ad_dc",
    "samba.tests.krb5.kdc_tgs_tests",
    environ={
        'ADMIN_USERNAME': '$USERNAME',
        'ADMIN_PASSWORD': '$PASSWORD',
        'STRICT_CHECKING': '0',
        'FAST_SUPPORT': have_fast_support,
        'TKT_SIG_SUPPORT': tkt_sig_support
    })
planpythontestsuite(
    "ad_dc",
    "samba.tests.krb5.fast_tests",
    environ={
        'ADMIN_USERNAME': '$USERNAME',
        'ADMIN_PASSWORD': '$PASSWORD',
        'STRICT_CHECKING': '0',
        'FAST_SUPPORT': have_fast_support,
        'TKT_SIG_SUPPORT': tkt_sig_support
    })
planpythontestsuite(
    "ad_dc",
    "samba.tests.krb5.ms_kile_client_principal_lookup_tests",
    environ={
        'ADMIN_USERNAME': '$USERNAME',
        'ADMIN_PASSWORD': '$PASSWORD',
        'STRICT_CHECKING': '0',
        'FAST_SUPPORT': have_fast_support,
        'TKT_SIG_SUPPORT': tkt_sig_support
    })

for env in [
        'vampire_dc',
        'promoted_dc']:
    planoldpythontestsuite(env, "samba.tests.kcc",
                           name="samba.tests.kcc",
                           environ={'TEST_SERVER': '$SERVER', 'TEST_USERNAME': '$USERNAME',
                                    'TEST_PASSWORD': '$PASSWORD',
                                    'TEST_ENV': env
                                    },
                           extra_path=[os.path.join(srcdir(), "samba/python"), ])
    planpythontestsuite(env, "samba.tests.samba_tool.visualize_drs")

planpythontestsuite("ad_dc_default:local", "samba.tests.kcc.kcc_utils")

for env in ["simpleserver", "fileserver", "nt4_dc", "ad_dc", "ad_dc_ntvfs",
            "ad_member", "offlinebackupdc", "restoredc", "renamedc", "labdc", 'schema_pair_dc']:
    planoldpythontestsuite(env, "netlogonsvc",
                           extra_path=[os.path.join(srcdir(), 'python/samba/tests')],
                           name="samba.tests.netlogonsvc.python(%s)" % env)

for env in ["ktest", "ad_member", "ad_dc_no_ntlm"]:
    planoldpythontestsuite(env, "ntlmdisabled",
                           extra_path=[os.path.join(srcdir(), 'python/samba/tests')],
                           name="samba.tests.ntlmdisabled.python(%s)" % env)

# Demote the vampire DC, it must be the last test each DC, before the dbcheck
for env in ['vampire_dc', 'promoted_dc', 'rodc']:
    planoldpythontestsuite(env, "samba.tests.samba_tool.demote",
                           name="samba.tests.samba_tool.demote",
                           environ={
                               'CONFIGFILE': '$PREFIX/%s/etc/smb.conf' % env
                           },
                           extra_args=['-U"$USERNAME%$PASSWORD"'],
                           extra_path=[os.path.join(srcdir(), "samba/python")]
                           )
# TODO: Verifying the databases really should be a part of the
# environment teardown.
# check the databases are all OK. PLEASE LEAVE THIS AS THE LAST TEST
for env in ["ad_dc_ntvfs", "ad_dc", "fl2000dc", "fl2003dc", "fl2008r2dc",
            'vampire_dc', 'promoted_dc', 'backupfromdc', 'restoredc',
            'renamedc', 'offlinebackupdc', 'labdc']:
    plantestsuite("samba4.blackbox.dbcheck(%s)" % env, env + ":local", ["PYTHON=%s" % python, os.path.join(bbdir, "dbcheck.sh"), '$PREFIX/provision', configuration])

#
# Tests to verify bug 13653 https://bugzilla.samba.org/show_bug.cgi?id=13653
# ad_dc has an lmdb backend, ad_dc_ntvfs has a tdb backend.
#
planoldpythontestsuite("ad_dc_ntvfs:local",
                       "samba.tests.blackbox.bug13653",
                       extra_args=['-U"$USERNAME%$PASSWORD"'],
                       environ={'TEST_ENV': 'ad_dc_ntvfs'})
planoldpythontestsuite("ad_dc:local",
                       "samba.tests.blackbox.bug13653",
                       extra_args=['-U"$USERNAME%$PASSWORD"'],
                       environ={'TEST_ENV': 'ad_dc'})
# cmocka tests not requiring a specific environment
#
plantestsuite("samba4.dsdb.samdb.ldb_modules.unique_object_sids", "none",
              [os.path.join(bindir(), "test_unique_object_sids")])
plantestsuite("samba4.dsdb.samdb.ldb_modules.encrypted_secrets.tdb", "none",
              [os.path.join(bindir(), "test_encrypted_secrets_tdb")])
plantestsuite("samba4.dsdb.samdb.ldb_modules.encrypted_secrets.mdb", "none",
              [os.path.join(bindir(), "test_encrypted_secrets_mdb")])
plantestsuite("lib.audit_logging.audit_logging", "none",
              [os.path.join(bindir(), "audit_logging_test")])
plantestsuite("lib.audit_logging.audit_logging.errors", "none",
              [os.path.join(bindir(), "audit_logging_error_test")])
plantestsuite("samba4.dsdb.samdb.ldb_modules.audit_util", "none",
              [os.path.join(bindir(), "test_audit_util")])
plantestsuite("samba4.dsdb.samdb.ldb_modules.audit_log", "none",
              [os.path.join(bindir(), "test_audit_log")])
plantestsuite("samba4.dsdb.samdb.ldb_modules.audit_log.errors", "none",
              [os.path.join(bindir(), "test_audit_log_errors")])
plantestsuite("samba4.dsdb.samdb.ldb_modules.group_audit", "none",
              [os.path.join(bindir(), "test_group_audit")])
plantestsuite("samba4.dsdb.samdb.ldb_modules.group_audit.errors", "none",
              [os.path.join(bindir(), "test_group_audit_errors")])
plantestsuite("samba4.dcerpc.dnsserver.dnsutils", "none",
              [os.path.join(bindir(), "test_rpc_dns_server_dnsutils")])
plantestsuite("libcli.drsuapi.repl_decrypt", "none",
              [os.path.join(bindir(), "test_repl_decrypt")])
plantestsuite("librpc.ndr.ndr_string", "none",
              [os.path.join(bindir(), "test_ndr_string")])
plantestsuite("librpc.ndr.ndr", "none",
              [os.path.join(bindir(), "test_ndr")])
plantestsuite("librpc.ndr.ndr_macros", "none",
              [os.path.join(bindir(), "test_ndr_macros")])
plantestsuite("librpc.ndr.ndr_dns_nbt", "none",
              [os.path.join(bindir(), "test_ndr_dns_nbt")])
plantestsuite("libcli.ldap.ldap_message", "none",
              [os.path.join(bindir(), "test_ldap_message")])

# process restart and limit tests, these break the environment so need to run
# in their own specific environment
planoldpythontestsuite("preforkrestartdc:local",
                       "samba.tests.prefork_restart",
                       extra_path=[
                           os.path.join(srcdir(), 'python/samba/tests')],
                       extra_args=['-U"$USERNAME%$PASSWORD"'],
                       name="samba.tests.prefork_restart")
planoldpythontestsuite("preforkrestartdc:local",
                       "samba.tests.blackbox.smbcontrol_process",
                       extra_path=[
                           os.path.join(srcdir(), 'python/samba/tests')],
                       extra_args=['-U"$USERNAME%$PASSWORD"'],
                       name="samba.tests.blackbox.smbcontrol_process")
planoldpythontestsuite("proclimitdc",
                       "samba.tests.process_limits",
                       extra_path=[
                           os.path.join(srcdir(), 'python/samba/tests')],
                       extra_args=['-U"$USERNAME%$PASSWORD"'],
                       name="samba.tests.process_limits")

planoldpythontestsuite("none", "samba.tests.usage")
planpythontestsuite("fileserver", "samba.tests.dcerpc.mdssvc")
