#!/usr/bin/python
# This script generates a list of testsuites that should be run as part of
# the Samba 3 test suite.

# The output of this script is parsed by selftest.pl, which then decides
# which of the tests to actually run. It will, for example, skip all tests
# listed in selftest/skip or only run a subset during "make quicktest".

# The idea is that this script outputs all of the tests of Samba 3, not
# just those that are known to pass, and list those that should be skipped
# or are known to fail in selftest/skip or selftest/samba3-knownfail. This makes it
# very easy to see what functionality is still missing in Samba 3 and makes
# it possible to run the testsuite against other servers, such as Samba 4 or
# Windows that have a different set of features.

# The syntax for a testsuite is "-- TEST --" on a single line, followed
# by the name of the test, the environment it needs and the command to run, all
# three separated by newlines. All other lines in the output are considered
# comments.

import os, sys
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "../../selftest")))
import selftesthelpers
from selftesthelpers import *
smbtorture4_options.extend([
   '--option=torture:sharedelay=100000',
   '--option=torture:writetimeupdatedelay=500000',
   ])

def plansmbtorture4testsuite(name, env, options, description=''):
    if description == '':
        modname = "samba3.%s" % (name, )
    else:
        modname = "samba3.%s %s" % (name, description)

    selftesthelpers.plansmbtorture4testsuite(
        name, env, options, target='samba3', modname=modname)


plantestsuite("samba3.blackbox.success", "s3dc:local", [os.path.join(samba3srcdir, "script/tests/test_success.sh")])
plantestsuite("samba3.blackbox.failure", "s3dc:local", [os.path.join(samba3srcdir, "script/tests/test_failure.sh")])

plantestsuite("samba3.local_s3", "s3dc:local", [os.path.join(samba3srcdir, "script/tests/test_local_s3.sh")])

plantestsuite("samba3.blackbox.registry.upgrade", "s3dc:local", [os.path.join(samba3srcdir, "script/tests/test_registry_upgrade.sh"), net, dbwrap_tool])

tests = ["FDPASS", "LOCK1", "LOCK2", "LOCK3", "LOCK4", "LOCK5", "LOCK6", "LOCK7", "LOCK9",
        "UNLINK", "BROWSE", "ATTR", "TRANS2", "TORTURE",
        "OPLOCK1", "OPLOCK2", "OPLOCK4", "STREAMERROR",
        "DIR", "DIR1", "DIR-CREATETIME", "TCON", "TCONDEV", "RW1", "RW2", "RW3", "LARGE_READX", "RW-SIGNING",
        "OPEN", "XCOPY", "RENAME", "DELETE", "DELETE-LN", "PROPERTIES", "W2K",
        "TCON2", "IOCTL", "CHKPATH", "FDSESS", "CHAIN1", "CHAIN2",
        "CHAIN3",
        "GETADDRINFO", "UID-REGRESSION-TEST", "SHORTNAME-TEST",
        "CASE-INSENSITIVE-CREATE", "SMB2-BASIC", "NTTRANS-FSCTL", "SMB2-NEGPROT",
        "SMB2-SESSION-REAUTH", "SMB2-SESSION-RECONNECT",
        "CLEANUP1",
        "CLEANUP2",
        "CLEANUP4",
        "BAD-NBT-SESSION"]

for t in tests:
    plantestsuite("samba3.smbtorture_s3.plain(s3dc).%s" % t, "s3dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
    plantestsuite("samba3.smbtorture_s3.crypt_client(s3dc).%s" % t, "s3dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "-e", "-l $LOCAL_PATH"])
    if t == "TORTURE":
        # this is a negative test to verify that the server rejects
        # access without encryption
        plantestsuite("samba3.smbtorture_s3.crypt_server(s3dc).%s" % t, "s3dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmpenc', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
    plantestsuite("samba3.smbtorture_s3.plain(dc).%s" % t, "dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

# non-crypt only

tests = ["OPLOCK-CANCEL"]
for t in tests:
    plantestsuite("samba3.smbtorture_s3.plain(s3dc).%s" % t, "s3dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

tests = ["RW1", "RW2", "RW3"]
for t in tests:
    plantestsuite("samba3.smbtorture_s3.vfs_aio_fork(simpleserver).%s" % t, "simpleserver", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/vfs_aio_fork', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

posix_tests = ["POSIX", "POSIX-APPEND"]

for t in posix_tests:
    plantestsuite("samba3.smbtorture_s3.plain(s3dc).%s" % t, "s3dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/posix_share', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
    plantestsuite("samba3.smbtorture_s3.crypt(s3dc).%s" % t, "s3dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/posix_share', '$USERNAME', '$PASSWORD', smbtorture3, "-e", "-l $LOCAL_PATH"])
    plantestsuite("samba3.smbtorture_s3.plain(dc).%s" % t, "dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/posix_share', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

env = "s3dc:local"
t = "CLEANUP3"
plantestsuite("samba3.smbtorture_s3.plain(%s).%s" % (env, t), env, [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', binpath('smbtorture3'), "", "-l $LOCAL_PATH"])

local_tests = [
    "LOCAL-SUBSTITUTE",
    "LOCAL-GENCACHE",
    "LOCAL-TALLOC-DICT",
    "LOCAL-BASE64",
    "LOCAL-RBTREE",
    "LOCAL-MEMCACHE",
    "LOCAL-STREAM-NAME",
    "LOCAL-WBCLIENT",
    "LOCAL-string_to_sid",
    "LOCAL-sid_to_string",
    "LOCAL-binary_to_sid",
    "LOCAL-DBTRANS",
    "LOCAL-TEVENT-SELECT",
    "LOCAL-CONVERT-STRING",
    "LOCAL-CONV-AUTH-INFO",
    "LOCAL-IDMAP-TDB-COMMON",
    "LOCAL-MESSAGING-READ1",
    "LOCAL-MESSAGING-READ2",
    "LOCAL-MESSAGING-READ3",
    "LOCAL-MESSAGING-READ4",
    "LOCAL-MESSAGING-FDPASS1",
    "LOCAL-MESSAGING-FDPASS2",
    "LOCAL-hex_encode_buf",
    "LOCAL-sprintf_append",
    "LOCAL-remove_duplicate_addrs2"]

for t in local_tests:
    plantestsuite("samba3.smbtorture_s3.%s" % t, "none", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//foo/bar', '""', '""', smbtorture3, ""])

plantestsuite("samba.vfstest.stream_depot", "s3dc:local", [os.path.join(samba3srcdir, "script/tests/stream-depot/run.sh"), binpath("vfstest"), "$PREFIX", configuration])
plantestsuite("samba.vfstest.xattr-tdb-1", "s3dc:local", [os.path.join(samba3srcdir, "script/tests/xattr-tdb-1/run.sh"), binpath("vfstest"), "$PREFIX", configuration])
plantestsuite("samba.vfstest.acl", "s3dc:local", [os.path.join(samba3srcdir, "script/tests/vfstest-acl/run.sh"), binpath("vfstest"), "$PREFIX", configuration])
plantestsuite("samba.vfstest.catia", "s3dc:local", [os.path.join(samba3srcdir, "script/tests/vfstest-catia/run.sh"), binpath("vfstest"), "$PREFIX", configuration])

for options in ["--option=clientusespnego=no", " --option=clientntlmv2auth=no --option=clientlanmanauth=yes --max-protocol=LANMAN2", ""]:
    env = "s3dc"
    plantestsuite("samba3.blackbox.smbclient_auth.plain (%s) %s" % (env, options), env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, options])

for env in ["s3dc", "member", "s3member", "dc", "s4member"]:
    plantestsuite("samba3.blackbox.smbclient_machine_auth.plain (%s:local)" % env, "%s:local" % env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_machine_auth.sh"), '$SERVER', smbclient3, configuration])

for env in ["s3dc", "member", "s3member"]:
    plantestsuite("samba3.blackbox.smbclient_auth.plain (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration])
    plantestsuite("samba3.blackbox.smbclient_auth.plain (%s) member creds" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$SERVER/$USERNAME', '$PASSWORD', smbclient3, configuration])

for env in ["member", "s3member"]:
    plantestsuite("samba3.blackbox.net_cred_change.(%s:local)" % env, "%s:local" % env, [os.path.join(samba3srcdir, "script/tests/test_net_cred_change.sh"), configuration])

env = "s3member"
t = "--krb5auth=$DOMAIN/$DC_USERNAME%$DC_PASSWORD"
plantestsuite("samba3.wbinfo_simple.(%s:local).%s" % (env, t), "%s:local" % env, [os.path.join(srcdir(), "nsswitch/tests/test_wbinfo_simple.sh"), t])

plantestsuite("samba3.ntlm_auth.krb5(ktest:local) old ccache", "ktest:local", [os.path.join(samba3srcdir, "script/tests/test_ntlm_auth_krb5.sh"), valgrindify(python), samba3srcdir, ntlm_auth3, '$PREFIX/ktest/krb5_ccache-2', '$SERVER', configuration])

plantestsuite("samba3.ntlm_auth.krb5(ktest:local)", "ktest:local", [os.path.join(samba3srcdir, "script/tests/test_ntlm_auth_krb5.sh"), valgrindify(python), samba3srcdir, ntlm_auth3, '$PREFIX/ktest/krb5_ccache-3', '$SERVER', configuration])


for env in ["maptoguest", "simpleserver"]:
    plantestsuite("samba3.blackbox.smbclient_auth.plain (%s) local creds" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', smbclient3, configuration + " --option=clientntlmv2auth=no --option=clientlanmanauth=yes"])

env = "maptoguest"
plantestsuite("samba3.blackbox.smbclient_auth.plain (%s) bad username" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', 'notmy$USERNAME', '$PASSWORD', smbclient3, configuration + " --option=clientntlmv2auth=no --option=clientlanmanauth=yes"])

# plain
for env in ["s3dc"]:
    plantestsuite("samba3.blackbox.smbclient_s3.plain (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$DC_USERNAME', '$DC_PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration])

for env in ["member", "s3member"]:
    plantestsuite("samba3.blackbox.smbclient_s3.plain (%s) member creds" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$SERVER', '$SERVER/$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration])

for env in ["s3dc"]:
    plantestsuite("samba3.blackbox.smbclient_s3.sign (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$DC_USERNAME', '$DC_PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "--signing=required"])

for env in ["member", "s3member"]:
    plantestsuite("samba3.blackbox.smbclient_s3.sign (%s) member creds" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$SERVER', '$SERVER/$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "--signing=required"])

for env in ["s3dc"]:
    # encrypted
    plantestsuite("samba3.blackbox.smbclient_s3.crypt (%s)" % env, env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "-e"])


    #
    # tar command tests
    #

    # find config.h
    try:
        config_h = os.environ["CONFIG_H"]
    except KeyError:
        config_h = os.path.join(samba4bindir, "default/include/config.h")

    # see if libarchive is supported
    f = open(config_h, 'r')
    try:
        have_libarchive = ("HAVE_LIBARCHIVE 1" in f.read())
    finally:
        f.close()

    # tar command enabled only if built with libarchive
    if have_libarchive:
        # Test smbclient/tarmode
        plantestsuite("samba3.blackbox.smbclient_tarmode (%s)" % env, env,
                      [os.path.join(samba3srcdir, "script/tests/test_smbclient_tarmode.sh"),
                       '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD',
                       '$LOCAL_PATH', '$PREFIX', smbclient3, configuration])

        # Test suite for new smbclient/tar with libarchive (GSoC 13)
        plantestsuite("samba3.blackbox.smbclient_tar (%s)" % env, env,
                      [os.path.join(samba3srcdir, "script/tests/test_smbclient_tarmode.pl"),
                       '-n', '$SERVER', '-i', '$SERVER_IP', '-s', 'tmp',
                       '-u', '$USERNAME', '-p', '$PASSWORD', '-l', '$LOCAL_PATH',
                       '-d', '$PREFIX', '-b', smbclient3,
                       '--subunit', '--', configuration])

#TODO encrypted against member, with member creds, and with DC creds
plantestsuite("samba3.blackbox.net.misc", "s3dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_misc.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration])
plantestsuite("samba3.blackbox.net.local.registry", "s3dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration])
plantestsuite("samba3.blackbox.net.registry.check", "s3dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry_check.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, dbwrap_tool])
plantestsuite("samba3.blackbox.net.rpc.registry", "s3dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, 'rpc'])

plantestsuite("samba3.blackbox.net.local.registry.roundtrip", "s3dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry_roundtrip.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration])
plantestsuite("samba3.blackbox.net.rpc.registry.roundtrip", "s3dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry_roundtrip.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, 'rpc'])

plantestsuite("samba3.blackbox.net.local.conf", "s3dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_conf.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration])
plantestsuite("samba3.blackbox.net.rpc.conf", "s3dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_conf.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, 'rpc'])


plantestsuite("samba3.blackbox.testparm", "s3dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_testparm_s3.sh"),
               "$LOCAL_PATH"])

plantestsuite(
    "samba3.pthreadpool", "s3dc",
    [os.path.join(samba3srcdir, "script/tests/test_pthreadpool.sh")])

#smbtorture4 tests

base = ["base.attr", "base.charset", "base.chkpath", "base.defer_open", "base.delaywrite", "base.delete",
        "base.deny1", "base.deny2", "base.deny3", "base.denydos", "base.dir1", "base.dir2",
        "base.disconnect", "base.fdpass", "base.lock",
        "base.mangle", "base.negnowait", "base.ntdeny1",
        "base.ntdeny2", "base.open", "base.openattr", "base.properties", "base.rename", "base.rw1",
        "base.secleak", "base.tcon", "base.tcondev", "base.trans2", "base.unlink", "base.vuid",
        "base.xcopy", "base.samba3error"]

raw = ["raw.acls", "raw.chkpath", "raw.close", "raw.composite", "raw.context", "raw.eas",
       "raw.ioctl", "raw.lock", "raw.mkdir", "raw.mux", "raw.notify", "raw.open", "raw.oplock",
       "raw.qfileinfo", "raw.qfsinfo", "raw.read", "raw.rename", "raw.search", "raw.seek",
       "raw.sfileinfo.base", "raw.sfileinfo.bug", "raw.streams", "raw.unlink", "raw.write",
       "raw.samba3hide", "raw.samba3badpath", "raw.sfileinfo.rename", "raw.session",
       "raw.samba3caseinsensitive", "raw.samba3posixtimedlock",
       "raw.samba3rootdirfid", "raw.sfileinfo.end-of-file",
       "raw.bench-oplock", "raw.bench-lock", "raw.bench-open", "raw.bench-tcon",
       "raw.samba3checkfsp", "raw.samba3closeerr", "raw.samba3oplocklogoff", "raw.samba3badnameblob"]

smb2 = smbtorture4_testsuites("smb2.")

rpc = ["rpc.authcontext", "rpc.samba3.bind", "rpc.samba3.srvsvc", "rpc.samba3.sharesec",
       "rpc.samba3.spoolss", "rpc.samba3.wkssvc", "rpc.samba3.winreg",
       "rpc.samba3.getaliasmembership-0",
       "rpc.samba3.netlogon", "rpc.samba3.sessionkey", "rpc.samba3.getusername",
       "rpc.samba3.smb1-pipe-name", "rpc.samba3.smb2-pipe-name",
       "rpc.samba3.smb-reauth1", "rpc.samba3.smb-reauth2",
       "rpc.svcctl", "rpc.ntsvcs", "rpc.winreg", "rpc.eventlog",
       "rpc.spoolss.printserver", "rpc.spoolss.win", "rpc.spoolss.notify", "rpc.spoolss.printer",
       "rpc.spoolss.driver",
       "rpc.lsa", "rpc.lsa-getuser", "rpc.lsa.lookupsids", "rpc.lsa.lookupnames",
       "rpc.lsa.privileges", "rpc.lsa.secrets",
       "rpc.samr", "rpc.samr.users", "rpc.samr.users.privileges", "rpc.samr.passwords",
       "rpc.samr.passwords.pwdlastset", "rpc.samr.passwords.lockout", "rpc.samr.passwords.badpwdcount", "rpc.samr.large-dc", "rpc.samr.machine.auth",
       "rpc.samr.priv", "rpc.samr.passwords.validate",
       "rpc.netlogon.admin",
       "rpc.schannel", "rpc.schannel2", "rpc.bench-schannel1", "rpc.join", "rpc.bind"]

local = ["local.ndr"]

idmap = [ "idmap.rfc2307" ]

rap = ["rap.basic", "rap.rpc", "rap.printing", "rap.sam"]

unix = ["unix.info2", "unix.whoami"]

nbt = ["nbt.dgram" ]

libsmbclient = ["libsmbclient"]

vfs = ["vfs.fruit"]

tests= base + raw + smb2 + rpc + unix + local + rap + nbt + libsmbclient + idmap + vfs

for t in tests:
    if t == "base.delaywrite":
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD -k yes --maximum-runtime=900')
    elif t == "rap.sam":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=doscharset=ISO-8859-1')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=doscharset=ISO-8859-1')
    elif t == "winbind.pac":
        plansmbtorture4testsuite(t, "s3member:local", '//$SERVER/tmp --realm=$REALM --machine-pass --option=torture:addc=$DC_SERVER', description="machine account")
    elif t == "unix.whoami":
        plansmbtorture4testsuite(t, "member:local", '//$SERVER/tmp --machine-pass', description="machine account")
        plansmbtorture4testsuite(t, "s3member:local", '//$SERVER/tmp --machine-pass --option=torture:addc=$DC_SERVER', description="machine account")
        for env in ["s3dc", "member"]:
            plansmbtorture4testsuite(t, env, '//$SERVER/tmp -U$DC_USERNAME%$DC_PASSWORD')
            plansmbtorture4testsuite(t, env, '//$SERVER/tmpguest -U%', description='anonymous connection')
        for env in ["plugin_s4_dc", "s3member"]:
            plansmbtorture4testsuite(t, env, '//$SERVER/tmp -U$DC_USERNAME@$REALM%$DC_PASSWORD --option=torture:addc=$DC_SERVER')
            plansmbtorture4testsuite(t, env, '//$SERVER/tmp -k yes -U$DC_USERNAME@$REALM%$DC_PASSWORD --option=torture:addc=$DC_SERVER', description='kerberos connection')
            plansmbtorture4testsuite(t, env, '//$SERVER/tmpguest -U% --option=torture:addc=$DC_SERVER', description='anonymous connection')
    elif t == "raw.samba3posixtimedlock":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmpguest -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/s3dc/share')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER_IP/tmpguest -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/plugin_s4_dc/share')
    elif t == "raw.chkpath":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmpcase -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER_IP/tmpcase -U$USERNAME%$PASSWORD')
    elif t == "raw.samba3hide" or t == "raw.samba3checkfsp" or t ==  "raw.samba3closeerr":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "simpleserver", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "raw.session" or t == "smb2.session":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD', 'plain')
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmpenc -U$USERNAME%$PASSWORD', 'enc')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER/tmp -k no -U$USERNAME%$PASSWORD', 'ntlm')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER/tmp -k yes -U$USERNAME%$PASSWORD', 'krb5')
    elif t == "rpc.lsa":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD', 'over ncacn_np ')
        plansmbtorture4testsuite(t, "s3dc", 'ncacn_ip_tcp:$SERVER_IP -U$USERNAME%$PASSWORD', 'over ncacn_ip_tcp ')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD', 'over ncacn_np ')
        plansmbtorture4testsuite(t, "plugin_s4_dc", 'ncacn_ip_tcp:$SERVER_IP -U$USERNAME%$PASSWORD', 'over ncacn_ip_tcp ')
    elif t == "rpc.samr.passwords.validate":
        plansmbtorture4testsuite(t, "s3dc", 'ncacn_ip_tcp:$SERVER_IP -U$USERNAME%$PASSWORD', 'over ncacn_ip_tcp ')
        plansmbtorture4testsuite(t, "plugin_s4_dc", 'ncacn_ip_tcp:$SERVER_IP -U$USERNAME%$PASSWORD', 'over ncacn_ip_tcp ')
    elif t == "smb2.durable-open" or t == "smb2.durable-v2-open" or t == "smb2.replay":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/durable -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER_IP/durable -U$USERNAME%$PASSWORD')
    elif t == "base.rw1":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/valid-users-tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/write-list-tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "idmap.rfc2307":
        plantestsuite(t, "s3member_rfc2307", [os.path.join(samba3srcdir, "../nsswitch/tests/test_idmap_rfc2307.sh"), '$DOMAIN', 'Administrator', '2000000', '"Domain Users"', '2000001', 'ou=idmap,dc=samba,dc=example,dc=com', '$DC_SERVER', '$DC_USERNAME', '$DC_PASSWORD'])
    elif t == "raw.acls":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/nfs4acl_simple -U$USERNAME%$PASSWORD', description='nfs4acl_xattr-simple')
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/nfs4acl_special -U$USERNAME%$PASSWORD', description='nfs4acl_xattr-special')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER_IP/tmpcase -U$USERNAME%$PASSWORD')
    elif t == "smb2.ioctl":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/fs_specific -U$USERNAME%$PASSWORD', 'fs_specific')
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.lock":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/aio -U$USERNAME%$PASSWORD', 'aio')
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "raw.read":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/aio -U$USERNAME%$PASSWORD', 'aio')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "raw.search":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
# test the dirsort module.
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmpsort -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "vfs.fruit":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=torture:share1=vfs_fruit --option=torture:share2=tmp --option=torture:localdir=$SELFTEST_PREFIX/s3dc/share')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=torture:share1=vfs_fruit --option=torture:share2=tmp --option=torture:localdir=$SELFTEST_PREFIX/plugin_s4_dc/share')
    elif t == "smb2.notify":
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --signing=required')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD --signing=required')
    else:
        plansmbtorture4testsuite(t, "s3dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "plugin_s4_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')


test = 'rpc.lsa.lookupsids'
auth_options = ["", "ntlm", "spnego", "spnego,ntlm" ]
signseal_options = ["", ",connect", ",sign", ",seal"]
endianness_options = ["", ",bigendian"]
for s in signseal_options:
    for e in endianness_options:
        for a in auth_options:
            binding_string = "ncacn_np:$SERVER[%s%s%s]" % (a, s, e)
            options = binding_string + " -U$USERNAME%$PASSWORD"
            plansmbtorture4testsuite(test, "s3dc", options, 'over ncacn_np with [%s%s%s] ' % (a, s, e))
            plantestsuite("samba3.blackbox.rpcclient over ncacn_np with [%s%s%s] " % (a, s, e), "s3dc:local", [os.path.join(samba3srcdir, "script/tests/test_rpcclient.sh"),
                                                             "none", options, configuration])

    # We should try more combinations in future, but this is all
    # the pre-calculated credentials cache supports at the moment
    e = ""
    a = ""
    binding_string = "ncacn_np:$SERVER[%s%s%s]" % (a, s, e)
    options = binding_string + " -k yes --krb5-ccache=$PREFIX/ktest/krb5_ccache-2"
    plansmbtorture4testsuite(test, "ktest", options, 'krb5 with old ccache ncacn_np with [%s%s%s] ' % (a, s, e))

    options = binding_string + " -k yes --krb5-ccache=$PREFIX/ktest/krb5_ccache-3"
    plansmbtorture4testsuite(test, "ktest", options, 'krb5 ncacn_np with [%s%s%s] ' % (a, s, e))

    auth_options2 = ["krb5", "spnego,krb5"]
    for a in auth_options2:
        binding_string = "ncacn_np:$SERVER[%s%s%s]" % (a, s, e)

        plantestsuite("samba3.blackbox.rpcclient krb5 ncacn_np with [%s%s%s] " % (a, s, e), "ktest:local", [os.path.join(samba3srcdir, "script/tests/test_rpcclient.sh"),
                                                                                                                              "$PREFIX/ktest/krb5_ccache-3", binding_string, "-k", configuration])

plantestsuite("samba3.blackbox.rpcclient_samlogon", "s3member:local", [os.path.join(samba3srcdir, "script/tests/test_rpcclient_samlogon.sh"),
								       "$DC_USERNAME", "$DC_PASSWORD", "ncacn_np:$DC_SERVER", configuration])

options_list = ["", "-e"]
for options in options_list:
    plantestsuite("samba3.blackbox.smbclient_krb5 old ccache %s" % options, "ktest:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_krb5.sh"),
                   "$PREFIX/ktest/krb5_ccache-2",
                   smbclient3, "$SERVER", options, configuration])

    plantestsuite("samba3.blackbox.smbclient_krb5 old ccache %s" % options, "ktest:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_krb5.sh"),
                   "$PREFIX/ktest/krb5_ccache-2",
                   smbclient3, "$SERVER", options, configuration])

    plantestsuite("samba3.blackbox.smbclient_large_file %s" % options, "ktest:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_posix_large.sh"),
                   "$PREFIX/ktest/krb5_ccache-3",
                   smbclient3, "$SERVER", "$PREFIX", options, "-k " + configuration])

    plantestsuite("samba3.blackbox.smbclient_posix_large %s krb5" % options, "ktest:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_posix_large.sh"),
                   "$PREFIX/ktest/krb5_ccache-3",
                   smbclient3, "$SERVER", "$PREFIX", options, "-k " + configuration])

    plantestsuite("samba3.blackbox.smbclient_posix_large %s NTLM" % options, "s3dc:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_posix_large.sh"),
                   "none",
                   smbclient3, "$SERVER", "$PREFIX", options, "-U$USERNAME%$PASSWORD " + configuration])

for e in endianness_options:
    for a in auth_options:
        for s in signseal_options:
            binding_string = "ncacn_ip_tcp:$SERVER_IP[%s%s%s]" % (a, s, e)
            options = binding_string + " -U$USERNAME%$PASSWORD"
            plansmbtorture4testsuite(test, "s3dc", options, 'over ncacn_ip_tcp with [%s%s%s] ' % (a, s, e))

plansmbtorture4testsuite('rpc.epmapper', 's3dc:local', 'ncalrpc: -U$USERNAME%$PASSWORD', 'over ncalrpc')
