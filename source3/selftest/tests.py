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

import os
import sys
import re
import platform
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "../../selftest")))
import selftesthelpers
from selftesthelpers import bindir, srcdir, scriptdir, binpath
from selftesthelpers import plantestsuite, samba3srcdir
from selftesthelpers import planpythontestsuite
from selftesthelpers import smbtorture3, configuration, smbclient3, smbtorture4
from selftesthelpers import net, wbinfo, dbwrap_tool, rpcclient, python
from selftesthelpers import smbget, smbcacls, smbcquotas, ntlm_auth3
from selftesthelpers import valgrindify, smbtorture4_testsuites
from selftesthelpers import smbtorture4_options
from selftesthelpers import smbcontrol
from selftesthelpers import smbstatus
from selftesthelpers import timelimit
smbtorture4_options.extend([
    '--option=torture:sharedelay=100000',
   '--option=torture:writetimeupdatedelay=500000',
])


def plansmbtorture4testsuite(name, env, options, description='', environ=None):
    if description == '':
        modname = "samba3.%s" % (name, )
    else:
        modname = "samba3.%s %s" % (name, description)

    selftesthelpers.plansmbtorture4testsuite(
        name, env, options, target='samba3', modname=modname, environ=environ)

def compare_versions(version1, version2):
    for i in range(max(len(version1),len(version2))):
         v1 = version1[i] if i < len(version1) else 0
         v2 = version2[i] if i < len(version2) else 0
         if v1 > v2:
            return 1
         elif v1 <v2:
            return -1
    return 0

# find config.h
try:
    config_h = os.environ["CONFIG_H"]
except KeyError:
    samba4bindir = bindir()
    config_h = os.path.join(samba4bindir, "default/include/config.h")

bbdir = os.path.join(srcdir(), "testprogs/blackbox")

# check available features
config_hash = dict()
f = open(config_h, 'r')
try:
    lines = f.readlines()
    config_hash = dict((x[0], ' '.join(x[1:]))
                       for x in map(lambda line: line.strip().split(' ')[1:],
                                    filter(lambda line: (line[0:7] == '#define') and (len(line.split(' ')) > 2), lines)))
finally:
    f.close()

linux_kernel_version = None
if platform.system() == 'Linux':
    m = re.search(r'(\d+).(\d+).(\d+)', platform.release())
    if m:
        linux_kernel_version = [int(m.group(1)), int(m.group(2)), int(m.group(3))]

have_linux_kernel_oplocks = False
if "HAVE_KERNEL_OPLOCKS_LINUX" in config_hash:
    if compare_versions(linux_kernel_version, [5,3,1]) >= 0:
        have_linux_kernel_oplocks = True

have_inotify = ("HAVE_INOTIFY" in config_hash)
have_ldwrap = ("HAVE_LDWRAP" in config_hash)
with_pthreadpool = ("WITH_PTHREADPOOL" in config_hash)

have_cluster_support = "CLUSTER_SUPPORT" in config_hash

def is_module_enabled(module):
    if module in config_hash["STRING_SHARED_MODULES"]:
        return True
    if module in config_hash["STRING_STATIC_MODULES"]:
        return True
    return False

plantestsuite("samba3.blackbox.success", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/test_success.sh")])
plantestsuite("samba3.blackbox.failure", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/test_failure.sh")])

plantestsuite("samba3.local_s3", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/test_local_s3.sh")])

plantestsuite("samba3.blackbox.registry.upgrade", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/test_registry_upgrade.sh"), net, dbwrap_tool])

fileserver_tests = [
         "FDPASS", "LOCK1", "LOCK2", "LOCK3", "LOCK4", "LOCK5", "LOCK6", "LOCK7",
         "LOCK9A", "LOCK9B",
         "LOCK10",
         "LOCK11",
         "LOCK12",
         "LOCK13",
         "UNLINK", "BROWSE", "ATTR", "TRANS2", "TORTURE",
         "OPLOCK1", "OPLOCK2", "OPLOCK4", "STREAMERROR",
         "DIR", "DIR1", "DIR-CREATETIME", "TCON", "TCONDEV", "RW1", "RW2", "RW3", "LARGE_READX", "RW-SIGNING",
         "OPEN", "XCOPY", "RENAME", "DELETE", "DELETE-LN", "PROPERTIES", "W2K",
         "TCON2", "IOCTL", "CHKPATH", "FDSESS", "CHAIN1", "CHAIN2", "OWNER-RIGHTS",
         "CHAIN3", "PIDHIGH", "CLI_SPLICE",
         "UID-REGRESSION-TEST", "SHORTNAME-TEST",
         "CASE-INSENSITIVE-CREATE", "SMB2-BASIC", "NTTRANS-FSCTL", "SMB2-NEGPROT",
         "SMB2-SESSION-REAUTH", "SMB2-SESSION-RECONNECT", "SMB2-FTRUNCATE",
         "SMB2-ANONYMOUS", "SMB2-DIR-FSYNC",
	 "SMB2-PATH-SLASH",
	 "SMB2-QUOTA1",
         "CLEANUP1",
         "CLEANUP2",
         "CLEANUP4",
         "DELETE-STREAM",
         "BAD-NBT-SESSION",
         "SMB1-WILD-MANGLE-UNLINK",
         "SMB1-WILD-MANGLE-RENAME"]

for t in fileserver_tests:
    fileserver_env = "fileserver_smb1"
    if "SMB2" in t:
        fileserver_env = "fileserver"
    plantestsuite("samba3.smbtorture_s3.plain.%s" % t, fileserver_env, [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
    plantestsuite("samba3.smbtorture_s3.crypt_client.%s" % t, "nt4_dc_smb1", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "-e", "-l $LOCAL_PATH"])
    if t == "TORTURE":
        # this is a negative test to verify that the server rejects
        # access without encryption
        plantestsuite("samba3.smbtorture_s3.crypt_server.%s" % t, "nt4_dc_smb1", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmpenc', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
    if t == "CLI_SPLICE":
        # We must test this against the SMB1 fallback.
        plantestsuite("samba3.smbtorture_s3.plain.%s" % t, "fileserver_smb1", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH", "-mNT1"])
    plantestsuite("samba3.smbtorture_s3.plain.%s" % t, "ad_dc_ntvfs", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

t = "TLDAP"
plantestsuite("samba3.smbtorture_s3.%s.sasl-sign" % t, "ad_dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER/tmp', '$DC_USERNAME', '$DC_PASSWORD', smbtorture3, "-T 'clientldapsaslwrapping=sign'", "", "-l $LOCAL_PATH"])
plantestsuite("samba3.smbtorture_s3.%s.sasl-seal" % t, "ad_dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER/tmp', '$DC_USERNAME', '$DC_PASSWORD', smbtorture3, "-T 'clientldapsaslwrapping=seal'", "", "-l $LOCAL_PATH"])
plantestsuite("samba3.smbtorture_s3.%s.ldaps" % t, "ad_dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER/tmp', '$DC_USERNAME', '$DC_PASSWORD', smbtorture3,  "-T 'clientldapsaslwrapping=ldaps'", "", "-l $LOCAL_PATH"])
plantestsuite("samba3.smbtorture_s3.%s.starttls" % t, "ad_dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER/tmp', '$DC_USERNAME', '$DC_PASSWORD', smbtorture3, "-T 'clientldapsaslwrapping=starttls'", "", "-l $LOCAL_PATH"])

if have_linux_kernel_oplocks:
    t = "OPLOCK5"
    plantestsuite("samba3.smbtorture_s3.plain.%s" % t,
                  "fileserver_smb1",
                  [os.path.join(samba3srcdir,
                                "script/tests/test_smbtorture_s3.sh"),
                   t,
                   '//$SERVER/tmp',
                   '$USERNAME',
                   '$PASSWORD',
                   smbtorture3,
                   "",
                   "-l $LOCAL_PATH",
                   "-mNT1"])
#
# RENAME-ACCESS needs to run against a special share - acl_xattr_ign_sysacl_windows
#
plantestsuite("samba3.smbtorture_s3.plain.%s" % "RENAME-ACCESS", "nt4_dc_smb1", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), "RENAME-ACCESS", '//$SERVER_IP/acl_xattr_ign_sysacl_windows', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
plantestsuite("samba3.smbtorture_s3.crypt_client.%s" % "RENAME-ACCESS", "nt4_dc_smb1", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), "RENAME-ACCESS", '//$SERVER_IP/acl_xattr_ign_sysacl_windows', '$USERNAME', '$PASSWORD', smbtorture3, "-e", "-l $LOCAL_PATH"])
# non-crypt only

tests = ["OPLOCK-CANCEL"]
for t in tests:
    plantestsuite("samba3.smbtorture_s3.plain.%s" % t, "nt4_dc", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/tmp', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

env = "nt4_dc_smb1"
tests = ["MANGLE-ILLEGAL"]
for t in tests:
    plantestsuite("samba3.smbtorture_s3.plain.%s" % t, env, [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/mangle_illegal', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

tests = ["RW1", "RW2", "RW3", "SMB2-BASIC"]
for t in tests:
    if t == "SMB2-BASIC":
        env = "simpleserver"
    else:
        env = "fileserver_smb1"

    plantestsuite("samba3.smbtorture_s3.vfs_aio_pthread(%s).%s" % (env, t), env, [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/vfs_aio_pthread', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
    plantestsuite("samba3.smbtorture_s3.vfs_aio_fork(%s).%s" % (env, t), env, [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/vfs_aio_fork', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])

plantestsuite("samba3.smbtorture_s3.hidenewfiles",
              "simpleserver",
              [os.path.join(samba3srcdir,
                            "script/tests/test_smbtorture_s3.sh"),
               'hide-new-files-timeout',
               '//$SERVER_IP/hidenewfiles',
               '$USERNAME',
               '$PASSWORD',
               smbtorture3,
               "",
               "-l $LOCAL_PATH"])
plantestsuite("samba3.smbtorture_s3.hidenewfiles_showdirs",
              "simpleserver",
              [os.path.join(samba3srcdir,
                            "script/tests/test_smbtorture_s3.sh"),
               'hide-new-files-timeout-showdirs',
               '//$SERVER_IP/hidenewfiles',
               '$USERNAME',
               '$PASSWORD',
               smbtorture3,
               "",
               "-l $LOCAL_PATH"])

plantestsuite("samba3.smbtorture_s3.smb1.SMB1-TRUNCATED-SESSSETUP",
                "fileserver_smb1",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB1-TRUNCATED-SESSSETUP',
                '//$SERVER_IP/tmp',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mNT1"])

plantestsuite("samba3.smbtorture_s3.smb1.SMB1-NEGOTIATE-EXIT",
                "fileserver_smb1",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB1-NEGOTIATE-EXIT',
                '//$SERVER_IP/tmp',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mNT1"])

plantestsuite("samba3.smbtorture_s3.smb1.SMB1-NEGOTIATE-TCON",
                "fileserver_smb1",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB1-NEGOTIATE-TCON',
                '//$SERVER_IP/tmp',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mNT1"])

#
# MSDFS attribute tests.
#
plantestsuite("samba3.smbtorture_s3.smb2.MSDFS-ATTRIBUTE",
                "fileserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'MSDFS-ATTRIBUTE',
                '//$SERVER_IP/msdfs-share',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mSMB2",
                "-f msdfs-src1"])

plantestsuite("samba3.smbtorture_s3.smb1.MSDFS-ATTRIBUTE",
                "fileserver_smb1",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'MSDFS-ATTRIBUTE',
                '//$SERVER_IP/msdfs-share',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mNT1",
                "-f msdfs-src1"])

#
# SMB2-DFS-PATHS needs to run against a special share msdfs-pathname-share
# This is an empty DFS share with no links, used merely to test
# incoming DFS pathnames and how they map to local paths.
#
plantestsuite("samba3.smbtorture_s3.smb2.SMB2-DFS-PATHS",
                "fileserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB2-DFS-PATHS',
                '//$SERVER_IP/msdfs-pathname-share',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mSMB2"])

# BUG: https://bugzilla.samba.org/show_bug.cgi?id=15277
# MacOSX clients send a leading '\\' character for DFS paths.
#
plantestsuite("samba3.smbtorture_s3.smb2.SMB2-DFS-FILENAME-LEADING-BACKSLASH",
                "fileserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB2-DFS-FILENAME-LEADING-BACKSLASH',
                '//$SERVER_IP/msdfs-pathname-share',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mSMB2"])

# BUG: https://bugzilla.samba.org/show_bug.cgi?id=15422
# Prevent bad pipenames.
#
plantestsuite("samba3.smbtorture_s3.smb2.SMB2-INVALID-PIPENAME",
                "fileserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB2-INVALID-PIPENAME',
                '//$SERVER_IP/tmp',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mSMB2"])

#
# SMB2-NON-DFS-SHARE needs to run against a special share non-msdfs-pathname-share
# This is an empty non-DFS share with no links, used merely to test
# incoming DFS pathnames and how they map to local paths. We are testing
# what happens if we set the FLAGS2_DFS_PATHNAMES and send DFS paths
# on a non-DFS share.
#
plantestsuite("samba3.smbtorture_s3.smb2.SMB2-NON-DFS-SHARE",
                "fileserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB2-NON-DFS-SHARE',
                '//$SERVER_IP/non-msdfs-pathname-share',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mSMB2"])

#
# SMB2-DFS-SHARE-NON-DFS-PATH needs to run against a special share msdfs-pathname-share
# This is an empty DFS share with no links, used merely to test
# incoming non-DFS pathnames and how they map to local paths.
#
plantestsuite("samba3.smbtorture_s3.smb2.SMB2-DFS-SHARE-NON-DFS-PATH",
                "fileserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB2-DFS-SHARE-NON-DFS-PATH',
                '//$SERVER_IP/msdfs-pathname-share',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mSMB2"])

#
# SMB1-DFS-PATHS needs to run against a special share msdfs-pathname-share
# This is an empty DFS share with no links, used merely to test
# incoming DFS pathnames and how they map to local paths.
#
plantestsuite("samba3.smbtorture_s3.smb1.SMB1-DFS-PATHS",
                "fileserver_smb1",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB1-DFS-PATHS',
                '//$SERVER_IP/msdfs-pathname-share',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mNT1"])

#
# SMB1-DFS-SEARCH-PATHS needs to run against a special share msdfs-pathname-share
# This is an empty DFS share with no links, used merely to test
# incoming DFS pathnames and how they map to local paths.
#
plantestsuite("samba3.smbtorture_s3.smb1.SMB1-DFS-SEARCH-PATHS",
                "fileserver_smb1",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB1-DFS-SEARCH-PATHS',
                '//$SERVER_IP/msdfs-pathname-share',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mNT1"])

#
# SMB1-DFS-OPERATIONS needs to run against a special share msdfs-pathname-share
# This is an empty DFS share with no links, used merely to test
# incoming DFS pathnames and how they map to local paths.
#
plantestsuite("samba3.smbtorture_s3.smb1.SMB1-DFS-OPERATIONS",
                "fileserver_smb1",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB1-DFS-OPERATIONS',
                '//$SERVER_IP/msdfs-pathname-share',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mNT1"])
#
# SMB1-DFS-BADPATH needs to run against a special share msdfs-pathname-share
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=15419
#
plantestsuite("samba3.smbtorture_s3.smb1.SMB1-DFS-BADPATH",
                "fileserver_smb1",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB1-DFS-BADPATH',
                '//$SERVER_IP/msdfs-pathname-share',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "-mNT1"])

#
# SMB2-STREAM-ACL needs to run against a special share - vfs_wo_fruit
#
plantestsuite("samba3.smbtorture_s3.plain.%s" % "SMB2-STREAM-ACL",
                "fileserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB2-STREAM-ACL',
                '//$SERVER_IP/vfs_wo_fruit',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "",
                "-l $LOCAL_PATH"])

#
# SMB2-LIST-DIR-ASYNC needs to run against a special share vfs_aio_pthread_async_dosmode_default1
#
plantestsuite("samba3.smbtorture_s3.plain.%s" % "SMB2-LIST-DIR-ASYNC",
                "simpleserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB2-LIST-DIR-ASYNC',
                '//$SERVER_IP/vfs_aio_pthread_async_dosmode_default1',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "",
                "-l $LOCAL_PATH"])
#
# SMB2-DEL-ON-CLOSE-NONEMPTY needs to run against a special fileserver share veto_files_delete
#
plantestsuite("samba3.smbtorture_s3.plain.%s" % "SMB2-DEL-ON-CLOSE-NONEMPTY",
                "fileserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB2-DEL-ON-CLOSE-NONEMPTY',
                '//$SERVER_IP/veto_files_delete',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "",
                "-l $LOCAL_PATH"])

#
# SMB2-DEL-ON-CLOSE-NONWRITE-DELETE-YES needs to run against a special fileserver share delete_yes_unwrite
#
plantestsuite("samba3.smbtorture_s3.plain.%s" % "SMB2-DEL-ON-CLOSE-NONWRITE-DELETE-YES",
                "fileserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB2-DEL-ON-CLOSE-NONWRITE-DELETE-YES',
                '//$SERVER_IP/delete_yes_unwrite',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "",
                "-l $LOCAL_PATH"])

#
# SMB2-DEL-ON-CLOSE-NONWRITE-DELETE-NO needs to run against a special fileserver share delete_no_unwrite
#
plantestsuite("samba3.smbtorture_s3.plain.%s" % "SMB2-DEL-ON-CLOSE-NONWRITE-DELETE-NO",
                "fileserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_s3.sh"),
                'SMB2-DEL-ON-CLOSE-NONWRITE-DELETE-NO',
                '//$SERVER_IP/delete_no_unwrite',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "",
                "-l $LOCAL_PATH"])

#
# Test doing an async read + disconnect on a pipe doesn't crash the server.
# BUG: https://bugzilla.samba.org/show_bug.cgi?id=15423
#
plantestsuite("samba3.smbtorture_s3.plain.%s" % "SMB2-PIPE-READ-ASYNC-DISCONNECT",
                "fileserver",
                [os.path.join(samba3srcdir,
                              "script/tests/test_smbtorture_nocrash_s3.sh"),
                'SMB2-PIPE-READ-ASYNC-DISCONNECT',
                '//$SERVER_IP/tmp',
                '$USERNAME',
                '$PASSWORD',
                smbtorture3,
                "",
                "-l $LOCAL_PATH"])

shares = [
    "vfs_aio_pthread_async_dosmode_default1",
    "vfs_aio_pthread_async_dosmode_default2"
]
for s in shares:
    plantestsuite("samba3.smbtorture_s3.%s(simpleserver).SMB2-BASIC" % s, "simpleserver", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), 'SMB2-BASIC', '//$SERVER_IP/' + s, '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
    t = "smb2.compound_find"
    plansmbtorture4testsuite(t, "simpleserver", "//%s/%s %s" % ('$SERVER_IP', s, ' -U$USERNAME%$PASSWORD'), description=s)

posix_tests = ["POSIX", "POSIX-APPEND", "POSIX-SYMLINK-ACL", "POSIX-SYMLINK-EA", "POSIX-OFD-LOCK",
               "POSIX-STREAM-DELETE", "WINDOWS-BAD-SYMLINK", "POSIX-MKDIR",
               "POSIX-BLOCKING-LOCK",
               "POSIX-ACL-OPLOCK",
               "POSIX-ACL-SHAREROOT",
               "POSIX-LS-WILDCARD",
               "POSIX-LS-SINGLE",
               "POSIX-READLINK",
               "POSIX-STAT",
               "POSIX-SYMLINK-PARENT",
               "POSIX-SYMLINK-CHMOD",
               "POSIX-DIR-DEFAULT-ACL",
               "POSIX-SYMLINK-RENAME",
               "POSIX-SYMLINK-GETPATHINFO",
               "POSIX-SYMLINK-SETPATHINFO",
              ]

for t in posix_tests:
    plantestsuite("samba3.smbtorture_s3.plain.%s" % t, "nt4_dc_smb1", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/posix_share', '$USERNAME', '$PASSWORD', smbtorture3, "", "-l $LOCAL_PATH"])
    plantestsuite("samba3.smbtorture_s3.crypt.%s" % t, "nt4_dc_smb1", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//$SERVER_IP/posix_share', '$USERNAME', '$PASSWORD', smbtorture3, "-e", "-l $LOCAL_PATH"])

local_tests = [
    "LOCAL-SUBSTITUTE",
    "LOCAL-GENCACHE",
    "LOCAL-BASE64",
    "LOCAL-RBTREE",
    "LOCAL-MEMCACHE",
    "LOCAL-STREAM-NAME",
    "LOCAL-STR-MATCH-MSWILD",
    "LOCAL-STR-MATCH-REGEX-SUB1",
    "LOCAL-string_to_sid",
    "LOCAL-sid_to_string",
    "LOCAL-binary_to_sid",
    "LOCAL-DBTRANS",
    "LOCAL-TEVENT-POLL",
    "LOCAL-CONVERT-STRING",
    "LOCAL-CONV-AUTH-INFO",
    "LOCAL-IDMAP-TDB-COMMON",
    "LOCAL-MESSAGING-READ1",
    "LOCAL-MESSAGING-READ2",
    "LOCAL-MESSAGING-READ3",
    "LOCAL-MESSAGING-READ4",
    "LOCAL-MESSAGING-FDPASS1",
    "LOCAL-MESSAGING-FDPASS2",
    "LOCAL-MESSAGING-FDPASS2a",
    "LOCAL-MESSAGING-FDPASS2b",
    "LOCAL-MESSAGING-SEND-ALL",
    "LOCAL-PTHREADPOOL-TEVENT",
    "LOCAL-CANONICALIZE-PATH",
    "LOCAL-DBWRAP-WATCH1",
    "LOCAL-DBWRAP-WATCH2",
    "LOCAL-DBWRAP-WATCH3",
    "LOCAL-DBWRAP-WATCH4",
    "LOCAL-DBWRAP-DO-LOCKED1",
    "LOCAL-G-LOCK1",
    "LOCAL-G-LOCK2",
    "LOCAL-G-LOCK3",
    "LOCAL-G-LOCK4",
    "LOCAL-G-LOCK4A",
    "LOCAL-G-LOCK5",
    "LOCAL-G-LOCK6",
    "LOCAL-G-LOCK7",
    "LOCAL-G-LOCK8",
    "LOCAL-NAMEMAP-CACHE1",
    "LOCAL-IDMAP-CACHE1",
    "LOCAL-TDB-VALIDATE",
    "LOCAL-hex_encode_buf",
    "LOCAL-remove_duplicate_addrs2"]

for t in local_tests:
    plantestsuite("samba3.smbtorture_s3.%s" % t, "none", [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//foo/bar', '""', '""', smbtorture3, ""])

plantestsuite("samba.vfstest.stream_depot", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/stream-depot/run.sh"), binpath("vfstest"), "$PREFIX", configuration])
plantestsuite("samba.vfstest.xattr-tdb-1", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/xattr-tdb-1/run.sh"), binpath("vfstest"), "$PREFIX", configuration])
plantestsuite("samba.vfstest.acl", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/vfstest-acl/run.sh"), binpath("vfstest"), "$PREFIX", configuration])
plantestsuite("samba.vfstest.catia", "nt4_dc:local", [os.path.join(samba3srcdir, "script/tests/vfstest-catia/run.sh"), binpath("vfstest"), "$PREFIX", configuration])
plantestsuite(
    "samba.vfstest.full_audit_segfault",
    "nt4_dc:local",
    [os.path.join(samba3srcdir,
                  "script/tests/full_audit_segfault/run.sh"),
     binpath("vfstest"),
     "$PREFIX",
     configuration])

plantestsuite("samba3.blackbox.smbclient_basic.NT1", "nt4_dc_schannel", [os.path.join(samba3srcdir, "script/tests/test_smbclient_basic.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, "-mNT1"])
plantestsuite("samba3.blackbox.smbclient_basic.NT1", "nt4_dc_smb1", [os.path.join(samba3srcdir, "script/tests/test_smbclient_basic.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, "-mNT1"])
plantestsuite("samba3.blackbox.smbclient_basic.SMB2_02", "nt4_dc_schannel", [os.path.join(samba3srcdir, "script/tests/test_smbclient_basic.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, "-mSMB2_02"])
plantestsuite("samba3.blackbox.smbclient_basic.SMB2_10", "nt4_dc_schannel", [os.path.join(samba3srcdir, "script/tests/test_smbclient_basic.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, "-mSMB2_10"])
plantestsuite("samba3.blackbox.smbclient_basic.SMB3_02", "nt4_dc_schannel", [os.path.join(samba3srcdir, "script/tests/test_smbclient_basic.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, "-mSMB3_02"])
plantestsuite("samba3.blackbox.smbclient_basic.SMB3_11", "nt4_dc_schannel", [os.path.join(samba3srcdir, "script/tests/test_smbclient_basic.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, "-mSMB3_11"])

plantestsuite("samba3.blackbox.smbclient_usernamemap", "ad_member_idmap_nss:local", [os.path.join(samba3srcdir, "script/tests/test_usernamemap.sh"), '$SERVER', smbclient3])

plantestsuite("samba3.blackbox.smbclient_basic", "ad_member", [os.path.join(samba3srcdir, "script/tests/test_smbclient_basic.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration])
for options in ["", "--option=clientntlmv2auth=no", "--option=clientusespnego=no", "--option=clientusespnego=no --option=clientntlmv2auth=no", "--option=clientntlmv2auth=no --option=clientlanmanauth=yes --max-protocol=LANMAN2", "--option=clientntlmv2auth=no --option=clientlanmanauth=yes --option=clientmaxprotocol=NT1"]:
    if "NT1" in options or "LANMAN2" in options:
        env = "nt4_dc_smb1_done"
    else:
        env = "nt4_dc"
    plantestsuite("samba3.blackbox.smbclient_auth.plain.%s" % (options), env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, options])

for env in ["nt4_dc", "nt4_member", "ad_member", "ad_dc", "s4member", "fl2000dc"]:
    plantestsuite("samba3.blackbox.smbclient_machine_auth.plain", "%s:local" % env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_machine_auth.sh"), '$SERVER', smbclient3, configuration])
    smb1_env = env
    if smb1_env == "ad_dc" or smb1_env == "nt4_dc":
        smb1_env = smb1_env + "_smb1_done"
    plantestsuite("samba3.blackbox.smbclient_ntlm.plain NT1", smb1_env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_ntlm.sh"), '$SERVER', '$DC_USERNAME', '$DC_PASSWORD', "never", smbclient3, "NT1", configuration])
    plantestsuite("samba3.blackbox.smbclient_ntlm.plain SMB3", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_ntlm.sh"), '$SERVER', '$DC_USERNAME', '$DC_PASSWORD', "never", smbclient3, "SMB3", configuration])


plantestsuite("samba3.blackbox.smbclient_log_basename", "ad_dc", [os.path.join(samba3srcdir, "script/tests/test_smbclient_log_basename.sh"), '$SERVER', smbclient3, '$PREFIX', configuration])

for options in ["--option=clientntlmv2auth=no", "--option=clientusespnego=no --option=clientntlmv2auth=no", "--option=clientusespnego=no --option=clientntlmv2auth=no -mNT1", ""]:
    # don't attempt to run SMB1 tests in nt4_member or ad_member
    # as these test envs don't support SMB1, use nt4_dc instead
    environs = ["nt4_member", "ad_member"]
    if "NT1" in options or "LANMAN2" in options:
        environs = ["nt4_dc_smb1_done"]
    for env in environs:
        plantestsuite("samba3.blackbox.smbclient_auth.plain.%s" % (options), env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, options])
        plantestsuite("samba3.blackbox.smbclient_auth.plain.%s.member_creds" % (options), env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$SERVER/$USERNAME', '$PASSWORD', smbclient3, configuration, options])

for env in ["nt4_member", "ad_member"]:
    plantestsuite("samba3.blackbox.smbclient_auth.empty_domain.domain_creds", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '/$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, options])
    plantestsuite("samba3.blackbox.smbclient_auth.empty_domain.member_creds", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '/$USERNAME', '$PASSWORD', smbclient3, configuration, options])
    plantestsuite("samba3.blackbox.smbclient_auth.dot_domain.domain_creds", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', './$DC_USERNAME', '$DC_PASSWORD', smbclient3, configuration, options])
    plantestsuite("samba3.blackbox.smbclient_auth.dot_domain.member_creds", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', './$USERNAME', '$PASSWORD', smbclient3, configuration, options])
    plantestsuite("samba3.blackbox.smbclient_auth.upn.domain_creds", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME@$REALM', '$DC_PASSWORD', smbclient3, configuration, options])
    plantestsuite("samba3.blackbox.smbclient_auth.upn.member_creds", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$USERNAME@$SERVER', '$PASSWORD', smbclient3, configuration, options])

env = "ad_dc_smb1"
plantestsuite("samba3.blackbox.smbspool", env, [os.path.join(samba3srcdir, "script/tests/test_smbspool.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD', env])

env = "ad_member_fips"
plantestsuite("samba3.blackbox.krbsmbspool", env, [os.path.join(samba3srcdir, "script/tests/test_smbspool_krb.sh"), '$SERVER', 'bob', 'Secret007', '$REALM'])

plantestsuite("samba3.blackbox.printing_var_exp", "nt4_dc", [os.path.join(samba3srcdir, "script/tests/test_printing_var_exp.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$DC_USERNAME', '$DC_PASSWORD'])

for env in ["ad_member:local", "nt4_dc:local"]:
    plantestsuite("samba3.blackbox.smbpasswd", env, [os.path.join(samba3srcdir, "script/tests/test_smbpasswd.sh"), '$SERVER', '$SERVER_IP', '$DC_USERNAME', '$DC_PASSWORD'])

env = "nt4_dc"
plantestsuite("samba3.blackbox.smbclient_auth.plain.ipv6", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IPV6', '$SERVER/$USERNAME', '$PASSWORD', smbclient3, configuration])

for env in ["nt4_member", "ad_member"]:
    plantestsuite("samba3.blackbox.net_cred_change", "%s:local" % env, [os.path.join(samba3srcdir, "script/tests/test_net_cred_change.sh"), configuration])

plantestsuite("samba3.blackbox.net_cred_change_at", "ad_member_s3_join:local", [os.path.join(samba3srcdir, "script/tests/test_net_cred_change_at.sh"), configuration, '$DC_SERVER'])
plantestsuite(
    "samba3.blackbox.update_keytab",
    "ad_member_idmap_nss:local",
    [
        os.path.join(samba3srcdir, "script/tests/test_update_keytab.sh"),
        "$DOMAIN",
        configuration,
    ],
)
plantestsuite(
    "samba3.blackbox.update_keytab_clustered",
    "clusteredmember:local",
    [
        os.path.join(samba3srcdir, "script/tests/test_update_keytab_clustered.sh"),
        "$DOMAIN",
        configuration,
    ],
)

env = "ad_member"
t = "--krb5auth=$DOMAIN/$DC_USERNAME%$DC_PASSWORD"
plantestsuite("samba3.wbinfo_simple.%s" % t, "%s:local" % env, [os.path.join(srcdir(), "nsswitch/tests/test_wbinfo_simple.sh"), t])
plantestsuite("samba3.wbinfo_name_lookup", env,
              [os.path.join(srcdir(),
                            "nsswitch/tests/test_wbinfo_name_lookup.sh"),
               '$DOMAIN', '$REALM', '$DC_USERNAME'])

env = "ad_member"
plantestsuite("samba3.wbinfo_user_info_cached", env,
              [os.path.join(srcdir(),
                            "nsswitch/tests/test_wbinfo_user_info_cached.sh"),
               '$DOMAIN', '$REALM', 'joe', 'Secret007', '"Samba Users"', env])
plantestsuite("samba3.wbinfo_user_info_cached.trustdom", env,
              [os.path.join(srcdir(),
                            "nsswitch/tests/test_wbinfo_user_info_cached.sh"),
               '$TRUST_F_BOTH_DOMAIN', '$TRUST_F_BOTH_REALM', 'joe', 'Secret007', '"Samba Users"', env])

env = "ad_member:local"
plantestsuite("samba3.wbinfo_user_info", env,
              [os.path.join(srcdir(),
                            "nsswitch/tests/test_wbinfo_user_info.sh"),
               '$DOMAIN', '$REALM', '$DOMAIN', 'alice', 'alice', 'jane', 'jane.doe', env])

plantestsuite("samba3.winbind_call_depth_trace", env,
              [os.path.join(srcdir(),
                            "source3/script/tests/test_winbind_call_depth_trace.sh"),
               smbcontrol, configuration, '$PREFIX', env])

env = "fl2008r2dc:local"
plantestsuite("samba3.wbinfo_user_info", env,
              [os.path.join(srcdir(),
                            "nsswitch/tests/test_wbinfo_user_info.sh"),
               '$TRUST_DOMAIN', '$TRUST_REALM', '$DOMAIN', 'alice', 'alice', 'jane', 'jane.doe', env])

env = "nt4_member:local"
plantestsuite("samba3.wbinfo_sids_to_xids", env,
              [os.path.join(srcdir(),
                            "nsswitch/tests/test_wbinfo_sids_to_xids.sh")])
plantestsuite(
    "samba.wbinfo_lookuprids_cache",
    env,
    [os.path.join(samba3srcdir,
                  "script/tests/test_wbinfo_lookuprids_cache.sh")])

env = "ad_member"
t = "WBCLIENT-MULTI-PING"
plantestsuite("samba3.smbtorture_s3.%s" % t, env, [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"), t, '//foo/bar', '""', '""', smbtorture3, ""])
plantestsuite("samba3.substitutions", env, [os.path.join(samba3srcdir, "script/tests/test_substitutions.sh"), "$SERVER", "alice", "Secret007", "$PREFIX"])

for env in ["maptoguest", "simpleserver"]:
    plantestsuite("samba3.blackbox.smbclient_auth.plain.local_creds", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', smbclient3, configuration + " --option=clientntlmv2auth=no --option=clientlanmanauth=yes"])

env = "maptoguest"
plantestsuite("samba3.blackbox.smbclient_auth.plain.bad_username", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_auth.sh"), '$SERVER', '$SERVER_IP', 'notmy$USERNAME', '$PASSWORD', smbclient3, configuration + " --option=clientntlmv2auth=no --option=clientlanmanauth=yes"])
plantestsuite("samba3.blackbox.smbclient_ntlm.plain.NT1", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_ntlm.sh"), '$SERVER', '$USERNAME', '$PASSWORD', "baduser", smbclient3, "NT1", configuration])
plantestsuite("samba3.blackbox.smbclient_ntlm.plain.SMB3", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_ntlm.sh"), '$SERVER', '$USERNAME', '$PASSWORD', "baduser", smbclient3, "SMB3", configuration])

# plain
env = "nt4_dc_smb1_done"
plantestsuite("samba3.blackbox.smbclient_s3.NT1.plain", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$DC_USERNAME', '$DC_PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "NT1"])
env = "nt4_dc"
plantestsuite("samba3.blackbox.smbclient_s3.SMB3.plain", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$DC_USERNAME', '$DC_PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "SMB3"])

for env in ["nt4_member", "ad_member"]:
    plantestsuite("samba3.blackbox.smbclient_s3.NT1.plain.member_creds", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$SERVER', '$SERVER/$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "NT1"])
    plantestsuite("samba3.blackbox.smbclient_s3.SMB3.plain.member_creds", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$SERVER', '$SERVER/$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "SMB3"])

env = "nt4_dc_smb1_done"
plantestsuite("samba3.blackbox.smbclient_s3.NT1.sign", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$DC_USERNAME', '$DC_PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "NT1", "--client-protection=sign"])
env = "nt4_dc"
plantestsuite("samba3.blackbox.smbclient_s3.SMB3.sign", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$DC_USERNAME', '$DC_PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "SMB3", "--client-protection=sign"])

for env in ["nt4_member", "ad_member"]:
    plantestsuite("samba3.blackbox.smbclient_s3.NT1.sign.member_creds", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$SERVER', '$SERVER/$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "NT1", "--client-protection=sign"])
    plantestsuite("samba3.blackbox.smbclient_s3.SMB3.sign.member_creds", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$SERVER', '$SERVER/$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "SMB3", "--client-protection=sign"])

env = "nt4_dc_smb1_done"
# encrypted
plantestsuite("samba3.blackbox.smbclient_s3.NT1.crypt", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "NT1", "--client-protection=encrypt"])
env = "nt4_dc"
plantestsuite("samba3.blackbox.smbclient_s3.SMB3.crypt", env, [os.path.join(samba3srcdir, "script/tests/test_smbclient_s3.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, wbinfo, net, configuration, "SMB3", "--client-protection=encrypt"])

for env in ["fileserver"]:
    plantestsuite("samba3.blackbox.preserve_case.NT1", env + "_smb1_done", [os.path.join(samba3srcdir, "script/tests/test_preserve_case.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, "NT1"])
    plantestsuite("samba3.blackbox.preserve_case.SMB2+", env, [os.path.join(samba3srcdir, "script/tests/test_preserve_case.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, '"SMB2 SMB3"'])
    plantestsuite("samba3.blackbox.dfree_command.NT1", env + "_smb1_done", [os.path.join(samba3srcdir, "script/tests/test_dfree_command.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, "NT1"])
    plantestsuite("samba3.blackbox.dfree_command.SMB3", env, [os.path.join(samba3srcdir, "script/tests/test_dfree_command.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, "SMB3"])
    plantestsuite("samba3.blackbox.dfree_quota.NT1", env + "_smb1_done", [os.path.join(samba3srcdir, "script/tests/test_dfree_quota.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', smbclient3, smbcquotas, smbcacls, "NT1"])
    plantestsuite("samba3.blackbox.dfree_quota.SMB3", env, [os.path.join(samba3srcdir, "script/tests/test_dfree_quota.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', smbclient3, smbcquotas, smbcacls, "SMB3"])
    plantestsuite("samba3.blackbox.smbcquotas", env, [os.path.join(samba3srcdir, "script/tests/test_smbcquota.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', smbcquotas])
    plantestsuite("samba3.blackbox.valid_users", env, [os.path.join(samba3srcdir, "script/tests/test_valid_users.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3])
    plantestsuite("samba3.blackbox.force_create_mode", env, [os.path.join(samba3srcdir, "script/tests/test_force_create_mode.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$PREFIX', env, smbclient3])
    plantestsuite("samba3.blackbox.dropbox", env, [os.path.join(samba3srcdir, "script/tests/test_dropbox.sh"), '$SERVER', '$DOMAIN', 'gooduser', '$PASSWORD', '$PREFIX', env, smbclient3])
    plantestsuite("samba3.blackbox.offline", env, [os.path.join(samba3srcdir, "script/tests/test_offline.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/offline', smbclient3])
    plantestsuite("samba3.blackbox.recycle", env, [os.path.join(samba3srcdir, "script/tests/test_recycle.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', '$PREFIX', smbclient3])
    plantestsuite("samba3.blackbox.fakedircreatetimes", env, [os.path.join(samba3srcdir, "script/tests/test_fakedircreatetimes.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/fakedircreatetimes', '$PREFIX', smbclient3])
    plantestsuite("samba3.blackbox.shadow_copy2.NT1", env + "_smb1_done", [os.path.join(samba3srcdir, "script/tests/test_shadow_copy.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/shadow', smbclient3, '-m', 'NT1'])
    plantestsuite("samba3.blackbox.shadow_copy2.SMB3", env, [os.path.join(samba3srcdir, "script/tests/test_shadow_copy.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/shadow', smbclient3, '-m', 'SMB3'])
    plantestsuite("samba3.blackbox.shadow_copy_torture", env, [os.path.join(samba3srcdir, "script/tests/test_shadow_copy_torture.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/shadow', smbtorture4, smbclient3])
    plantestsuite("samba3.blackbox.smbclient.forceuser_validusers", env, [os.path.join(samba3srcdir, "script/tests/test_forceuser_validusers.sh"), '$SERVER', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', smbclient3])
    plantestsuite("samba3.blackbox.netshareenum", env, [os.path.join(samba3srcdir, "script/tests/test_shareenum.sh"), '$SERVER', '$USERNAME', '$PASSWORD', rpcclient])
    plantestsuite("samba3.blackbox.acl_xattr.NT1", env + "_smb1_done", [os.path.join(samba3srcdir, "script/tests/test_acl_xattr.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, '-mNT1'])
    plantestsuite("samba3.blackbox.acl_xattr.SMB3", env, [os.path.join(samba3srcdir, "script/tests/test_acl_xattr.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, '-mSMB3'])
    plantestsuite("samba3.blackbox.worm.NT1", env + "_smb1_done", [os.path.join(samba3srcdir, "script/tests/test_worm.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/worm', '$PREFIX', smbclient3, '-mNT1'])
    plantestsuite("samba3.blackbox.worm.SMB3", env, [os.path.join(samba3srcdir, "script/tests/test_worm.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/worm', '$PREFIX', smbclient3, '-mSMB3'])
    plantestsuite("samba3.blackbox.smb2.not_casesensitive", env, [os.path.join(samba3srcdir, "script/tests/test_smb2_not_casesensitive.sh"), '//$SERVER/tmp', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', smbclient3])
    plantestsuite("samba3.blackbox.inherit_owner.default.NT1", env + "_smb1_done", [os.path.join(samba3srcdir, "script/tests/test_inherit_owner.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, net, 'tmp', '0', '0', '-m', 'NT1'])
    plantestsuite("samba3.blackbox.inherit_owner.default.SMB3", env, [os.path.join(samba3srcdir, "script/tests/test_inherit_owner.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, net, 'tmp', '0', '0', '-m', 'SMB3'])
    plantestsuite("samba3.blackbox.inherit_owner.full.NT1", env + "_smb1_done", [os.path.join(samba3srcdir, "script/tests/test_inherit_owner.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, net, 'inherit_owner', '1', '1', '-m', 'NT1'])
    plantestsuite("samba3.blackbox.inherit_owner.full.SMB3", env, [os.path.join(samba3srcdir, "script/tests/test_inherit_owner.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, net, 'inherit_owner', '1', '1', '-m', 'SMB3'])
    plantestsuite("samba3.blackbox.inherit_owner.unix.NT1", env + "_smb1_done", [os.path.join(samba3srcdir, "script/tests/test_inherit_owner.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, net, 'inherit_owner_u', '0', '1', '-m', 'NT1'])
    plantestsuite("samba3.blackbox.inherit_owner.unix.SMB3", env, [os.path.join(samba3srcdir, "script/tests/test_inherit_owner.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, net, 'inherit_owner_u', '0', '1', '-m', 'SMB3'])
    plantestsuite("samba3.blackbox.large_acl.NT1", env + "_smb1_done", [os.path.join(samba3srcdir, "script/tests/test_large_acl.sh"), '$SERVER', '$USERNAME', '$PASSWORD', smbclient3, smbcacls, '-m', 'NT1'])
    plantestsuite("samba3.blackbox.large_acl.SMB3", env, [os.path.join(samba3srcdir, "script/tests/test_large_acl.sh"), '$SERVER', '$USERNAME', '$PASSWORD', smbclient3, smbcacls, '-m', 'SMB3'])
    plantestsuite("samba3.blackbox.give_owner", env, [os.path.join(samba3srcdir, "script/tests/test_give_owner.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, net, 'tmp'])
    plantestsuite("samba3.blackbox.delete_stream", env, [os.path.join(samba3srcdir, "script/tests/test_delete_stream.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3, smbcacls, net, 'acl_streams_xattr'])
    plantestsuite("samba3.blackbox.homes", env, [os.path.join(samba3srcdir, "script/tests/test_homes.sh"), '$SERVER', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', '$PREFIX', smbclient3, configuration])
    plantestsuite("samba3.blackbox.force_group_change", env,
		[os.path.join(samba3srcdir, "script/tests/test_force_group_change.sh"),
		'$SERVER', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', smbclient3, smbcontrol])
    plantestsuite("samba3.blackbox.zero-data", env,
                  [os.path.join(samba3srcdir, "script/tests/test_zero_data.sh"),
                   '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH'])
    plantestsuite("samba3.blackbox.timestamps", env,
                  [os.path.join(samba3srcdir, "script/tests/test_timestamps.sh"),
                   '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH', smbclient3])
    plantestsuite("samba3.blackbox.volumeserialnumber", env,
                  [os.path.join(samba3srcdir, "script/tests/test_volume_serial_number.sh"),
                   '$SERVER_IP', '$USERNAME', '$PASSWORD', 'volumeserialnumber', smbclient3])
    plantestsuite("samba3.blackbox.smb1_system_security", env + "_smb1_done",
                  [os.path.join(samba3srcdir, "script/tests/test_smb1_system_security.sh"),
                   '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', smbtorture3, net, 'tmp'])
    plantestsuite("samba3.blackbox.sacl_get_set", env,
                  [os.path.join(samba3srcdir, "script/tests/test_sacl_set_get.sh"),
                   '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', smbtorture3, net, 'tmp'])
    plantestsuite("samba3.blackbox.NT1.shadow_copy_torture", env + "_smb1_done",
                  [os.path.join(samba3srcdir, "script/tests/test_smb1_shadow_copy_torture.sh"),
                   '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/shadow', smbtorture4])
    plantestsuite("samba3.blackbox.smbclient_iconv.SMB2", env,
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_iconv.sh"),
                   '$SERVER', '$SERVER_IP', 'bad_iconv', '$USERNAME', '$PASSWORD', smbclient3])
    plantestsuite("samba3.blackbox.smbclient_iconv.NT1", env + "_smb1_done",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_iconv.sh"),
                   '$SERVER', '$SERVER_IP', 'bad_iconv', '$USERNAME', '$PASSWORD', smbclient3, '-mNT1'])
    plantestsuite("samba3.blackbox.smbclient_iconv.CORE", env + "_smb1_done",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_iconv.sh"),
                   '$SERVER', '$SERVER_IP', 'bad_iconv', '$USERNAME', '$PASSWORD', smbclient3, '-mCORE'])
    plantestsuite("samba3.blackbox.test_veto_rmdir", env,
                  [os.path.join(samba3srcdir, "script/tests/test_veto_rmdir.sh"),
                  '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/veto', smbclient3])
    plantestsuite("samba3.blackbox.test_dangle_rmdir", env,
                  [os.path.join(samba3srcdir, "script/tests/test_delete_veto_files_only_rmdir.sh"),
                  '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/veto', smbclient3])
    plantestsuite("samba3.blackbox.test_list_servers.NT1",
                  env + "_smb1_done",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_list_servers.sh"),
                  '$SERVER',
                  '$SERVER_IP',
                  '$USERNAME',
                  '$PASSWORD',
                  smbclient3,
                  "-mNT1"])
    plantestsuite("samba3.blackbox.test_list_servers.SMB2",
                  env,
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_list_servers.sh"),
                  '$SERVER',
                  '$SERVER_IP',
                  '$USERNAME',
                  '$PASSWORD',
                  smbclient3,
                  "-mSMB3"])

    plantestsuite("samba3.blackbox.test_symlink_traversal.SMB2", env,
                  [os.path.join(samba3srcdir, "script/tests/test_symlink_traversal_smb2.sh"),
                  '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/local_symlinks',
                  '$PREFIX', smbclient3])

    plantestsuite("samba3.blackbox.test_symlink_traversal.SMB1", env + "_smb1_done",
                  [os.path.join(samba3srcdir, "script/tests/test_symlink_traversal_smb1.sh"),
                  '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/local_symlinks',
                  '$PREFIX', smbclient3])

    plantestsuite("samba3.blackbox.test_symlink_traversal.SMB1.posix", env + "_smb1_done",
                  [os.path.join(samba3srcdir, "script/tests/test_symlink_traversal_smb1_posix.sh"),
                  '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/local_symlinks',
                  '$PREFIX', smbclient3])

    plantestsuite("samba3.blackbox.test_symlink_rename.SMB1.posix", env + "_smb1_done",
                  [os.path.join(samba3srcdir, "script/tests/test_symlink_rename_smb1_posix.sh"),
                  '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/local_symlinks',
                  '$PREFIX', smbclient3])

    plantestsuite("samba3.blackbox.test_veto_files", env,
                  [os.path.join(samba3srcdir, "script/tests/test_veto_files.sh"),
                  '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/veto', smbclient3])

    plantestsuite("samba3.blackbox.stream_dir_rename", env,
                  [os.path.join(samba3srcdir, "script/tests/test_stream_dir_rename.sh"),
                  '$SERVER', '$USERNAME', '$PASSWORD', '$PREFIX', smbclient3])

    plantestsuite("samba3.blackbox.test_symlink_dosmode", env,
                  [os.path.join(samba3srcdir, "script/tests/test_symlink_dosmode.sh"),
                  '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', '$LOCAL_PATH/local_symlinks',
                  '$PREFIX', smbclient3])
    #
    # tar command tests
    #

    # Test smbclient/tarmode
    plantestsuite("samba3.blackbox.smbclient_tarmode.NT1", env + "_smb1_done",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_tarmode.sh"),
                   '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD',
                   '$LOCAL_PATH/tarmode/smbclient_tar', '$PREFIX', smbclient3, configuration, "-mNT1"])
    plantestsuite("samba3.blackbox.smbclient_tarmode.SMB3", env,
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_tarmode.sh"),
                   '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD',
                   '$LOCAL_PATH/tarmode/smbclient_tar', '$PREFIX', smbclient3, configuration, "-mSMB3"])

    # Test suite for new smbclient/tar with libarchive (GSoC 13)
    plantestsuite("samba3.blackbox.smbclient_tar.NT1", env + "_smb1_done",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_tarmode.pl"),
                   '-n', '$SERVER', '-i', '$SERVER_IP', '-s', 'tarmode2',
                   '-u', '$USERNAME', '-p', '$PASSWORD', '-l', '$LOCAL_PATH/tarmode2',
                   '-d', 'smbclient_tar.NT1', '-b', smbclient3,
                   '--subunit', '--', configuration, '-mNT1'])
    plantestsuite("samba3.blackbox.smbclient_tar.SMB3", env,
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_tarmode.pl"),
                   '-n', '$SERVER', '-i', '$SERVER_IP', '-s', 'tarmode2',
                   '-u', '$USERNAME', '-p', '$PASSWORD', '-l', '$LOCAL_PATH/tarmode2',
                   '-d', 'smbclient_tar.SMB3', '-b', smbclient3,
                   '--subunit', '--', configuration, '-mSMB3'])
    plantestsuite("samba3.blackbox.fifo", env,
                  [os.path.join(samba3srcdir, "script/tests/test_fifo.sh"),
                  '$SERVER', '$DOMAIN', 'gooduser', '$PASSWORD', '$PREFIX', env, smbclient3])
    plantestsuite("samba3.blackbox.test_full_audit_success_badname", env,
                  [os.path.join(samba3srcdir, "script/tests/test_bad_auditnames.sh"),
                  '$SERVER', 'full_audit_success_bad_name', '$USERNAME', '$PASSWORD', smbclient3])
    plantestsuite("samba3.blackbox.test_full_audit_fail_badname", env,
                  [os.path.join(samba3srcdir, "script/tests/test_bad_auditnames.sh"),
                  '$SERVER', 'full_audit_fail_bad_name', '$USERNAME', '$PASSWORD', smbclient3])
    plantestsuite("samba3.blackbox.fruit.resource_stream", env,
                  [os.path.join(samba3srcdir, "script/tests/test_fruit_resource_stream.sh"),
                  '$SERVER', 'fruit_resource_stream', '$USERNAME', '$PASSWORD',
                  '$LOCAL_PATH/fruit_resource_stream', smbclient3])

plantestsuite("samba3.blackbox.smbclient_old_dir", "fileserver_smb1",
              [os.path.join(samba3srcdir,
                            "script/tests/test_old_dirlisting.sh"),
               timelimit, smbclient3])

for env in ["fileserver:local"]:
    plantestsuite("samba3.blackbox.net_usershare", env, [os.path.join(samba3srcdir, "script/tests/test_net_usershare.sh"), '$SERVER', '$SERVER_IP', '$USERNAME', '$PASSWORD', smbclient3])

    plantestsuite("samba3.blackbox.smbstatus", env, [os.path.join(samba3srcdir, "script/tests/test_smbstatus.sh"), '$SERVER', '$SERVER_IP', '$DOMAIN', '$USERNAME', '$PASSWORD', '$USERID', '$LOCAL_PATH', '$PREFIX', smbclient3, smbstatus, configuration, "SMB3"])
    plantestsuite("samba3.blackbox.net_registry_import", env, [os.path.join(samba3srcdir, "script/tests/test_net_registry_import.sh"), '$SERVER', '$LOCAL_PATH', '$USERNAME', '$PASSWORD'])

env = 'ad_member'
plantestsuite("samba3.blackbox.smbget",
              env,
              [
                  os.path.join(samba3srcdir, "script/tests/test_smbget.sh"),
                  '$SERVER',
                  '$SERVER_IP',
                  '$DOMAIN',
                  '$REALM',
                  'smbget_user',
                  '$PASSWORD',
                  '$DOMAIN_USER',
                  '$DOMAIN_USER_PASSWORD',
                  '$LOCAL_PATH/smbget',
                  smbget
              ])

plantestsuite("samba3.blackbox.server_addresses",
              "simpleserver",
              [os.path.join(samba3srcdir,
                            "script/tests/test_server_addresses.sh")])

# TODO encrypted against member, with member creds, and with DC creds
plantestsuite("samba3.blackbox.net.misc NT1", "ad_dc_smb1_done:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_misc.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, "NT1"])
plantestsuite("samba3.blackbox.net.misc SMB3", "ad_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_misc.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, "SMB3"])
plantestsuite("samba3.blackbox.net.local.registry", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration])
plantestsuite("samba3.blackbox.net.registry.check", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry_check.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, dbwrap_tool])
plantestsuite("samba3.blackbox.net.rpc.registry", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, 'rpc'])

plantestsuite("samba3.blackbox.net.local.registry.roundtrip", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry_roundtrip.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration])
plantestsuite("samba3.blackbox.net.rpc.registry.roundtrip", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_registry_roundtrip.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, 'rpc'])

plantestsuite("samba3.blackbox.net.local.conf", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_conf.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration])
plantestsuite("samba3.blackbox.net.rpc.conf", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_conf.sh"),
               scriptdir, "$SMB_CONF_PATH", net, configuration, 'rpc'])


plantestsuite("samba3.blackbox.testparm", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_testparm_s3.sh"),
               "$LOCAL_PATH"])

plantestsuite(
    "samba3.pthreadpool", "none",
    [os.path.join(samba3srcdir, "script/tests/test_pthreadpool.sh")])

if with_pthreadpool and have_ldwrap:
    plantestsuite("samba3.pthreadpool_cmocka", "none",
                  [os.path.join(bindir(), "pthreadpooltest_cmocka")])

if with_pthreadpool:
    plantestsuite("samba3.libwbclient_threads",
                  "nt4_member",
                  [os.path.join(samba3srcdir,
                                "script/tests/test_libwbclient_threads.sh"),
                   "$DOMAIN", "$DC_USERNAME"])
    plantestsuite("b15464_testcase", "none",
                  [os.path.join(bbdir, "b15464-testcase.sh"),
                   binpath("b15464-testcase"),
                   binpath("plugins/libnss_winbind.so.2")])

plantestsuite("samba3.test_nfs4_acl", "none",
              [os.path.join(bindir(), "test_nfs4_acls"),
               "$SMB_CONF_PATH"])

plantestsuite("samba3.test_vfs_full_audit", "none",
              [os.path.join(bindir(), "test_vfs_full_audit"),
               "$SMB_CONF_PATH"])

plantestsuite("samba3.test_vfs_posixacl", "none",
              [os.path.join(bindir(), "test_vfs_posixacl"),
               "$SMB_CONF_PATH"])

if is_module_enabled("vfs_gpfs"):
    plantestsuite("samba3.test_vfs_gpfs", "none",
                  [os.path.join(bindir(), "test_vfs_gpfs")])

plantestsuite(
    "samba3.resolvconf", "none",
    [os.path.join(samba3srcdir, "script/tests/test_resolvconf.sh")])

plantestsuite("samba3.tevent_glib_glue", "none",
    [os.path.join(samba3srcdir, "script/tests/test_tevent_glib_glue.sh")])

plantestsuite("samba3.async_req", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_async_req.sh")])

# smbtorture4 tests

base = ["base.attr", "base.charset", "base.chkpath", "base.createx_access", "base.defer_open", "base.delaywrite", "base.delete",
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
       "raw.samba3rootdirfid", "raw.samba3rootdirfid2", "raw.sfileinfo.end-of-file",
       "raw.bench-oplock", "raw.bench-lock", "raw.bench-open", "raw.bench-tcon",
       "raw.samba3checkfsp", "raw.samba3closeerr", "raw.samba3oplocklogoff", "raw.samba3badnameblob"]

smb2 = smbtorture4_testsuites("smb2.")

rpc = ["rpc.authcontext",
       "rpc.samba3.bind",
       "rpc.samba3.srvsvc",
       "rpc.samba3.sharesec",
       "rpc.samba3.spoolss",
       "rpc.samba3.wkssvc",
       "rpc.samba3.winreg",
       "rpc.samba3.getaliasmembership-0",
       "rpc.samba3.netlogon",
       "rpc.samba3.sessionkey",
       "rpc.samba3.getusername",
       "rpc.samba3.smb1-pipe-name",
       "rpc.samba3.smb2-pipe-name",
       "rpc.samba3.smb-reauth1",
       "rpc.samba3.smb-reauth2",
       "rpc.samba3.lsa_over_netlogon",
       "rpc.samba3.pipes_supported_interfaces",
       "rpc.mgmt",
       "rpc.svcctl",
       "rpc.ntsvcs",
       "rpc.winreg",
       "rpc.eventlog",
       "rpc.spoolss.printserver",
       "rpc.spoolss.win",
       "rpc.spoolss.notify",
       "rpc.spoolss.printer",
       "rpc.spoolss.driver",
       "rpc.lsa",
       "rpc.lsa-getuser",
       "rpc.lsa.lookupsids",
       "rpc.lsa.lookupnames",
       "rpc.lsa.privileges",
       "rpc.lsa.secrets",
       "rpc.mdssvc",
       "rpc.samr",
       "rpc.samr.users",
       "rpc.samr.users.privileges",
       "rpc.samr.passwords.default",
       "rpc.samr.passwords.pwdlastset",
       "rpc.samr.passwords.lockout",
       "rpc.samr.passwords.badpwdcount",
       "rpc.samr.large-dc",
       "rpc.samr.machine.auth",
       "rpc.samr.priv",
       "rpc.samr.passwords.validate",
       "rpc.samr.handletype",
       "rpc.netlogon.admin",
       "rpc.netlogon.zerologon",
       "rpc.schannel",
       "rpc.schannel2",
       "rpc.bench-schannel1",
       "rpc.schannel_anon_setpw",
       "rpc.join",
       "rpc.bind",
       "rpc.initshutdown",
       "rpc.wkssvc",
       "rpc.srvsvc"]

local = ["local.nss"]

idmap = ["idmap.rfc2307", "idmap.alloc", "idmap.rid", "idmap.ad", "idmap.nss"]

rap = ["rap.basic", "rap.rpc", "rap.printing", "rap.sam"]

unix = ["unix.info2", "unix.whoami"]

nbt = ["nbt.dgram"]

vfs = [
    "vfs.fruit",
    "vfs.acl_xattr",
    "vfs.streams_xattr",
    "vfs.fruit_netatalk",
    "vfs.fruit_file_id",
    "vfs.fruit_timemachine",
    "vfs.fruit_conversion",
    "vfs.unfruit",
]

tests = base + raw + smb2 + rpc + unix + local + rap + nbt + idmap + vfs

for t in tests:
    if t == "base.delaywrite" or t == "base.deny1" or t == "base.deny2":
        plansmbtorture4testsuite(t, "fileserver_smb1", '//$SERVER/tmp -U$USERNAME%$PASSWORD --maximum-runtime=900')
    elif t == "base.createx_access":
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER/tmp -U$USERNAME%$PASSWORD -k yes --maximum-runtime=900')
    elif t == "rap.sam":
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=doscharset=ISO-8859-1')
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=doscharset=ISO-8859-1')
    elif t == "winbind.pac":
        plansmbtorture4testsuite(t, "ad_member:local", '//$SERVER/tmp --realm=$REALM --machine-pass --option=torture:addc=$DC_SERVER', description="machine account")
    elif t == "unix.whoami":
        plansmbtorture4testsuite(t, "nt4_member:local", '//$SERVER/tmp --machine-pass', description="machine account")
        plansmbtorture4testsuite(t, "ad_dc_smb1:local", '//$SERVER/tmp --machine-pass', description="machine account")
        plansmbtorture4testsuite(t, "ad_member:local", '//$SERVER/tmp --machine-pass --option=torture:addc=$DC_SERVER', description="machine account")
        plansmbtorture4testsuite(t, "ad_dc_smb1:local", '//$SERVER/tmp --machine-pass --option=torture:addc=$DC_SERVER', description="machine account")
        for env in ["nt4_dc_smb1", "nt4_member"]:
            plansmbtorture4testsuite(t, env, '//$SERVER/tmp -U$DC_USERNAME%$DC_PASSWORD')
            plansmbtorture4testsuite(t, env, '//$SERVER/tmpguest -U%', description='anonymous connection')
        for env in ["ad_dc_smb1", "ad_member"]:
            plansmbtorture4testsuite(t, env, '//$SERVER/tmp -U$DC_USERNAME@$REALM%$DC_PASSWORD --option=torture:addc=$DC_SERVER')
            plansmbtorture4testsuite(t, env, '//$SERVER/tmp -k yes -U$DC_USERNAME@$REALM%$DC_PASSWORD --option=torture:addc=$DC_SERVER', description='kerberos connection')
            plansmbtorture4testsuite(t, env, '//$SERVER/tmpguest -U% --option=torture:addc=$DC_SERVER', description='anonymous connection')
            plansmbtorture4testsuite(t, env, '//$SERVER/tmp -k no -U$DC_USERNAME@$REALM%$DC_PASSWORD', description='ntlm user@realm')
    elif t == "raw.samba3posixtimedlock":
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmpguest -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc_smb1/share')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/brl_delay_inject1 -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc_smb1/share',
                                 description="brl_delay_inject1")
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/brl_delay_inject2 -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc_smb1/share',
                                 description="brl_delay_inject2")
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER_IP/tmpguest -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/ad_dc_smb1/share')
    elif t == "smb2.samba3misc":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmpguest -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/brl_delay_inject1 -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share',
                                 description="brl_delay_inject1")
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/brl_delay_inject2 -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share',
                                 description="brl_delay_inject2")
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER_IP/tmpguest -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/ad_dc/share')
    elif t == "raw.chkpath":
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmpcase -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER_IP/tmpcase -U$USERNAME%$PASSWORD')
    elif t == "raw.samba3hide" or t == "raw.samba3checkfsp" or t == "raw.samba3closeerr":
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "fileserver_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "raw.session":
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD', 'plain')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmpenc -U$USERNAME%$PASSWORD', 'enc')
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER/tmp -k no -U$USERNAME%$PASSWORD', 'ntlm')
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER/tmp -k yes -U$USERNAME%$PASSWORD', 'krb5')
    elif t == "smb2.session":
        alice_creds = "--option='torture:user2name=alice' --option='torture:user2password=Secret007'"
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD', 'plain')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmpenc -U$USERNAME%$PASSWORD', 'enc')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -k no -U$USERNAME%$PASSWORD ' + alice_creds, 'ntlm')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -k yes -U$USERNAME%$PASSWORD ' + alice_creds, 'krb5')
        # Certain tests fail when run against ad_member with MIT kerberos because the private krb5.conf overrides the provisioned lib/krb5.conf,
        # ad_member_idmap_rid sets "create krb5.conf = no"
        plansmbtorture4testsuite(t, "ad_member_idmap_rid", '//$SERVER/tmp -k yes -U$DC_USERNAME@$REALM%$DC_PASSWORD', 'krb5')
    elif t == "smb2.session-require-signing":
        plansmbtorture4testsuite(t, "ad_member_idmap_rid", '//$SERVER_IP/tmp -U$DC_USERNAME@$REALM%$DC_PASSWORD')
    elif t == "rpc.lsa":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD', 'over ncacn_np ')
        plansmbtorture4testsuite(t, "nt4_dc", 'ncacn_ip_tcp:$SERVER_IP -U$USERNAME%$PASSWORD', 'over ncacn_ip_tcp ')
    elif t.startswith("rpc.lsa."):
        # This avoids the rpc.lsa.* tests running under ncacn_ip_tcp:
        # (there is rpc.lsa.secrets fails due to OpenPolicy2 for example)
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    elif t == "rpc.mdssvc":
        plansmbtorture4testsuite(t, "fileserver", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.durable-open" or t == "smb2.durable-v2-open" or t == "smb2.replay" or t == "smb2.durable-v2-delay":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/durable -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER_IP/durable -U$USERNAME%$PASSWORD')
    elif t == "base.rw1":
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/valid-users-tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/write-list-tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "idmap.rfc2307":
        plantestsuite(t, "ad_member_rfc2307",
                      [os.path.join(samba3srcdir,
                                    "../nsswitch/tests/test_idmap_rfc2307.sh"),
                       '$DOMAIN',
                       'Administrator', '2000000',
                       'Guest', '2000001',
                       '"Domain Users"', '2000002',
                       'DnsAdmins', '2000003',
                       '2000005', '35',
                       'ou=idmap,dc=samba,dc=example,dc=com',
                       '$DC_SERVER', '$DC_USERNAME', '$DC_PASSWORD'])
    elif t == "idmap.alloc":
        plantestsuite(t, "ad_member_rfc2307", [os.path.join(samba3srcdir, "../nsswitch/tests/test_idmap_nss.sh"), '$DOMAIN'])
    elif t == "idmap.nss":
        plantestsuite(t, "ad_member_idmap_nss:local", [os.path.join(samba3srcdir, "../nsswitch/tests/test_idmap_nss_use_upn.sh")])
    elif t == "idmap.rid":
        plantestsuite(t, "ad_member_idmap_rid", [os.path.join(samba3srcdir, "../nsswitch/tests/test_idmap_rid.sh"), '$DOMAIN', '2000000'])
        plantestsuite(t,
                      "admem_idmap_autorid",
                      [os.path.join(samba3srcdir,
                                    "../nsswitch/tests/test_idmap_rid.sh"),
                       '$DOMAIN',
                       '2000000'])
    elif t == "idmap.ad":
        plantestsuite(t, "ad_member_idmap_ad", [os.path.join(samba3srcdir, "../nsswitch/tests/test_idmap_ad.sh"), '$DOMAIN', '$DC_SERVER', '$DC_PASSWORD', '$TRUST_DOMAIN', '$TRUST_SERVER', '$TRUST_PASSWORD'])
    elif t == "raw.acls":
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/nfs4acl_simple_40 -U$USERNAME%$PASSWORD', description='nfs4acl_xattr-simple-40')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/nfs4acl_special_40 -U$USERNAME%$PASSWORD', description='nfs4acl_xattr-special-40')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/nfs4acl_simple_41 -U$USERNAME%$PASSWORD', description='nfs4acl_xattr-simple-41')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/nfs4acl_xdr_40 -U$USERNAME%$PASSWORD', description='nfs4acl_xattr-xdr-40')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/nfs4acl_xdr_41 -U$USERNAME%$PASSWORD', description='nfs4acl_xattr-xdr-41')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/nfs4acl_nfs_40 -U$USERNAME%$PASSWORD', description='nfs4acl_xattr-nfs-40')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/nfs4acl_nfs_41 -U$USERNAME%$PASSWORD', description='nfs4acl_xattr-nfs-41')
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER_IP/tmpcase -U$USERNAME%$PASSWORD')
    elif t == "smb2.ioctl":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/fs_specific -U$USERNAME%$PASSWORD', 'fs_specific')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.ioctl-on-stream":
        plansmbtorture4testsuite(t, "fileserver", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.lock":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/aio -U$USERNAME%$PASSWORD', 'aio')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    elif t == "raw.lock" or t == "base.lock":
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    elif t == "raw.read":
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/aio -U$USERNAME%$PASSWORD', 'aio')
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "raw.search":
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
# test the dirsort module.
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmpsort -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "vfs.fruit":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/vfs_fruit -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share --option=torture:share2=vfs_wo_fruit', 'metadata_netatalk')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/vfs_fruit_metadata_stream -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share --option=torture:share2=vfs_wo_fruit', 'metadata_stream')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/vfs_fruit_stream_depot -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share --option=torture:share2=vfs_wo_fruit_stream_depot', 'streams_depot')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/vfs_fruit_delete_empty_adfiles -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share --option=torture:share2=vfs_wo_fruit', 'fruit_delete_empty_adfiles')
    elif t == "vfs.fruit_netatalk":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/vfs_fruit_xattr -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share')
    elif t == "vfs.fruit_timemachine":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/vfs_fruit_timemachine -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share')
    elif t == "vfs.fruit_file_id":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/vfs_fruit_zero_fileid -U$USERNAME%$PASSWORD')
    elif t == "vfs.fruit_conversion":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=torture:share2=vfs_fruit_wipe_intentionally_left_blank_rfork --option=torture:delete_empty_adfiles=false', 'wipe_intentionally_left_blank_rfork')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=torture:share2=vfs_fruit_delete_empty_adfiles --option=torture:delete_empty_adfiles=true', 'delete_empty_adfiles')
    elif t == "vfs.unfruit":
        creds = '-U$USERNAME%$PASSWORD'
        share2 = '--option=torture:share2=tmp'
        netopt = '--option=torture:net=%s' % net
        shareopt = '--option=torture:sharename'

        plansmbtorture4testsuite(t, "nt4_dc:local", '//$SERVER_IP/vfs_fruit %s %s %s %s=%s' % (creds, share2, netopt, shareopt, 'vfs_fruit'), 'metadata_netatalk')
        plansmbtorture4testsuite(t, "nt4_dc:local", '//$SERVER_IP/vfs_fruit_metadata_stream %s %s %s %s=%s' % (creds, share2, netopt, shareopt, 'vfs_fruit_metadata_stream'), 'metadata_stream')
        plansmbtorture4testsuite(t, "nt4_dc:local", '//$SERVER_IP/vfs_fruit_stream_depot %s %s %s %s=%s' % (creds, share2, netopt, shareopt, 'vfs_fruit_stream_depot'), 'streams_depot')
    elif t == "rpc.schannel_anon_setpw":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$%', description="anonymous password set")
        plansmbtorture4testsuite(t, "nt4_dc_schannel", '//$SERVER_IP/tmp -U$%', description="anonymous password set (schannel enforced server-side)")
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$%', description="anonymous password set")
    elif t == "local.nss":
        for env in ["nt4_dc:local", "ad_member:local", "nt4_member:local", "ad_dc:local"]:
            plansmbtorture4testsuite(t,
                                     env,
                                     '//$SERVER/tmp -U$USERNAME%$PASSWORD',
                                     environ = {
                                        'ENVNAME': env,
                                     })
    elif t == "smb2.change_notify_disabled":
        plansmbtorture4testsuite(t, "simpleserver", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.notify" or t == "raw.notify" or t == "smb2.oplock" or t == "raw.oplock":
        tmp_env = "nt4_dc"
        if t == "raw.notify" or t == "raw.oplock":
            tmp_env = "nt4_dc_smb1"
        # These tests are a little slower so don't duplicate them with ad_dc
        plansmbtorture4testsuite(t, tmp_env, '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --client-protection=sign')
    elif t == "smb2.dosmode":
        plansmbtorture4testsuite(t, "simpleserver", '//$SERVER/dosmode -U$USERNAME%$PASSWORD')
    elif t == "smb2.kernel-oplocks":
        if have_linux_kernel_oplocks:
            plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER/kernel_oplocks -U$USERNAME%$PASSWORD --option=torture:localdir=$SELFTEST_PREFIX/nt4_dc/share')
    elif t == "smb2.notify-inotify":
        if have_inotify:
            plansmbtorture4testsuite(t, "fileserver", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    elif t == "vfs.acl_xattr":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    elif t == "vfs.streams_xattr":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/vfs_wo_fruit -U$USERNAME%$PASSWORD')
    elif t == "smb2.compound_find":
        plansmbtorture4testsuite(t, "fileserver", '//$SERVER/compound_find -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "fileserver", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.compound":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/aio -U$USERNAME%$PASSWORD', 'aio')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.compound_async":
        plansmbtorture4testsuite(t, "fileserver", '//$SERVER_IP/aio_delay_inject -U$USERNAME%$PASSWORD')
    elif t == "smb2.ea":
        plansmbtorture4testsuite(t, "fileserver", '//$SERVER/ea_acl_xattr --option=torture:acl_xattr_name=hackme -U$USERNAME%$PASSWORD')
    elif t == "rpc.samba3.netlogon" or t == "rpc.samba3.sessionkey":
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=torture:wksname=samba3rpctest')
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER/tmp -U$USERNAME%$PASSWORD --option=torture:wksname=samba3rpctest')
    elif t == "smb2.streams":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/streams_xattr -U$USERNAME%$PASSWORD', 'streams_xattr')
    elif t == "smb2.stream-inherit-perms":
        plansmbtorture4testsuite(t, "fileserver", '//$SERVER/inherit_perms -U$USERNAME%$PASSWORD')
    elif t == "smb2.aio_delay":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/aio_delay_inject -U$USERNAME%$PASSWORD')
    elif t == "smb2.delete-on-close-perms":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/delete_readonly -U$USERNAME%$PASSWORD --option=torture:delete_readonly=true')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.fileid":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/vfs_fruit_xattr -U$USERNAME%$PASSWORD')
    elif t == "smb2.acls_non_canonical":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/acls_non_canonical -U$USERNAME%$PASSWORD')
    elif t == "smb2.async_dosmode":
        plansmbtorture4testsuite("smb2.async_dosmode",
                                 "simpleserver",
                                 "//$SERVER_IP/async_dosmode_shadow_copy2 -U$USERNAME%$PASSWORD")
    elif t == "smb2.rename":
        plansmbtorture4testsuite(t, "fileserver", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    elif t == "smb2.twrp":
        # This is being driven by samba3.blackbox.shadow_copy_torture
        pass
    elif t == "smb2.create_no_streams":
        plansmbtorture4testsuite(t, "fileserver", '//$SERVER_IP/nfs4acl_simple_40 -U$USERNAME%$PASSWORD')
    elif t == "rpc.wkssvc":
        plansmbtorture4testsuite(t, "ad_member", '//$SERVER/tmp -U$DC_USERNAME%$DC_PASSWORD')
    elif t == "rpc.srvsvc":
        plansmbtorture4testsuite(t, "ad_member", '//$SERVER/tmp -U$DC_USERNAME%$DC_PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$DC_USERNAME%$DC_PASSWORD')
    elif t == "rpc.samba3.lsa_over_netlogon":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    elif t == "rpc.samba3.pipes_supported_interfaces":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    elif t == "rpc.spoolss.notify":
        plansmbtorture4testsuite(t, "ad_member", '//$SERVER_IP/tmp -U$DC_USERNAME%$DC_PASSWORD')
    elif (t in base and t != "base.charset") \
        or (t in rap and t != "rap.printing") \
        or (t in unix) \
        or (t in ["rpc.authcontext",
                  "rpc.join",
                  "rpc.samba3.bind",
                  "rpc.samba3.getusername",
                  "rpc.samba3.sharesec",
                  "rpc.samba3.smb1-pipe-name",
                  "rpc.samba3.smb-reauth1",
                  "rpc.samba3.smb-reauth2",
                  "rpc.samba3.spoolss",
                  "rpc.samba3.wkssvc",]) \
        or (t in ["raw.close",
                  "raw.composite",
                  "raw.eas",
                  "raw.mkdir",
                  "raw.open",
                  "raw.rename",
                  "raw.samba3badnameblob",
                  "raw.samba3badpath",
                  "raw.samba3caseinsensitive",
                  "raw.samba3oplocklogoff",
                  "raw.samba3posixtimedlock",
                  "raw.samba3rootdirfid",
                  "raw.samba3rootdirfid2",
                  "raw.seek",
                  "raw.sfileinfo.bug",
                  "raw.sfileinfo.end-of-file",
                  "raw.sfileinfo.rename",
                  "raw.streams",
                  "raw.unlink",
                  "raw.write",]) :
        plansmbtorture4testsuite(t, "nt4_dc_smb1", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc_smb1", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t in ["base.mangle", "base.tcon", "raw.mkdir"]:
        plansmbtorture4testsuite(t, "nt4_dc_smb1_done", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc_smb1_done", '//$SERVER/tmp -U$USERNAME%$PASSWORD')
    elif t == "rpc.samr.passwords.validate":
        plansmbtorture4testsuite(t, "nt4_dc", 'ncacn_ip_tcp:$SERVER_IP[seal] -U$USERNAME%$PASSWORD', 'over ncacn_ip_tcp ')
    elif t == "rpc.samr.users.privileges":
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD --option=torture:nt4_dc=true')
    elif t == "rpc.samr" or t.startswith("rpc.samr."):
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
    else:
        plansmbtorture4testsuite(t, "nt4_dc", '//$SERVER_IP/tmp -U$USERNAME%$PASSWORD')
        plansmbtorture4testsuite(t, "ad_dc", '//$SERVER/tmp -U$USERNAME%$PASSWORD')

plantestsuite(
    "idmap_ad.ticket_expiry",
    "ad_member_idmap_ad:local",
    [os.path.join(samba3srcdir, "../nsswitch/tests/test_ticket_expiry.sh"),
     '$DOMAIN'])

plansmbtorture4testsuite(
    "notifyd",
    "fileserver:local",
    '//foo/bar -U%')

plansmbtorture4testsuite(
    "smb2.streams",
    "simpleserver",
    '//$SERVER/external_streams_depot -U$USERNAME%$PASSWORD')

vfs_io_uring_tests = {
    "smb2.connect",
    "smb2.credits",
    "smb2.rw",
    "smb2.bench",
    "smb2.ioctl",
}
for t in vfs_io_uring_tests:
    plansmbtorture4testsuite(t, "fileserver",
                             '//$SERVER_IP/io_uring -U$USERNAME%$PASSWORD',
                             "vfs_io_uring")

test = 'rpc.lsa.lookupsids'
auth_options = ["", "ntlm", "spnego", "spnego,ntlm", "spnego,smb1", "spnego,smb2"]
signseal_options = ["", ",connect", ",packet", ",sign", ",seal"]
endianness_options = ["", ",bigendian"]
for s in signseal_options:
    for e in endianness_options:
        for a in auth_options:
            binding_string = "ncacn_np:$SERVER[%s%s%s]" % (a, s, e)
            options = binding_string + " -U$USERNAME%$PASSWORD"
            if "smb1" in a:
                plansmbtorture4testsuite(test, "nt4_dc_smb1_done", options, 'over ncacn_np with [%s%s%s] ' % (a, s, e))
            else:
                plansmbtorture4testsuite(test, "nt4_dc", options, 'over ncacn_np with [%s%s%s] ' % (a, s, e))
            plantestsuite(
                f'samba3.blackbox.rpcclient over ncacn_np with [{a}{s}{e}] ',
                "nt4_dc:local",
                [os.path.join(samba3srcdir, "script/tests/test_rpcclient.sh"),
                 "none",
                 options + " -c getusername",
                 configuration])
            plantestsuite(
                f'samba3.blackbox.rpcclient over ncalrpc with [{a}{s}{e}] ',
                "nt4_dc:local",
                [os.path.join(samba3srcdir, "script/tests/test_rpcclient.sh"),
                 "none",
                 f'ncalrpc:[{a}{s}{e}] -c epmmap',
                 configuration])
            if s != ",connect":
                plantestsuite(
                    f'samba3.blackbox.rpcclient over ncacn_ip_tcp with [{a}{s}{e}] ',
                    "nt4_dc:local",
                    [os.path.join(samba3srcdir, "script/tests/test_rpcclient.sh"),
                     "none",
                     f'ncacn_ip_tcp:"$SERVER_IP"[{a}{s}{e}] -c epmmap -U"$USERNAME"%"$PASSWORD"',
                     configuration])

    # We should try more combinations in future, but this is all
    # the pre-calculated credentials cache supports at the moment
    #
    # As the ktest env requires SMB3_00 we need to use "smb2" until
    # dcerpc client code in smbtorture support autonegotiation
    # of any smb dialect.
    e = ""
    a = "smb2"
    binding_string = "ncacn_np:$SERVER[%s%s%s]" % (a, s, e)
    options = binding_string + " --use-krb5-ccache=$PREFIX/ktest/krb5_ccache-2"
    plansmbtorture4testsuite(test, "ktest", options, 'krb5 with old ccache ncacn_np with [%s%s%s] ' % (a, s, e))

    options = binding_string + " --use-krb5-ccache=$PREFIX/ktest/krb5_ccache-3"
    plansmbtorture4testsuite(test, "ktest", options, 'krb5 ncacn_np with [%s%s%s] ' % (a, s, e))

    auth_options2 = ["krb5", "spnego,krb5"]
    for a in auth_options2:
        binding_string = "ncacn_np:$SERVER[%s%s%s]" % (a, s, e)

        plantestsuite(
            f'samba3.blackbox.rpcclient krb5 ncacn_np with [{a}{s}{e}] ',
            "ktest:local",
            [os.path.join(samba3srcdir, "script/tests/test_rpcclient.sh"),
             "$PREFIX/ktest/krb5_ccache-3",
             binding_string,
             "--use-krb5-ccache=$PREFIX/ktest/krb5_ccache-3 -c getusername",
             configuration])

plantestsuite("samba3.blackbox.rpcclient_samlogon", "ad_member:local", [os.path.join(samba3srcdir, "script/tests/test_rpcclient_samlogon.sh"),
                                                                        "$DC_USERNAME", "$DC_PASSWORD", "ncacn_np:$DC_SERVER", configuration])
plantestsuite("samba3.blackbox.sharesec", "simpleserver:local",
              [os.path.join(samba3srcdir, "script/tests/test_sharesec.sh"),
               configuration, os.path.join(bindir(), "sharesec"),
               os.path.join(bindir(), "net"), "tmp"])

plantestsuite("samba3.blackbox.close-denied-share", "simpleserver:local",
              [os.path.join(samba3srcdir,
                            "script/tests/test_close_denied_share.sh"),
               configuration,
               os.path.join(bindir(), "sharesec"),
               os.path.join(bindir(), "smbclient"),
               os.path.join(bindir(), "smbcontrol"),
               '$SERVER_IP',
               "tmp"])

plantestsuite("samba3.blackbox.force-close-share", "simpleserver:local",
              [os.path.join(samba3srcdir,
                            "script/tests/test_force_close_share.sh"),
               configuration,
               os.path.join(bindir(), "smbclient"),
               os.path.join(bindir(), "smbcontrol"),
               '$SERVER_IP',
               "aio_delay_inject",
               '$PREFIX/force-close-share'])

plantestsuite("samba3.blackbox.open-eintr", "simpleserver:local",
              [os.path.join(samba3srcdir,
                            "script/tests/test_open_eintr.sh"),
               configuration,
               os.path.join(bindir(), "smbclient"),
               os.path.join(bindir(), "smbcontrol"),
               '$SERVER_IP',
               "error_inject"])

plantestsuite("samba3.blackbox.chdir-cache", "simpleserver:local",
              [os.path.join(samba3srcdir,
                            "script/tests/test_chdir_cache.sh"),
               configuration,
               os.path.join(bindir(), "smbclient"),
               os.path.join(bindir(), "smbcontrol"),
               '$SERVER_IP',
               "error_inject",
               '$PREFIX',
               'simpleserver'])

plantestsuite("samba3.blackbox.rofs_error", "simpleserver",
              [os.path.join(samba3srcdir, "script/tests/test_rofs.sh"),
               configuration,
               os.path.join(bindir(), "smbclient"),
               '$SERVER_IP',
               "error_inject"])

plantestsuite("samba3.blackbox.zero_readsize",
              "simpleserver:local",
              [os.path.join(samba3srcdir,
                            "script/tests/test_zero_readsize.sh"),
               configuration,
               os.path.join(bindir(), "smbclient"),
               os.path.join(bindir(), "smbcontrol"),
               '$SERVER_IP',
               "tmp",
               "$PREFIX",
               "-mSMB2"])

plantestsuite("samba3.blackbox.netfileenum", "simpleserver:local",
              [os.path.join(samba3srcdir,
                            "script/tests/test_netfileenum.sh"),
               os.path.join(bindir(), "smbclient"),
               os.path.join(bindir(), "rpcclient"),
               os.path.join(bindir(), "net"),
               '$SERVER_IP',
               'tmp'])

plantestsuite("samba3.blackbox.netshareenum_username", "fileserver",
              [os.path.join(samba3srcdir,
                            "script/tests/test_user_in_sharelist.sh"),
               os.path.join(bindir(), "rpcclient"),
               '$SERVER_IP'])

plantestsuite("samba3.blackbox.net_tdb", "simpleserver:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_tdb.sh"),
               smbclient3, '$SERVER', 'tmp', '$USERNAME', '$PASSWORD',
               configuration, '$LOCAL_PATH', '$LOCK_DIR'])

plantestsuite("samba3.blackbox.aio-outstanding", "simpleserver:local",
              [os.path.join(samba3srcdir,
                            "script/tests/test_aio_outstanding.sh"),
               configuration,
               os.path.join(bindir(), "smbclient"),
               '$SERVER_IP',
               "aio_delay_inject"])

plantestsuite("samba3.blackbox.deadtime", "simpleserver:local",
              [os.path.join(samba3srcdir, "script/tests/test_deadtime.sh"),
               '$SERVER_IP'])

plantestsuite("samba3.blackbox.smbd_error", "simpleserver:local",
              [os.path.join(samba3srcdir, "script/tests/test_smbd_error.sh")])

plantestsuite("samba3.blackbox.smbd_no_krb5", "ad_member:local",
              [os.path.join(samba3srcdir, "script/tests/test_smbd_no_krb5.sh"),
               smbclient3, '$SERVER', "$DC_USERNAME", "$DC_PASSWORD", "$PREFIX"])

plantestsuite("samba3.blackbox.smb1_lanman_plaintext", "simpleserver:local",
              [os.path.join(samba3srcdir, "script/tests/test_smb1_lanman_plaintext.sh"),
               smbclient3, '$SERVER', "$USERNAME", "$PASSWORD"])

plantestsuite("samba3.blackbox.smb1_lanman_plaintext", "nt4_member:local",
              [os.path.join(samba3srcdir, "script/tests/test_smb1_lanman_plaintext.sh"),
               smbclient3, '$SERVER', "$USERNAME", "$PASSWORD"])

plantestsuite("samba3.blackbox.winbind_ignore_domain", "ad_member_idmap_ad:local",
              [os.path.join(samba3srcdir, "script/tests/test_winbind_ignore_domains.sh")])

plantestsuite("samba3.blackbox.durable_v2_delay", "simpleserver:local",
              [os.path.join(samba3srcdir, "script/tests/test_durable_handle_reconnect.sh")])

plantestsuite("samba3.blackbox.net_cache_samlogon", "ad_member:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_cache_samlogon.sh"),
               '$SERVER', 'tmp', '$DC_USERNAME', '$DC_PASSWORD'])

plantestsuite("samba3.blackbox.net_rpc_share_allowedusers", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_rpc_share_allowedusers.sh"),
               "$SERVER", "$USERNAME", "$PASSWORD", "$PREFIX/net_rpc_share_allowedusers",
               configuration])

plantestsuite("samba3.blackbox.net_dom_join_fail_dc", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_dom_join_fail_dc.sh"),
               "$USERNAME", "$PASSWORD", "$SERVER", "$PREFIX/net_dom_join_fail_dc",
               configuration])
plantestsuite("samba3.blackbox.net_rpc_join", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_rpc_join.sh"),
               "$USERNAME", "$PASSWORD", "$SERVER", "$PREFIX/net_rpc_join",
               configuration])
plantestsuite("samba3.blackbox.net_rpc_oldjoin", "nt4_dc:local",
              [os.path.join(samba3srcdir, "script/tests/test_net_rpc_oldjoin.sh"),
               "$SERVER", "$PREFIX/net_rpc_oldjoin",
               "$SMB_CONF_PATH"])
plantestsuite("samba3.blackbox.net_rpc_join_creds", "nt4_dc",
              [os.path.join(samba3srcdir, "script/tests/test_net_rpc_join_creds.sh"),
               "$DOMAIN", "$USERNAME", "$PASSWORD", "$SERVER", "$PREFIX/net_rpc_join_creds",
               configuration])

plantestsuite("samba3.blackbox.rpcclient_srvsvc", "simpleserver",
              [os.path.join(samba3srcdir, "script/tests/test_rpcclientsrvsvc.sh"),
               "$USERNAME", "$PASSWORD", "$SERVER",
               os.path.join(bindir(), "rpcclient"), "tmp"])

plantestsuite("samba3.blackbox.rpcclient_lookup", "simpleserver",
              [os.path.join(samba3srcdir, "script/tests/test_rpcclient_lookup.sh"),
               "$USERNAME", "$PASSWORD", "$SERVER",
               os.path.join(bindir(), "rpcclient")])

plantestsuite("samba3.blackbox.rpcclient_dfs", "fileserver:local",
              [os.path.join(samba3srcdir, "script/tests/test_rpcclient_dfs.sh"),
               "$USERNAME", "$PASSWORD", "$SERVER",
               os.path.join(bindir(), "rpcclient")])

plantestsuite("samba3.blackbox.rpcclient.pw-nt-hash", "simpleserver",
              [os.path.join(samba3srcdir, "script/tests/test_rpcclient_pw_nt_hash.sh"),
               "$USERNAME", "$PASSWORD", "$SERVER",
               os.path.join(bindir(), "rpcclient")])

plantestsuite("samba3.blackbox.smbclient.encryption_off", "simpleserver",
              [os.path.join(samba3srcdir, "script/tests/test_smbclient_encryption_off.sh"),
               "$USERNAME", "$PASSWORD", "$SERVER",
               smbclient3])

plantestsuite("samba3.blackbox.smbXsrv_client_dead_rec", "fileserver:local",
              [os.path.join(samba3srcdir,
                            "script/tests/test_smbXsrv_client_dead_rec.sh"),
               configuration,
               '$SERVER_IP',
               "tmp"])

if have_cluster_support:
    plantestsuite("samba3.blackbox.smbXsrv_client_cross_node", "clusteredmember:local",
                  [os.path.join(samba3srcdir,
                                "script/tests/test_smbXsrv_client_cross_node.sh"),
                   configuration,
                   '$CTDB_SERVER_NAME_NODE0', '$CTDB_SERVER_NAME_NODE1',
                   "tmp"])
    plantestsuite("samba3.blackbox.smbXsrv_client_ctdb_registered_ips", "clusteredmember:local",
                  [os.path.join(samba3srcdir,
                                "script/tests/test_smbXsrv_client_ctdb_registered_ips.sh"),
                   configuration,
                   '$CTDB_IFACE_IP',
                   "tmp"])
    plantestsuite("samba3.blackbox.registry_share", "clusteredmember",
                  [os.path.join(samba3srcdir,
                                "script/tests/test_registry_share.sh"),
                   "$SERVER", '$DC_USERNAME', "$DC_PASSWORD"])

env = 'fileserver'
plantestsuite("samba3.blackbox.virus_scanner", "%s:local" % (env),
              [os.path.join(samba3srcdir,
                            "script/tests/test_virus_scanner.sh"),
               '$SERVER_IP',
               "virusfilter",
               '$LOCAL_PATH',
               smbclient3])

for env in ['fileserver', 'simpleserver']:
    plantestsuite("samba3.blackbox.smbclient.encryption", env,
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_encryption.sh"),
                   "$USERNAME", "$PASSWORD", "$SERVER",
                   smbclient3, env])

plantestsuite("samba3.blackbox.smbclient.kerberos", 'ad_dc',
              [os.path.join(samba3srcdir,
                            "script/tests/test_smbclient_kerberos.sh"),
               "alice",
               "$REALM",
               "Secret007",
               "$SERVER",
               smbclient3,
               env])
for env in ['ad_dc_fips', 'ad_member_fips']:
    plantestsuite("samba3.blackbox.smbclient.kerberos", env,
                  [os.path.join(samba3srcdir,
                                "script/tests/test_smbclient_kerberos.sh"),
                   "alice",
                   "$REALM",
                   "Secret007",
                   "$SERVER",
                   smbclient3,
                   env],
                  environ={'GNUTLS_FORCE_FIPS_MODE': '1',
                           'OPENSSL_FORCE_FIPS_MODE': '1'})

plantestsuite("samba3.blackbox.rpcclient_netsessenum", "ad_member",
              [os.path.join(samba3srcdir,
                            "script/tests/test_rpcclient_netsessenum.sh"),
               "$DOMAIN", "$DC_USERNAME", "$DC_PASSWORD", "$SERVER",
               os.path.join(bindir(), "rpcclient"), smbtorture3, "tmp"])

# The ktest environment uses:
# server min protocol = SMB3_00
# client max protocol = SMB3
options_list = ["", "--client-protection=encrypt"]
for options in options_list:
    plantestsuite("samba3.blackbox.smbclient_krb5 old ccache %s" % options, "ktest:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_krb5.sh"),
                   "$PREFIX/ktest/krb5_ccache-2",
                   smbclient3, "$SERVER", options, configuration])

    plantestsuite("samba3.blackbox.smbclient_krb5 new ccache %s" % options, "ktest:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_krb5.sh"),
                   "$PREFIX/ktest/krb5_ccache-3",
                   smbclient3, "$SERVER", options, configuration])

    plantestsuite("samba3.blackbox.smbclient_large_file %s krb5" % options, "ktest:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_large_file.sh"),
                   "$PREFIX/ktest/krb5_ccache-3",
                   smbclient3, "$SERVER", "$PREFIX", options, "--use-krb5-ccache=$PREFIX/ktest/krb5_ccache-3 " + configuration])

options_list = ["-mNT1", "-mNT1 --client-protection=encrypt", "-mSMB3", "-mSMB3 --client-protection=encrypt"]
for options in options_list:
    env = "nt4_dc"
    if "NT1" in options:
        env = "nt4_dc_smb1_done"
    plantestsuite("samba3.blackbox.smbclient_large_file %s NTLM" % options, "%s:local" % env,
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_large_file.sh"),
                   "none",
                   smbclient3, "$SERVER", "$PREFIX", options, "-U$USERNAME%$PASSWORD " + configuration])

for alias in ["foo", "bar"]:
    plantestsuite("samba3.blackbox.smbclient_netbios_aliases [%s]" % alias, "ad_member:local",
                  [os.path.join(samba3srcdir, "script/tests/test_smbclient_netbios_aliases.sh"),
                   smbclient3, alias, "$DC_USERNAME", "$DC_PASSWORD", "$PREFIX",
                   configuration])

for e in endianness_options:
    for a in auth_options:
        for s in signseal_options:
            binding_string = "ncacn_ip_tcp:$SERVER_IP[%s%s%s]" % (a, s, e)
            options = binding_string + " -U$USERNAME%$PASSWORD"
            plansmbtorture4testsuite(test, "nt4_dc", options, 'over ncacn_ip_tcp with [%s%s%s] ' % (a, s, e))

plansmbtorture4testsuite('rpc.epmapper', 'nt4_dc:local', 'ncalrpc: -U$USERNAME%$PASSWORD', 'over ncalrpc')
plansmbtorture4testsuite('rpc.fsrvp', 'nt4_dc:local', 'ncacn_np:$SERVER_IP -U$USERNAME%$PASSWORD', 'over ncacn_np')

for env in ["ad_member_idmap_rid:local", "maptoguest:local"]:
    plantestsuite("samba3.blackbox.guest", env,
                  [os.path.join(samba3srcdir, "script/tests/test_guest_auth.sh"),
                   '$SERVER', smbclient3, smbcontrol, net, configuration])

plantestsuite("samba3.blackbox.smbclient-mget",
              "fileserver",
              [os.path.join(samba3srcdir, "script/tests/test_smbclient_mget.sh"),
               smbclient3,
               "$SERVER",
               "tmp",
               "$USERNAME",
               "$PASSWORD",
               "valid_users"])

plantestsuite("samba3.blackbox.smbclient-bug15435",
              "fileserver",
              [os.path.join(samba3srcdir, "script/tests/test_bug15435_widelink_dfs.sh"),
               "$SERVER",
               "$SERVER_IP",
               "$USERNAME",
               "$PASSWORD",
               smbclient3,
               configuration])

plantestsuite("samba3.blackbox.widelink_dfs_ci",
              "fileserver",
              [os.path.join(samba3srcdir, "script/tests/test_widelink_dfs_ci.sh"),
               "$SERVER",
               "$SERVER_IP",
               "msdfs-share-wl",
               "$USERNAME",
               "$PASSWORD",
               "$PREFIX",
               smbclient3])


if have_cluster_support:
    t = "readdir-timestamp"
    plantestsuite(
        "samba3.smbtorture_s3.plain.%s" % t,
        "clusteredmember",
        [os.path.join(samba3srcdir,
                      "script/tests/test_smbtorture_s3.sh"),
         t,
         '//foo/bar',
         '$DOMAIN\\\\$DC_USERNAME',
         '$DC_PASSWORD',
         smbtorture3,
         "",
         "-b $PREFIX/clusteredmember/unclists/tmp.txt -N 5 -o 10"])

    plantestsuite(
        "samba3.net_machine_account",
        "clusteredmember",
        [os.path.join(samba3srcdir,
                      "script/tests/test_net_machine_account.sh"),
         "bin/net",
         "$SERVERCONFFILE",
         "$SERVER_IP"])

plantestsuite(
    "samba3.net_lookup_ldap",
    "ad_dc:local",
    [os.path.join(samba3srcdir,
                  "script/tests/test_net_lookup.sh"),
     '$DC_SERVER',
     '$DC_USERNAME',
     '$DC_PASSWORD',
     "bin/net",
     "bin/samba-tool",
     '$DNSNAME'])

for auth in ["$DC_USERNAME", "$DOMAIN\\\\$DC_USERNAME", "$DC_USERNAME@$REALM" ]:
    plantestsuite(
        "samba3.blackbox.net_ads_kerberos (%s)" % auth,
        "ad_member:local",
        [os.path.join(samba3srcdir,
                      "script/tests/test_net_ads_kerberos.sh"),
         auth,
         '$REALM',
         '$DC_PASSWORD',
         '$PREFIX',
         configuration])

plantestsuite("samba3.blackbox.force-user-unlink",
              "maptoguest:local",
              [os.path.join(samba3srcdir,
                            "script/tests/test_force_user_unlink.sh")])

plansmbtorture4testsuite(
    "vfs.fruit_validate_afpinfo", "fileserver",
    '//$SERVER_IP/vfs_fruit -U$USERNAME%$PASSWORD --option=torture:validate_afpinfo=yes')
plansmbtorture4testsuite(
    "vfs.fruit_validate_afpinfo", "fileserver",
    '//$SERVER_IP/vfs_fruit_zero_fileid -U$USERNAME%$PASSWORD --option=torture:validate_afpinfo=no')

plantestsuite("samba3.blackbox.nt4_trusts",
              "fl2008r2dc",
              [os.path.join(samba3srcdir, "script/tests/test_nt4_trust.sh")])

plantestsuite("samba3.blackbox.list_nt4_trusts",
              "ad_member_idmap_ad",
              [os.path.join(samba3srcdir, "script/tests/test_list_nt4_trust.sh")])

def planclusteredmembertestsuite(tname, prefix):
    '''Define a clustered test for the clusteredmember environment'''

    tshare = 'tmp'

    autharg = '-U${DOMAIN}/${DC_USERNAME}%${DC_PASSWORD}'
    namearg = 'clustered.%s' % tname
    modnamearg = 'samba3.%s' % namearg
    extraargs = ''

    prefix = os.path.join(prefix, 'clusteredmember')
    unclist = os.path.join(prefix, 'unclists/%s.txt' % tshare)

    unclistarg = '--unclist=%s' % unclist
    sharearg = '//$SERVER_IP/%s' % tshare

    return selftesthelpers.plansmbtorture4testsuite(
        tname,
        'clusteredmember',
        [extraargs, unclistarg, sharearg, autharg, tname],
        target='samba3',
        modname=modnamearg)


if have_cluster_support:
    CLUSTERED_TESTS = [ 'smb2.deny.deny2' ]

    for test in CLUSTERED_TESTS:
        planclusteredmembertestsuite(test, "$PREFIX")

    CLUSTERED_LOCAL_TESTS = [
        "ctdbd-conn1",
        "local-dbwrap-ctdb1"
    ]

    for t in CLUSTERED_LOCAL_TESTS:
        plantestsuite(
            "samba3.%s" % t,
            "clusteredmember:local",
            [os.path.join(samba3srcdir, "script/tests/test_smbtorture_s3.sh"),
             t,
             '//foo/bar',
             '""',
             '""',
             smbtorture3,
             "-N 1000 -o 2000"])

planpythontestsuite("fileserver_smb1", "samba.tests.smb3unix")
planpythontestsuite("fileserver_smb1", "samba.tests.reparsepoints")
planpythontestsuite("fileserver_smb1", "samba.tests.smb2symlink")
planpythontestsuite("fileserver_smb1", "samba.tests.smb1posix")
