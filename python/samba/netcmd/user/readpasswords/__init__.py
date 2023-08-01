# user management
#
# user readpasswords commands
#
# Copyright Jelmer Vernooij 2010 <jelmer@samba.org>
# Copyright Theresa Halloran 2011 <theresahalloran@gmail.com>
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

import base64
import errno
import fcntl
import os
import signal
import time
from subprocess import Popen, PIPE, STDOUT

import ldb
import samba.getopt as options
from samba import Ldb, dsdb
from samba.dcerpc import misc, security
from samba.ndr import ndr_unpack
from samba.common import get_bytes
from samba.netcmd import CommandError, Option

from ..common import (
    GetPasswordCommand,
    gpg_decrypt,
    decrypt_samba_gpg_help,
    virtual_attributes_help
)


class cmd_user_getpassword(GetPasswordCommand):
    """Get the password fields of a user/computer account.

This command gets the logon password for a user/computer account.

The username specified on the command is the sAMAccountName.
The username may also be specified using the --filter option.

The command must be run from the root user id or another authorized user id.
The '-H' or '--URL' option only supports ldapi:// or [tdb://] and can be
used to adjust the local path. By default tdb:// is used by default.

The '--attributes' parameter takes a comma separated list of attributes,
which will be printed or given to the script specified by '--script'. If a
specified attribute is not available on an object it's silently omitted.
All attributes defined in the schema (e.g. the unicodePwd attribute holds
the NTHASH) and the following virtual attributes are possible (see --help
for which virtual attributes are supported in your environment):

   virtualClearTextUTF16: The raw cleartext as stored in the
                          'Primary:CLEARTEXT' (or 'Primary:SambaGPG'
                          with '--decrypt-samba-gpg') buffer inside of the
                          supplementalCredentials attribute. This typically
                          contains valid UTF-16-LE, but may contain random
                          bytes, e.g. for computer accounts.

   virtualClearTextUTF8:  As virtualClearTextUTF16, but converted to UTF-8
                          (only from valid UTF-16-LE).

   virtualSSHA:           As virtualClearTextUTF8, but a salted SHA-1
                          checksum, useful for OpenLDAP's '{SSHA}' algorithm.

   virtualCryptSHA256:    As virtualClearTextUTF8, but a salted SHA256
                          checksum, useful for OpenLDAP's '{CRYPT}' algorithm,
                          with a $5$... salt, see crypt(3) on modern systems.
                          The number of rounds used to calculate the hash can
                          also be specified. By appending ";rounds=x" to the
                          attribute name i.e. virtualCryptSHA256;rounds=10000
                          will calculate a SHA256 hash with 10,000 rounds.
                          Non numeric values for rounds are silently ignored.
                          The value is calculated as follows:
                          1) If a value exists in 'Primary:userPassword' with
                             the specified number of rounds it is returned.
                          2) If 'Primary:CLEARTEXT', or 'Primary:SambaGPG'
                             with '--decrypt-samba-gpg'. Calculate a hash with
                             the specified number of rounds.
                          3) Return the first CryptSHA256 value in
                             'Primary:userPassword'.


   virtualCryptSHA512:    As virtualClearTextUTF8, but a salted SHA512
                          checksum, useful for OpenLDAP's '{CRYPT}' algorithm,
                          with a $6$... salt, see crypt(3) on modern systems.
                          The number of rounds used to calculate the hash can
                          also be specified. By appending ";rounds=x" to the
                          attribute name i.e. virtualCryptSHA512;rounds=10000
                          will calculate a SHA512 hash with 10,000 rounds.
                          Non numeric values for rounds are silently ignored.
                          The value is calculated as follows:
                          1) If a value exists in 'Primary:userPassword' with
                             the specified number of rounds it is returned.
                          2) If 'Primary:CLEARTEXT', or 'Primary:SambaGPG'
                             with '--decrypt-samba-gpg'. Calculate a hash with
                             the specified number of rounds.
                          3) Return the first CryptSHA512 value in
                             'Primary:userPassword'.

   virtualWDigestNN:      The individual hash values stored in
                          'Primary:WDigest' where NN is the hash number in
                          the range 01 to 29.
                          NOTE: As at 22-05-2017 the documentation:
                          3.1.1.8.11.3.1 WDIGEST_CREDENTIALS Construction
                        https://msdn.microsoft.com/en-us/library/cc245680.aspx
                          is incorrect.

   virtualKerberosSalt:   This results the salt string that is used to compute
                          Kerberos keys from a UTF-8 cleartext password.

   virtualSambaGPG:       The raw cleartext as stored in the
                          'Primary:SambaGPG' buffer inside of the
                          supplementalCredentials attribute.
                          See the 'password hash gpg key ids' option in
                          smb.conf.

The '--decrypt-samba-gpg' option triggers decryption of the
Primary:SambaGPG buffer. Check with '--help' if this feature is available
in your environment or not (the python-gpgme package is required).  Please
note that you might need to set the GNUPGHOME environment variable.  If the
decryption key has a passphrase you have to make sure that the GPG_AGENT_INFO
environment variable has been set correctly and the passphrase is already
known by the gpg-agent.

Attributes with time values can take an additional format specifier, which
converts the time value into the requested format. The format can be specified
by adding ";format=formatSpecifier" to the requested attribute name, whereby
"formatSpecifier" must be a valid specifier. The syntax looks like:

  --attributes=attributeName;format=formatSpecifier

The following format specifiers are available:
  - GeneralizedTime (e.g. 20210224113259.0Z)
  - UnixTime        (e.g. 1614166392)
  - TimeSpec        (e.g. 161416639.267546892)

Attributes with an original NTTIME value of 0 and 9223372036854775807 are
treated as non-existing value.

Example1:
samba-tool user getpassword TestUser1 --attributes=pwdLastSet,virtualClearTextUTF8

Example2:
samba-tool user getpassword --filter=samaccountname=TestUser3 --attributes=msDS-KeyVersionNumber,unicodePwd,virtualClearTextUTF16

"""
    def __init__(self):
        super(cmd_user_getpassword, self).__init__()

    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for sam.ldb database or local ldapi server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        Option("--attributes", type=str,
               help=virtual_attributes_help,
               metavar="ATTRIBUTELIST", dest="attributes"),
        Option("--decrypt-samba-gpg",
               help=decrypt_samba_gpg_help,
               action="store_true", default=False, dest="decrypt_samba_gpg"),
    ]

    takes_args = ["username?"]

    def run(self, username=None, H=None, filter=None,
            attributes=None, decrypt_samba_gpg=None,
            sambaopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()

        if decrypt_samba_gpg and not gpg_decrypt:
            raise CommandError(decrypt_samba_gpg_help)

        if filter is None and username is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        if attributes is None:
            raise CommandError("Please specify --attributes")

        password_attrs = self.parse_attributes(attributes)

        samdb = self.connect_system_samdb(url=H, allow_local=True)

        obj = self.get_account_attributes(samdb, username,
                                          basedn=None,
                                          filter=filter,
                                          scope=ldb.SCOPE_SUBTREE,
                                          attrs=password_attrs,
                                          decrypt=decrypt_samba_gpg)

        ldif = samdb.write_ldif(obj, ldb.CHANGETYPE_NONE)
        self.outf.write("%s" % ldif)
        self.outf.write("Got password OK\n")


class cmd_user_syncpasswords(GetPasswordCommand):
    """Sync the password of user accounts.

This syncs logon passwords for user accounts.

Note that this command should run on a single domain controller only
(typically the PDC-emulator). However the "password hash gpg key ids"
option should to be configured on all domain controllers.

The command must be run from the root user id or another authorized user id.
The '-H' or '--URL' option only supports ldapi:// and can be used to adjust the
local path.  By default, ldapi:// is used with the default path to the
privileged ldapi socket.

This command has three modes: "Cache Initialization", "Sync Loop Run" and
"Sync Loop Terminate".


Cache Initialization
====================

The first time, this command needs to be called with
'--cache-ldb-initialize' in order to initialize its cache.

The cache initialization requires '--attributes' and allows the following
optional options: '--decrypt-samba-gpg', '--script', '--filter' or
'-H/--URL'.

The '--attributes' parameter takes a comma separated list of attributes,
which will be printed or given to the script specified by '--script'. If a
specified attribute is not available on an object it will be silently omitted.
All attributes defined in the schema (e.g. the unicodePwd attribute holds
the NTHASH) and the following virtual attributes are possible (see '--help'
for supported virtual attributes in your environment):

   virtualClearTextUTF16: The raw cleartext as stored in the
                          'Primary:CLEARTEXT' (or 'Primary:SambaGPG'
                          with '--decrypt-samba-gpg') buffer inside of the
                          supplementalCredentials attribute. This typically
                          contains valid UTF-16-LE, but may contain random
                          bytes, e.g. for computer accounts.

   virtualClearTextUTF8:  As virtualClearTextUTF16, but converted to UTF-8
                          (only from valid UTF-16-LE).

   virtualSSHA:           As virtualClearTextUTF8, but a salted SHA-1
                          checksum, useful for OpenLDAP's '{SSHA}' algorithm.

   virtualCryptSHA256:    As virtualClearTextUTF8, but a salted SHA256
                          checksum, useful for OpenLDAP's '{CRYPT}' algorithm,
                          with a $5$... salt, see crypt(3) on modern systems.
                          The number of rounds used to calculate the hash can
                          also be specified. By appending ";rounds=x" to the
                          attribute name i.e. virtualCryptSHA256;rounds=10000
                          will calculate a SHA256 hash with 10,000 rounds.
                          Non numeric values for rounds are silently ignored.
                          The value is calculated as follows:
                          1) If a value exists in 'Primary:userPassword' with
                             the specified number of rounds it is returned.
                          2) If 'Primary:CLEARTEXT', or 'Primary:SambaGPG' with
                             '--decrypt-samba-gpg'. Calculate a hash with
                             the specified number of rounds
                          3) Return the first CryptSHA256 value in
                             'Primary:userPassword'.

   virtualCryptSHA512:    As virtualClearTextUTF8, but a salted SHA512
                          checksum, useful for OpenLDAP's '{CRYPT}' algorithm,
                          with a $6$... salt, see crypt(3) on modern systems.
                          The number of rounds used to calculate the hash can
                          also be specified. By appending ";rounds=x" to the
                          attribute name i.e. virtualCryptSHA512;rounds=10000
                          will calculate a SHA512 hash with 10,000 rounds.
                          Non numeric values for rounds are silently ignored.
                          The value is calculated as follows:
                          1) If a value exists in 'Primary:userPassword' with
                             the specified number of rounds it is returned.
                          2) If 'Primary:CLEARTEXT', or 'Primary:SambaGPG' with
                             '--decrypt-samba-gpg'. Calculate a hash with
                             the specified number of rounds.
                          3) Return the first CryptSHA512 value in
                             'Primary:userPassword'.

   virtualWDigestNN:      The individual hash values stored in
                          'Primary:WDigest' where NN is the hash number in
                          the range 01 to 29.
                          NOTE: As at 22-05-2017 the documentation:
                          3.1.1.8.11.3.1 WDIGEST_CREDENTIALS Construction
                        https://msdn.microsoft.com/en-us/library/cc245680.aspx
                          is incorrect.

   virtualKerberosSalt:   This results the salt string that is used to compute
                          Kerberos keys from a UTF-8 cleartext password.

   virtualSambaGPG:       The raw cleartext as stored in the
                          'Primary:SambaGPG' buffer inside of the
                          supplementalCredentials attribute.
                          See the 'password hash gpg key ids' option in
                          smb.conf.

The '--decrypt-samba-gpg' option triggers decryption of the
Primary:SambaGPG buffer. Check with '--help' if this feature is available
in your environment or not (the python-gpgme package is required).  Please
note that you might need to set the GNUPGHOME environment variable.  If the
decryption key has a passphrase you have to make sure that the GPG_AGENT_INFO
environment variable has been set correctly and the passphrase is already
known by the gpg-agent.

The '--script' option specifies a custom script that is called whenever any
of the dirsyncAttributes (see below) was changed. The script is called
without any arguments. It gets the LDIF for exactly one object on STDIN.
If the script processed the object successfully it has to respond with a
single line starting with 'DONE-EXIT: ' followed by an optional message.

Note that the script might be called without any password change, e.g. if
the account was disabled (a userAccountControl change) or the
sAMAccountName was changed. The objectGUID,isDeleted,isRecycled attributes
are always returned as unique identifier of the account. It might be useful
to also ask for non-password attributes like: objectSid, sAMAccountName,
userPrincipalName, userAccountControl, pwdLastSet and msDS-KeyVersionNumber.
Depending on the object, some attributes may not be present/available,
but you always get the current state (and not a diff).

If no '--script' option is specified, the LDIF will be printed on STDOUT or
into the logfile.

The default filter for the LDAP_SERVER_DIRSYNC_OID search is:
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=512)\\
    (!(sAMAccountName=krbtgt*)))
This means only normal (non-krbtgt) user
accounts are monitored.  The '--filter' can modify that, e.g. if it's
required to also sync computer accounts.


Sync Loop Run
=============

This (default) mode runs in an endless loop waiting for password related
changes in the active directory database. It makes use of the
LDAP_SERVER_DIRSYNC_OID and LDAP_SERVER_NOTIFICATION_OID controls in order
get changes in a reliable fashion. Objects are monitored for changes of the
following dirsyncAttributes:

  unicodePwd, dBCSPwd, supplementalCredentials, pwdLastSet, sAMAccountName,
  userPrincipalName and userAccountControl.

It recovers from LDAP disconnects and updates the cache in conservative way
(in single steps after each successfully processed change).  An error from
the script (specified by '--script') will result in fatal error and this
command will exit.  But the cache state should be still valid and can be
resumed in the next "Sync Loop Run".

The '--logfile' option specifies an optional (required if '--daemon' is
specified) logfile that takes all output of the command. The logfile is
automatically reopened if fstat returns st_nlink == 0.

The optional '--daemon' option will put the command into the background.

You can stop the command without the '--daemon' option, also by hitting
strg+c.

If you specify the '--no-wait' option the command skips the
LDAP_SERVER_NOTIFICATION_OID 'waiting' step and exit once
all LDAP_SERVER_DIRSYNC_OID changes are consumed.

Sync Loop Terminate
===================

In order to terminate an already running command (likely as daemon) the
'--terminate' option can be used. This also requires the '--logfile' option
to be specified.


Example1:
samba-tool user syncpasswords --cache-ldb-initialize \\
    --attributes=virtualClearTextUTF8
samba-tool user syncpasswords

Example2:
samba-tool user syncpasswords --cache-ldb-initialize \\
    --attributes=objectGUID,objectSID,sAMAccountName,\\
    userPrincipalName,userAccountControl,pwdLastSet,\\
    msDS-KeyVersionNumber,virtualCryptSHA512 \\
    --script=/path/to/my-custom-syncpasswords-script.py
samba-tool user syncpasswords --daemon \\
    --logfile=/var/log/samba/user-syncpasswords.log
samba-tool user syncpasswords --terminate \\
    --logfile=/var/log/samba/user-syncpasswords.log

"""
    def __init__(self):
        super(cmd_user_syncpasswords, self).__init__()

    synopsis = "%prog [--cache-ldb-initialize] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("--cache-ldb-initialize",
               help="Initialize the cache for the first time",
               dest="cache_ldb_initialize", action="store_true"),
        Option("--cache-ldb", help="optional LDB URL user-syncpasswords-cache.ldb", type=str,
               metavar="CACHE-LDB-PATH", dest="cache_ldb"),
        Option("-H", "--URL", help="optional LDB URL for a local ldapi server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="optional LDAP filter to set password on", type=str,
               metavar="LDAP-SEARCH-FILTER", dest="filter"),
        Option("--attributes", type=str,
               help=virtual_attributes_help,
               metavar="ATTRIBUTELIST", dest="attributes"),
        Option("--decrypt-samba-gpg",
               help=decrypt_samba_gpg_help,
               action="store_true", default=False, dest="decrypt_samba_gpg"),
        Option("--script", help="Script that is called for each password change", type=str,
               metavar="/path/to/syncpasswords.script", dest="script"),
        Option("--no-wait", help="Don't block waiting for changes",
               action="store_true", default=False, dest="nowait"),
        Option("--logfile", type=str,
               help="The logfile to use (required in --daemon mode).",
               metavar="/path/to/syncpasswords.log", dest="logfile"),
        Option("--daemon", help="daemonize after initial setup",
               action="store_true", default=False, dest="daemon"),
        Option("--terminate",
               help="Send a SIGTERM to an already running (daemon) process",
               action="store_true", default=False, dest="terminate"),
    ]

    def run(self, cache_ldb_initialize=False, cache_ldb=None,
            H=None, filter=None,
            attributes=None, decrypt_samba_gpg=None,
            script=None, nowait=None, logfile=None, daemon=None, terminate=None,
            sambaopts=None, versionopts=None):

        self.lp = sambaopts.get_loadparm()
        self.logfile = None
        self.samdb_url = None
        self.samdb = None
        self.cache = None

        if not cache_ldb_initialize:
            if attributes is not None:
                raise CommandError("--attributes is only allowed together with --cache-ldb-initialize")
            if decrypt_samba_gpg:
                raise CommandError("--decrypt-samba-gpg is only allowed together with --cache-ldb-initialize")
            if script is not None:
                raise CommandError("--script is only allowed together with --cache-ldb-initialize")
            if filter is not None:
                raise CommandError("--filter is only allowed together with --cache-ldb-initialize")
            if H is not None:
                raise CommandError("-H/--URL is only allowed together with --cache-ldb-initialize")
        else:
            if nowait is not False:
                raise CommandError("--no-wait is not allowed together with --cache-ldb-initialize")
            if logfile is not None:
                raise CommandError("--logfile is not allowed together with --cache-ldb-initialize")
            if daemon is not False:
                raise CommandError("--daemon is not allowed together with --cache-ldb-initialize")
            if terminate is not False:
                raise CommandError("--terminate is not allowed together with --cache-ldb-initialize")

        if nowait is True:
            if daemon is True:
                raise CommandError("--daemon is not allowed together with --no-wait")
            if terminate is not False:
                raise CommandError("--terminate is not allowed together with --no-wait")

        if terminate is True and daemon is True:
            raise CommandError("--terminate is not allowed together with --daemon")

        if daemon is True and logfile is None:
            raise CommandError("--daemon is only allowed together with --logfile")

        if terminate is True and logfile is None:
            raise CommandError("--terminate is only allowed together with --logfile")

        if script is not None:
            if not os.path.exists(script):
                raise CommandError("script[%s] does not exist!" % script)

            sync_command = "%s" % os.path.abspath(script)
        else:
            sync_command = None

        dirsync_filter = filter
        if dirsync_filter is None:
            dirsync_filter = "(&" + \
                               "(objectClass=user)" + \
                               "(userAccountControl:%s:=%u)" % (
                                   ldb.OID_COMPARATOR_AND, dsdb.UF_NORMAL_ACCOUNT) + \
                               "(!(sAMAccountName=krbtgt*))" + \
                             ")"

        dirsync_secret_attrs = [
            "unicodePwd",
            "dBCSPwd",
            "supplementalCredentials",
        ]

        dirsync_attrs = dirsync_secret_attrs + [
            "pwdLastSet",
            "sAMAccountName",
            "userPrincipalName",
            "userAccountControl",
            "isDeleted",
            "isRecycled",
        ]

        password_attrs = None

        if cache_ldb_initialize:
            if H is None:
                H = "ldapi://%s" % os.path.abspath(self.lp.private_path("ldap_priv/ldapi"))

            if decrypt_samba_gpg and not gpg_decrypt:
                raise CommandError(decrypt_samba_gpg_help)

            password_attrs = self.parse_attributes(attributes)
            lower_attrs = [x.lower() for x in password_attrs]
            # We always return these in order to track deletions
            for a in ["objectGUID", "isDeleted", "isRecycled"]:
                if a.lower() not in lower_attrs:
                    password_attrs += [a]

        if cache_ldb is not None:
            if cache_ldb.lower().startswith("ldapi://"):
                raise CommandError("--cache_ldb ldapi:// is not supported")
            elif cache_ldb.lower().startswith("ldap://"):
                raise CommandError("--cache_ldb ldap:// is not supported")
            elif cache_ldb.lower().startswith("ldaps://"):
                raise CommandError("--cache_ldb ldaps:// is not supported")
            elif cache_ldb.lower().startswith("tdb://"):
                pass
            else:
                if not os.path.exists(cache_ldb):
                    cache_ldb = self.lp.private_path(cache_ldb)
        else:
            cache_ldb = self.lp.private_path("user-syncpasswords-cache.ldb")

        self.lockfile = "%s.pid" % cache_ldb

        def log_msg(msg):
            if self.logfile is not None:
                info = os.fstat(0)
                if info.st_nlink == 0:
                    logfile = self.logfile
                    self.logfile = None
                    log_msg("Closing logfile[%s] (st_nlink == 0)\n" % (logfile))
                    logfd = os.open(logfile, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                    os.dup2(logfd, 0)
                    os.dup2(logfd, 1)
                    os.dup2(logfd, 2)
                    os.close(logfd)
                    log_msg("Reopened logfile[%s]\n" % (logfile))
                    self.logfile = logfile
            msg = "%s: pid[%d]: %s" % (
                    time.ctime(),
                    os.getpid(),
                    msg)
            self.outf.write(msg)
            return

        def load_cache():
            cache_attrs = [
                "samdbUrl",
                "dirsyncFilter",
                "dirsyncAttribute",
                "dirsyncControl",
                "passwordAttribute",
                "decryptSambaGPG",
                "syncCommand",
                "currentPid",
            ]

            self.cache = Ldb(cache_ldb)
            self.cache_dn = ldb.Dn(self.cache, "KEY=USERSYNCPASSWORDS")
            res = self.cache.search(base=self.cache_dn, scope=ldb.SCOPE_BASE,
                                    attrs=cache_attrs)
            if len(res) == 1:
                try:
                    self.samdb_url = str(res[0]["samdbUrl"][0])
                except KeyError as e:
                    self.samdb_url = None
            else:
                self.samdb_url = None
            if self.samdb_url is None and not cache_ldb_initialize:
                raise CommandError("cache_ldb[%s] not initialized, use --cache-ldb-initialize the first time" % (
                                   cache_ldb))
            if self.samdb_url is not None and cache_ldb_initialize:
                raise CommandError("cache_ldb[%s] already initialized, --cache-ldb-initialize not allowed" % (
                                   cache_ldb))
            if self.samdb_url is None:
                self.samdb_url = H
                self.dirsync_filter = dirsync_filter
                self.dirsync_attrs = dirsync_attrs
                self.dirsync_controls = ["dirsync:1:0:0", "extended_dn:1:0"]
                self.password_attrs = password_attrs
                self.decrypt_samba_gpg = decrypt_samba_gpg
                self.sync_command = sync_command
                add_ldif = "dn: %s\n" % self.cache_dn +\
                           "objectClass: userSyncPasswords\n" +\
                           "samdbUrl:: %s\n" % base64.b64encode(get_bytes(self.samdb_url)).decode('utf8') +\
                           "dirsyncFilter:: %s\n" % base64.b64encode(get_bytes(self.dirsync_filter)).decode('utf8') +\
                           "".join("dirsyncAttribute:: %s\n" % base64.b64encode(get_bytes(a)).decode('utf8') for a in self.dirsync_attrs) +\
                           "dirsyncControl: %s\n" % self.dirsync_controls[0] +\
                           "".join("passwordAttribute:: %s\n" % base64.b64encode(get_bytes(a)).decode('utf8') for a in self.password_attrs)
                if self.decrypt_samba_gpg:
                    add_ldif += "decryptSambaGPG: TRUE\n"
                else:
                    add_ldif += "decryptSambaGPG: FALSE\n"
                if self.sync_command is not None:
                    add_ldif += "syncCommand: %s\n" % self.sync_command
                add_ldif += "currentTime: %s\n" % ldb.timestring(int(time.time()))
                self.cache.add_ldif(add_ldif)
                self.current_pid = None
                self.outf.write("Initialized cache_ldb[%s]\n" % (cache_ldb))
                msgs = self.cache.parse_ldif(add_ldif)
                changetype, msg = next(msgs)
                ldif = self.cache.write_ldif(msg, ldb.CHANGETYPE_NONE)
                self.outf.write("%s" % ldif)
            else:
                self.dirsync_filter = str(res[0]["dirsyncFilter"][0])
                self.dirsync_attrs = []
                for a in res[0]["dirsyncAttribute"]:
                    self.dirsync_attrs.append(str(a))
                self.dirsync_controls = [str(res[0]["dirsyncControl"][0]), "extended_dn:1:0"]
                self.password_attrs = []
                for a in res[0]["passwordAttribute"]:
                    self.password_attrs.append(str(a))
                decrypt_string = str(res[0]["decryptSambaGPG"][0])
                assert(decrypt_string in ["TRUE", "FALSE"])
                if decrypt_string == "TRUE":
                    self.decrypt_samba_gpg = True
                else:
                    self.decrypt_samba_gpg = False
                if "syncCommand" in res[0]:
                    self.sync_command = str(res[0]["syncCommand"][0])
                else:
                    self.sync_command = None
                if "currentPid" in res[0]:
                    self.current_pid = int(res[0]["currentPid"][0])
                else:
                    self.current_pid = None
                log_msg("Using cache_ldb[%s]\n" % (cache_ldb))

            return

        def run_sync_command(dn, ldif):
            log_msg("Call Popen[%s] for %s\n" % (self.sync_command, dn))
            sync_command_p = Popen(self.sync_command,
                                   stdin=PIPE,
                                   stdout=PIPE,
                                   stderr=STDOUT)

            res = sync_command_p.poll()
            assert res is None

            input = "%s" % (ldif)
            reply = sync_command_p.communicate(
                input.encode('utf-8'))[0].decode('utf-8')
            log_msg("%s\n" % (reply))
            res = sync_command_p.poll()
            if res is None:
                sync_command_p.terminate()
            res = sync_command_p.wait()

            if reply.startswith("DONE-EXIT: "):
                return

            log_msg("RESULT: %s\n" % (res))
            raise Exception("ERROR: %s - %s\n" % (res, reply))

        def handle_object(idx, dirsync_obj):
            binary_guid = dirsync_obj.dn.get_extended_component("GUID")
            guid = ndr_unpack(misc.GUID, binary_guid)
            binary_sid = dirsync_obj.dn.get_extended_component("SID")
            sid = ndr_unpack(security.dom_sid, binary_sid)
            domain_sid, rid = sid.split()
            if rid == security.DOMAIN_RID_KRBTGT:
                log_msg("# Dirsync[%d] SKIP: DOMAIN_RID_KRBTGT\n\n" % (idx))
                return
            for a in list(dirsync_obj.keys()):
                for h in dirsync_secret_attrs:
                    if a.lower() == h.lower():
                        del dirsync_obj[a]
                        dirsync_obj["# %s::" % a] = ["REDACTED SECRET ATTRIBUTE"]
            dirsync_ldif = self.samdb.write_ldif(dirsync_obj, ldb.CHANGETYPE_NONE)
            log_msg("# Dirsync[%d] %s %s\n%s" % (idx, guid, sid, dirsync_ldif))
            obj = self.get_account_attributes(self.samdb,
                                              username="%s" % sid,
                                              basedn="<GUID=%s>" % guid,
                                              filter="(objectClass=user)",
                                              scope=ldb.SCOPE_BASE,
                                              attrs=self.password_attrs,
                                              decrypt=self.decrypt_samba_gpg)
            ldif = self.samdb.write_ldif(obj, ldb.CHANGETYPE_NONE)
            log_msg("# Passwords[%d] %s %s\n" % (idx, guid, sid))
            if self.sync_command is None:
                self.outf.write("%s" % (ldif))
                return
            self.outf.write("# attrs=%s\n" % (sorted(obj.keys())))
            run_sync_command(obj.dn, ldif)

        def check_current_pid_conflict(terminate):
            flags = os.O_RDWR
            if not terminate:
                flags |= os.O_CREAT

            try:
                self.lockfd = os.open(self.lockfile, flags, 0o600)
            except IOError as e4:
                (err, msg) = e4.args
                if err == errno.ENOENT:
                    if terminate:
                        return False
                log_msg("check_current_pid_conflict: failed to open[%s] - %s (%d)" %
                        (self.lockfile, msg, err))
                raise

            got_exclusive = False
            try:
                fcntl.lockf(self.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                got_exclusive = True
            except IOError as e5:
                (err, msg) = e5.args
                if err != errno.EACCES and err != errno.EAGAIN:
                    log_msg("check_current_pid_conflict: failed to get exclusive lock[%s] - %s (%d)" %
                            (self.lockfile, msg, err))
                    raise

            if not got_exclusive:
                buf = os.read(self.lockfd, 64)
                self.current_pid = None
                try:
                    self.current_pid = int(buf)
                except ValueError as e:
                    pass
                if self.current_pid is not None:
                    return True

            if got_exclusive and terminate:
                try:
                    os.ftruncate(self.lockfd, 0)
                except IOError as e2:
                    (err, msg) = e2.args
                    log_msg("check_current_pid_conflict: failed to truncate [%s] - %s (%d)" %
                            (self.lockfile, msg, err))
                    raise
                os.close(self.lockfd)
                self.lockfd = -1
                return False

            try:
                fcntl.lockf(self.lockfd, fcntl.LOCK_SH)
            except IOError as e6:
                (err, msg) = e6.args
                log_msg("check_current_pid_conflict: failed to get shared lock[%s] - %s (%d)" %
                        (self.lockfile, msg, err))

            # We leave the function with the shared lock.
            return False

        def update_pid(pid):
            if self.lockfd != -1:
                got_exclusive = False
                # Try 5 times to get the exclusive lock.
                for i in range(0, 5):
                    try:
                        fcntl.lockf(self.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        got_exclusive = True
                    except IOError as e:
                        (err, msg) = e.args
                        if err != errno.EACCES and err != errno.EAGAIN:
                            log_msg("update_pid(%r): failed to get exclusive lock[%s] - %s (%d)" %
                                    (pid, self.lockfile, msg, err))
                            raise
                    if got_exclusive:
                        break
                    time.sleep(1)
                if not got_exclusive:
                    log_msg("update_pid(%r): failed to get exclusive lock[%s]" %
                            (pid, self.lockfile))
                    raise CommandError("update_pid(%r): failed to get "
                                       "exclusive lock[%s] after 5 seconds" %
                                       (pid, self.lockfile))

                if pid is not None:
                    buf = "%d\n" % pid
                else:
                    buf = None
                try:
                    os.ftruncate(self.lockfd, 0)
                    if buf is not None:
                        os.write(self.lockfd, get_bytes(buf))
                except IOError as e3:
                    (err, msg) = e3.args
                    log_msg("check_current_pid_conflict: failed to write pid to [%s] - %s (%d)" %
                            (self.lockfile, msg, err))
                    raise
            self.current_pid = pid
            if self.current_pid is not None:
                log_msg("currentPid: %d\n" % self.current_pid)

            modify_ldif = "dn: %s\n" % (self.cache_dn) +\
                          "changetype: modify\n" +\
                          "replace: currentPid\n"
            if self.current_pid is not None:
                modify_ldif += "currentPid: %d\n" % (self.current_pid)
            modify_ldif += "replace: currentTime\n" +\
                           "currentTime: %s\n" % ldb.timestring(int(time.time()))
            self.cache.modify_ldif(modify_ldif)
            return

        def update_cache(res_controls):
            assert len(res_controls) > 0
            assert res_controls[0].oid == "1.2.840.113556.1.4.841"
            res_controls[0].critical = True
            self.dirsync_controls = [str(res_controls[0]), "extended_dn:1:0"]
            # This cookie can be extremely long
            # log_msg("dirsyncControls: %r\n" % self.dirsync_controls)

            modify_ldif = "dn: %s\n" % (self.cache_dn) +\
                          "changetype: modify\n" +\
                          "replace: dirsyncControl\n" +\
                          "dirsyncControl: %s\n" % (self.dirsync_controls[0]) +\
                          "replace: currentTime\n" +\
                          "currentTime: %s\n" % ldb.timestring(int(time.time()))
            self.cache.modify_ldif(modify_ldif)
            return

        def check_object(dirsync_obj, res_controls):
            assert len(res_controls) > 0
            assert res_controls[0].oid == "1.2.840.113556.1.4.841"

            binary_sid = dirsync_obj.dn.get_extended_component("SID")
            sid = ndr_unpack(security.dom_sid, binary_sid)
            dn = "KEY=%s" % sid
            lastCookie = str(res_controls[0])

            res = self.cache.search(base=dn, scope=ldb.SCOPE_BASE,
                                    expression="(lastCookie=%s)" % (
                                        ldb.binary_encode(lastCookie)),
                                    attrs=[])
            if len(res) == 1:
                return True
            return False

        def update_object(dirsync_obj, res_controls):
            assert len(res_controls) > 0
            assert res_controls[0].oid == "1.2.840.113556.1.4.841"

            binary_sid = dirsync_obj.dn.get_extended_component("SID")
            sid = ndr_unpack(security.dom_sid, binary_sid)
            dn = "KEY=%s" % sid
            lastCookie = str(res_controls[0])

            self.cache.transaction_start()
            try:
                res = self.cache.search(base=dn, scope=ldb.SCOPE_BASE,
                                        expression="(objectClass=*)",
                                        attrs=["lastCookie"])
                if len(res) == 0:
                    add_ldif  = "dn: %s\n" % (dn) +\
                                "objectClass: userCookie\n" +\
                                "lastCookie: %s\n" % (lastCookie) +\
                                "currentTime: %s\n" % ldb.timestring(int(time.time()))
                    self.cache.add_ldif(add_ldif)
                else:
                    modify_ldif = "dn: %s\n" % (dn) +\
                                  "changetype: modify\n" +\
                                  "replace: lastCookie\n" +\
                                  "lastCookie: %s\n" % (lastCookie) +\
                                  "replace: currentTime\n" +\
                                  "currentTime: %s\n" % ldb.timestring(int(time.time()))
                    self.cache.modify_ldif(modify_ldif)
                self.cache.transaction_commit()
            except Exception as e:
                self.cache.transaction_cancel()

            return

        def dirsync_loop():
            while True:
                res = self.samdb.search(expression=str(self.dirsync_filter),
                                        scope=ldb.SCOPE_SUBTREE,
                                        attrs=self.dirsync_attrs,
                                        controls=self.dirsync_controls)
                log_msg("dirsync_loop(): results %d\n" % len(res))
                ri = 0
                for r in res:
                    done = check_object(r, res.controls)
                    if not done:
                        handle_object(ri, r)
                        update_object(r, res.controls)
                    ri += 1
                update_cache(res.controls)
                if len(res) == 0:
                    break

        def sync_loop(wait):
            notify_attrs = ["name", "uSNCreated", "uSNChanged", "objectClass"]
            notify_controls = ["notification:1", "show_recycled:1"]
            notify_handle = self.samdb.search_iterator(expression="objectClass=*",
                                                       scope=ldb.SCOPE_SUBTREE,
                                                       attrs=notify_attrs,
                                                       controls=notify_controls,
                                                       timeout=-1)

            if wait is True:
                log_msg("Resuming monitoring\n")
            else:
                log_msg("Getting changes\n")
            self.outf.write("dirsyncFilter: %s\n" % self.dirsync_filter)
            self.outf.write("dirsyncControls: %r\n" % self.dirsync_controls)
            self.outf.write("syncCommand: %s\n" % self.sync_command)
            dirsync_loop()

            if wait is not True:
                return

            for msg in notify_handle:
                if not isinstance(msg, ldb.Message):
                    self.outf.write("referral: %s\n" % msg)
                    continue
                created = msg.get("uSNCreated")[0]
                changed = msg.get("uSNChanged")[0]
                log_msg("# Notify %s uSNCreated[%s] uSNChanged[%s]\n" %
                        (msg.dn, created, changed))

                dirsync_loop()

            res = notify_handle.result()

        def daemonize():
            self.samdb = None
            self.cache = None
            orig_pid = os.getpid()
            pid = os.fork()
            if pid == 0:
                os.setsid()
                pid = os.fork()
                if pid == 0:  # Actual daemon
                    pid = os.getpid()
                    log_msg("Daemonized as pid %d (from %d)\n" % (pid, orig_pid))
                    load_cache()
                    return
            os._exit(0)

        if cache_ldb_initialize:
            self.samdb_url = H
            self.samdb = self.connect_system_samdb(url=self.samdb_url,
                                                   verbose=True)
            load_cache()
            return

        if logfile is not None:
            import resource      # Resource usage information.
            maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
            if maxfd == resource.RLIM_INFINITY:
                maxfd = 1024  # Rough guess at maximum number of open file descriptors.
            logfd = os.open(logfile, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            self.outf.write("Using logfile[%s]\n" % logfile)
            for fd in range(0, maxfd):
                if fd == logfd:
                    continue
                try:
                    os.close(fd)
                except OSError:
                    pass
            os.dup2(logfd, 0)
            os.dup2(logfd, 1)
            os.dup2(logfd, 2)
            os.close(logfd)
            log_msg("Attached to logfile[%s]\n" % (logfile))
            self.logfile = logfile

        load_cache()
        conflict = check_current_pid_conflict(terminate)
        if terminate:
            if self.current_pid is None:
                log_msg("No process running.\n")
                return
            if not conflict:
                log_msg("Process %d is not running anymore.\n" % (
                        self.current_pid))
                update_pid(None)
                return
            log_msg("Sending SIGTERM to process %d.\n" % (
                    self.current_pid))
            os.kill(self.current_pid, signal.SIGTERM)
            return
        if conflict:
            raise CommandError("Exiting pid %d, command is already running as pid %d" % (
                               os.getpid(), self.current_pid))

        if daemon is True:
            daemonize()
        update_pid(os.getpid())

        wait = True
        while wait is True:
            retry_sleep_min = 1
            retry_sleep_max = 600
            if nowait is True:
                wait = False
                retry_sleep = 0
            else:
                retry_sleep = retry_sleep_min

            while self.samdb is None:
                if retry_sleep != 0:
                    log_msg("Wait before connect - sleep(%d)\n" % retry_sleep)
                    time.sleep(retry_sleep)
                retry_sleep = retry_sleep * 2
                if retry_sleep >= retry_sleep_max:
                    retry_sleep = retry_sleep_max
                log_msg("Connecting to '%s'\n" % self.samdb_url)
                try:
                    self.samdb = self.connect_system_samdb(url=self.samdb_url)
                except Exception as msg:
                    self.samdb = None
                    log_msg("Connect to samdb Exception => (%s)\n" % msg)
                    if wait is not True:
                        raise

            try:
                sync_loop(wait)
            except ldb.LdbError as e7:
                (enum, estr) = e7.args
                self.samdb = None
                log_msg("ldb.LdbError(%d) => (%s)\n" % (enum, estr))

        update_pid(None)
        return
