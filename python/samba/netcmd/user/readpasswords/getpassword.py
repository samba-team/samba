# user management
#
# user getpassword command
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

import ldb
import samba.getopt as options
from samba.netcmd import CommandError, Option

from .common import (
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
