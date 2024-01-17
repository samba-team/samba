# user management
#
# user get-kerberos-ticket command - obtain a TGT for a database user
#
# Copyright Jelmer Vernooij 2010 <jelmer@samba.org>
# Copyright Theresa Halloran 2011 <theresahalloran@gmail.com>
# Copyright Andrew Bartlett 2023 <abartlet@samba.org>
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
from samba.credentials import Credentials
from .common import (
    GetPasswordCommand,
    gpg_decrypt,
    decrypt_samba_gpg_help,
)
from samba.dcerpc import samr

class cmd_user_get_kerberos_ticket(GetPasswordCommand):
    """Get a Kerberos Ticket Granting Ticket as a user

This command gets a Kerberos TGT using the password for a user/computer account.

The username specified on the command is the sAMAccountName.
The username may also be specified using the --filter option.

The command must be run from the root user id or another authorized
user id. The '-H' or '--URL' option supports ldap:// for remote Group
Managed Service accounts, and ldapi:// or tdb:// can be used to
adjust the local path. tdb:// is used by default for a bare path.

The --output-krb5-ccache option should point to a location for the
credentials cache.  The default is a FILE: type cache if no prefix is
specified.

The '--decrypt-samba-gpg' option triggers decryption of the
Primary:SambaGPG buffer to get the password.

Check with '--help' if this feature is available
in your environment or not (the python-gpgme package is required).  Please
note that you might need to set the GNUPGHOME environment variable.  If the
decryption key has a passphrase you have to make sure that the GPG_AGENT_INFO
environment variable has been set correctly and the passphrase is already
known by the gpg-agent.

Example1:
samba-tool user get-kerberos-ticket TestUser1 --output-krb5-ccache=/srv/service/krb5_ccache

Example2:
samba-tool user get-kerberos-ticket --filter='(samAccountName=TestUser3)' --output-krb5-ccache=FILE:/srv/service/krb5_ccache

    """
    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
        "hostopts": options.HostOptions,
    }

    takes_options = [
        Option("--filter", help="LDAP Filter to get Kerberos ticket for (must match single account)", type=str),
        Option("--output-krb5-ccache", type=str,
               help="Location of Kerberos credentials cache to write ticket into",
               metavar="CCACHE", dest="output_krb5_ccache"),
        Option("--decrypt-samba-gpg",
               help=decrypt_samba_gpg_help,
               action="store_true", default=False, dest="decrypt_samba_gpg"),
    ]

    takes_args = ["username?"]

    def run(self, username=None, H=None, filter=None,
            attributes=None, decrypt_samba_gpg=None,
            sambaopts=None, versionopts=None, hostopts=None,
            credopts=None, output_krb5_ccache=None):
        self.lp = sambaopts.get_loadparm()

        if decrypt_samba_gpg and not gpg_decrypt:
            raise CommandError(decrypt_samba_gpg_help)

        if filter is None and username is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        password_attrs = ["virtualClearTextUTF16", "samAccountName", "unicodePwd"]

        creds = credopts.get_credentials(self.lp)
        samdb = self.connect_for_passwords(url=hostopts.H, require_ldapi=False, creds=creds)

        obj = self.get_account_attributes(samdb, username,
                                          basedn=None,
                                          filter=filter,
                                          scope=ldb.SCOPE_SUBTREE,
                                          attrs=password_attrs,
                                          decrypt=decrypt_samba_gpg)

        lp_ctx = sambaopts.get_loadparm()

        creds = Credentials()
        creds.set_username(str(obj["samAccountName"][0]))
        creds.set_realm(samdb.domain_dns_name())

        utf16_pw = obj.get("virtualClearTextUTF16", idx=0)
        nt_pass = obj.get("unicodePwd", idx=0)
        if utf16_pw is not None:
            creds.set_utf16_password(utf16_pw)
        elif nt_pass is not None:
            nt_hash = samr.Password()
            nt_hash.hash = list(nt_pass)
            creds.set_nt_hash(nt_hash)
        else:
            if samdb.url.startswith("ldap://") or samdb.url.startswith("ldaps://"):
                raise CommandError("No password was available for this user.  "
                                   "Only Group Managed Service accounts allow access to passwords over LDAP, "
                                   "you may need to access the sam.ldb directly on the Samba AD DC and export the file.")
            else:
                raise CommandError("No password was available for this user")
        creds.guess(lp_ctx)
        creds.get_named_ccache(lp_ctx, output_krb5_ccache)
