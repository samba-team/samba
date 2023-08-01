# user management
#
# user show command
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

import samba.getopt as options
from samba import dsdb, ldb
from samba.auth import system_session
from samba.netcmd import Option, common
from samba.samdb import SamDB

from ..common import GetPasswordCommand


class cmd_user_show(GetPasswordCommand):
    """Display a user AD object.

This command displays a user account and it's attributes in the Active
Directory domain.
The username specified on the command is the sAMAccountName.

The command may be run from the root userid or another authorized userid.

The -H or --URL= option can be used to execute the command against a remote
server.

The '--attributes' parameter takes a comma separated list of the requested
attributes. Without '--attributes' or with '--attributes=*' all usually
available attributes are selected.
Hidden attributes in addition to all usually available attributes can be
selected with e.g. '--attributes=*,msDS-UserPasswordExpiryTimeComputed'.
If a specified attribute is not available on a user object it's silently
omitted.

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
samba-tool user show User1 -H ldap://samba.samdom.example.com \\
    -U administrator --password=passw1rd

Example1 shows how to display a users attributes in the domain against a remote
LDAP server.

The -H parameter is used to specify the remote target server.

Example2:
samba-tool user show User2

Example2 shows how to display a users attributes in the domain against a local
LDAP server.

Example3:
samba-tool user show User2 --attributes=objectSid,memberOf

Example3 shows how to display a users objectSid and memberOf attributes.

Example4:
samba-tool user show User2 \\
    --attributes='pwdLastSet;format=GeneralizedTime,pwdLastSet;format=UnixTime'

The result of Example 4 provides the pwdLastSet attribute values in the
specified format:
    dn: CN=User2,CN=Users,DC=samdom,DC=example,DC=com
    pwdLastSet;format=GeneralizedTime: 20210120105207.0Z
    pwdLastSet;format=UnixTime: 1611139927
"""
    synopsis = "%prog <username> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--attributes",
               help=("Comma separated list of attributes, "
                     "which will be printed. "
                     "Possible supported virtual attributes: "
                     "virtualGeneralizedTime, virtualUnixTime, virtualTimeSpec."),
               type=str, dest="user_attrs"),
    ]

    takes_args = ["username"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, username, credopts=None, sambaopts=None, versionopts=None,
            H=None, user_attrs=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        self.inject_virtual_attributes(samdb)

        if user_attrs:
            attrs = self.parse_attributes(user_attrs)
        else:
            attrs = ["*"]

        filter = ("(&(sAMAccountType=%d)(sAMAccountName=%s))" %
                  (dsdb.ATYPE_NORMAL_ACCOUNT, ldb.binary_encode(username)))

        domaindn = samdb.domain_dn()

        obj = self.get_account_attributes(samdb, username,
                                          basedn=domaindn,
                                          filter=filter,
                                          scope=ldb.SCOPE_SUBTREE,
                                          attrs=attrs,
                                          decrypt=False,
                                          support_pw_attrs=False)
        user_ldif = common.get_ldif_for_editor(samdb, obj)
        self.outf.write(user_ldif)
