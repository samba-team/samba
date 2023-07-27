# user management
#
# user edit command
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

import os
from subprocess import CalledProcessError, check_call

import samba.getopt as options
from samba import dsdb, ldb
from samba.auth import system_session
from samba.common import get_bytes
from samba.netcmd import Command, CommandError, Option, common
from samba.samdb import SamDB


class cmd_user_edit(Command):
    """Modify User AD object.

This command will allow editing of a user account in the Active Directory
domain. You will then be able to add or change attributes and their values.

The username specified on the command is the sAMAccountName.

The command may be run from the root userid or another authorized userid.

The -H or --URL= option can be used to execute the command against a remote
server.

Example1:
samba-tool user edit User1 -H ldap://samba.samdom.example.com \\
    -U administrator --password=passw1rd

Example1 shows how to edit a users attributes in the domain against a remote
LDAP server.

The -H parameter is used to specify the remote target server.

Example2:
samba-tool user edit User2

Example2 shows how to edit a users attributes in the domain against a local
LDAP server.

Example3:
samba-tool user edit User3 --editor=nano

Example3 shows how to edit a users attributes in the domain against a local
LDAP server using the 'nano' editor.

"""
    synopsis = "%prog <username> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--editor", help="Editor to use instead of the system default,"
               " or 'vi' if no system default is set.", type=str),
    ]

    takes_args = ["username"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, username, credopts=None, sambaopts=None, versionopts=None,
            H=None, editor=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        filter = ("(&(sAMAccountType=%d)(sAMAccountName=%s))" %
                  (dsdb.ATYPE_NORMAL_ACCOUNT, ldb.binary_encode(username)))

        domaindn = samdb.domain_dn()

        try:
            res = samdb.search(base=domaindn,
                               expression=filter,
                               scope=ldb.SCOPE_SUBTREE)
            user_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find user "%s"' % (username))

        import tempfile
        for msg in res:
            result_ldif = common.get_ldif_for_editor(samdb, msg)

            if editor is None:
                editor = os.environ.get('EDITOR')
                if editor is None:
                    editor = 'vi'

            with tempfile.NamedTemporaryFile(suffix=".tmp") as t_file:
                t_file.write(get_bytes(result_ldif))
                t_file.flush()
                try:
                    check_call([editor, t_file.name])
                except CalledProcessError as e:
                    raise CalledProcessError("ERROR: ", e)
                with open(t_file.name) as edited_file:
                    edited_message = edited_file.read()


        msgs_edited = samdb.parse_ldif(edited_message)
        msg_edited = next(msgs_edited)[1]

        res_msg_diff = samdb.msg_diff(msg, msg_edited)
        if len(res_msg_diff) == 0:
            self.outf.write("Nothing to do\n")
            return

        try:
            samdb.modify(res_msg_diff)
        except Exception as e:
            raise CommandError("Failed to modify user '%s': " % username, e)

        self.outf.write("Modified User '%s' successfully\n" % username)
