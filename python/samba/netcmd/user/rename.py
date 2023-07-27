# user management
#
# user rename command
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
from samba.netcmd import Command, CommandError, Option
from samba.samdb import SamDB


class cmd_user_rename(Command):
    """Rename a user and related attributes.

    This command allows to set the user's name related attributes. The user's
    CN will be renamed automatically.
    The user's new CN will be made up by combining the given-name, initials
    and surname. A dot ('.') will be appended to the initials automatically
    if required.
    Use the --force-new-cn option to specify the new CN manually and the
    --reset-cn option to reset this change.

    Use an empty attribute value to remove the specified attribute.

    The username specified on the command is the sAMAccountName.

    The command may be run locally from the root userid or another authorized
    userid.

    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example1:
    samba-tool user rename johndoe --surname='Bloggs'

    Example1 shows how to change the surname of a user 'johndoe' to 'Bloggs' on
    the local server. The user's CN will be renamed automatically, based on
    the given name, initials and surname.

    Example2:
    samba-tool user rename johndoe --force-new-cn='John Bloggs (Sales)' \\
        --surname=Bloggs -H ldap://samba.samdom.example.com -U administrator

    Example2 shows how to rename the CN of a user 'johndoe' to 'John Bloggs (Sales)'.
    Additionally the surname ('sn' attribute) is set to 'Bloggs'.
    The -H parameter is used to specify the remote target server.
    """

    synopsis = "%prog <username> [options]"

    takes_options = [
        Option("-H", "--URL",
               help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--surname",
               help="New surname",
               type=str),
        Option("--given-name",
               help="New given name",
               type=str),
        Option("--initials",
               help="New initials",
               type=str),
        Option("--force-new-cn",
               help="Specify a new CN (RDN) instead of using a combination "
                    "of the given name, initials and surname.",
               type=str, metavar="NEW_CN"),
        Option("--reset-cn",
               help="Set the CN (RDN) to the combination of the given name, "
                    "initials and surname. Use this option to reset "
                    "the changes made with the --force-new-cn option.",
               action="store_true"),
        Option("--display-name",
               help="New display name",
               type=str),
        Option("--mail-address",
               help="New email address",
               type=str),
        Option("--samaccountname",
               help="New account name (sAMAccountName/logon name)",
               type=str),
        Option("--upn",
               help="New user principal name",
               type=str),
    ]

    takes_args = ["username"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, username, credopts=None, sambaopts=None,
            versionopts=None, H=None, surname=None, given_name=None,
            initials=None, display_name=None, mail_address=None,
            samaccountname=None, upn=None, force_new_cn=None,
            reset_cn=None):
        # illegal options
        if force_new_cn and reset_cn:
            raise CommandError("It is not allowed to specify --force-new-cn "
                               "together with --reset-cn.")
        if force_new_cn == "":
            raise CommandError("Failed to rename user - delete protected "
                               "attribute 'CN'")
        if samaccountname == "":
            raise CommandError("Failed to rename user - delete protected "
                               "attribute 'sAMAccountName'")

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        domain_dn = ldb.Dn(samdb, samdb.domain_dn())

        filter = ("(&(sAMAccountType=%d)(sAMAccountName=%s))" %
                  (dsdb.ATYPE_NORMAL_ACCOUNT, ldb.binary_encode(username)))
        try:
            res = samdb.search(base=domain_dn,
                               expression=filter,
                               scope=ldb.SCOPE_SUBTREE,
                               attrs=["sAMAccountName",
                                      "givenName",
                                      "initials",
                                      "sn",
                                      "mail",
                                      "userPrincipalName",
                                      "displayName",
                                      "cn"])
            old_user = res[0]
            user_dn = old_user.dn
        except IndexError:
            raise CommandError('Unable to find user "%s"' % (username))

        user_parent_dn = user_dn.parent()
        old_cn = old_user["cn"][0]

        # use the sAMAccountname as CN if no name is given
        new_fallback_cn = samaccountname if samaccountname is not None \
                                     else old_user["sAMAccountName"]

        if force_new_cn is not None:
            new_user_cn = force_new_cn
        else:
            new_user_cn = samdb.fullname_from_names(old_attrs=old_user,
                                                    given_name=given_name,
                                                    initials=initials,
                                                    surname=surname,
                                                    fallback_default=new_fallback_cn)

        # CN must change, if the new CN is different and the old CN is the
        # standard CN or the change is forced with force-new-cn or reset-cn
        expected_cn = samdb.fullname_from_names(old_attrs=old_user,
                                        fallback_default=old_user["sAMAccountName"])
        must_change_cn = str(old_cn) != str(new_user_cn) and \
                         (str(old_cn) == str(expected_cn) or \
                          reset_cn or bool(force_new_cn))

        new_user_dn = ldb.Dn(samdb, "CN=%s" % new_user_cn)
        new_user_dn.add_base(user_parent_dn)

        if upn is not None:
            if self.is_valid_upn(samdb, upn) == False:
                raise CommandError('"%s" is not a valid upn. '
                                   'You can manage the upn '
                                   'suffixes with the "samba-tool domain '
                                   'trust namespaces" command.' % upn)

        user_attrs = ldb.Message()
        user_attrs.dn = user_dn
        samdb.prepare_attr_replace(user_attrs, old_user, "givenName", given_name)
        samdb.prepare_attr_replace(user_attrs, old_user, "initials", initials)
        samdb.prepare_attr_replace(user_attrs, old_user, "sn", surname)
        samdb.prepare_attr_replace(user_attrs, old_user, "displayName", display_name)
        samdb.prepare_attr_replace(user_attrs, old_user, "mail", mail_address)
        samdb.prepare_attr_replace(user_attrs, old_user, "sAMAccountName", samaccountname)
        samdb.prepare_attr_replace(user_attrs, old_user, "userPrincipalName", upn)

        attributes_changed = len(user_attrs) > 0

        samdb.transaction_start()
        try:
            if attributes_changed == True:
                samdb.modify(user_attrs)
            if must_change_cn == True:
                samdb.rename(user_dn, new_user_dn)
        except Exception as e:
            samdb.transaction_cancel()
            raise CommandError('Failed to rename user "%s"' % username, e)
        samdb.transaction_commit()

        if must_change_cn == True:
            self.outf.write('Renamed CN of user "%s" from "%s" to "%s" '
                            'successfully\n' % (username, old_cn, new_user_cn))

        if attributes_changed == True:
            self.outf.write('Following attributes of user "%s" have been '
                            'changed successfully:\n' % (username))
            for attr in user_attrs.keys():
                if (attr == "dn"):
                    continue
                self.outf.write('%s: %s\n' % (attr, user_attrs[attr]
                                if user_attrs[attr] else '[removed]'))

    def is_valid_upn(self, samdb, upn):
        domain_dns = samdb.domain_dns_name()
        forest_dns = samdb.forest_dns_name()
        upn_suffixes = [domain_dns, forest_dns]

        config_basedn = samdb.get_config_basedn()
        partitions_dn = "CN=Partitions,%s" % config_basedn
        res = samdb.search(
            base=partitions_dn,
            scope=ldb.SCOPE_BASE,
            expression="(objectClass=crossRefContainer)",
            attrs=['uPNSuffixes'])

        if (len(res) >= 1):
            msg = res[0]
            if 'uPNSuffixes' in msg:
                for s in msg['uPNSuffixes']:
                    upn_suffixes.append(str(s).lower())

        upn_split = upn.split('@')
        if (len(upn_split) < 2):
            return False

        upn_suffix = upn_split[-1].lower()
        if upn_suffix not in upn_suffixes:
            return False

        return True
