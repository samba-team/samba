# user management
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
import ldb
import os
from subprocess import check_call, CalledProcessError
from samba.auth import system_session
from samba.samdb import SamDB, SamDBError
from samba import (
    dsdb,
)

from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
    common
)
from samba.common import get_bytes

from .add import cmd_user_add
from .common import (
    GetPasswordCommand,
    disabled_virtual_attributes,
    decrypt_samba_gpg_help,
    get_crypt_value,
    gpg_decrypt,
    virtual_attributes,
    virtual_attributes_help
)
from .delete import cmd_user_delete
from .disable import cmd_user_disable
from .enable import cmd_user_enable
from .getgroups import cmd_user_getgroups
from .getpassword import cmd_user_getpassword, cmd_user_syncpasswords
from .list import cmd_user_list
from .password import cmd_user_password
from .setexpiry import cmd_user_setexpiry
from .setpassword import cmd_user_setpassword
from .setprimarygroup import cmd_user_setprimarygroup


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

class cmd_user_move(Command):
    """Move a user to an organizational unit/container.

    This command moves a user account into the specified organizational unit
    or container.
    The username specified on the command is the sAMAccountName.
    The name of the organizational unit or container can be specified as a
    full DN or without the domainDN component.

    The command may be run from the root userid or another authorized userid.

    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example1:
    samba-tool user move User1 'OU=OrgUnit,DC=samdom,DC=example,DC=com' \\
        -H ldap://samba.samdom.example.com -U administrator

    Example1 shows how to move a user User1 into the 'OrgUnit' organizational
    unit on a remote LDAP server.

    The -H parameter is used to specify the remote target server.

    Example2:
    samba-tool user move User1 CN=Users

    Example2 shows how to move a user User1 back into the CN=Users container
    on the local server.
    """

    synopsis = "%prog <username> <new_parent_dn> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["username", "new_parent_dn"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self, username, new_parent_dn, credopts=None, sambaopts=None,
            versionopts=None, H=None):
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
                               scope=ldb.SCOPE_SUBTREE)
            user_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find user "%s"' % (username))

        try:
            full_new_parent_dn = samdb.normalize_dn_in_domain(new_parent_dn)
        except Exception as e:
            raise CommandError('Invalid new_parent_dn "%s": %s' %
                               (new_parent_dn, e))

        full_new_user_dn = ldb.Dn(samdb, str(user_dn))
        full_new_user_dn.remove_base_components(len(user_dn) - 1)
        full_new_user_dn.add_base(full_new_parent_dn)

        try:
            samdb.rename(user_dn, full_new_user_dn)
        except Exception as e:
            raise CommandError('Failed to move user "%s"' % username, e)
        self.outf.write('Moved user "%s" into "%s"\n' %
                        (username, full_new_parent_dn))


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


class cmd_user_add_unix_attrs(Command):
    """Add RFC2307 attributes to a user.

This command adds Unix attributes to a user account in the Active
Directory domain.

The username specified on the command is the sAMaccountName.

You must supply a unique uidNumber.

Unix (RFC2307) attributes will be added to the user account.

If you supply a gidNumber with '--gid-number', this will be used for the
users Unix 'gidNumber' attribute.

If '--gid-number' is not supplied, the users Unix gidNumber will be set to the
one found in 'Domain Users', this means Domain Users must have a gidNumber
attribute.

if '--unix-home' is not supplied, the users Unix home directory will be
set to /home/DOMAIN/username

if '--login-shell' is not supplied, the users Unix login shell will be
set to '/bin/sh'

if ---gecos' is not supplied, the users Unix gecos field will be set to the
users 'CN'

Add 'idmap_ldb:use rfc2307 = Yes' to the smb.conf on DCs, to use these
attributes for UID/GID mapping.

The command may be run from the root userid or another authorised userid.
The -H or --URL= option can be used to execute the command against a
remote server.

Example1:
samba-tool user addunixattrs User1 10001

Example1 shows how to add RFC2307 attributes to a domain enabled user
account, Domain Users will be set as the users gidNumber.

The users Unix ID will be set to '10001', provided this ID isn't already
in use.

Example2:
samba-tool user addunixattrs User2 10002 --gid-number=10001 \
--unix-home=/home/User2

Example2 shows how to add RFC2307 attributes to a domain enabled user
account.

The users Unix ID will be set to '10002', provided this ID isn't already
in use.

The users gidNumber attribute will be set to '10001'

The users Unix home directory will be set to '/home/user2'

Example3:
samba-tool user addunixattrs User3 10003 --gid-number=10001 \
--login-shell=/bin/false --gecos='User3 test'

Example3 shows how to add RFC2307 attributes to a domain enabled user
account.

The users Unix ID will be set to '10003', provided this ID isn't already
in use.

The users gidNumber attribute will be set to '10001'

The users Unix login shell will be set to '/bin/false'

The users gecos field will be set to 'User3 test'

Example4:
samba-tool user addunixattrs User4 10004 --gid-number=10001 \
--unix-home=/home/User4 --login-shell=/bin/bash --gecos='User4 test'

Example4 shows how to add RFC2307 attributes to a domain enabled user
account.

The users Unix ID will be set to '10004', provided this ID isn't already
in use.

The users gidNumber attribute will be set to '10001'

The users Unix home directory will be set to '/home/User4'

The users Unix login shell will be set to '/bin/bash'

The users gecos field will be set to 'User4 test'

"""

    synopsis = "%prog <username> <uid-number> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--gid-number", help="User's Unix/RFC2307 GID", type=str),
        Option("--unix-home", help="User's Unix/RFC2307 home directory",
               type=str),
        Option("--login-shell", help="User's Unix/RFC2307 login shell",
               type=str),
        Option("--gecos", help="User's Unix/RFC2307 GECOS field", type=str),
        Option("--uid", help="User's Unix/RFC2307 username", type=str),
    ]

    takes_args = ["username", "uid-number"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, username, uid_number, credopts=None, sambaopts=None,
            versionopts=None, H=None, gid_number=None, unix_home=None,
            login_shell=None, gecos=None, uid=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        domaindn = samdb.domain_dn()

        # Check that uidNumber supplied isn't already in use
        filter = ("(&(objectClass=person)(uidNumber={}))"
                  .format(uid_number))
        res = samdb.search(domaindn,
                           scope=ldb.SCOPE_SUBTREE,
                           expression=filter)
        if (len(res) != 0):
            raise CommandError("uidNumber {} is already being used."
                               .format(uid_number))

        # Check user exists and doesn't have a uidNumber
        filter = "(samaccountname={})".format(ldb.binary_encode(username))
        res = samdb.search(domaindn,
                           scope=ldb.SCOPE_SUBTREE,
                           expression=filter)
        if (len(res) == 0):
            raise CommandError("Unable to find user '{}'".format(username))

        user_dn = res[0].dn

        if "uidNumber" in res[0]:
            raise CommandError("User {} is already a Unix user."
                               .format(username))

        if gecos is None:
            gecos = res[0]["cn"][0]

        if uid is None:
            uid = res[0]["cn"][0]

        if gid_number is None:
            search_filter = ("(samaccountname={})"
                              .format(ldb.binary_encode('Domain Users')))
            try:
                res = samdb.search(domaindn,
                                   scope=ldb.SCOPE_SUBTREE,
                                   expression=search_filter)
                for msg in res:
                    gid_number=msg.get('gidNumber')
            except IndexError:
                raise CommandError('Domain Users does not have a'
                                   ' gidNumber attribute')

        if login_shell is None:
            login_shell = "/bin/sh"

        if unix_home is None:
            # obtain nETBIOS Domain Name
            unix_domain = samdb.domain_netbios_name()
            if unix_domain is None:
                raise CommandError('Unable to find Unix domain')

            tmpl = lp.get('template homedir')
            unix_home = tmpl.replace('%D', unix_domain).replace('%U', username)

        if not lp.get("idmap_ldb:use rfc2307"):
            self.outf.write("You are setting a Unix/RFC2307 UID & GID. "
                            "You may want to set 'idmap_ldb:use rfc2307 = Yes'"
                            " in smb.conf to use the attributes for "
                            "XID/SID-mapping.\n")

        user_mod = """
dn: {0}
changetype: modify
add: uidNumber
uidNumber: {1}
add: gidnumber
gidNumber: {2}
add: gecos
gecos: {3}
add: uid
uid: {4}
add: loginshell
loginShell: {5}
add: unixHomeDirectory
unixHomeDirectory: {6}
""".format(user_dn, uid_number, gid_number, gecos, uid, login_shell, unix_home)

        samdb.transaction_start()
        try:
            samdb.modify_ldif(user_mod)
        except ldb.LdbError as e:
            raise CommandError("Failed to modify user '{0}': {1}"
                               .format(username, e))
        else:
            samdb.transaction_commit()
            self.outf.write("Modified User '{}' successfully\n"
                            .format(username))

class cmd_user_unlock(Command):
    """Unlock a user account.

    This command unlocks a user account in the Active Directory domain. The
    username specified on the command is the sAMAccountName. The username may
    also be specified using the --filter option.

    The command may be run from the root userid or another authorized userid.
    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example:
    samba-tool user unlock user1 -H ldap://samba.samdom.example.com \\
        --username=Administrator --password=Passw0rd

    The example shows how to unlock a user account in the domain against a
    remote LDAP server. The -H parameter is used to specify the remote target
    server. The --username= and --password= options are used to pass the
    username and password of a user that exists on the remote server and is
    authorized to issue the command on that server.
"""

    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_options = [
        Option("-H",
               "--URL",
               help="LDB URL for database or target server",
               type=str,
               metavar="URL",
               dest="H"),
        Option("--filter",
               help="LDAP Filter to set password on",
               type=str),
    ]

    takes_args = ["username?"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    def run(self,
            username=None,
            sambaopts=None,
            credopts=None,
            versionopts=None,
            filter=None,
            H=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be "
                               "specified!")

        if filter is None:
            filter = ("(&(objectClass=user)(sAMAccountName=%s))" % (
                ldb.binary_encode(username)))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H,
                      session_info=system_session(),
                      credentials=creds,
                      lp=lp)
        try:
            samdb.unlock_account(filter)
        except (SamDBError, ldb.LdbError) as msg:
            raise CommandError("Failed to unlock user '%s': %s" % (
                               username or filter, msg))

class cmd_user_sensitive(Command):
    """Set/unset or show UF_NOT_DELEGATED for an account."""

    synopsis = "%prog <accountname> [(show|on|off)] [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["accountname", "cmd"]

    def run(self, accountname, cmd, H=None, credopts=None, sambaopts=None,
            versionopts=None):

        if cmd not in ("show", "on", "off"):
            raise CommandError("invalid argument: '%s' (choose from 'show', 'on', 'off')" % cmd)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        sam = SamDB(url=H, session_info=system_session(),
                    credentials=creds, lp=lp)

        search_filter = "sAMAccountName=%s" % ldb.binary_encode(accountname)
        flag = dsdb.UF_NOT_DELEGATED;

        if cmd == "show":
            res = sam.search(scope=ldb.SCOPE_SUBTREE, expression=search_filter,
                             attrs=["userAccountControl"])
            if len(res) == 0:
                raise Exception("Unable to find account where '%s'" % search_filter)

            uac = int(res[0].get("userAccountControl")[0])

            self.outf.write("Account-DN: %s\n" % str(res[0].dn))
            self.outf.write("UF_NOT_DELEGATED: %s\n" % bool(uac & flag))

            return

        if cmd == "on":
            on = True
        elif cmd == "off":
            on = False

        try:
            sam.toggle_userAccountFlags(search_filter, flag, flags_str="Not-Delegated",
                                        on=on, strict=True)
        except Exception as err:
            raise CommandError(err)


class cmd_user(SuperCommand):
    """User management."""

    subcommands = {}
    subcommands["add"] = cmd_user_add()
    subcommands["create"] = cmd_user_add()
    subcommands["delete"] = cmd_user_delete()
    subcommands["disable"] = cmd_user_disable()
    subcommands["enable"] = cmd_user_enable()
    subcommands["list"] = cmd_user_list()
    subcommands["setexpiry"] = cmd_user_setexpiry()
    subcommands["password"] = cmd_user_password()
    subcommands["getgroups"] = cmd_user_getgroups()
    subcommands["setprimarygroup"] = cmd_user_setprimarygroup()
    subcommands["setpassword"] = cmd_user_setpassword()
    subcommands["getpassword"] = cmd_user_getpassword()
    subcommands["syncpasswords"] = cmd_user_syncpasswords()
    subcommands["edit"] = cmd_user_edit()
    subcommands["show"] = cmd_user_show()
    subcommands["move"] = cmd_user_move()
    subcommands["rename"] = cmd_user_rename()
    subcommands["unlock"] = cmd_user_unlock()
    subcommands["addunixattrs"] = cmd_user_add_unix_attrs()
    subcommands["sensitive"] = cmd_user_sensitive()
