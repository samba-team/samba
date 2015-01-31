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
import pwd
from getpass import getpass
from samba.auth import system_session
from samba.samdb import SamDB
from samba import (
    dsdb,
    gensec,
    generate_random_password,
    )
from samba.net import Net

from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
    )


class cmd_user_create(Command):
    """Create a new user.

This command creates a new user account in the Active Directory domain.  The username specified on the command is the sAMaccountName.

User accounts may represent physical entities, such as people or may be used as service accounts for applications.  User accounts are also referred to as security principals and are assigned a security identifier (SID).

A user account enables a user to logon to a computer and domain with an identity that can be authenticated.  To maximize security, each user should have their own unique user account and password.  A user's access to domain resources is based on permissions assigned to the user account.

Unix (RFC2307) attributes may be added to the user account. Attributes taken from NSS are obtained on the local machine. Explicitly given values override values obtained from NSS. Configure 'idmap_ldb:use rfc2307 = Yes' to use these attributes for UID/GID mapping.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user add User1 passw0rd --given-name=John --surname=Smith --must-change-at-next-login -H ldap://samba.samdom.example.com -Uadministrator%passw1rd

Example1 shows how to create a new user in the domain against a remote LDAP server.  The -H parameter is used to specify the remote target server.  The -U option is used to pass the userid and password authorized to issue the command remotely.

Example2:
sudo samba-tool user add User2 passw2rd --given-name=Jane --surname=Doe --must-change-at-next-login

Example2 shows how to create a new user in the domain against the local server.   sudo is used so a user may run the command as root.  In this example, after User2 is created, he/she will be forced to change their password when they logon.

Example3:
samba-tool user add User3 passw3rd --userou='OU=OrgUnit'

Example3 shows how to create a new user in the OrgUnit organizational unit.

Example4:
samba-tool user create User4 passw4rd --rfc2307-from-nss --gecos 'some text'

Example4 shows how to create a new user with Unix UID, GID and login-shell set from the local NSS and GECOS set to 'some text'.

Example5:
samba-tool user add User5 passw5rd --nis-domain=samdom --unix-home=/home/User5 \
           --uid-number=10005 --login-shell=/bin/false --gid-number=10000

Example5 shows how to create an RFC2307/NIS domain enabled user account. If
--nis-domain is set, then the other four parameters are mandatory.

"""
    synopsis = "%prog <username> [<password>] [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
                metavar="URL", dest="H"),
        Option("--must-change-at-next-login",
                help="Force password to be changed on next login",
                action="store_true"),
        Option("--random-password",
                help="Generate random password",
                action="store_true"),
        Option("--use-username-as-cn",
                help="Force use of username as user's CN",
                action="store_true"),
        Option("--userou",
                help="DN of alternative location (without domainDN counterpart) to default CN=Users in which new user object will be created. E. g. 'OU=<OU name>'",
                type=str),
        Option("--surname", help="User's surname", type=str),
        Option("--given-name", help="User's given name", type=str),
        Option("--initials", help="User's initials", type=str),
        Option("--profile-path", help="User's profile path", type=str),
        Option("--script-path", help="User's logon script path", type=str),
        Option("--home-drive", help="User's home drive letter", type=str),
        Option("--home-directory", help="User's home directory path", type=str),
        Option("--job-title", help="User's job title", type=str),
        Option("--department", help="User's department", type=str),
        Option("--company", help="User's company", type=str),
        Option("--description", help="User's description", type=str),
        Option("--mail-address", help="User's email address", type=str),
        Option("--internet-address", help="User's home page", type=str),
        Option("--telephone-number", help="User's phone number", type=str),
        Option("--physical-delivery-office", help="User's office location", type=str),
        Option("--rfc2307-from-nss",
                help="Copy Unix user attributes from NSS (will be overridden by explicit UID/GID/GECOS/shell)",
                action="store_true"),
        Option("--nis-domain", help="User's Unix/RFC2307 NIS domain", type=str),
        Option("--unix-home", help="User's Unix/RFC2307 home directory",
                type=str),
        Option("--uid", help="User's Unix/RFC2307 username", type=str),
        Option("--uid-number", help="User's Unix/RFC2307 numeric UID", type=int),
        Option("--gid-number", help="User's Unix/RFC2307 primary GID number", type=int),
        Option("--gecos", help="User's Unix/RFC2307 GECOS field", type=str),
        Option("--login-shell", help="User's Unix/RFC2307 login shell", type=str),
    ]

    takes_args = ["username", "password?"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, username, password=None, credopts=None, sambaopts=None,
            versionopts=None, H=None, must_change_at_next_login=False,
            random_password=False, use_username_as_cn=False, userou=None,
            surname=None, given_name=None, initials=None, profile_path=None,
            script_path=None, home_drive=None, home_directory=None,
            job_title=None, department=None, company=None, description=None,
            mail_address=None, internet_address=None, telephone_number=None,
            physical_delivery_office=None, rfc2307_from_nss=False,
            nis_domain=None, unix_home=None, uid=None, uid_number=None,
            gid_number=None, gecos=None, login_shell=None):

        if random_password:
            password = generate_random_password(128, 255)

        while True:
            if password is not None and password is not '':
                break
            password = getpass("New Password: ")
            passwordverify = getpass("Retype Password: ")
            if not password == passwordverify:
                password = None
                self.outf.write("Sorry, passwords do not match.\n")

        if rfc2307_from_nss:
                pwent = pwd.getpwnam(username)
                if uid is None:
                    uid = username
                if uid_number is None:
                    uid_number = pwent[2]
                if gid_number is None:
                    gid_number = pwent[3]
                if gecos is None:
                    gecos = pwent[4]
                if login_shell is None:
                    login_shell = pwent[6]

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        if uid_number or gid_number:
            if not lp.get("idmap_ldb:use rfc2307"):
                self.outf.write("You are setting a Unix/RFC2307 UID or GID. You may want to set 'idmap_ldb:use rfc2307 = Yes' to use those attributes for XID/SID-mapping.\n")

        if nis_domain is not None:
            if None in (uid_number, login_shell, unix_home, gid_number):
                raise CommandError('Missing parameters. To enable NIS features, '
                                   'the following options have to be given: '
                                   '--nis-domain=, --uidNumber=, --login-shell='
                                   ', --unix-home=, --gid-number= Operation '
                                   'cancelled.')

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.newuser(username, password, force_password_change_at_next_login_req=must_change_at_next_login,
                          useusernameascn=use_username_as_cn, userou=userou, surname=surname, givenname=given_name, initials=initials,
                          profilepath=profile_path, homedrive=home_drive, scriptpath=script_path, homedirectory=home_directory,
                          jobtitle=job_title, department=department, company=company, description=description,
                          mailaddress=mail_address, internetaddress=internet_address,
                          telephonenumber=telephone_number, physicaldeliveryoffice=physical_delivery_office,
                          nisdomain=nis_domain, unixhome=unix_home, uid=uid,
                          uidnumber=uid_number, gidnumber=gid_number,
                          gecos=gecos, loginshell=login_shell)
        except Exception, e:
            raise CommandError("Failed to add user '%s': " % username, e)

        self.outf.write("User '%s' created successfully\n" % username)


class cmd_user_add(cmd_user_create):
    __doc__ = cmd_user_create.__doc__
    # take this print out after the add subcommand is removed.
    # the add subcommand is deprecated but left in for now to allow people to
    # migrate to create

    def run(self, *args, **kwargs):
        self.err.write(
            "Note: samba-tool user add is deprecated.  "
            "Please use samba-tool user create for the same function.\n")
        return super(self, cmd_user_add).run(*args, **kwargs)


class cmd_user_delete(Command):
    """Delete a user.

This command deletes a user account from the Active Directory domain.  The username specified on the command is the sAMAccountName.

Once the account is deleted, all permissions and memberships associated with that account are deleted.  If a new user account is added with the same name as a previously deleted account name, the new user does not have the previous permissions.  The new account user will be assigned a new security identifier (SID) and permissions and memberships will have to be added.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user delete User1 -H ldap://samba.samdom.example.com --username=administrator --password=passw1rd

Example1 shows how to delete a user in the domain against a remote LDAP server.  The -H parameter is used to specify the remote target server.  The --username= and --password= options are used to pass the username and password of a user that exists on the remote server and is authorized to issue the command on that server.

Example2:
sudo samba-tool user delete User2

Example2 shows how to delete a user in the domain against the local server.   sudo is used so a user may run the command as root.

"""
    synopsis = "%prog <username> [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
    ]

    takes_args = ["username"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, username, credopts=None, sambaopts=None, versionopts=None,
            H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        try:
            samdb = SamDB(url=H, session_info=system_session(),
                          credentials=creds, lp=lp)
            samdb.deleteuser(username)
        except Exception, e:
            raise CommandError('Failed to remove user "%s"' % username, e)
        self.outf.write("Deleted user %s\n" % username)


class cmd_user_list(Command):
    """List all users."""

    synopsis = "%prog [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, sambaopts=None, credopts=None, versionopts=None, H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)

        domain_dn = samdb.domain_dn()
        res = samdb.search(domain_dn, scope=ldb.SCOPE_SUBTREE,
                    expression=("(&(objectClass=user)(userAccountControl:%s:=%u))"
                    % (ldb.OID_COMPARATOR_AND, dsdb.UF_NORMAL_ACCOUNT)),
                    attrs=["samaccountname"])
        if (len(res) == 0):
            return

        for msg in res:
            self.outf.write("%s\n" % msg.get("samaccountname", idx=0))


class cmd_user_enable(Command):
    """Enable an user.

This command enables a user account for logon to an Active Directory domain.  The username specified on the command is the sAMAccountName.  The username may also be specified using the --filter option.

There are many reasons why an account may become disabled.  These include:
- If a user exceeds the account policy for logon attempts
- If an administrator disables the account
- If the account expires

The samba-tool user enable command allows an administrator to enable an account which has become disabled.

Additionally, the enable function allows an administrator to have a set of created user accounts defined and setup with default permissions that can be easily enabled for use.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user enable Testuser1 --URL=ldap://samba.samdom.example.com --username=administrator --password=passw1rd

Example1 shows how to enable a user in the domain against a remote LDAP server.  The --URL parameter is used to specify the remote target server.  The --username= and --password= options are used to pass the username and password of a user that exists on the remote server and is authorized to update that server.

Example2:
su samba-tool user enable Testuser2

Example2 shows how to enable user Testuser2 for use in the domain on the local server. sudo is used so a user may run the command as root.

Example3:
samba-tool user enable --filter=samaccountname=Testuser3

Example3 shows how to enable a user in the domain against a local LDAP server.  It uses the --filter=samaccountname to specify the username.

"""
    synopsis = "%prog (<username>|--filter <filter>) [options]"


    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        ]

    takes_args = ["username?"]

    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, filter=None, H=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)
        try:
            samdb.enable_account(filter)
        except Exception, msg:
            raise CommandError("Failed to enable user '%s': %s" % (username or filter, msg))
        self.outf.write("Enabled user '%s'\n" % (username or filter))


class cmd_user_disable(Command):
    """Disable an user."""

    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        ]

    takes_args = ["username?"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, filter=None, H=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)
        try:
            samdb.disable_account(filter)
        except Exception, msg:
            raise CommandError("Failed to disable user '%s': %s" % (username or filter, msg))


class cmd_user_setexpiry(Command):
    """Set the expiration of a user account.

The user can either be specified by their sAMAccountName or using the --filter option.

When a user account expires, it becomes disabled and the user is unable to logon.  The administrator may issue the samba-tool user enable command to enable the account for logon.  The permissions and memberships associated with the account are retained when the account is enabled.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command on a remote server.

Example1:
samba-tool user setexpiry User1 --days=20 --URL=ldap://samba.samdom.example.com --username=administrator --password=passw1rd

Example1 shows how to set the expiration of an account in a remote LDAP server.  The --URL parameter is used to specify the remote target server.  The --username= and --password= options are used to pass the username and password of a user that exists on the remote server and is authorized to update that server.

Example2:
su samba-tool user setexpiry User2

Example2 shows how to set the account expiration of user User2 so it will never expire.  The user in this example resides on the  local server.   sudo is used so a user may run the command as root.

Example3:
samba-tool user setexpiry --days=20 --filter=samaccountname=User3

Example3 shows how to set the account expiration date to end of day 20 days from the current day.  The username or sAMAccountName is specified using the --filter= paramter and the username in this example is User3.

Example4:
samba-tool user setexpiry --noexpiry User4
Example4 shows how to set the account expiration so that it will never expire.  The username and sAMAccountName in this example is User4.

"""
    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        Option("--days", help="Days to expiry", type=int, default=0),
        Option("--noexpiry", help="Password does never expire", action="store_true", default=False),
    ]

    takes_args = ["username?"]

    def run(self, username=None, sambaopts=None, credopts=None,
            versionopts=None, H=None, filter=None, days=None, noexpiry=None):
        if username is None and filter is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
            credentials=creds, lp=lp)

        try:
            samdb.setexpiry(filter, days*24*3600, no_expiry_req=noexpiry)
        except Exception, msg:
            # FIXME: Catch more specific exception
            raise CommandError("Failed to set expiry for user '%s': %s" % (
                username or filter, msg))
        if noexpiry:
            self.outf.write("Expiry for user '%s' disabled.\n" % (
                username or filter))
        else:
            self.outf.write("Expiry for user '%s' set to %u days.\n" % (
                username or filter, days))


class cmd_user_password(Command):
    """Change password for a user account (the one provided in authentication).
"""

    synopsis = "%prog [options]"

    takes_options = [
        Option("--newpassword", help="New password", type=str),
        ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
        "versionopts": options.VersionOptions,
        }

    def run(self, credopts=None, sambaopts=None, versionopts=None,
                newpassword=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        # get old password now, to get the password prompts in the right order
        old_password = creds.get_password()

        net = Net(creds, lp, server=credopts.ipaddress)

        password = newpassword
        while True:
            if password is not None and password is not '':
                break
            password = getpass("New Password: ")
            passwordverify = getpass("Retype Password: ")
            if not password == passwordverify:
                password = None
                self.outf.write("Sorry, passwords do not match.\n")

        try:
            net.change_password(password)
        except Exception, msg:
            # FIXME: catch more specific exception
            raise CommandError("Failed to change password : %s" % msg)
        self.outf.write("Changed password OK\n")


class cmd_user_setpassword(Command):
    """Set or reset the password of a user account.

This command sets or resets the logon password for a user account.  The username specified on the command is the sAMAccountName.  The username may also be specified using the --filter option.

If the password is not specified on the command through the --newpassword parameter, the user is prompted for the password to be entered through the command line.

It is good security practice for the administrator to use the --must-change-at-next-login option which requires that when the user logs on to the account for the first time following the password change, he/she must change the password.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user setpassword TestUser1 --newpassword=passw0rd --URL=ldap://samba.samdom.example.com -Uadministrator%passw1rd

Example1 shows how to set the password of user TestUser1 on a remote LDAP server.  The --URL parameter is used to specify the remote target server.  The -U option is used to pass the username and password of a user that exists on the remote server and is authorized to update the server.

Example2:
sudo samba-tool user setpassword TestUser2 --newpassword=passw0rd --must-change-at-next-login

Example2 shows how an administrator would reset the TestUser2 user's password to passw0rd.  The user is running under the root userid using the sudo command.  In this example the user TestUser2 must change their password the next time they logon to the account.

Example3:
samba-tool user setpassword --filter=samaccountname=TestUser3 --newpassword=passw0rd

Example3 shows how an administrator would reset TestUser3 user's password to passw0rd using the --filter= option to specify the username.

"""
    synopsis = "%prog (<username>|--filter <filter>) [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("--filter", help="LDAP Filter to set password on", type=str),
        Option("--newpassword", help="Set password", type=str),
        Option("--must-change-at-next-login",
               help="Force password to be changed on next login",
               action="store_true"),
        Option("--random-password",
                help="Generate random password",
                action="store_true"),
        ]

    takes_args = ["username?"]

    def run(self, username=None, filter=None, credopts=None, sambaopts=None,
            versionopts=None, H=None, newpassword=None,
            must_change_at_next_login=False, random_password=False):
        if filter is None and username is None:
            raise CommandError("Either the username or '--filter' must be specified!")

        if random_password:
            password = generate_random_password(128, 255)
        else:
            password = newpassword

        while 1:
            if password is not None and password is not '':
                break
            password = getpass("New Password: ")

        if filter is None:
            filter = "(&(objectClass=user)(sAMAccountName=%s))" % (ldb.binary_encode(username))

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        creds.set_gensec_features(creds.get_gensec_features() | gensec.FEATURE_SEAL)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        try:
            samdb.setpassword(filter, password,
                              force_change_at_next_login=must_change_at_next_login,
                              username=username)
        except Exception, msg:
            # FIXME: catch more specific exception
            raise CommandError("Failed to set password for user '%s': %s" % (username or filter, msg))
        self.outf.write("Changed password OK\n")


class cmd_user(SuperCommand):
    """User management."""

    subcommands = {}
    subcommands["add"] = cmd_user_create()
    subcommands["create"] = cmd_user_create()
    subcommands["delete"] = cmd_user_delete()
    subcommands["disable"] = cmd_user_disable()
    subcommands["enable"] = cmd_user_enable()
    subcommands["list"] = cmd_user_list()
    subcommands["setexpiry"] = cmd_user_setexpiry()
    subcommands["password"] = cmd_user_password()
    subcommands["setpassword"] = cmd_user_setpassword()
