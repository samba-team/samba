# user management
#
# add user
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

import pwd
from getpass import getpass

import samba.getopt as options
from samba import generate_random_password
from samba.auth import system_session
from samba.netcmd import Command, CommandError, Option
from samba.samdb import SamDB


class cmd_user_add(Command):
    """Add a new user.

This command adds a new user account to the Active Directory domain.  The username specified on the command is the sAMaccountName.

User accounts may represent physical entities, such as people or may be used as service accounts for applications.  User accounts are also referred to as security principals and are assigned a security identifier (SID).

A user account enables a user to logon to a computer and domain with an identity that can be authenticated.  To maximize security, each user should have their own unique user account and password.  A user's access to domain resources is based on permissions assigned to the user account.

Unix (RFC2307) attributes may be added to the user account. Attributes taken from NSS are obtained on the local machine. Explicitly given values override values obtained from NSS. Configure 'idmap_ldb:use rfc2307 = Yes' to use these attributes for UID/GID mapping.

The command may be run from the root userid or another authorized userid.  The -H or --URL= option can be used to execute the command against a remote server.

Example1:
samba-tool user add User1 passw0rd --given-name=John --surname=Smith --must-change-at-next-login -H ldap://samba.samdom.example.com -Uadministrator%passw1rd

Example1 shows how to add a new user to the domain against a remote LDAP server.  The -H parameter is used to specify the remote target server.  The -U option is used to pass the userid and password authorized to issue the command remotely.

Example2:
sudo samba-tool user add User2 passw2rd --given-name=Jane --surname=Doe --must-change-at-next-login

Example2 shows how to add a new user to the domain against the local server.   sudo is used so a user may run the command as root.  In this example, after User2 is created, he/she will be forced to change their password when they logon.

Example3:
samba-tool user add User3 passw3rd --userou='OU=OrgUnit'

Example3 shows how to add a new user in the OrgUnit organizational unit.

Example4:
samba-tool user add User4 passw4rd --rfc2307-from-nss --gecos 'some text'

Example4 shows how to add a new user with Unix UID, GID and login-shell set from the local NSS and GECOS set to 'some text'.

Example5:
samba-tool user add User5 passw5rd --nis-domain=samdom --unix-home=/home/User5 \\
    --uid-number=10005 --login-shell=/bin/false --gid-number=10000

Example5 shows how to add a new RFC2307/NIS domain enabled user account. If
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
        Option("--smartcard-required",
               help="Require a smartcard for interactive logons",
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
            gid_number=None, gecos=None, login_shell=None,
            smartcard_required=False):

        if smartcard_required:
            if password is not None and password != '':
                raise CommandError('It is not allowed to specify '
                                   '--newpassword '
                                   'together with --smartcard-required.')
            if must_change_at_next_login:
                raise CommandError('It is not allowed to specify '
                                   '--must-change-at-next-login '
                                   'together with --smartcard-required.')

        if random_password and not smartcard_required:
            password = generate_random_password(128, 255)

        while True:
            if smartcard_required:
                break
            if password is not None and password != '':
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
                                   '--nis-domain=, --uid-number=, --login-shell='
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
                          gecos=gecos, loginshell=login_shell,
                          smartcard_required=smartcard_required)
        except Exception as e:
            raise CommandError("Failed to add user '%s': " % username, e)

        self.outf.write("User '%s' added successfully\n" % username)
