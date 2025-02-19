# samba-tool contact management
#
# Copyright Bjoern Baumbach 2019 <bbaumbach@samba.org>
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
import tempfile
from subprocess import check_call, CalledProcessError
from operator import attrgetter
from samba.auth import system_session
from samba.samdb import SamDB
from samba import (
    credentials,
    dsdb,
)
from samba.net import Net

from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option,
)
from samba.common import get_bytes
from . import common


class cmd_add(Command):
    """Add a new contact.

    This command adds a new contact to the Active Directory domain.

    The name of the new contact can be specified by the first argument
    'contactname' or the --given-name, --initial and --surname arguments.
    If no 'contactname' is given, contact's name will be made up of the given
    arguments by combining the given-name, initials and surname. Each argument
    is optional. A dot ('.') will be appended to the initials automatically.

    Example1:
    samba-tool contact add "James T. Kirk" --job-title=Captain \\
        -H ldap://samba.samdom.example.com -UAdministrator%Passw1rd

    The example shows how to add a new contact to the domain against a remote
    LDAP server.

    Example2:
    samba-tool contact add --given-name=James --initials=T --surname=Kirk

    The example shows how to add a new contact to the domain against a local
    server. The resulting name is "James T. Kirk".
    """

    synopsis = "%prog [contactname] [options]"

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
        Option("--ou",
               help=("DN of alternative location (with or without domainDN "
                     "counterpart) in which the new contact will be created. "
                     "E.g. 'OU=<OU name>'. "
                     "Default is the domain base."),
               type=str),
        Option("--surname", help="Contact's surname", type=str),
        Option("--given-name", help="Contact's given name", type=str),
        Option("--initials", help="Contact's initials", type=str),
        Option("--display-name", help="Contact's display name", type=str),
        Option("--job-title", help="Contact's job title", type=str),
        Option("--department", help="Contact's department", type=str),
        Option("--company", help="Contact's company", type=str),
        Option("--description", help="Contact's description", type=str),
        Option("--mail-address", help="Contact's email address", type=str),
        Option("--internet-address", help="Contact's home page", type=str),
        Option("--telephone-number", help="Contact's phone number", type=str),
        Option("--mobile-number",
               help="Contact's mobile phone number",
               type=str),
        Option("--physical-delivery-office",
               help="Contact's office location",
               type=str),
    ]

    takes_args = ["fullcontactname?"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    def run(self,
            fullcontactname=None,
            sambaopts=None,
            credopts=None,
            H=None,
            ou=None,
            surname=None,
            given_name=None,
            initials=None,
            display_name=None,
            job_title=None,
            department=None,
            company=None,
            description=None,
            mail_address=None,
            internet_address=None,
            telephone_number=None,
            mobile_number=None,
            physical_delivery_office=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        try:
            samdb = SamDB(url=H,
                          session_info=system_session(),
                          credentials=creds,
                          lp=lp)
            ret_name = samdb.newcontact(
                fullcontactname=fullcontactname,
                ou=ou,
                surname=surname,
                givenname=given_name,
                initials=initials,
                displayname=display_name,
                jobtitle=job_title,
                department=department,
                company=company,
                description=description,
                mailaddress=mail_address,
                internetaddress=internet_address,
                telephonenumber=telephone_number,
                mobilenumber=mobile_number,
                physicaldeliveryoffice=physical_delivery_office)
        except Exception as e:
            raise CommandError("Failed to add contact", e)

        self.outf.write("Contact '%s' added successfully\n" % ret_name)


class cmd_delete(Command):
    """Delete a contact.

    This command deletes a contact object from the Active Directory domain.

    The contactname specified on the command is the common name or the
    distinguished name of the contact object. The distinguished name of the
    contact can be specified with or without the domainDN component.

    Example:
    samba-tool contact delete Contact1 \\
        -H ldap://samba.samdom.example.com \\
        --username=Administrator --password=Passw1rd

    The example shows how to delete a contact in the domain against a remote
    LDAP server.
    """
    synopsis = "%prog <contactname> [options]"

    takes_options = [
        Option("-H",
               "--URL",
               help="LDB URL for database or target server",
               type=str,
               metavar="URL",
               dest="H"),
    ]

    takes_args = ["contactname"]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    def run(self,
            contactname,
            sambaopts=None,
            credopts=None,
            H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H,
                      session_info=system_session(),
                      credentials=creds,
                      lp=lp)
        base_dn = samdb.domain_dn()
        scope = ldb.SCOPE_SUBTREE

        filter = ("(&(objectClass=contact)(name=%s))" %
                  ldb.binary_encode(contactname))

        if contactname.upper().startswith("CN="):
            # contact is specified by DN
            filter = "(objectClass=contact)"
            scope = ldb.SCOPE_BASE
            try:
                base_dn = samdb.normalize_dn_in_domain(contactname)
            except Exception as e:
                raise CommandError('Invalid dn "%s": %s' %
                                   (contactname, e))

        try:
            res = samdb.search(base=base_dn,
                               scope=scope,
                               expression=filter,
                               attrs=["dn"])
            contact_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find contact "%s"' % (contactname))

        if len(res) > 1:
            for msg in sorted(res, key=attrgetter('dn')):
                self.outf.write("found: %s\n" % msg.dn)
            raise CommandError("Multiple results for contact '%s'\n"
                               "Please specify the contact's full DN" %
                               contactname)

        try:
            samdb.delete(contact_dn)
        except Exception as e:
            raise CommandError('Failed to remove contact "%s"' % contactname, e)
        self.outf.write("Deleted contact %s\n" % contactname)


class cmd_list(Command):
    """List all contacts.
    """

    synopsis = "%prog [options]"

    takes_options = [
        Option("-H",
               "--URL",
               help="LDB URL for database or target server",
               type=str,
               metavar="URL",
               dest="H"),
        Option("-b", "--base-dn",
               help="Specify base DN to use.",
               type=str),
        Option("--full-dn",
               dest="full_dn",
               default=False,
               action='store_true',
               help="Display contact's full DN instead of the name."),
    ]

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    def run(self,
            sambaopts=None,
            credopts=None,
            H=None,
            base_dn=None,
            full_dn=False):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)

        samdb = SamDB(url=H,
                      session_info=system_session(),
                      credentials=creds,
                      lp=lp)

        search_dn = samdb.domain_dn()
        if base_dn:
            search_dn = samdb.normalize_dn_in_domain(base_dn)

        res = samdb.search(search_dn,
                           scope=ldb.SCOPE_SUBTREE,
                           expression="(objectClass=contact)",
                           attrs=["name"])
        if (len(res) == 0):
            return

        if full_dn:
            for msg in sorted(res, key=attrgetter('dn')):
                self.outf.write("%s\n" % msg.dn)
            return

        for msg in res:
            contact_name = msg.get("name", idx=0)

            self.outf.write("%s\n" % contact_name)


class cmd_edit(Command):
    """Modify a contact.

    This command will allow editing of a contact object in the Active Directory
    domain. You will then be able to add or change attributes and their values.

    The contactname specified on the command is the common name or the
    distinguished name of the contact object. The distinguished name of the
    contact can be specified with or without the domainDN component.

    The command may be run from the root userid or another authorized userid.

    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example1:
    samba-tool contact edit Contact1 -H ldap://samba.samdom.example.com \\
        -U Administrator --password=Passw1rd

    Example1 shows how to edit a contact's attributes in the domain against a
    remote LDAP server.

    The -H parameter is used to specify the remote target server.

    Example2:
    samba-tool contact edit CN=Contact2,OU=people,DC=samdom,DC=example,DC=com

    Example2 shows how to edit a contact's attributes in the domain against a
    local server. The contact, which is located in the 'people' OU,
    is specified by the full distinguished name.

    Example3:
    samba-tool contact edit Contact3 --editor=nano

    Example3 shows how to edit a contact's attributes in the domain against a
    local server using the 'nano' editor.
    """
    synopsis = "%prog <contactname> [options]"

    takes_options = [
        Option("-H",
               "--URL",
               help="LDB URL for database or target server",
               type=str,
               metavar="URL",
               dest="H"),
        Option("--editor",
               help="Editor to use instead of the system default, "
                    "or 'vi' if no system default is set.",
               type=str),
    ]

    takes_args = ["contactname"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    def run(self,
            contactname,
            sambaopts=None,
            credopts=None,
            H=None,
            editor=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        base_dn = samdb.domain_dn()
        scope = ldb.SCOPE_SUBTREE

        filter = ("(&(objectClass=contact)(name=%s))" %
                   ldb.binary_encode(contactname))

        if contactname.upper().startswith("CN="):
            # contact is specified by DN
            filter = "(objectClass=contact)"
            scope = ldb.SCOPE_BASE
            try:
                base_dn = samdb.normalize_dn_in_domain(contactname)
            except Exception as e:
                raise CommandError('Invalid dn "%s": %s' %
                                   (contactname, e))

        try:
            res = samdb.search(base=base_dn,
                               scope=scope,
                               expression=filter)
            contact_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find contact "%s"' % (contactname))

        if len(res) > 1:
            for msg in sorted(res, key=attrgetter('dn')):
                self.outf.write("found: %s\n" % msg.dn)
            raise CommandError("Multiple results for contact '%s'\n"
                               "Please specify the contact's full DN" %
                               contactname)

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
            raise CommandError("Failed to modify contact '%s': " % contactname,
                               e)

        self.outf.write("Modified contact '%s' successfully\n" % contactname)


class cmd_show(Command):
    """Display a contact.

    This command displays a contact object with it's attributes in the Active
    Directory domain.

    The contactname specified on the command is the common name or the
    distinguished name of the contact object. The distinguished name of the
    contact can be specified with or without the domainDN component.

    The command may be run from the root userid or another authorized userid.

    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example1:
    samba-tool contact show Contact1 -H ldap://samba.samdom.example.com \\
        -U Administrator --password=Passw1rd

    Example1 shows how to display a contact's attributes in the domain against
    a remote LDAP server.

    The -H parameter is used to specify the remote target server.

    Example2:
    samba-tool contact show CN=Contact2,OU=people,DC=samdom,DC=example,DC=com

    Example2 shows how to display a contact's attributes in the domain against
    a local server. The contact, which is located in the 'people' OU, is
    specified by the full distinguished name.

    Example3:
    samba-tool contact show Contact3 --attributes=mail,mobile

    Example3 shows how to display a contact's mail and mobile attributes.
    """
    synopsis = "%prog <contactname> [options]"

    takes_options = [
        Option("-H",
               "--URL",
               help="LDB URL for database or target server",
               type=str,
               metavar="URL",
               dest="H"),
        Option("--attributes",
               help=("Comma separated list of attributes, "
                     "which will be printed."),
               type=str,
               dest="contact_attrs"),
    ]

    takes_args = ["contactname"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    def run(self,
            contactname,
            sambaopts=None,
            credopts=None,
            H=None,
            contact_attrs=None):

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H,
                      session_info=system_session(),
                      credentials=creds,
                      lp=lp)
        base_dn = samdb.domain_dn()
        scope = ldb.SCOPE_SUBTREE

        attrs = None
        if contact_attrs:
            attrs = contact_attrs.split(",")

        filter = ("(&(objectClass=contact)(name=%s))" %
                  ldb.binary_encode(contactname))

        if contactname.upper().startswith("CN="):
            # contact is specified by DN
            filter = "(objectClass=contact)"
            scope = ldb.SCOPE_BASE
            try:
                base_dn = samdb.normalize_dn_in_domain(contactname)
            except Exception as e:
                raise CommandError('Invalid dn "%s": %s' %
                                   (contactname, e))

        try:
            res = samdb.search(base=base_dn,
                               expression=filter,
                               scope=scope,
                               attrs=attrs)
            contact_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find contact "%s"' % (contactname))

        if len(res) > 1:
            for msg in sorted(res, key=attrgetter('dn')):
                self.outf.write("found: %s\n" % msg.dn)
            raise CommandError("Multiple results for contact '%s'\n"
                               "Please specify the contact's DN" %
                               contactname)

        for msg in res:
            contact_ldif = common.get_ldif_for_editor(samdb, msg)
            self.outf.write(contact_ldif)


class cmd_move(Command):
    """Move a contact object to an organizational unit or container.

    The contactname specified on the command is the common name or the
    distinguished name of the contact object. The distinguished name of the
    contact can be specified with or without the domainDN component.

    The name of the organizational unit or container can be specified as the
    distinguished name, with or without the domainDN component.

    The command may be run from the root userid or another authorized userid.

    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example1:
    samba-tool contact move Contact1 'OU=people' \\
        -H ldap://samba.samdom.example.com -U Administrator

    Example1 shows how to move a contact Contact1 into the 'people'
    organizational unit on a remote LDAP server.

    The -H parameter is used to specify the remote target server.

    Example2:
    samba-tool contact move Contact1 OU=Contacts,DC=samdom,DC=example,DC=com

    Example2 shows how to move a contact Contact1 into the OU=Contacts
    organizational unit on the local server.
    """

    synopsis = "%prog <contactname> <new_parent_dn> [options]"

    takes_options = [
        Option("-H",
               "--URL",
               help="LDB URL for database or target server",
               type=str,
               metavar="URL",
               dest="H"),
    ]

    takes_args = ["contactname", "new_parent_dn"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }

    def run(self,
            contactname,
            new_parent_dn,
            sambaopts=None,
            credopts=None,
            H=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H,
                      session_info=system_session(),
                      credentials=creds,
                      lp=lp)
        base_dn = samdb.domain_dn()
        scope = ldb.SCOPE_SUBTREE

        filter = ("(&(objectClass=contact)(name=%s))" %
                  ldb.binary_encode(contactname))

        if contactname.upper().startswith("CN="):
            # contact is specified by DN
            filter = "(objectClass=contact)"
            scope = ldb.SCOPE_BASE
            try:
                base_dn = samdb.normalize_dn_in_domain(contactname)
            except Exception as e:
                raise CommandError('Invalid dn "%s": %s' %
                                   (contactname, e))

        try:
            res = samdb.search(base=base_dn,
                               scope=scope,
                               expression=filter,
                               attrs=["dn"])
            contact_dn = res[0].dn
        except IndexError:
            raise CommandError('Unable to find contact "%s"' % (contactname))

        if len(res) > 1:
            for msg in sorted(res, key=attrgetter('dn')):
                self.outf.write("found: %s\n" % msg.dn)
            raise CommandError("Multiple results for contact '%s'\n"
                               "Please specify the contact's full DN" %
                               contactname)

        try:
            full_new_parent_dn = samdb.normalize_dn_in_domain(new_parent_dn)
        except Exception as e:
            raise CommandError('Invalid new_parent_dn "%s": %s' %
                               (new_parent_dn, e))

        full_new_contact_dn = ldb.Dn(samdb, str(contact_dn))
        full_new_contact_dn.remove_base_components(len(contact_dn) - 1)
        full_new_contact_dn.add_base(full_new_parent_dn)

        try:
            samdb.rename(contact_dn, full_new_contact_dn)
        except Exception as e:
            raise CommandError('Failed to move contact "%s"' % contactname, e)
        self.outf.write('Moved contact "%s" into "%s"\n' %
                        (contactname, full_new_parent_dn))

class cmd_rename(Command):
    """Rename a contact and related attributes.

    This command allows to set the contact's name related attributes.
    The contact's new CN will be made up by combining the given-name, initials
    and surname. A dot ('.') will be appended to the initials automatically, if
    required.
    Use the --force-new-cn option to specify the new CN manually and the
    --reset-cn option to reset this changes.

    Use an empty attribute value to remove the specified attribute.

    The contactname specified on the command is the CN.

    The command may be run locally from the root userid or another authorized
    userid.

    The -H or --URL= option can be used to execute the command against a remote
    server.

    Example1:
    samba-tool contact rename "John Doe" --surname=Bloggs \\
        --force-new-cn=John

    Example1 shows how to change the surname ('sn' attribute) of a contact
    'John Doe' to 'Bloggs' and change the CN to 'John' on the local server.

    Example2:
    samba-tool contact rename "J Doe" --given-name=John
        -H ldap://samba.samdom.example.com -U administrator

    Example2 shows how to rename the given name of a contact 'J Doe' to
    'John'. The contact's cn will be renamed automatically, based on
    the given name, initials and surname, if the previous CN is the
    standard combination of the previous name attributes.
    The -H parameter is used to specify the remote target server.
    """

    synopsis = "%prog <contactname> [options]"

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
        ]

    takes_args = ["contactname"]
    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "credopts": options.CredentialsOptions,
    }


    def run(self, contactname, credopts=None, sambaopts=None,
            H=None, surname=None, given_name=None, initials=None, force_new_cn=None,
            display_name=None, mail_address=None, reset_cn=None):
        # illegal options
        if force_new_cn and reset_cn:
            raise CommandError("It is not allowed to specify --force-new-cn "
                               "together with --reset-cn.")
        if force_new_cn == "":
            raise CommandError("Failed to rename contact - delete protected "
                               "attribute 'CN'")

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp, fallback_machine=True)
        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)
        domain_dn = ldb.Dn(samdb, samdb.domain_dn())

        filter = ("(&(objectClass=contact)(name=%s))" %
                  ldb.binary_encode(contactname))
        try:
            res = samdb.search(base=domain_dn,
                               scope=ldb.SCOPE_SUBTREE,
                               expression=filter,
                               attrs=["name",
                                      "sn",
                                      "givenName",
                                      "cn",
                                      "initials",
                                      "displayName",
                                      "mail"]
                             )
            old_contact = res[0]
            contact_dn = old_contact.dn
        except IndexError:
           raise CommandError('Unable to find contact "%s"' % (contactname))

        contact_parent_dn = contact_dn.parent()
        old_cn = old_contact["cn"][0]

        if force_new_cn is not None:
            new_cn = force_new_cn
        else:
            new_cn = samdb.fullname_from_names(old_attrs=old_contact,
                                               given_name=given_name,
                                               initials=initials,
                                               surname=surname)

        # change CN, if the new CN is different and the old CN is the
        # standard CN or the change is forced with force-new-cn or reset-cn
        excepted_cn = samdb.fullname_from_names(old_attrs=old_contact)
        must_change_cn = str(old_cn) != str(new_cn) and \
                         (str(old_cn) == str(excepted_cn) or \
                          reset_cn or bool(force_new_cn))

        new_contact_dn = ldb.Dn(samdb, "CN=%s" % new_cn)
        new_contact_dn.add_base(contact_parent_dn)

        if new_cn == "" and must_change_cn:
            raise CommandError("Failed to rename contact '%s' - "
                               "can not set an empty CN "
                               "(please use --force-new-cn to specify a "
                               "different CN or --given-name, --initials or "
                               "--surname to set name attributes)" % old_cn)

        # format given attributes
        contact_attrs = ldb.Message()
        contact_attrs.dn = contact_dn
        samdb.prepare_attr_replace(contact_attrs, old_contact, "givenName", given_name)
        samdb.prepare_attr_replace(contact_attrs, old_contact, "sn", surname)
        samdb.prepare_attr_replace(contact_attrs, old_contact, "initials", initials)
        samdb.prepare_attr_replace(contact_attrs, old_contact, "displayName", display_name)
        samdb.prepare_attr_replace(contact_attrs, old_contact, "mail", mail_address)

        contact_attributes_changed = len(contact_attrs) > 0

        # update the contact with formatted attributes
        samdb.transaction_start()
        try:
            if contact_attributes_changed == True:
                samdb.modify(contact_attrs)
            if must_change_cn:
                samdb.rename(contact_dn, new_contact_dn)
        except Exception as e:
            samdb.transaction_cancel()
            raise CommandError('Failed to rename contact "%s"' % contactname, e)
        samdb.transaction_commit()

        if must_change_cn:
            self.outf.write('Renamed CN of contact "%s" from "%s" to "%s" '
                            'successfully\n' % (contactname, old_cn, new_cn))

        if contact_attributes_changed:
            self.outf.write('Following attributes of contact "%s" have been '
                            'changed successfully:\n' % (contactname))
            for attr in contact_attrs.keys():
                if attr == "dn":
                    continue
                self.outf.write('%s: %s\n' % (attr, contact_attrs[attr]
                            if contact_attrs[attr] else '[removed]'))

class cmd_contact(SuperCommand):
    """Contact management."""

    subcommands = {}
    subcommands["add"] = cmd_add()
    subcommands["create"] = cmd_add()
    subcommands["delete"] = cmd_delete()
    subcommands["edit"] = cmd_edit()
    subcommands["list"] = cmd_list()
    subcommands["move"] = cmd_move()
    subcommands["show"] = cmd_show()
    subcommands["rename"] = cmd_rename()
