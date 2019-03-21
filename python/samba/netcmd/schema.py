# Manipulate ACLs on directory objects
#
# Copyright (C) William Brown <william@blackhats.net.au> 2018
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
from samba.ms_schema import bitFields
from samba.auth import system_session
from samba.samdb import SamDB
from samba.netcmd import (
    Command,
    CommandError,
    SuperCommand,
    Option
)


class cmd_schema_attribute_modify(Command):
    """Modify attribute settings in the schema partition.

    This commands allows minor modifications to attributes in the schema. Active
    Directory does not allow many changes to schema, but important modifications
    are related to indexing. This command overwrites the value of searchflags,
    so be sure to view the current content before making changes.

    Example1:
    samba-tool schema attribute modify uid \\
        --searchflags="fATTINDEX,fPRESERVEONDELETE"

    This alters the uid attribute to be indexed and to be preserved when
    converted to a tombstone.

    Important search flag values are:

    fATTINDEX: create an equality index for this attribute.
    fPDNTATTINDEX: create a container index for this attribute (ie OU).
    fANR: specify that this attribute is a member of the ambiguous name
         resolution set.
    fPRESERVEONDELETE: indicate that the value of this attribute should be
         preserved when the object is converted to a tombstone (deleted).
    fCOPY: hint to clients that this attribute should be copied.
    fTUPLEINDEX: create a tuple index for this attribute. This is used in
          substring queries.
    fSUBTREEATTINDEX: create a browsing index for this attribute. VLV searches
          require this.
    fCONFIDENTIAL: indicate that the attribute is confidental and requires
          special access checks.
    fNEVERVALUEAUDIT: indicate that changes to this value should NOT be audited.
    fRODCFILTEREDATTRIBUTE: indicate that this value should not be replicated to
          RODCs.
    fEXTENDEDLINKTRACKING: indicate to the DC to perform extra link tracking.
    fBASEONLY: indicate that this attribute should only be displayed when the
           search scope of the query is SCOPE_BASE or a single object result.
    fPARTITIONSECRET: indicate that this attribute is a partition secret and
           requires special access checks.

    The authoritative source of this information is the MS-ADTS.
    """
    synopsis = "%prog attribute [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("--searchflags", help="Search Flags for the attribute", type=str),
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["attribute"]

    def run(self, attribute, H=None, credopts=None, sambaopts=None,
            versionopts=None, searchflags=None):

        if searchflags is None:
            raise CommandError('A value to modify must be provided.')

        # Parse the search flags to a set of bits to modify.

        searchflags_int = None
        if searchflags is not None:
            searchflags_int = 0
            flags = searchflags.split(',')
            # We have to normalise all the values. To achieve this predictably
            # we title case (Fattrindex), then swapcase (fATTINDEX)
            flags = [x.capitalize().swapcase() for x in flags]
            for flag in flags:
                if flag not in bitFields['searchflags'].keys():
                    raise CommandError("Unknown flag '%s', please see --help" % flag)
                bit_loc = 31 - bitFields['searchflags'][flag]
                # Now apply the bit.
                searchflags_int = searchflags_int | (1 << bit_loc)

        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        schema_dn = samdb.schema_dn()
        # For now we make assumptions about the CN
        attr_dn = 'cn=%s,%s' % (attribute, schema_dn)

        m = ldb.Message()
        m.dn = ldb.Dn(samdb, attr_dn)

        if searchflags_int is not None:
            m['searchFlags'] = ldb.MessageElement(
                str(searchflags_int), ldb.FLAG_MOD_REPLACE, 'searchFlags')

        samdb.modify(m)
        samdb.set_schema_update_now()
        self.outf.write("modified %s" % attr_dn)


class cmd_schema_attribute_show(Command):
    """Show details about an attribute from the schema.

    Schema attribute definitions define and control the behaviour of directory
    attributes on objects. This displays the details of a single attribute.
    """
    synopsis = "%prog attribute [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["attribute"]

    def run(self, attribute, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        schema_dn = samdb.schema_dn()

        filt = '(&(objectClass=attributeSchema)(|(lDAPDisplayName={0})(cn={0})(name={0})))'.format(attribute)

        res = samdb.search(base=schema_dn, scope=ldb.SCOPE_SUBTREE,
                           expression=filt)

        if len(res) == 0:
            raise CommandError('No schema objects matched "%s"' % attribute)
        if len(res) > 1:
            raise CommandError('Multiple schema objects matched "%s": this is a serious issue you should report!' % attribute)

        # Get the content of searchFlags (if any) and manipulate them to
        # show our friendly names.

        # WARNING: If you are reading this in the future trying to change an
        # ldb message dynamically, and wondering why you get an operations
        # error, it's related to talloc references.
        #
        # When you create *any* python reference, IE:
        # flags = res[0]['attr']
        # this creates a talloc_reference that may live forever due to pythons
        # memory management model. However, when you create this reference it
        # blocks talloc_realloc from functions in msg.add(element).
        #
        # As a result, you MUST avoid ALL new variable references UNTIL you have
        # modified the message as required, even if it makes your code more
        # verbose.

        if 'searchFlags' in res[0].keys():
            flags_i = None
            try:
                # See above
                flags_i = int(str(res[0]['searchFlags']))
            except ValueError:
                raise CommandError('Invalid schemaFlags value "%s": this is a serious issue you should report!' % res[0]['searchFlags'])
            # Work out what keys we have.
            out = []
            for flag in bitFields['searchflags'].keys():
                if flags_i & (1 << (31 - bitFields['searchflags'][flag])) != 0:
                    out.append(flag)
            if len(out) > 0:
                res[0].add(ldb.MessageElement(out, ldb.FLAG_MOD_ADD, 'searchFlagsDecoded'))

        user_ldif = samdb.write_ldif(res[0], ldb.CHANGETYPE_NONE)
        self.outf.write(user_ldif)


class cmd_schema_attribute_show_oc(Command):
    """Show what objectclasses MAY or MUST contain an attribute.

    This is useful to determine "if I need uid, what objectclasses could be
    applied to achieve this."
    """
    synopsis = "%prog attribute [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["attribute"]

    def run(self, attribute, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        schema_dn = samdb.schema_dn()

        may_filt = '(&(objectClass=classSchema)' \
            '(|(mayContain={0})(systemMayContain={0})))'.format(attribute)
        must_filt = '(&(objectClass=classSchema)' \
            '(|(mustContain={0})(systemMustContain={0})))'.format(attribute)

        may_res = samdb.search(base=schema_dn, scope=ldb.SCOPE_SUBTREE,
                               expression=may_filt, attrs=['cn'])
        must_res = samdb.search(base=schema_dn, scope=ldb.SCOPE_SUBTREE,
                                expression=must_filt, attrs=['cn'])

        self.outf.write('--- MAY contain ---\n')
        for msg in may_res:
            self.outf.write('%s\n' % msg['cn'][0])

        self.outf.write('--- MUST contain ---\n')
        for msg in must_res:
            self.outf.write('%s\n' % msg['cn'][0])


class cmd_schema_objectclass_show(Command):
    """Show details about an objectClass from the schema.

    Schema objectClass definitions define and control the behaviour of directory
    objects including what attributes they may contain. This displays the
    details of an objectClass.
    """
    synopsis = "%prog objectclass [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server",
               type=str, metavar="URL", dest="H"),
    ]

    takes_args = ["objectclass"]

    def run(self, objectclass, H=None, credopts=None, sambaopts=None, versionopts=None):
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)

        samdb = SamDB(url=H, session_info=system_session(),
                      credentials=creds, lp=lp)

        schema_dn = samdb.schema_dn()

        filt = '(&(objectClass=classSchema)' \
               '(|(lDAPDisplayName={0})(cn={0})(name={0})))'.format(objectclass)

        res = samdb.search(base=schema_dn, scope=ldb.SCOPE_SUBTREE,
                           expression=filt)

        for msg in res:
            user_ldif = samdb.write_ldif(msg, ldb.CHANGETYPE_NONE)
            self.outf.write(user_ldif)


class cmd_schema_attribute(SuperCommand):
    """Query and manage attributes in the schema partition."""
    subcommands = {}
    subcommands["modify"] = cmd_schema_attribute_modify()
    subcommands["show"] = cmd_schema_attribute_show()
    subcommands["show_oc"] = cmd_schema_attribute_show_oc()


class cmd_schema_objectclass(SuperCommand):
    """Query and manage objectclasses in the schema partition."""
    subcommands = {}
    subcommands["show"] = cmd_schema_objectclass_show()


class cmd_schema(SuperCommand):
    """Schema querying and management."""

    subcommands = {}
    subcommands["attribute"] = cmd_schema_attribute()
    subcommands["objectclass"] = cmd_schema_objectclass()
