# domain management - domain schemaupgrade
#
# Copyright Matthias Dieter Wallnoefer 2009
# Copyright Andrew Kroeger 2009
# Copyright Jelmer Vernooij 2007-2012
# Copyright Giampaolo Lauria 2011
# Copyright Matthieu Patou <mat@matws.net> 2011
# Copyright Andrew Bartlett 2008-2015
# Copyright Stefan Metzmacher 2012
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
import shutil
import subprocess
import tempfile

import ldb
import samba.getopt as options
from samba.auth import system_session
from samba.netcmd import Command, CommandError, Option
from samba.netcmd.fsmo import get_fsmo_roleowner
from samba.provision import setup_path
from samba.samdb import SamDB


class ldif_schema_update:
    """Helper class for applying LDIF schema updates"""

    def __init__(self):
        self.is_defunct = False
        self.unknown_oid = None
        self.dn = None
        self.ldif = ""

    def can_ignore_failure(self, error):
        """Checks if we can safely ignore failure to apply an LDIF update"""
        (num, errstr) = error.args

        # Microsoft has marked objects as defunct that Samba doesn't know about
        if num == ldb.ERR_NO_SUCH_OBJECT and self.is_defunct:
            print("Defunct object %s doesn't exist, skipping" % self.dn)
            return True
        elif self.unknown_oid is not None:
            print("Skipping unknown OID %s for object %s" % (self.unknown_oid, self.dn))
            return True

        return False

    def apply(self, samdb):
        """Applies a single LDIF update to the schema"""

        try:
            try:
                samdb.modify_ldif(self.ldif, controls=['relax:0'])
            except ldb.LdbError as e:
                if e.args[0] == ldb.ERR_INVALID_ATTRIBUTE_SYNTAX:

                    # REFRESH after a failed change

                    # Otherwise the OID-to-attribute mapping in
                    # _apply_updates_in_file() won't work, because it
                    # can't lookup the new OID in the schema
                    samdb.set_schema_update_now()

                    samdb.modify_ldif(self.ldif, controls=['relax:0'])
                else:
                    raise
        except ldb.LdbError as e:
            if self.can_ignore_failure(e):
                return 0
            else:
                print("Exception: %s" % e)
                print("Encountered while trying to apply the following LDIF")
                print("----------------------------------------------------")
                print("%s" % self.ldif)

                raise

        return 1


class cmd_domain_schema_upgrade(Command):
    """Domain schema upgrading"""

    synopsis = "%prog [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptions,
    }

    takes_options = [
        Option("-H", "--URL", help="LDB URL for database or target server", type=str,
               metavar="URL", dest="H"),
        Option("-q", "--quiet", help="Be quiet", action="store_true"),  # unused
        Option("-v", "--verbose", help="Be verbose", action="store_true"),
        Option("--schema", type="choice", metavar="SCHEMA",
               choices=["2012", "2012_R2", "2016", "2019"],
               help="The schema file to upgrade to. Default is (Windows) 2019.",
               default="2019"),
        Option("--ldf-file", type=str, default=None,
               help="Just apply the schema updates in the adprep/.LDF file(s) specified"),
        Option("--base-dir", type=str, default=None,
               help="Location of ldf files Default is ${SETUPDIR}/adprep.")
    ]

    def _apply_updates_in_file(self, samdb, ldif_file):
        """
        Applies a series of updates specified in an .LDIF file. The .LDIF file
        is based on the adprep Schema updates provided by Microsoft.
        """
        count = 0
        ldif_op = ldif_schema_update()

        # parse the file line by line and work out each update operation to apply
        for line in ldif_file:

            line = line.rstrip()

            # the operations in the .LDIF file are separated by blank lines. If
            # we hit a blank line, try to apply the update we've parsed so far
            if line == '':

                # keep going if we haven't parsed anything yet
                if ldif_op.ldif == '':
                    continue

                # Apply the individual change
                count += ldif_op.apply(samdb)

                # start storing the next operation from scratch again
                ldif_op = ldif_schema_update()
                continue

            # replace the placeholder domain name in the .ldif file with the real domain
            if line.upper().endswith('DC=X'):
                line = line[:-len('DC=X')] + str(samdb.get_default_basedn())
            elif line.upper().endswith('CN=X'):
                line = line[:-len('CN=X')] + str(samdb.get_default_basedn())

            values = line.split(':')

            if values[0].lower() == 'dn':
                ldif_op.dn = values[1].strip()

            # replace the Windows-specific operation with the Samba one
            if values[0].lower() == 'changetype':
                line = line.lower().replace(': ntdsschemaadd',
                                            ': add')
                line = line.lower().replace(': ntdsschemamodify',
                                            ': modify')
                line = line.lower().replace(': ntdsschemamodrdn',
                                            ': modrdn')
                line = line.lower().replace(': ntdsschemadelete',
                                            ': delete')

            if values[0].lower() in ['rdnattid', 'subclassof',
                                     'systemposssuperiors',
                                     'systemmaycontain',
                                     'systemauxiliaryclass']:
                _, value = values

                # The Microsoft updates contain some OIDs we don't recognize.
                # Query the DB to see if we can work out the OID this update is
                # referring to. If we find a match, then replace the OID with
                # the ldapDisplayname
                if '.' in value:
                    res = samdb.search(base=samdb.get_schema_basedn(),
                                       expression="(|(attributeId=%s)(governsId=%s))" %
                                       (value, value),
                                       attrs=['ldapDisplayName'])

                    if len(res) != 1:
                        ldif_op.unknown_oid = value
                    else:
                        display_name = str(res[0]['ldapDisplayName'][0])
                        line = line.replace(value, ' ' + display_name)

            # Microsoft has marked objects as defunct that Samba doesn't know about
            if values[0].lower() == 'isdefunct' and values[1].strip().lower() == 'true':
                ldif_op.is_defunct = True

            # Samba has added the showInAdvancedViewOnly attribute to all objects,
            # so rather than doing an add, we need to do a replace
            if values[0].lower() == 'add' and values[1].strip().lower() == 'showinadvancedviewonly':
                line = 'replace: showInAdvancedViewOnly'

            # Add the line to the current LDIF operation (including the newline
            # we stripped off at the start of the loop)
            ldif_op.ldif += line + '\n'

        return count

    def _apply_update(self, samdb, update_file, base_dir):
        """Wrapper function for parsing an LDIF file and applying the updates"""

        print("Applying %s updates..." % update_file)

        ldif_file = None
        try:
            ldif_file = open(os.path.join(base_dir, update_file))

            count = self._apply_updates_in_file(samdb, ldif_file)

        finally:
            if ldif_file:
                ldif_file.close()

        print("%u changes applied" % count)

        return count

    def run(self, **kwargs):
        try:
            from samba.ms_schema_markdown import read_ms_markdown
        except ImportError as e:
            self.outf.write("Exception in importing markdown: %s\n" % e)
            raise CommandError('Failed to import module markdown')
        from samba.schema import Schema

        updates_allowed_overridden = False
        sambaopts = kwargs.get("sambaopts")
        credopts = kwargs.get("credopts")
        lp = sambaopts.get_loadparm()
        creds = credopts.get_credentials(lp)
        H = kwargs.get("H")
        target_schema = kwargs.get("schema")
        ldf_files = kwargs.get("ldf_file")
        base_dir = kwargs.get("base_dir")

        temp_folder = None

        # we set the transaction_index_cache_size to 200,000 to ensure it is
        # not too small, if it's too small the performance of the upgrade will
        # be negatively impacted. (similarly to the join operation)
        samdb = SamDB(url=H, session_info=system_session(), credentials=creds, lp=lp,
                      options=['transaction_index_cache_size:200000'])

        # we're not going to get far if the config doesn't allow schema updates
        if lp.get("dsdb:schema update allowed") is None:
            lp.set("dsdb:schema update allowed", "yes")
            print("Temporarily overriding 'dsdb:schema update allowed' setting")
            updates_allowed_overridden = True

        own_dn = ldb.Dn(samdb, samdb.get_dsServiceName())
        master = get_fsmo_roleowner(samdb, str(samdb.get_schema_basedn()),
                                    'schema')
        if own_dn != master:
            raise CommandError("This server is not the schema master.")

        # if specific LDIF files were specified, just apply them
        if ldf_files:
            schema_updates = ldf_files.split(",")
        else:
            schema_updates = []

            # work out the version of the target schema we're upgrading to
            end = Schema.get_version(target_schema)

            # work out the version of the schema we're currently using
            res = samdb.search(base=samdb.get_schema_basedn(),
                               scope=ldb.SCOPE_BASE, attrs=['objectVersion'])

            if len(res) != 1:
                raise CommandError('Could not determine current schema version')
            start = int(res[0]['objectVersion'][0]) + 1

            diff_dir = setup_path("adprep/WindowsServerDocs")
            if base_dir is None:
                # Read from the Schema-Updates.md file
                temp_folder = tempfile.mkdtemp()

                update_file = setup_path("adprep/WindowsServerDocs/Schema-Updates.md")

                try:
                    read_ms_markdown(update_file, temp_folder)
                except Exception as e:
                    print("Exception in markdown parsing: %s" % e)
                    shutil.rmtree(temp_folder)
                    raise CommandError('Failed to upgrade schema')

                base_dir = temp_folder

            for version in range(start, end + 1):
                update = 'Sch%d.ldf' % version
                schema_updates.append(update)

                # Apply patches if we parsed the Schema-Updates.md file
                diff = os.path.abspath(os.path.join(diff_dir, update + '.diff'))
                if temp_folder and os.path.exists(diff):
                    try:
                        p = subprocess.Popen(['patch', update, '-i', diff],
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, cwd=temp_folder)
                    except (OSError, IOError):
                        shutil.rmtree(temp_folder)
                        raise CommandError("Failed to upgrade schema. "
                                           "Is '/usr/bin/patch' missing?")

                    stdout, stderr = p.communicate()

                    if p.returncode:
                        print("Exception in patch: %s\n%s" % (stdout, stderr))
                        shutil.rmtree(temp_folder)
                        raise CommandError('Failed to upgrade schema')

                    print("Patched %s using %s" % (update, diff))

        if base_dir is None:
            base_dir = setup_path("adprep")

        samdb.transaction_start()
        count = 0
        error_encountered = False

        try:
            # Apply the schema updates needed to move to the new schema version
            for ldif_file in schema_updates:
                count += self._apply_update(samdb, ldif_file, base_dir)

            if count > 0:
                samdb.transaction_commit()
                print("Schema successfully updated")
            else:
                print("No changes applied to schema")
                samdb.transaction_cancel()
        except Exception as e:
            print("Exception: %s" % e)
            print("Error encountered, aborting schema upgrade")
            samdb.transaction_cancel()
            error_encountered = True

        if updates_allowed_overridden:
            lp.set("dsdb:schema update allowed", "no")

        if temp_folder:
            shutil.rmtree(temp_folder)

        if error_encountered:
            raise CommandError('Failed to upgrade schema')
