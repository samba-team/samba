#!/usr/bin/env python
#
# Samba4 AD database checker
#
# Copyright (C) Andrew Tridgell 2011
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

import ldb, sys
import samba.getopt as options
from samba import dsdb
from samba import common
from samba.auth import system_session
from samba.samdb import SamDB
from samba.dcerpc import misc
from samba.netcmd import (
    Command,
    CommandError,
    Option
    )


class dsdb_DN(object):
    '''a class to manipulate DN components'''

    def __init__(self, samdb, dnstring, syntax_oid):
        if syntax_oid in [ dsdb.DSDB_SYNTAX_BINARY_DN, dsdb.DSDB_SYNTAX_STRING_DN ]:
            colons = dnstring.split(':')
            if len(colons) < 4:
                raise Exception("invalid DN prefix")
            prefix_len = 4 + len(colons[1]) + int(colons[1])
            self.prefix = dnstring[0:prefix_len]
            self.dnstring = dnstring[prefix_len:]
        else:
            self.dnstring = dnstring
            self.prefix = ''
        try:
            self.dn = ldb.Dn(samdb, self.dnstring)
        except Exception, msg:
            print("ERROR: bad DN string '%s'" % self.dnstring)
            raise

    def __str__(self):
        return self.prefix + str(self.dn.extended_str(mode=1))


class cmd_dbcheck(Command):
    """check local AD database for errors"""
    synopsis = "dbcheck <DN> [options]"

    takes_optiongroups = {
        "sambaopts": options.SambaOptions,
        "versionopts": options.VersionOptions,
        "credopts": options.CredentialsOptionsDouble,
    }

    takes_args = ["DN?"]

    takes_options = [
        Option("--scope", dest="scope", default="SUB",
            help="Pass search scope that builds DN list. Options: SUB, ONE, BASE"),
        Option("--fix", dest="fix", default=False, action='store_true',
               help='Fix any errors found'),
        Option("--yes", dest="yes", default=False, action='store_true',
               help="don't confirm changes, just do them all as a single transaction"),
        Option("--cross-ncs", dest="cross_ncs", default=False, action='store_true',
               help="cross naming context boundaries"),
        Option("-v", "--verbose", dest="verbose", action="store_true", default=False,
            help="Print more details of checking"),
        Option("-H", help="LDB URL for database or target server (defaults to local SAM database)", type=str),
        ]

    def run(self, H=None, DN=None, verbose=False, fix=False, yes=False, cross_ncs=False,
            scope="SUB", credopts=None, sambaopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.samdb = SamDB(session_info=system_session(), url=H,
                           credentials=self.creds, lp=self.lp)
        if H is None:
            self.local_samdb = self.samdb
        else:
            self.local_samdb = SamDB(session_info=system_session(), url=None,
                                     credentials=self.creds, lp=self.lp)

        self.verbose = verbose
        self.fix = fix
        self.yes = yes

        scope_map = { "SUB": ldb.SCOPE_SUBTREE, "BASE":ldb.SCOPE_BASE, "ONE":ldb.SCOPE_ONELEVEL }
        scope = scope.upper()
        if not scope in scope_map:
            raise CommandError("Unknown scope %s" % scope)
        self.search_scope = scope_map[scope]

        controls = []
        if H is not None:
            controls.append('paged_results:1:1000')
        if cross_ncs:
            controls.append("search_options:1:2")

        if self.yes and self.fix:
            self.samdb.transaction_start()

        res = self.samdb.search(base=DN, scope=self.search_scope, attrs=['dn'], controls=controls)
        print('Checking %u objects' % len(res))
        error_count = 0
        for object in res:
            error_count += self.check_object(object.dn)
        if error_count != 0 and not self.fix:
            print("Please use --fix to fix these errors")
        print('Checked %u objects (%u errors)' % (len(res), error_count))

        if self.yes and self.fix:
            self.samdb.transaction_commit()

        if error_count != 0:
            sys.exit(1)



    ################################################################
    # a local confirm function that obeys the --fix and --yes options
    def confirm(self, msg):
        '''confirm a change'''
        if not self.fix:
            return False
        return common.confirm(msg, forced=self.yes)


    ################################################################
    # handle empty attributes
    def err_empty_attribute(self, dn, attrname):
        '''fix empty attributes'''
        print("ERROR: Empty attribute %s in %s" % (attrname, dn))
        if not self.confirm('Remove empty attribute %s from %s?' % (attrname, dn)):
            print("Not fixing empty attribute %s" % attrname)
            return

        m = ldb.Message()
        m.dn = dn
        m[attrname] = ldb.MessageElement('', ldb.FLAG_MOD_DELETE, attrname)
        if self.verbose:
            print(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            self.samdb.modify(m, controls=["relax:0"], validate=False)
        except Exception, msg:
            print("Failed to remove empty attribute %s : %s" % (attrname, msg))
            return
        print("Removed empty attribute %s" % attrname)


    ################################################################
    # handle normalisation mismatches
    def err_normalise_mismatch(self, dn, attrname, values):
        '''fix attribute normalisation errors'''
        print("ERROR: Normalisation error for attribute %s in %s" % (attrname, dn))
        mod_list = []
        for val in values:
            normalised = self.samdb.dsdb_normalise_attributes(self.local_samdb, attrname, [val])
            if len(normalised) != 1:
                print("Unable to normalise value '%s'" % val)
                mod_list.append((val, ''))
            elif (normalised[0] != val):
                print("value '%s' should be '%s'" % (val, normalised[0]))
                mod_list.append((val, normalised[0]))
        if not self.confirm('Fix normalisation for %s from %s?' % (attrname, dn)):
            print("Not fixing attribute %s" % attrname)
            return

        m = ldb.Message()
        m.dn = dn
        for i in range(0, len(mod_list)):
            (val, nval) = mod_list[i]
            m['value_%u' % i] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
            if nval != '':
                m['normv_%u' % i] = ldb.MessageElement(nval, ldb.FLAG_MOD_ADD, attrname)

        if self.verbose:
            print(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            self.samdb.modify(m, controls=["relax:0"], validate=False)
        except Exception, msg:
            print("Failed to normalise attribute %s : %s" % (attrname, msg))
            return
        print("Normalised attribute %s" % attrname)


    ################################################################
    # handle a missing GUID extended DN component
    def err_incorrect_dn_GUID(self, dn, attrname, val, dsdb_dn, errstr):
        print("ERROR: %s component for %s in object %s - %s" % (errstr, attrname, dn, val))
        try:
            res = self.samdb.search(base=dsdb_dn.dn, scope=ldb.SCOPE_BASE,
                                    attrs=[], controls=["extended_dn:1:1"])
        except ldb.LdbError, (enum, estr):
            print("unable to find object for DN %s - cannot fix (%s)" % (dsdb_dn.dn, estr))
            return
        dsdb_dn.dn = res[0].dn

        if not self.confirm('Change DN to %s?' % str(dsdb_dn)):
            print("Not fixing %s" % errstr)
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        m['new_value'] = ldb.MessageElement(str(dsdb_dn), ldb.FLAG_MOD_ADD, attrname)
        if self.verbose:
            print(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            self.samdb.modify(m)
        except Exception, msg:
            print("Failed to fix %s on attribute %s : %s" % (errstr, attrname, msg))
            return
        print("Fixed %s on attribute %s" % (errstr, attrname))


    ################################################################
    # handle a DN pointing to a deleted object
    def err_deleted_dn(self, dn, attrname, val, dsdb_dn, correct_dn):
        print("ERROR: target DN is deleted for %s in object %s - %s" % (attrname, dn, val))
        print("Target GUID points at deleted DN %s" % correct_dn)
        if not self.confirm('Remove DN?'):
            print("Not removing")
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        if self.verbose:
            print(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            self.samdb.modify(m)
        except Exception, msg:
            print("Failed to remove deleted DN attribute %s : %s" % (attrname, msg))
            return
        print("Removed deleted DN on attribute %s" % attrname)


    ################################################################
    # handle a DN string being incorrect
    def err_dn_target_mismatch(self, dn, attrname, val, dsdb_dn, correct_dn):
        print("ERROR: incorrect DN string component for %s in object %s - %s" % (attrname, dn, val))
        dsdb_dn.dn = correct_dn

        if not self.confirm('Change DN to %s?' % str(dsdb_dn)):
            print("Not fixing %s" % errstr)
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        m['new_value'] = ldb.MessageElement(str(dsdb_dn), ldb.FLAG_MOD_ADD, attrname)
        if self.verbose:
            print(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            self.samdb.modify(m)
        except Exception, msg:
            print("Failed to fix incorrect DN string on attribute %s : %s" % (attrname, msg))
            return
        print("Fixed incorrect DN string on attribute %s" % (attrname))


    ################################################################
    # specialised checking for a dn attribute
    def check_dn(self, obj, attrname, syntax_oid):
        '''check a DN attribute for correctness'''
        error_count = 0
        for val in obj[attrname]:
            dsdb_dn = dsdb_DN(self.samdb, val, syntax_oid)

            # all DNs should have a GUID component
            guid = dsdb_dn.dn.get_extended_component("GUID")
            if guid is None:
                error_count += 1
                self.err_incorrect_dn_GUID(obj.dn, attrname, val, dsdb_dn, "missing GUID")
                continue

            guidstr = str(misc.GUID(guid))

            # check its the right GUID
            try:
                res = self.samdb.search(base="<GUID=%s>" % guidstr, scope=ldb.SCOPE_BASE,
                                        attrs=['isDeleted'], controls=["extended_dn:1:1", "show_deleted:1"])
            except ldb.LdbError, (enum, estr):
                error_count += 1
                self.err_incorrect_dn_GUID(obj.dn, attrname, val, dsdb_dn, "incorrect GUID")
                continue

            # the target DN might be deleted
            if (dsdb_dn.prefix != "B:32:18E2EA80684F11D2B9AA00C04F79F805:" and
                'isDeleted' in res[0] and
                res[0]['isDeleted'][0].upper() == "TRUE"):
                # note that we don't check this for the special wellKnownObjects prefix
                # for Deleted Objects, as we expect that to be deleted
                error_count += 1
                self.err_deleted_dn(obj.dn, attrname, val, dsdb_dn, res[0].dn)
                continue

            # check the DN matches in string form
            if res[0].dn.extended_str() != dsdb_dn.dn.extended_str():
                error_count += 1
                self.err_dn_target_mismatch(obj.dn, attrname, val, dsdb_dn, res[0].dn)
                continue

        return error_count



    ################################################################
    # check one object - calls to individual error handlers above
    def check_object(self, dn):
        '''check one object'''
        if self.verbose:
            print("Checking object %s" % dn)
        res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE, controls=["extended_dn:1:1"], attrs=['*', 'ntSecurityDescriptor'])
        if len(res) != 1:
            print("Object %s disappeared during check" % dn)
            return 1
        obj = res[0]
        error_count = 0
        for attrname in obj:
            if attrname == 'dn':
                continue

            # check for empty attributes
            for val in obj[attrname]:
                if val == '':
                    self.err_empty_attribute(dn, attrname)
                    error_count += 1
                    continue

            # get the syntax oid for the attribute, so we can can have
            # special handling for some specific attribute types
            syntax_oid = self.local_samdb.get_syntax_oid_from_lDAPDisplayName(attrname)

            if syntax_oid in [ dsdb.DSDB_SYNTAX_BINARY_DN, dsdb.DSDB_SYNTAX_OR_NAME,
                               dsdb.DSDB_SYNTAX_STRING_DN, ldb.LDB_SYNTAX_DN ]:
                # it's some form of DN, do specialised checking on those
                error_count += self.check_dn(obj, attrname, syntax_oid)

            # check for incorrectly normalised attributes
            for val in obj[attrname]:
                normalised = self.samdb.dsdb_normalise_attributes(self.local_samdb, attrname, [val])
                if len(normalised) != 1 or normalised[0] != val:
                    self.err_normalise_mismatch(dn, attrname, obj[attrname])
                    error_count += 1
                    break
        return error_count
