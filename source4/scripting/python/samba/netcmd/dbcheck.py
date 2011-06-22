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
from samba.common import confirm
from samba.auth import system_session
from samba.samdb import SamDB
from samba.netcmd import (
    Command,
    CommandError,
    Option
    )

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
               help="don't confirm changes, just do them all"),
        Option("--cross-ncs", dest="cross_ncs", default=False, action='store_true',
               help="cross naming context boundaries"),
        Option("-v", "--verbose", dest="verbose", action="store_true", default=False,
            help="Print more details of checking"),
        ]

    def run(self, DN=None, verbose=False, fix=False, yes=False, cross_ncs=False,
            scope="SUB", credopts=None, sambaopts=None, versionopts=None):
        self.lp = sambaopts.get_loadparm()
        self.creds = credopts.get_credentials(self.lp, fallback_machine=True)

        self.samdb = SamDB(session_info=system_session(), url=None,
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
        if cross_ncs:
            controls.append("search_options:1:2")

        res = self.samdb.search(base=DN, scope=self.search_scope, attrs=['dn'], controls=controls)
        print('Checking %u objects' % len(res))
        error_count = 0
        for object in res:
            error_count += self.check_object(object.dn)
        if error_count != 0 and not self.fix:
            print("Please use --fix to fix these errors")
        print('Checked %u objects (%u errors)' % (len(res), error_count))
        if error_count != 0:
            sys.exit(1)


    ################################################################
    # handle empty attributes
    def empty_attribute(self, dn, attrname):
        '''fix empty attributes'''
        print("ERROR: Empty attribute %s in %s" % (attrname, dn))
        if not self.fix:
            return
        if not confirm('Remove empty attribute %s from %s?' % (attrname, dn), self.yes):
            print("Not fixing empty attribute %s" % attrname)
            return

        m = ldb.Message()
        m.dn = dn
        m[attrname] = ldb.MessageElement('', ldb.FLAG_MOD_DELETE, attrname)
        try:
            self.samdb.modify(m, controls=["relax:0"], validate=False)
        except Exception, msg:
            print("Failed to remove empty attribute %s : %s" % (attrname, msg))
            return
        print("Removed empty attribute %s" % attrname)


    ################################################################
    # handle normalisation mismatches
    def normalise_mismatch(self, dn, attrname, values):
        '''fix attribute normalisation errors'''
        print("ERROR: Normalisation error for attribute %s in %s" % (attrname, dn))
        mod_list = []
        for val in values:
            normalised = self.samdb.dsdb_normalise_attributes(self.samdb, attrname, [val])
            if len(normalised) != 1:
                print("Unable to normalise value '%s'" % val)
                mod_list.append((val, ''))
            elif (normalised[0] != val):
                print("value '%s' should be '%s'" % (val, normalised[0]))
                mod_list.append((val, normalised[0]))
        if not self.fix:
            return
        if not confirm('Fix normalisation for %s from %s?' % (attrname, dn), self.yes):
            print("Not fixing attribute %s" % attrname)
            return

        m = ldb.Message()
        m.dn = dn
        for i in range(0, len(mod_list)):
            (val, nval) = mod_list[i]
            m['value_%u' % i] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
            if nval != '':
                m['normv_%u' % i] = ldb.MessageElement(nval, ldb.FLAG_MOD_ADD, attrname)

        try:
            self.samdb.modify(m, controls=["relax:0"], validate=False)
        except Exception, msg:
            print("Failed to normalise attribute %s : %s" % (attrname, msg))
            return
        print("Normalised attribute %s" % attrname)


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
                    self.empty_attribute(dn, attrname)
                    error_count += 1
                    continue

            # check for incorrectly normalised attributes
            for val in obj[attrname]:
                normalised = self.samdb.dsdb_normalise_attributes(self.samdb, attrname, [val])
                if len(normalised) != 1 or normalised[0] != val:
                    self.normalise_mismatch(dn, attrname, obj[attrname])
                    error_count += 1
                    break
        return error_count
