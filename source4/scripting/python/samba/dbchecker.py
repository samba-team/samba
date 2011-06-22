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
from samba import dsdb
from samba import common
from samba.dcerpc import misc


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

class dbcheck(object):
    """check a SAM database for errors"""

    def __init__(self, samdb, samdb_schema=None, verbose=False, fix=False, yes=False, quiet=False):
        self.samdb = samdb
        self.samdb_schema = (samdb_schema or samdb)
        self.verbose = verbose
        self.fix = fix
        self.yes = yes
        self.quiet = quiet

    def check_database(self, DN=None, scope=ldb.SCOPE_SUBTREE, controls=[], attrs=['*']):
        '''perform a database check, returning the number of errors found'''

        res = self.samdb.search(base=DN, scope=scope, attrs=['dn'], controls=controls)
        self.report('Checking %u objects' % len(res))
        error_count = 0
        for object in res:
            error_count += self.check_object(object.dn, attrs=attrs)
        if error_count != 0 and not self.fix:
            self.report("Please use --fix to fix these errors")
        self.report('Checked %u objects (%u errors)' % (len(res), error_count))

        return error_count


    def report(self, msg):
        '''print a message unless quiet is set'''
        if not self.quiet:
            print(msg)


    ################################################################
    # a local confirm function that obeys the --fix and --yes options
    def confirm(self, msg):
        '''confirm a change'''
        if not self.fix:
            return False
        if self.quiet:
            return self.yes
        return common.confirm(msg, forced=self.yes)


    ################################################################
    # handle empty attributes
    def err_empty_attribute(self, dn, attrname):
        '''fix empty attributes'''
        self.report("ERROR: Empty attribute %s in %s" % (attrname, dn))
        if not self.confirm('Remove empty attribute %s from %s?' % (attrname, dn)):
            self.report("Not fixing empty attribute %s" % attrname)
            return

        m = ldb.Message()
        m.dn = dn
        m[attrname] = ldb.MessageElement('', ldb.FLAG_MOD_DELETE, attrname)
        if self.verbose:
            self.report(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            self.samdb.modify(m, controls=["relax:0"], validate=False)
        except Exception, msg:
            self.report("Failed to remove empty attribute %s : %s" % (attrname, msg))
            return
        self.report("Removed empty attribute %s" % attrname)


    ################################################################
    # handle normalisation mismatches
    def err_normalise_mismatch(self, dn, attrname, values):
        '''fix attribute normalisation errors'''
        self.report("ERROR: Normalisation error for attribute %s in %s" % (attrname, dn))
        mod_list = []
        for val in values:
            normalised = self.samdb.dsdb_normalise_attributes(self.samdb_schema, attrname, [val])
            if len(normalised) != 1:
                self.report("Unable to normalise value '%s'" % val)
                mod_list.append((val, ''))
            elif (normalised[0] != val):
                self.report("value '%s' should be '%s'" % (val, normalised[0]))
                mod_list.append((val, normalised[0]))
        if not self.confirm('Fix normalisation for %s from %s?' % (attrname, dn)):
            self.report("Not fixing attribute %s" % attrname)
            return

        m = ldb.Message()
        m.dn = dn
        for i in range(0, len(mod_list)):
            (val, nval) = mod_list[i]
            m['value_%u' % i] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
            if nval != '':
                m['normv_%u' % i] = ldb.MessageElement(nval, ldb.FLAG_MOD_ADD, attrname)

        if self.verbose:
            self.report(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            self.samdb.modify(m, controls=["relax:0"], validate=False)
        except Exception, msg:
            self.report("Failed to normalise attribute %s : %s" % (attrname, msg))
            return
        self.report("Normalised attribute %s" % attrname)


    ################################################################
    # handle a missing GUID extended DN component
    def err_incorrect_dn_GUID(self, dn, attrname, val, dsdb_dn, errstr):
        self.report("ERROR: %s component for %s in object %s - %s" % (errstr, attrname, dn, val))
        try:
            res = self.samdb.search(base=str(dsdb_dn.dn), scope=ldb.SCOPE_BASE,
                                    attrs=[], controls=["extended_dn:1:1"])
        except ldb.LdbError, (enum, estr):
            self.report("unable to find object for DN %s - cannot fix (%s)" % (dsdb_dn.dn, estr))
            return
        dsdb_dn.dn = res[0].dn

        if not self.confirm('Change DN to %s?' % str(dsdb_dn)):
            self.report("Not fixing %s" % errstr)
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        m['new_value'] = ldb.MessageElement(str(dsdb_dn), ldb.FLAG_MOD_ADD, attrname)
        if self.verbose:
            self.report(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            self.samdb.modify(m)
        except Exception, msg:
            self.report("Failed to fix %s on attribute %s : %s" % (errstr, attrname, msg))
            return
        self.report("Fixed %s on attribute %s" % (errstr, attrname))


    ################################################################
    # handle a DN pointing to a deleted object
    def err_deleted_dn(self, dn, attrname, val, dsdb_dn, correct_dn):
        self.report("ERROR: target DN is deleted for %s in object %s - %s" % (attrname, dn, val))
        self.report("Target GUID points at deleted DN %s" % correct_dn)
        if not self.confirm('Remove DN?'):
            self.report("Not removing")
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        if self.verbose:
            self.report(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            self.samdb.modify(m)
        except Exception, msg:
            self.report("Failed to remove deleted DN attribute %s : %s" % (attrname, msg))
            return
        self.report("Removed deleted DN on attribute %s" % attrname)


    ################################################################
    # handle a DN string being incorrect
    def err_dn_target_mismatch(self, dn, attrname, val, dsdb_dn, correct_dn):
        self.report("ERROR: incorrect DN string component for %s in object %s - %s" % (attrname, dn, val))
        dsdb_dn.dn = correct_dn

        if not self.confirm('Change DN to %s?' % str(dsdb_dn)):
            self.report("Not fixing %s" % errstr)
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        m['new_value'] = ldb.MessageElement(str(dsdb_dn), ldb.FLAG_MOD_ADD, attrname)
        if self.verbose:
            self.report(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            self.samdb.modify(m)
        except Exception, msg:
            self.report("Failed to fix incorrect DN string on attribute %s : %s" % (attrname, msg))
            return
        self.report("Fixed incorrect DN string on attribute %s" % (attrname))


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
    def check_object(self, dn, attrs=['*']):
        '''check one object'''
        if self.verbose:
            self.report("Checking object %s" % dn)
        res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE, controls=["extended_dn:1:1"], attrs=attrs)
        if len(res) != 1:
            self.report("Object %s disappeared during check" % dn)
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
            syntax_oid = self.samdb_schema.get_syntax_oid_from_lDAPDisplayName(attrname)

            if syntax_oid in [ dsdb.DSDB_SYNTAX_BINARY_DN, dsdb.DSDB_SYNTAX_OR_NAME,
                               dsdb.DSDB_SYNTAX_STRING_DN, ldb.LDB_SYNTAX_DN ]:
                # it's some form of DN, do specialised checking on those
                error_count += self.check_dn(obj, attrname, syntax_oid)

            # check for incorrectly normalised attributes
            for val in obj[attrname]:
                normalised = self.samdb.dsdb_normalise_attributes(self.samdb_schema, attrname, [val])
                if len(normalised) != 1 or normalised[0] != val:
                    self.err_normalise_mismatch(dn, attrname, obj[attrname])
                    error_count += 1
                    break
        return error_count
