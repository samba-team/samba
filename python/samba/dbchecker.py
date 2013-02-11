# Samba4 AD database checker
#
# Copyright (C) Andrew Tridgell 2011
# Copyright (C) Matthieu Patou <mat@matws.net> 2011
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
from samba import dsdb
from samba import common
from samba.dcerpc import misc
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import drsblobs
from samba.common import dsdb_Dn
from samba.dcerpc import security
from samba.descriptor import get_wellknown_sds, get_diff_sds
from samba.auth import system_session, admin_session


class dbcheck(object):
    """check a SAM database for errors"""

    def __init__(self, samdb, samdb_schema=None, verbose=False, fix=False,
                 yes=False, quiet=False, in_transaction=False,
                 reset_well_known_acls=False):
        self.samdb = samdb
        self.dict_oid_name = None
        self.samdb_schema = (samdb_schema or samdb)
        self.verbose = verbose
        self.fix = fix
        self.yes = yes
        self.quiet = quiet
        self.remove_all_unknown_attributes = False
        self.remove_all_empty_attributes = False
        self.fix_all_normalisation = False
        self.fix_all_DN_GUIDs = False
        self.fix_all_binary_dn = False
        self.remove_all_deleted_DN_links = False
        self.fix_all_target_mismatch = False
        self.fix_all_metadata = False
        self.fix_time_metadata = False
        self.fix_all_missing_backlinks = False
        self.fix_all_orphaned_backlinks = False
        self.fix_rmd_flags = False
        self.fix_ntsecuritydescriptor = False
        self.fix_ntsecuritydescriptor_owner_group = False
        self.seize_fsmo_role = False
        self.move_to_lost_and_found = False
        self.fix_instancetype = False
        self.reset_well_known_acls = reset_well_known_acls
        self.reset_all_well_known_acls = False
        self.in_transaction = in_transaction
        self.infrastructure_dn = ldb.Dn(samdb, "CN=Infrastructure," + samdb.domain_dn())
        self.naming_dn = ldb.Dn(samdb, "CN=Partitions,%s" % samdb.get_config_basedn())
        self.schema_dn = samdb.get_schema_basedn()
        self.rid_dn = ldb.Dn(samdb, "CN=RID Manager$,CN=System," + samdb.domain_dn())
        self.ntds_dsa = ldb.Dn(samdb, samdb.get_dsServiceName())
        self.class_schemaIDGUID = {}
        self.wellknown_sds = get_wellknown_sds(self.samdb)

        self.name_map = {}
        try:
            res = samdb.search(base="CN=DnsAdmins,CN=Users,%s" % samdb.domain_dn(), scope=ldb.SCOPE_BASE,
                           attrs=["objectSid"])
            dnsadmins_sid = ndr_unpack(security.dom_sid, res[0]["objectSid"][0])
            self.name_map['DnsAdmins'] = str(dnsadmins_sid)
        except ldb.LdbError, (enum, estr):
            if enum != ldb.ERR_NO_SUCH_OBJECT:
                raise
            pass

        self.system_session_info = system_session()
        self.admin_session_info = admin_session(None, samdb.get_domain_sid())

        res = self.samdb.search(base=self.ntds_dsa, scope=ldb.SCOPE_BASE, attrs=['msDS-hasMasterNCs', 'hasMasterNCs'])
        if "msDS-hasMasterNCs" in res[0]:
            self.write_ncs = res[0]["msDS-hasMasterNCs"]
        else:
            # If the Forest Level is less than 2003 then there is no
            # msDS-hasMasterNCs, so we fall back to hasMasterNCs
            # no need to merge as all the NCs that are in hasMasterNCs must
            # also be in msDS-hasMasterNCs (but not the opposite)
            if "hasMasterNCs" in res[0]:
                self.write_ncs = res[0]["hasMasterNCs"]
            else:
                self.write_ncs = None


    def check_database(self, DN=None, scope=ldb.SCOPE_SUBTREE, controls=[], attrs=['*']):
        '''perform a database check, returning the number of errors found'''

        res = self.samdb.search(base=DN, scope=scope, attrs=['dn'], controls=controls)
        self.report('Checking %u objects' % len(res))
        error_count = 0

        for object in res:
            error_count += self.check_object(object.dn, attrs=attrs)

        if DN is None:
            error_count += self.check_rootdse()

        if error_count != 0 and not self.fix:
            self.report("Please use --fix to fix these errors")

        self.report('Checked %u objects (%u errors)' % (len(res), error_count))
        return error_count

    def report(self, msg):
        '''print a message unless quiet is set'''
        if not self.quiet:
            print(msg)

    def confirm(self, msg, allow_all=False, forced=False):
        '''confirm a change'''
        if not self.fix:
            return False
        if self.quiet:
            return self.yes
        if self.yes:
            forced = True
        return common.confirm(msg, forced=forced, allow_all=allow_all)

    ################################################################
    # a local confirm function with support for 'all'
    def confirm_all(self, msg, all_attr):
        '''confirm a change with support for "all" '''
        if not self.fix:
            return False
        if self.quiet:
            return self.yes
        if getattr(self, all_attr) == 'NONE':
            return False
        if getattr(self, all_attr) == 'ALL':
            forced = True
        else:
            forced = self.yes
        c = common.confirm(msg, forced=forced, allow_all=True)
        if c == 'ALL':
            setattr(self, all_attr, 'ALL')
            return True
        if c == 'NONE':
            setattr(self, all_attr, 'NONE')
            return False
        return c

    def do_modify(self, m, controls, msg, validate=True):
        '''perform a modify with optional verbose output'''
        if self.verbose:
            self.report(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            controls = controls + ["local_oid:%s:0" % dsdb.DSDB_CONTROL_DBCHECK]
            self.samdb.modify(m, controls=controls, validate=validate)
        except Exception, err:
            self.report("%s : %s" % (msg, err))
            return False
        return True

    def do_rename(self, from_dn, to_rdn, to_base, controls, msg):
        '''perform a modify with optional verbose output'''
        if self.verbose:
            self.report("""dn: %s
changeType: modrdn
newrdn: %s
deleteOldRdn: 1
newSuperior: %s""" % (str(from_dn), str(to_rdn), str(to_base)))
        try:
            to_dn = to_rdn + to_base
            controls = controls + ["local_oid:%s:0" % dsdb.DSDB_CONTROL_DBCHECK]
            self.samdb.rename(from_dn, to_dn, controls=controls)
        except Exception, err:
            self.report("%s : %s" % (msg, err))
            return False
        return True

    def err_empty_attribute(self, dn, attrname):
        '''fix empty attributes'''
        self.report("ERROR: Empty attribute %s in %s" % (attrname, dn))
        if not self.confirm_all('Remove empty attribute %s from %s?' % (attrname, dn), 'remove_all_empty_attributes'):
            self.report("Not fixing empty attribute %s" % attrname)
            return

        m = ldb.Message()
        m.dn = dn
        m[attrname] = ldb.MessageElement('', ldb.FLAG_MOD_DELETE, attrname)
        if self.do_modify(m, ["relax:0", "show_recycled:1"],
                          "Failed to remove empty attribute %s" % attrname, validate=False):
            self.report("Removed empty attribute %s" % attrname)

    def err_normalise_mismatch(self, dn, attrname, values):
        '''fix attribute normalisation errors'''
        self.report("ERROR: Normalisation error for attribute %s in %s" % (attrname, dn))
        mod_list = []
        for val in values:
            normalised = self.samdb.dsdb_normalise_attributes(
                self.samdb_schema, attrname, [val])
            if len(normalised) != 1:
                self.report("Unable to normalise value '%s'" % val)
                mod_list.append((val, ''))
            elif (normalised[0] != val):
                self.report("value '%s' should be '%s'" % (val, normalised[0]))
                mod_list.append((val, normalised[0]))
        if not self.confirm_all('Fix normalisation for %s from %s?' % (attrname, dn), 'fix_all_normalisation'):
            self.report("Not fixing attribute %s" % attrname)
            return

        m = ldb.Message()
        m.dn = dn
        for i in range(0, len(mod_list)):
            (val, nval) = mod_list[i]
            m['value_%u' % i] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
            if nval != '':
                m['normv_%u' % i] = ldb.MessageElement(nval, ldb.FLAG_MOD_ADD,
                    attrname)

        if self.do_modify(m, ["relax:0", "show_recycled:1"],
                          "Failed to normalise attribute %s" % attrname,
                          validate=False):
            self.report("Normalised attribute %s" % attrname)

    def err_normalise_mismatch_replace(self, dn, attrname, values):
        '''fix attribute normalisation errors'''
        normalised = self.samdb.dsdb_normalise_attributes(self.samdb_schema, attrname, values)
        self.report("ERROR: Normalisation error for attribute '%s' in '%s'" % (attrname, dn))
        self.report("Values/Order of values do/does not match: %s/%s!" % (values, list(normalised)))
        if list(normalised) == values:
            return
        if not self.confirm_all("Fix normalisation for '%s' from '%s'?" % (attrname, dn), 'fix_all_normalisation'):
            self.report("Not fixing attribute '%s'" % attrname)
            return

        m = ldb.Message()
        m.dn = dn
        m[attrname] = ldb.MessageElement(normalised, ldb.FLAG_MOD_REPLACE, attrname)

        if self.do_modify(m, ["relax:0", "show_recycled:1"],
                          "Failed to normalise attribute %s" % attrname,
                          validate=False):
            self.report("Normalised attribute %s" % attrname)

    def is_deleted_objects_dn(self, dsdb_dn):
        '''see if a dsdb_Dn is the special Deleted Objects DN'''
        return dsdb_dn.prefix == "B:32:18E2EA80684F11D2B9AA00C04F79F805:"

    def err_deleted_dn(self, dn, attrname, val, dsdb_dn, correct_dn):
        """handle a DN pointing to a deleted object"""
        self.report("ERROR: target DN is deleted for %s in object %s - %s" % (attrname, dn, val))
        self.report("Target GUID points at deleted DN %s" % correct_dn)
        if not self.confirm_all('Remove DN link?', 'remove_all_deleted_DN_links'):
            self.report("Not removing")
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        if self.do_modify(m, ["show_recycled:1", "local_oid:%s:0" % dsdb.DSDB_CONTROL_DBCHECK],
                          "Failed to remove deleted DN attribute %s" % attrname):
            self.report("Removed deleted DN on attribute %s" % attrname)

    def err_missing_dn_GUID(self, dn, attrname, val, dsdb_dn):
        """handle a missing target DN (both GUID and DN string form are missing)"""
        # check if its a backlink
        linkID = self.samdb_schema.get_linkId_from_lDAPDisplayName(attrname)
        if (linkID & 1 == 0) and str(dsdb_dn).find('DEL\\0A') == -1:
            self.report("Not removing dangling forward link")
            return
        self.err_deleted_dn(dn, attrname, val, dsdb_dn, dsdb_dn)

    def err_incorrect_dn_GUID(self, dn, attrname, val, dsdb_dn, errstr):
        """handle a missing GUID extended DN component"""
        self.report("ERROR: %s component for %s in object %s - %s" % (errstr, attrname, dn, val))
        controls=["extended_dn:1:1", "show_recycled:1"]
        try:
            res = self.samdb.search(base=str(dsdb_dn.dn), scope=ldb.SCOPE_BASE,
                                    attrs=[], controls=controls)
        except ldb.LdbError, (enum, estr):
            self.report("unable to find object for DN %s - (%s)" % (dsdb_dn.dn, estr))
            self.err_missing_dn_GUID(dn, attrname, val, dsdb_dn)
            return
        if len(res) == 0:
            self.report("unable to find object for DN %s" % dsdb_dn.dn)
            self.err_missing_dn_GUID(dn, attrname, val, dsdb_dn)
            return
        dsdb_dn.dn = res[0].dn

        if not self.confirm_all('Change DN to %s?' % str(dsdb_dn), 'fix_all_DN_GUIDs'):
            self.report("Not fixing %s" % errstr)
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        m['new_value'] = ldb.MessageElement(str(dsdb_dn), ldb.FLAG_MOD_ADD, attrname)

        if self.do_modify(m, ["show_recycled:1"],
                          "Failed to fix %s on attribute %s" % (errstr, attrname)):
            self.report("Fixed %s on attribute %s" % (errstr, attrname))

    def err_incorrect_binary_dn(self, dn, attrname, val, dsdb_dn, errstr):
        """handle an incorrect binary DN component"""
        self.report("ERROR: %s binary component for %s in object %s - %s" % (errstr, attrname, dn, val))
        controls=["extended_dn:1:1", "show_recycled:1"]

        if not self.confirm_all('Change DN to %s?' % str(dsdb_dn), 'fix_all_binary_dn'):
            self.report("Not fixing %s" % errstr)
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        m['new_value'] = ldb.MessageElement(str(dsdb_dn), ldb.FLAG_MOD_ADD, attrname)

        if self.do_modify(m, ["show_recycled:1"],
                          "Failed to fix %s on attribute %s" % (errstr, attrname)):
            self.report("Fixed %s on attribute %s" % (errstr, attrname))

    def err_dn_target_mismatch(self, dn, attrname, val, dsdb_dn, correct_dn, errstr):
        """handle a DN string being incorrect"""
        self.report("ERROR: incorrect DN string component for %s in object %s - %s" % (attrname, dn, val))
        dsdb_dn.dn = correct_dn

        if not self.confirm_all('Change DN to %s?' % str(dsdb_dn), 'fix_all_target_mismatch'):
            self.report("Not fixing %s" % errstr)
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        m['new_value'] = ldb.MessageElement(str(dsdb_dn), ldb.FLAG_MOD_ADD, attrname)
        if self.do_modify(m, ["show_recycled:1"],
                          "Failed to fix incorrect DN string on attribute %s" % attrname):
            self.report("Fixed incorrect DN string on attribute %s" % (attrname))

    def err_unknown_attribute(self, obj, attrname):
        '''handle an unknown attribute error'''
        self.report("ERROR: unknown attribute '%s' in %s" % (attrname, obj.dn))
        if not self.confirm_all('Remove unknown attribute %s' % attrname, 'remove_all_unknown_attributes'):
            self.report("Not removing %s" % attrname)
            return
        m = ldb.Message()
        m.dn = obj.dn
        m['old_value'] = ldb.MessageElement([], ldb.FLAG_MOD_DELETE, attrname)
        if self.do_modify(m, ["relax:0", "show_recycled:1"],
                          "Failed to remove unknown attribute %s" % attrname):
            self.report("Removed unknown attribute %s" % (attrname))

    def err_missing_backlink(self, obj, attrname, val, backlink_name, target_dn):
        '''handle a missing backlink value'''
        self.report("ERROR: missing backlink attribute '%s' in %s for link %s in %s" % (backlink_name, target_dn, attrname, obj.dn))
        if not self.confirm_all('Fix missing backlink %s' % backlink_name, 'fix_all_missing_backlinks'):
            self.report("Not fixing missing backlink %s" % backlink_name)
            return
        m = ldb.Message()
        m.dn = obj.dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        m['new_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_ADD, attrname)
        if self.do_modify(m, ["show_recycled:1"],
                          "Failed to fix missing backlink %s" % backlink_name):
            self.report("Fixed missing backlink %s" % (backlink_name))

    def err_incorrect_rmd_flags(self, obj, attrname, revealed_dn):
        '''handle a incorrect RMD_FLAGS value'''
        rmd_flags = int(revealed_dn.dn.get_extended_component("RMD_FLAGS"))
        self.report("ERROR: incorrect RMD_FLAGS value %u for attribute '%s' in %s for link %s" % (rmd_flags, attrname, obj.dn, revealed_dn.dn.extended_str()))
        if not self.confirm_all('Fix incorrect RMD_FLAGS %u' % rmd_flags, 'fix_rmd_flags'):
            self.report("Not fixing incorrect RMD_FLAGS %u" % rmd_flags)
            return
        m = ldb.Message()
        m.dn = obj.dn
        m['old_value'] = ldb.MessageElement(str(revealed_dn), ldb.FLAG_MOD_DELETE, attrname)
        if self.do_modify(m, ["show_recycled:1", "reveal_internals:0", "show_deleted:0"],
                          "Failed to fix incorrect RMD_FLAGS %u" % rmd_flags):
            self.report("Fixed incorrect RMD_FLAGS %u" % (rmd_flags))

    def err_orphaned_backlink(self, obj, attrname, val, link_name, target_dn):
        '''handle a orphaned backlink value'''
        self.report("ERROR: orphaned backlink attribute '%s' in %s for link %s in %s" % (attrname, obj.dn, link_name, target_dn))
        if not self.confirm_all('Remove orphaned backlink %s' % link_name, 'fix_all_orphaned_backlinks'):
            self.report("Not removing orphaned backlink %s" % link_name)
            return
        m = ldb.Message()
        m.dn = obj.dn
        m['value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        if self.do_modify(m, ["show_recycled:1", "relax:0"],
                          "Failed to fix orphaned backlink %s" % link_name):
            self.report("Fixed orphaned backlink %s" % (link_name))

    def err_no_fsmoRoleOwner(self, obj):
        '''handle a missing fSMORoleOwner'''
        self.report("ERROR: fSMORoleOwner not found for role %s" % (obj.dn))
        res = self.samdb.search("",
                                scope=ldb.SCOPE_BASE, attrs=["dsServiceName"])
        assert len(res) == 1
        serviceName = res[0]["dsServiceName"][0]
        if not self.confirm_all('Sieze role %s onto current DC by adding fSMORoleOwner=%s' % (obj.dn, serviceName), 'seize_fsmo_role'):
            self.report("Not Siezing role %s onto current DC by adding fSMORoleOwner=%s" % (obj.dn, serviceName))
            return
        m = ldb.Message()
        m.dn = obj.dn
        m['value'] = ldb.MessageElement(serviceName, ldb.FLAG_MOD_ADD, 'fSMORoleOwner')
        if self.do_modify(m, [],
                          "Failed to sieze role %s onto current DC by adding fSMORoleOwner=%s" % (obj.dn, serviceName)):
            self.report("Siezed role %s onto current DC by adding fSMORoleOwner=%s" % (obj.dn, serviceName))

    def err_missing_parent(self, obj):
        '''handle a missing parent'''
        self.report("ERROR: parent object not found for %s" % (obj.dn))
        if not self.confirm_all('Move object %s into LostAndFound?' % (obj.dn), 'move_to_lost_and_found'):
            self.report('Not moving object %s into LostAndFound' % (obj.dn))
            return

        keep_transaction = True
        self.samdb.transaction_start()
        try:
            nc_root = self.samdb.get_nc_root(obj.dn);
            lost_and_found = self.samdb.get_wellknown_dn(nc_root, dsdb.DS_GUID_LOSTANDFOUND_CONTAINER)
            new_dn = ldb.Dn(self.samdb, str(obj.dn))
            new_dn.remove_base_components(len(new_dn) - 1)
            if self.do_rename(obj.dn, new_dn, lost_and_found, ["show_deleted:0", "relax:0"],
                              "Failed to rename object %s into lostAndFound at %s" % (obj.dn, new_dn + lost_and_found)):
                self.report("Renamed object %s into lostAndFound at %s" % (obj.dn, new_dn + lost_and_found))

                m = ldb.Message()
                m.dn = obj.dn
                m['lastKnownParent'] = ldb.MessageElement(str(obj.dn.parent()), ldb.FLAG_MOD_REPLACE, 'lastKnownParent')

                if self.do_modify(m, [],
                                  "Failed to set lastKnownParent on lostAndFound object at %s" % (new_dn + lost_and_found)):
                    self.report("Set lastKnownParent on lostAndFound object at %s" % (new_dn + lost_and_found))
                    keep_transaction = True
        except:
            self.samdb.transaction_cancel()
            raise

        if keep_transaction:
            self.samdb.transaction_commit()
        else:
            self.samdb.transaction_cancel()


    def err_wrong_instancetype(self, obj, calculated_instancetype):
        '''handle a wrong instanceType'''
        self.report("ERROR: wrong instanceType %s on %s, should be %d" % (obj["instanceType"], obj.dn, calculated_instancetype))
        if not self.confirm_all('Change instanceType from %s to %d on %s?' % (obj["instanceType"], calculated_instancetype, obj.dn), 'fix_instancetype'):
            self.report('Not changing instanceType from %s to %d on %s' % (obj["instanceType"], calculated_instancetype, obj.dn))
            return

        m = ldb.Message()
        m.dn = obj.dn
        m['value'] = ldb.MessageElement(str(calculated_instancetype), ldb.FLAG_MOD_REPLACE, 'instanceType')
        if self.do_modify(m, ["local_oid:%s:0" % dsdb.DSDB_CONTROL_DBCHECK_MODIFY_RO_REPLICA],
                          "Failed to correct missing instanceType on %s by setting instanceType=%d" % (obj.dn, calculated_instancetype)):
            self.report("Corrected instancetype on %s by setting instanceType=%d" % (obj.dn, calculated_instancetype))

    def find_revealed_link(self, dn, attrname, guid):
        '''return a revealed link in an object'''
        res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=[attrname],
                                controls=["show_deleted:0", "extended_dn:0", "reveal_internals:0"])
        syntax_oid = self.samdb_schema.get_syntax_oid_from_lDAPDisplayName(attrname)
        for val in res[0][attrname]:
            dsdb_dn = dsdb_Dn(self.samdb, val, syntax_oid)
            guid2 = dsdb_dn.dn.get_extended_component("GUID")
            if guid == guid2:
                return dsdb_dn
        return None

    def check_dn(self, obj, attrname, syntax_oid):
        '''check a DN attribute for correctness'''
        error_count = 0
        for val in obj[attrname]:
            dsdb_dn = dsdb_Dn(self.samdb, val, syntax_oid)

            # all DNs should have a GUID component
            guid = dsdb_dn.dn.get_extended_component("GUID")
            if guid is None:
                error_count += 1
                self.err_incorrect_dn_GUID(obj.dn, attrname, val, dsdb_dn,
                    "missing GUID")
                continue

            guidstr = str(misc.GUID(guid))

            attrs = ['isDeleted']

            if (str(attrname).lower() == 'msds-hasinstantiatedncs') and (obj.dn == self.ntds_dsa):
                fixing_msDS_HasInstantiatedNCs = True
                attrs.append("instanceType")
            else:
                fixing_msDS_HasInstantiatedNCs = False

            linkID = self.samdb_schema.get_linkId_from_lDAPDisplayName(attrname)
            reverse_link_name = self.samdb_schema.get_backlink_from_lDAPDisplayName(attrname)
            if reverse_link_name is not None:
                attrs.append(reverse_link_name)

            # check its the right GUID
            try:
                res = self.samdb.search(base="<GUID=%s>" % guidstr, scope=ldb.SCOPE_BASE,
                                        attrs=attrs, controls=["extended_dn:1:1", "show_recycled:1"])
            except ldb.LdbError, (enum, estr):
                error_count += 1
                self.err_incorrect_dn_GUID(obj.dn, attrname, val, dsdb_dn, "incorrect GUID")
                continue

            if fixing_msDS_HasInstantiatedNCs:
                dsdb_dn.prefix = "B:8:%08X:" % int(res[0]['instanceType'][0])
                dsdb_dn.binary = "%08X" % int(res[0]['instanceType'][0])

                if str(dsdb_dn) != val:
                    error_count +=1
                    self.err_incorrect_binary_dn(obj.dn, attrname, val, dsdb_dn, "incorrect instanceType part of Binary DN")
                    continue

            # now we have two cases - the source object might or might not be deleted
            is_deleted = 'isDeleted' in obj and obj['isDeleted'][0].upper() == 'TRUE'
            target_is_deleted = 'isDeleted' in res[0] and res[0]['isDeleted'][0].upper() == 'TRUE'

            # the target DN is not allowed to be deleted, unless the target DN is the
            # special Deleted Objects container
            if target_is_deleted and not is_deleted and not self.is_deleted_objects_dn(dsdb_dn):
                error_count += 1
                self.err_deleted_dn(obj.dn, attrname, val, dsdb_dn, res[0].dn)
                continue

            # check the DN matches in string form
            if res[0].dn.extended_str() != dsdb_dn.dn.extended_str():
                error_count += 1
                self.err_dn_target_mismatch(obj.dn, attrname, val, dsdb_dn,
                                            res[0].dn, "incorrect string version of DN")
                continue

            if is_deleted and not target_is_deleted and reverse_link_name is not None:
                revealed_dn = self.find_revealed_link(obj.dn, attrname, guid)
                rmd_flags = revealed_dn.dn.get_extended_component("RMD_FLAGS")
                if rmd_flags is not None and (int(rmd_flags) & 1) == 0:
                    # the RMD_FLAGS for this link should be 1, as the target is deleted
                    self.err_incorrect_rmd_flags(obj, attrname, revealed_dn)
                    continue

            # check the reverse_link is correct if there should be one
            if reverse_link_name is not None:
                match_count = 0
                if reverse_link_name in res[0]:
                    for v in res[0][reverse_link_name]:
                        if v == obj.dn.extended_str():
                            match_count += 1
                if match_count != 1:
                    error_count += 1
                    if linkID & 1:
                        self.err_orphaned_backlink(obj, attrname, val, reverse_link_name, dsdb_dn.dn)
                    else:
                        self.err_missing_backlink(obj, attrname, val, reverse_link_name, dsdb_dn.dn)
                    continue

        return error_count


    def get_originating_time(self, val, attid):
        '''Read metadata properties and return the originating time for
           a given attributeId.

           :return: the originating time or 0 if not found
        '''

        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob, str(val))
        obj = repl.ctr

        for o in repl.ctr.array:
            if o.attid == attid:
                return o.originating_change_time

        return 0

    def process_metadata(self, val):
        '''Read metadata properties and list attributes in it'''

        list_att = []

        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob, str(val))
        obj = repl.ctr

        for o in repl.ctr.array:
            att = self.samdb_schema.get_lDAPDisplayName_by_attid(o.attid)
            list_att.append(att.lower())

        return list_att


    def fix_metadata(self, dn, attr):
        '''re-write replPropertyMetaData elements for a single attribute for a
        object. This is used to fix missing replPropertyMetaData elements'''
        res = self.samdb.search(base = dn, scope=ldb.SCOPE_BASE, attrs = [attr],
                                controls = ["search_options:1:2", "show_recycled:1"])
        msg = res[0]
        nmsg = ldb.Message()
        nmsg.dn = dn
        nmsg[attr] = ldb.MessageElement(msg[attr], ldb.FLAG_MOD_REPLACE, attr)
        if self.do_modify(nmsg, ["relax:0", "provision:0", "show_recycled:1"],
                          "Failed to fix metadata for attribute %s" % attr):
            self.report("Fixed metadata for attribute %s" % attr)

    def ace_get_effective_inherited_type(self, ace):
        if ace.flags & security.SEC_ACE_FLAG_INHERIT_ONLY:
            return None

        check = False
        if ace.type == security.SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT:
            check = True
        elif ace.type == security.SEC_ACE_TYPE_ACCESS_DENIED_OBJECT:
            check = True
        elif ace.type == security.SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT:
            check = True
        elif ace.type == security.SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT:
            check = True

        if not check:
            return None

        if not ace.object.flags & security.SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT:
            return None

        return str(ace.object.inherited_type)

    def lookup_class_schemaIDGUID(self, cls):
        if cls in self.class_schemaIDGUID:
            return self.class_schemaIDGUID[cls]

        flt = "(&(ldapDisplayName=%s)(objectClass=classSchema))" % cls
        res = self.samdb.search(base=self.schema_dn,
                                expression=flt,
                                attrs=["schemaIDGUID"])
        t = str(ndr_unpack(misc.GUID, res[0]["schemaIDGUID"][0]))

        self.class_schemaIDGUID[cls] = t
        return t

    def process_sd(self, dn, obj):
        sd_attr = "nTSecurityDescriptor"
        sd_val = obj[sd_attr]

        sd = ndr_unpack(security.descriptor, str(sd_val))

        is_deleted = 'isDeleted' in obj and obj['isDeleted'][0].upper() == 'TRUE'
        if is_deleted:
            # we don't fix deleted objects
            return (sd, None)

        sd_clean = security.descriptor()
        sd_clean.owner_sid = sd.owner_sid
        sd_clean.group_sid = sd.group_sid
        sd_clean.type = sd.type
        sd_clean.revision = sd.revision

        broken = False
        last_inherited_type = None

        aces = []
        if sd.sacl is not None:
            aces = sd.sacl.aces
        for i in range(0, len(aces)):
            ace = aces[i]

            if not ace.flags & security.SEC_ACE_FLAG_INHERITED_ACE:
                sd_clean.sacl_add(ace)
                continue

            t = self.ace_get_effective_inherited_type(ace)
            if t is None:
                continue

            if last_inherited_type is not None:
                if t != last_inherited_type:
                    # if it inherited from more than
                    # one type it's very likely to be broken
                    #
                    # If not the recalculation will calculate
                    # the same result.
                    broken = True
                continue

            last_inherited_type = t

        aces = []
        if sd.dacl is not None:
            aces = sd.dacl.aces
        for i in range(0, len(aces)):
            ace = aces[i]

            if not ace.flags & security.SEC_ACE_FLAG_INHERITED_ACE:
                sd_clean.dacl_add(ace)
                continue

            t = self.ace_get_effective_inherited_type(ace)
            if t is None:
                continue

            if last_inherited_type is not None:
                if t != last_inherited_type:
                    # if it inherited from more than
                    # one type it's very likely to be broken
                    #
                    # If not the recalculation will calculate
                    # the same result.
                    broken = True
                continue

            last_inherited_type = t

        if broken:
            return (sd_clean, sd)

        if last_inherited_type is None:
            # ok
            return (sd, None)

        cls = None
        try:
            cls = obj["objectClass"][-1]
        except KeyError, e:
            pass

        if cls is None:
            res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                                    attrs=["isDeleted", "objectClass"],
                                    controls=["show_recycled:1"])
            o = res[0]
            is_deleted = 'isDeleted' in o and o['isDeleted'][0].upper() == 'TRUE'
            if is_deleted:
                # we don't fix deleted objects
                return (sd, None)
            cls = o["objectClass"][-1]

        t = self.lookup_class_schemaIDGUID(cls)

        if t != last_inherited_type:
            # broken
            return (sd_clean, sd)

        # ok
        return (sd, None)

    def err_wrong_sd(self, dn, sd, sd_broken):
        '''re-write the SD due to incorrect inherited ACEs'''
        sd_attr = "nTSecurityDescriptor"
        sd_val = ndr_pack(sd)
        sd_flags = security.SECINFO_DACL | security.SECINFO_SACL

        if not self.confirm_all('Fix %s on %s?' % (sd_attr, dn), 'fix_ntsecuritydescriptor'):
            self.report('Not fixing %s on %s\n' % (sd_attr, dn))
            return

        nmsg = ldb.Message()
        nmsg.dn = dn
        nmsg[sd_attr] = ldb.MessageElement(sd_val, ldb.FLAG_MOD_REPLACE, sd_attr)
        if self.do_modify(nmsg, ["sd_flags:1:%d" % sd_flags],
                          "Failed to fix attribute %s" % sd_attr):
            self.report("Fixed attribute '%s' of '%s'\n" % (sd_attr, dn))

    def err_wrong_default_sd(self, dn, sd, sd_old, diff):
        '''re-write the SD due to not matching the default (optional mode for fixing an incorrect provision)'''
        sd_attr = "nTSecurityDescriptor"
        sd_val = ndr_pack(sd)
        sd_old_val = ndr_pack(sd_old)
        sd_flags = security.SECINFO_DACL | security.SECINFO_SACL
        if sd.owner_sid is not None:
            sd_flags |= security.SECINFO_OWNER
        if sd.group_sid is not None:
            sd_flags |= security.SECINFO_GROUP

        if not self.confirm_all('Reset %s on %s back to provision default?\n%s' % (sd_attr, dn, diff), 'reset_all_well_known_acls'):
            self.report('Not resetting %s on %s\n' % (sd_attr, dn))
            return

        m = ldb.Message()
        m.dn = dn
        m[sd_attr] = ldb.MessageElement(sd_val, ldb.FLAG_MOD_REPLACE, sd_attr)
        if self.do_modify(m, ["sd_flags:1:%d" % sd_flags],
                          "Failed to reset attribute %s" % sd_attr):
            self.report("Fixed attribute '%s' of '%s'\n" % (sd_attr, dn))

    def err_missing_sd_owner(self, dn, sd):
        '''re-write the SD due to a missing owner or group'''
        sd_attr = "nTSecurityDescriptor"
        sd_val = ndr_pack(sd)
        sd_flags = security.SECINFO_OWNER | security.SECINFO_GROUP

        if not self.confirm_all('Fix missing owner or group in %s on %s?' % (sd_attr, dn), 'fix_ntsecuritydescriptor_owner_group'):
            self.report('Not fixing missing owner or group %s on %s\n' % (sd_attr, dn))
            return

        nmsg = ldb.Message()
        nmsg.dn = dn
        nmsg[sd_attr] = ldb.MessageElement(sd_val, ldb.FLAG_MOD_REPLACE, sd_attr)

        # By setting the session_info to admin_session_info and
        # setting the security.SECINFO_OWNER | security.SECINFO_GROUP
        # flags we cause the descriptor module to set the correct
        # owner and group on the SD, replacing the None/NULL values
        # for owner_sid and group_sid currently present.
        #
        # The admin_session_info matches that used in provision, and
        # is the best guess we can make for an existing object that
        # hasn't had something specifically set.
        #
        # This is important for the dns related naming contexts.
        self.samdb.set_session_info(self.admin_session_info)
        if self.do_modify(nmsg, ["sd_flags:1:%d" % sd_flags],
                          "Failed to fix metadata for attribute %s" % sd_attr):
            self.report("Fixed attribute '%s' of '%s'\n" % (sd_attr, dn))
        self.samdb.set_session_info(self.system_session_info)

    def is_fsmo_role(self, dn):
        if dn == self.samdb.domain_dn:
            return True
        if dn == self.infrastructure_dn:
            return True
        if dn == self.naming_dn:
            return True
        if dn == self.schema_dn:
            return True
        if dn == self.rid_dn:
            return True

        return False

    def calculate_instancetype(self, dn):
        instancetype = 0
        nc_root = self.samdb.get_nc_root(dn)
        if dn == nc_root:
            instancetype |= dsdb.INSTANCE_TYPE_IS_NC_HEAD
            try:
                self.samdb.search(base=dn.parent(), scope=ldb.SCOPE_BASE, attrs=[], controls=["show_recycled:1"])
            except ldb.LdbError, (enum, estr):
                if enum != ldb.ERR_NO_SUCH_OBJECT:
                    raise
            else:
                instancetype |= dsdb.INSTANCE_TYPE_NC_ABOVE

        if self.write_ncs is not None and str(nc_root) in self.write_ncs:
            instancetype |= dsdb.INSTANCE_TYPE_WRITE

        return instancetype

    def get_wellknown_sd(self, dn):
        for [sd_dn, descriptor_fn] in self.wellknown_sds:
            if dn == sd_dn:
                domain_sid = security.dom_sid(self.samdb.get_domain_sid())
                return ndr_unpack(security.descriptor,
                                  descriptor_fn(domain_sid,
                                                name_map=self.name_map))

        raise KeyError

    def check_object(self, dn, attrs=['*']):
        '''check one object'''
        if self.verbose:
            self.report("Checking object %s" % dn)
        if '*' in attrs:
            attrs.append("replPropertyMetaData")

        try:
            sd_flags = 0
            sd_flags |= security.SECINFO_OWNER
            sd_flags |= security.SECINFO_GROUP
            sd_flags |= security.SECINFO_DACL
            sd_flags |= security.SECINFO_SACL

            res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                                    controls=[
                                        "extended_dn:1:1",
                                        "show_recycled:1",
                                        "show_deleted:1",
                                        "sd_flags:1:%d" % sd_flags,
                                    ],
                                    attrs=attrs)
        except ldb.LdbError, (enum, estr):
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                if self.in_transaction:
                    self.report("ERROR: Object %s disappeared during check" % dn)
                    return 1
                return 0
            raise
        if len(res) != 1:
            self.report("ERROR: Object %s failed to load during check" % dn)
            return 1
        obj = res[0]
        error_count = 0
        list_attrs_from_md = []
        list_attrs_seen = []
        got_repl_property_meta_data = False

        for attrname in obj:
            if attrname == 'dn':
                continue

            if str(attrname).lower() == 'replpropertymetadata':
                list_attrs_from_md = self.process_metadata(obj[attrname])
                got_repl_property_meta_data = True
                continue

            if str(attrname).lower() == 'ntsecuritydescriptor':
                (sd, sd_broken) = self.process_sd(dn, obj)
                if sd_broken is not None:
                    self.err_wrong_sd(dn, sd, sd_broken)
                    error_count += 1
                    continue

                if sd.owner_sid is None or sd.group_sid is None:
                    self.err_missing_sd_owner(dn, sd)
                    error_count += 1
                    continue

                if self.reset_well_known_acls:
                    try:
                        well_known_sd = self.get_wellknown_sd(dn)
                    except KeyError:
                        continue

                    current_sd = ndr_unpack(security.descriptor,
                                            str(obj[attrname][0]))

                    diff = get_diff_sds(well_known_sd, current_sd, security.dom_sid(self.samdb.get_domain_sid()))
                    if diff != "":
                        self.err_wrong_default_sd(dn, well_known_sd, current_sd, diff)
                        error_count += 1
                        continue
                continue

            if str(attrname).lower() == 'objectclass':
                normalised = self.samdb.dsdb_normalise_attributes(self.samdb_schema, attrname, list(obj[attrname]))
                if list(normalised) != list(obj[attrname]):
                    self.err_normalise_mismatch_replace(dn, attrname, list(obj[attrname]))
                    error_count += 1
                continue

            # check for empty attributes
            for val in obj[attrname]:
                if val == '':
                    self.err_empty_attribute(dn, attrname)
                    error_count += 1
                    continue

            # get the syntax oid for the attribute, so we can can have
            # special handling for some specific attribute types
            try:
                syntax_oid = self.samdb_schema.get_syntax_oid_from_lDAPDisplayName(attrname)
            except Exception, msg:
                self.err_unknown_attribute(obj, attrname)
                error_count += 1
                continue

            flag = self.samdb_schema.get_systemFlags_from_lDAPDisplayName(attrname)
            if (not flag & dsdb.DS_FLAG_ATTR_NOT_REPLICATED
                and not flag & dsdb.DS_FLAG_ATTR_IS_CONSTRUCTED
                and not self.samdb_schema.get_linkId_from_lDAPDisplayName(attrname)):
                list_attrs_seen.append(str(attrname).lower())

            if syntax_oid in [ dsdb.DSDB_SYNTAX_BINARY_DN, dsdb.DSDB_SYNTAX_OR_NAME,
                               dsdb.DSDB_SYNTAX_STRING_DN, ldb.SYNTAX_DN ]:
                # it's some form of DN, do specialised checking on those
                error_count += self.check_dn(obj, attrname, syntax_oid)

            # check for incorrectly normalised attributes
            for val in obj[attrname]:
                normalised = self.samdb.dsdb_normalise_attributes(self.samdb_schema, attrname, [val])
                if len(normalised) != 1 or normalised[0] != val:
                    self.err_normalise_mismatch(dn, attrname, obj[attrname])
                    error_count += 1
                    break

            if str(attrname).lower() == "instancetype":
                calculated_instancetype = self.calculate_instancetype(dn)
                if len(obj["instanceType"]) != 1 or obj["instanceType"][0] != str(calculated_instancetype):
                    self.err_wrong_instancetype(obj, calculated_instancetype)

        show_dn = True
        if got_repl_property_meta_data:
            rdn = (str(dn).split(","))[0]
            if rdn == "CN=Deleted Objects":
                isDeletedAttId = 131120
                # It's 29/12/9999 at 23:59:59 UTC as specified in MS-ADTS 7.1.1.4.2 Deleted Objects Container

                expectedTimeDo = 2650466015990000000
                originating = self.get_originating_time(obj["replPropertyMetaData"], isDeletedAttId)
                if originating != expectedTimeDo:
                    if self.confirm_all("Fix isDeleted originating_change_time on '%s'" % str(dn), 'fix_time_metadata'):
                        nmsg = ldb.Message()
                        nmsg.dn = dn
                        nmsg["isDeleted"] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_REPLACE, "isDeleted")
                        error_count += 1
                        self.samdb.modify(nmsg, controls=["provision:0"])

                    else:
                        self.report("Not fixing isDeleted originating_change_time on '%s'" % str(dn))
            for att in list_attrs_seen:
                if not att in list_attrs_from_md:
                    if show_dn:
                        self.report("On object %s" % dn)
                        show_dn = False
                    error_count += 1
                    self.report("ERROR: Attribute %s not present in replication metadata" % att)
                    if not self.confirm_all("Fix missing replPropertyMetaData element '%s'" % att, 'fix_all_metadata'):
                        self.report("Not fixing missing replPropertyMetaData element '%s'" % att)
                        continue
                    self.fix_metadata(dn, att)

        if self.is_fsmo_role(dn):
            if "fSMORoleOwner" not in obj:
                self.err_no_fsmoRoleOwner(obj)
                error_count += 1

        try:
            if dn != self.samdb.get_root_basedn():
                res = self.samdb.search(base=dn.parent(), scope=ldb.SCOPE_BASE,
                                        controls=["show_recycled:1", "show_deleted:1"])
        except ldb.LdbError, (enum, estr):
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                self.err_missing_parent(obj)
                error_count += 1
            else:
                raise

        return error_count

    ################################################################
    # check special @ROOTDSE attributes
    def check_rootdse(self):
        '''check the @ROOTDSE special object'''
        dn = ldb.Dn(self.samdb, '@ROOTDSE')
        if self.verbose:
            self.report("Checking object %s" % dn)
        res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE)
        if len(res) != 1:
            self.report("Object %s disappeared during check" % dn)
            return 1
        obj = res[0]
        error_count = 0

        # check that the dsServiceName is in GUID form
        if not 'dsServiceName' in obj:
            self.report('ERROR: dsServiceName missing in @ROOTDSE')
            return error_count+1

        if not obj['dsServiceName'][0].startswith('<GUID='):
            self.report('ERROR: dsServiceName not in GUID form in @ROOTDSE')
            error_count += 1
            if not self.confirm('Change dsServiceName to GUID form?'):
                return error_count
            res = self.samdb.search(base=ldb.Dn(self.samdb, obj['dsServiceName'][0]),
                                    scope=ldb.SCOPE_BASE, attrs=['objectGUID'])
            guid_str = str(ndr_unpack(misc.GUID, res[0]['objectGUID'][0]))
            m = ldb.Message()
            m.dn = dn
            m['dsServiceName'] = ldb.MessageElement("<GUID=%s>" % guid_str,
                                                    ldb.FLAG_MOD_REPLACE, 'dsServiceName')
            if self.do_modify(m, [], "Failed to change dsServiceName to GUID form", validate=False):
                self.report("Changed dsServiceName to GUID form")
        return error_count


    ###############################################
    # re-index the database
    def reindex_database(self):
        '''re-index the whole database'''
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, "@ATTRIBUTES")
        m['add']    = ldb.MessageElement('NONE', ldb.FLAG_MOD_ADD, 'force_reindex')
        m['delete'] = ldb.MessageElement('NONE', ldb.FLAG_MOD_DELETE, 'force_reindex')
        return self.do_modify(m, [], 're-indexed database', validate=False)

    ###############################################
    # reset @MODULES
    def reset_modules(self):
        '''reset @MODULES to that needed for current sam.ldb (to read a very old database)'''
        m = ldb.Message()
        m.dn = ldb.Dn(self.samdb, "@MODULES")
        m['@LIST'] = ldb.MessageElement('samba_dsdb', ldb.FLAG_MOD_REPLACE, '@LIST')
        return self.do_modify(m, [], 'reset @MODULES on database', validate=False)
