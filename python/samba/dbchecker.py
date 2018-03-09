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

from __future__ import print_function
import ldb
import samba
import time
from base64 import b64decode
from samba import dsdb
from samba import common
from samba.dcerpc import misc
from samba.dcerpc import drsuapi
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import drsblobs
from samba.common import dsdb_Dn
from samba.dcerpc import security
from samba.descriptor import get_wellknown_sds, get_diff_sds
from samba.auth import system_session, admin_session
from samba.netcmd import CommandError
from samba.netcmd.fsmo import get_fsmo_roleowner


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
        self.fix_all_duplicates = False
        self.fix_all_DN_GUIDs = False
        self.fix_all_binary_dn = False
        self.remove_implausible_deleted_DN_links = False
        self.remove_plausible_deleted_DN_links = False
        self.fix_all_string_dn_component_mismatch = False
        self.fix_all_GUID_dn_component_mismatch = False
        self.fix_all_SID_dn_component_mismatch = False
        self.fix_all_old_dn_string_component_mismatch = False
        self.fix_all_metadata = False
        self.fix_time_metadata = False
        self.fix_undead_linked_attributes = False
        self.fix_all_missing_backlinks = False
        self.fix_all_orphaned_backlinks = False
        self.fix_all_missing_forward_links = False
        self.duplicate_link_cache = dict()
        self.recover_all_forward_links = False
        self.fix_rmd_flags = False
        self.fix_ntsecuritydescriptor = False
        self.fix_ntsecuritydescriptor_owner_group = False
        self.seize_fsmo_role = False
        self.move_to_lost_and_found = False
        self.fix_instancetype = False
        self.fix_replmetadata_zero_invocationid = False
        self.fix_replmetadata_duplicate_attid = False
        self.fix_replmetadata_wrong_attid = False
        self.fix_replmetadata_unsorted_attid = False
        self.fix_deleted_deleted_objects = False
        self.fix_incorrect_deleted_objects = False
        self.fix_dn = False
        self.fix_base64_userparameters = False
        self.fix_utf8_userparameters = False
        self.fix_doubled_userparameters = False
        self.fix_sid_rid_set_conflict = False
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
        self.fix_all_missing_objectclass = False
        self.fix_missing_deleted_objects = False
        self.fix_replica_locations = False
        self.fix_missing_rid_set_master = False

        self.dn_set = set()
        self.link_id_cache = {}
        self.name_map = {}
        try:
            res = samdb.search(base="CN=DnsAdmins,CN=Users,%s" % samdb.domain_dn(), scope=ldb.SCOPE_BASE,
                           attrs=["objectSid"])
            dnsadmins_sid = ndr_unpack(security.dom_sid, res[0]["objectSid"][0])
            self.name_map['DnsAdmins'] = str(dnsadmins_sid)
        except ldb.LdbError as e5:
            (enum, estr) = e5.args
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

        res = self.samdb.search(base="", scope=ldb.SCOPE_BASE, attrs=['namingContexts'])
        self.deleted_objects_containers = []
        self.ncs_lacking_deleted_containers = []
        self.dns_partitions = []
        try:
            self.ncs = res[0]["namingContexts"]
        except KeyError:
            pass
        except IndexError:
            pass

        for nc in self.ncs:
            try:
                dn = self.samdb.get_wellknown_dn(ldb.Dn(self.samdb, nc),
                                                 dsdb.DS_GUID_DELETED_OBJECTS_CONTAINER)
                self.deleted_objects_containers.append(dn)
            except KeyError:
                self.ncs_lacking_deleted_containers.append(ldb.Dn(self.samdb, nc))

        domaindns_zone = 'DC=DomainDnsZones,%s' % self.samdb.get_default_basedn()
        forestdns_zone = 'DC=ForestDnsZones,%s' % self.samdb.get_root_basedn()
        domain = self.samdb.search(scope=ldb.SCOPE_ONELEVEL,
                                   attrs=["msDS-NC-Replica-Locations", "msDS-NC-RO-Replica-Locations"],
                                   base=self.samdb.get_partitions_dn(),
                                   expression="(&(objectClass=crossRef)(ncName=%s))" % domaindns_zone)
        if len(domain) == 1:
            self.dns_partitions.append((ldb.Dn(self.samdb, forestdns_zone), domain[0]))

        forest = self.samdb.search(scope=ldb.SCOPE_ONELEVEL,
                                   attrs=["msDS-NC-Replica-Locations", "msDS-NC-RO-Replica-Locations"],
                                   base=self.samdb.get_partitions_dn(),
                                   expression="(&(objectClass=crossRef)(ncName=%s))" % forestdns_zone)
        if len(forest) == 1:
            self.dns_partitions.append((ldb.Dn(self.samdb, domaindns_zone), forest[0]))

        fsmo_dn = ldb.Dn(self.samdb, "CN=RID Manager$,CN=System," + self.samdb.domain_dn())
        rid_master = get_fsmo_roleowner(self.samdb, fsmo_dn, "rid")
        if ldb.Dn(self.samdb, self.samdb.get_dsServiceName()) == rid_master:
            self.is_rid_master = True
        else:
            self.is_rid_master = False

        # To get your rid set
        # 1. Get server name
        res = self.samdb.search(base=ldb.Dn(self.samdb, self.samdb.get_serverName()),
                                scope=ldb.SCOPE_BASE, attrs=["serverReference"])
        # 2. Get server reference
        self.server_ref_dn = ldb.Dn(self.samdb, res[0]['serverReference'][0])

        # 3. Get RID Set
        res = self.samdb.search(base=self.server_ref_dn,
                                scope=ldb.SCOPE_BASE, attrs=['rIDSetReferences'])
        if "rIDSetReferences" in res[0]:
            self.rid_set_dn = ldb.Dn(self.samdb, res[0]['rIDSetReferences'][0])
        else:
            self.rid_set_dn = None

        self.compatibleFeatures = []
        self.requiredFeatures = []

        try:
            res = self.samdb.search(scope=ldb.SCOPE_BASE,
                                    base="@SAMBA_DSDB",
                                    attrs=["compatibleFeatures",
                                    "requiredFeatures"])
            if "compatibleFeatures" in res[0]:
                self.compatibleFeatures = res[0]["compatibleFeatures"]
            if "requiredFeatures" in res[0]:
                self.requiredFeatures = res[0]["requiredFeatures"]
        except ldb.LdbError as e6:
            (enum, estr) = e6.args
            if enum != ldb.ERR_NO_SUCH_OBJECT:
                raise
            pass

    def check_database(self, DN=None, scope=ldb.SCOPE_SUBTREE, controls=[], attrs=['*']):
        '''perform a database check, returning the number of errors found'''
        res = self.samdb.search(base=DN, scope=scope, attrs=['dn'], controls=controls)
        self.report('Checking %u objects' % len(res))
        error_count = 0

        error_count += self.check_deleted_objects_containers()

        self.attribute_or_class_ids = set()

        for object in res:
            self.dn_set.add(str(object.dn))
            error_count += self.check_object(object.dn, attrs=attrs)

        if DN is None:
            error_count += self.check_rootdse()

        if error_count != 0 and not self.fix:
            self.report("Please use --fix to fix these errors")

        self.report('Checked %u objects (%u errors)' % (len(res), error_count))
        return error_count

    def check_deleted_objects_containers(self):
        """This function only fixes conflicts on the Deleted Objects
        containers, not the attributes"""
        error_count = 0
        for nc in self.ncs_lacking_deleted_containers:
            if nc == self.schema_dn:
                continue
            error_count += 1
            self.report("ERROR: NC %s lacks a reference to a Deleted Objects container" % nc)
            if not self.confirm_all('Fix missing Deleted Objects container for %s?' % (nc), 'fix_missing_deleted_objects'):
                continue

            dn = ldb.Dn(self.samdb, "CN=Deleted Objects")
            dn.add_base(nc)

            conflict_dn = None
            try:
                # If something already exists here, add a conflict
                res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=[],
                                        controls=["show_deleted:1", "extended_dn:1:1",
                                                  "show_recycled:1", "reveal_internals:0"])
                if len(res) != 0:
                    guid = res[0].dn.get_extended_component("GUID")
                    conflict_dn = ldb.Dn(self.samdb,
                                         "CN=Deleted Objects\\0ACNF:%s" % str(misc.GUID(guid)))
                    conflict_dn.add_base(nc)

            except ldb.LdbError as e2:
                (enum, estr) = e2.args
                if enum == ldb.ERR_NO_SUCH_OBJECT:
                    pass
                else:
                    self.report("Couldn't check for conflicting Deleted Objects container: %s" % estr)
                    return 1

            if conflict_dn is not None:
                try:
                    self.samdb.rename(dn, conflict_dn, ["show_deleted:1", "relax:0", "show_recycled:1"])
                except ldb.LdbError as e1:
                    (enum, estr) = e1.args
                    self.report("Couldn't move old Deleted Objects placeholder: %s to %s: %s" % (dn, conflict_dn, estr))
                    return 1

            # Refresh wellKnownObjects links
            res = self.samdb.search(base=nc, scope=ldb.SCOPE_BASE,
                                    attrs=['wellKnownObjects'],
                                    controls=["show_deleted:1", "extended_dn:0",
                                              "show_recycled:1", "reveal_internals:0"])
            if len(res) != 1:
                self.report("wellKnownObjects was not found for NC %s" % nc)
                return 1

            # Prevent duplicate deleted objects containers just in case
            wko = res[0]["wellKnownObjects"]
            listwko = []
            proposed_objectguid = None
            for o in wko:
                dsdb_dn = dsdb_Dn(self.samdb, o, dsdb.DSDB_SYNTAX_BINARY_DN)
                if self.is_deleted_objects_dn(dsdb_dn):
                    self.report("wellKnownObjects had duplicate Deleted Objects value %s" % o)
                    # We really want to put this back in the same spot
                    # as the original one, so that on replication we
                    # merge, rather than conflict.
                    proposed_objectguid = dsdb_dn.dn.get_extended_component("GUID")
                listwko.append(o)

            if proposed_objectguid is not None:
                guid_suffix = "\nobjectGUID: %s" % str(misc.GUID(proposed_objectguid))
            else:
                wko_prefix = "B:32:%s" % dsdb.DS_GUID_DELETED_OBJECTS_CONTAINER
                listwko.append('%s:%s' % (wko_prefix, dn))
                guid_suffix = ""

            # Insert a brand new Deleted Objects container
            self.samdb.add_ldif("""dn: %s
objectClass: top
objectClass: container
description: Container for deleted objects
isDeleted: TRUE
isCriticalSystemObject: TRUE
showInAdvancedViewOnly: TRUE
systemFlags: -1946157056%s""" % (dn, guid_suffix),
                                controls=["relax:0", "provision:0"])

            delta = ldb.Message()
            delta.dn = ldb.Dn(self.samdb, str(res[0]["dn"]))
            delta["wellKnownObjects"] = ldb.MessageElement(listwko,
                                                           ldb.FLAG_MOD_REPLACE,
                                                           "wellKnownObjects")

            # Insert the link to the brand new container
            if self.do_modify(delta, ["relax:0"],
                              "NC %s lacks Deleted Objects WKGUID" % nc,
                              validate=False):
                self.report("Added %s well known guid link" % dn)

            self.deleted_objects_containers.append(dn)

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
        if getattr(self, all_attr) == 'NONE':
            return False
        if getattr(self, all_attr) == 'ALL':
            forced = True
        else:
            forced = self.yes
        if self.quiet:
            return forced
        c = common.confirm(msg, forced=forced, allow_all=True)
        if c == 'ALL':
            setattr(self, all_attr, 'ALL')
            return True
        if c == 'NONE':
            setattr(self, all_attr, 'NONE')
            return False
        return c

    def do_delete(self, dn, controls, msg):
        '''delete dn with optional verbose output'''
        if self.verbose:
            self.report("delete DN %s" % dn)
        try:
            controls = controls + ["local_oid:%s:0" % dsdb.DSDB_CONTROL_DBCHECK]
            self.samdb.delete(dn, controls=controls)
        except Exception as err:
            if self.in_transaction:
                raise CommandError("%s : %s" % (msg, err))
            self.report("%s : %s" % (msg, err))
            return False
        return True

    def do_modify(self, m, controls, msg, validate=True):
        '''perform a modify with optional verbose output'''
        if self.verbose:
            self.report(self.samdb.write_ldif(m, ldb.CHANGETYPE_MODIFY))
        try:
            controls = controls + ["local_oid:%s:0" % dsdb.DSDB_CONTROL_DBCHECK]
            self.samdb.modify(m, controls=controls, validate=validate)
        except Exception as err:
            if self.in_transaction:
                raise CommandError("%s : %s" % (msg, err))
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
        except Exception as err:
            if self.in_transaction:
                raise CommandError("%s : %s" % (msg, err))
            self.report("%s : %s" % (msg, err))
            return False
        return True

    def get_attr_linkID_and_reverse_name(self, attrname):
        if attrname in self.link_id_cache:
            return self.link_id_cache[attrname]
        linkID = self.samdb_schema.get_linkId_from_lDAPDisplayName(attrname)
        if linkID:
            revname = self.samdb_schema.get_backlink_from_lDAPDisplayName(attrname)
        else:
            revname = None
        self.link_id_cache[attrname] = (linkID, revname)
        return linkID, revname

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

    def err_duplicate_values(self, dn, attrname, dup_values, values):
        '''fix attribute normalisation errors'''
        self.report("ERROR: Duplicate values for attribute '%s' in '%s'" % (attrname, dn))
        self.report("Values contain a duplicate: [%s]/[%s]!" % (','.join(dup_values), ','.join(values)))
        if not self.confirm_all("Fix duplicates for '%s' from '%s'?" % (attrname, dn), 'fix_all_duplicates'):
            self.report("Not fixing attribute '%s'" % attrname)
            return

        m = ldb.Message()
        m.dn = dn
        m[attrname] = ldb.MessageElement(values, ldb.FLAG_MOD_REPLACE, attrname)

        if self.do_modify(m, ["relax:0", "show_recycled:1"],
                          "Failed to remove duplicate value on attribute %s" % attrname,
                          validate=False):
            self.report("Removed duplicate value on attribute %s" % attrname)

    def is_deleted_objects_dn(self, dsdb_dn):
        '''see if a dsdb_Dn is the special Deleted Objects DN'''
        return dsdb_dn.prefix == "B:32:%s:" % dsdb.DS_GUID_DELETED_OBJECTS_CONTAINER

    def err_missing_objectclass(self, dn):
        """handle object without objectclass"""
        self.report("ERROR: missing objectclass in object %s.  If you have another working DC, please run 'samba-tool drs replicate --full-sync --local <destinationDC> <sourceDC> %s'" % (dn, self.samdb.get_nc_root(dn)))
        if not self.confirm_all("If you cannot re-sync from another DC, do you wish to delete object '%s'?" % dn, 'fix_all_missing_objectclass'):
            self.report("Not deleting object with missing objectclass '%s'" % dn)
            return
        if self.do_delete(dn, ["relax:0"],
                          "Failed to remove DN %s" % dn):
            self.report("Removed DN %s" % dn)

    def err_deleted_dn(self, dn, attrname, val, dsdb_dn, correct_dn, remove_plausible=False):
        """handle a DN pointing to a deleted object"""
        if not remove_plausible:
            self.report("ERROR: target DN is deleted for %s in object %s - %s" % (attrname, dn, val))
            self.report("Target GUID points at deleted DN %r" % str(correct_dn))
            if not self.confirm_all('Remove DN link?', 'remove_implausible_deleted_DN_links'):
                self.report("Not removing")
                return
        else:
            self.report("WARNING: target DN is deleted for %s in object %s - %s" % (attrname, dn, val))
            self.report("Target GUID points at deleted DN %r" % str(correct_dn))
            if not self.confirm_all('Remove stale DN link?', 'remove_plausible_deleted_DN_links'):
                self.report("Not removing")
                return

        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        if self.do_modify(m, ["show_recycled:1",
                              "local_oid:%s:0" % dsdb.DSDB_CONTROL_REPLMD_VANISH_LINKS],
                          "Failed to remove deleted DN attribute %s" % attrname):
            self.report("Removed deleted DN on attribute %s" % attrname)

    def err_missing_target_dn_or_GUID(self, dn, attrname, val, dsdb_dn):
        """handle a missing target DN (if specified, GUID form can't be found,
        and otherwise DN string form can't be found)"""
        # check if its a backlink
        linkID, _ = self.get_attr_linkID_and_reverse_name(attrname)
        if (linkID & 1 == 0) and str(dsdb_dn).find('\\0ADEL') == -1:

            linkID, reverse_link_name \
                = self.get_attr_linkID_and_reverse_name(attrname)
            if reverse_link_name is not None:
                self.report("WARNING: no target object found for GUID "
                            "component for one-way forward link "
                            "%s in object "
                            "%s - %s" % (attrname, dn, val))
                self.report("Not removing dangling forward link")
                return 0

            nc_root = self.samdb.get_nc_root(dn)
            target_nc_root = self.samdb.get_nc_root(dsdb_dn.dn)
            if nc_root != target_nc_root:
                # We don't bump the error count as Samba produces these
                # in normal operation
                self.report("WARNING: no target object found for GUID "
                            "component for cross-partition link "
                            "%s in object "
                            "%s - %s" % (attrname, dn, val))
                self.report("Not removing dangling one-way "
                            "cross-partition link "
                            "(we might be mid-replication)")
                return 0

            # Due to our link handling one-way links pointing to
            # missing objects are plausible.
            #
            # We don't bump the error count as Samba produces these
            # in normal operation
            self.report("WARNING: no target object found for GUID "
                        "component for DN value %s in object "
                        "%s - %s" % (attrname, dn, val))
            self.err_deleted_dn(dn, attrname, val,
                                dsdb_dn, dsdb_dn, True)
            return 0

        # We bump the error count here, as we should have deleted this
        self.report("ERROR: no target object found for GUID "
                    "component for link %s in object "
                    "%s - %s" % (attrname, dn, val))
        self.err_deleted_dn(dn, attrname, val, dsdb_dn, dsdb_dn, False)
        return 1

    def err_missing_dn_GUID_component(self, dn, attrname, val, dsdb_dn, errstr):
        """handle a missing GUID extended DN component"""
        self.report("ERROR: %s component for %s in object %s - %s" % (errstr, attrname, dn, val))
        controls=["extended_dn:1:1", "show_recycled:1"]
        try:
            res = self.samdb.search(base=str(dsdb_dn.dn), scope=ldb.SCOPE_BASE,
                                    attrs=[], controls=controls)
        except ldb.LdbError as e7:
            (enum, estr) = e7.args
            self.report("unable to find object for DN %s - (%s)" % (dsdb_dn.dn, estr))
            if enum != ldb.ERR_NO_SUCH_OBJECT:
                raise
            self.err_missing_target_dn_or_GUID(dn, attrname, val, dsdb_dn)
            return
        if len(res) == 0:
            self.report("unable to find object for DN %s" % dsdb_dn.dn)
            self.err_missing_target_dn_or_GUID(dn, attrname, val, dsdb_dn)
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

    def err_dn_string_component_old(self, dn, attrname, val, dsdb_dn, correct_dn):
        """handle a DN string being incorrect"""
        self.report("NOTE: old (due to rename or delete) DN string component for %s in object %s - %s" % (attrname, dn, val))
        dsdb_dn.dn = correct_dn

        if not self.confirm_all('Change DN to %s?' % str(dsdb_dn),
                                'fix_all_old_dn_string_component_mismatch'):
            self.report("Not fixing old string component")
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        m['new_value'] = ldb.MessageElement(str(dsdb_dn), ldb.FLAG_MOD_ADD, attrname)
        if self.do_modify(m, ["show_recycled:1"],
                          "Failed to fix old DN string on attribute %s" % (attrname)):
            self.report("Fixed old DN string on attribute %s" % (attrname))

    def err_dn_component_target_mismatch(self, dn, attrname, val, dsdb_dn, correct_dn, mismatch_type):
        """handle a DN string being incorrect"""
        self.report("ERROR: incorrect DN %s component for %s in object %s - %s" % (mismatch_type, attrname, dn, val))
        dsdb_dn.dn = correct_dn

        if not self.confirm_all('Change DN to %s?' % str(dsdb_dn),
                                'fix_all_%s_dn_component_mismatch' % mismatch_type):
            self.report("Not fixing %s component mismatch" % mismatch_type)
            return
        m = ldb.Message()
        m.dn = dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)
        m['new_value'] = ldb.MessageElement(str(dsdb_dn), ldb.FLAG_MOD_ADD, attrname)
        if self.do_modify(m, ["show_recycled:1"],
                          "Failed to fix incorrect DN %s on attribute %s" % (mismatch_type, attrname)):
            self.report("Fixed incorrect DN %s on attribute %s" % (mismatch_type, attrname))

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

    def err_undead_linked_attribute(self, obj, attrname, val):
        '''handle a link that should not be there on a deleted object'''
        self.report("ERROR: linked attribute '%s' to '%s' is present on "
                    "deleted object %s" % (attrname, val, obj.dn))
        if not self.confirm_all('Remove linked attribute %s' % attrname, 'fix_undead_linked_attributes'):
            self.report("Not removing linked attribute %s" % attrname)
            return
        m = ldb.Message()
        m.dn = obj.dn
        m['old_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_DELETE, attrname)

        if self.do_modify(m, ["show_recycled:1", "show_deleted:1", "reveal_internals:0",
                              "local_oid:%s:0" % dsdb.DSDB_CONTROL_REPLMD_VANISH_LINKS],
                          "Failed to delete forward link %s" % attrname):
            self.report("Fixed undead forward link %s" % (attrname))

    def err_missing_backlink(self, obj, attrname, val, backlink_name, target_dn):
        '''handle a missing backlink value'''
        self.report("ERROR: missing backlink attribute '%s' in %s for link %s in %s" % (backlink_name, target_dn, attrname, obj.dn))
        if not self.confirm_all('Fix missing backlink %s' % backlink_name, 'fix_all_missing_backlinks'):
            self.report("Not fixing missing backlink %s" % backlink_name)
            return
        m = ldb.Message()
        m.dn = target_dn
        m['new_value'] = ldb.MessageElement(val, ldb.FLAG_MOD_ADD, backlink_name)
        if self.do_modify(m, ["show_recycled:1", "relax:0"],
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

    def err_orphaned_backlink(self, obj_dn, backlink_attr, backlink_val,
                              target_dn, forward_attr, forward_syntax,
                              check_duplicates=True):
        '''handle a orphaned backlink value'''
        if check_duplicates is True and self.has_duplicate_links(target_dn, forward_attr, forward_syntax):
            self.report("WARNING: Keep orphaned backlink attribute " + \
                        "'%s' in '%s' for link '%s' in '%s'" % (
                        backlink_attr, obj_dn, forward_attr, target_dn))
            return
        self.report("ERROR: orphaned backlink attribute '%s' in %s for link %s in %s" % (backlink_attr, obj_dn, forward_attr, target_dn))
        if not self.confirm_all('Remove orphaned backlink %s' % backlink_attr, 'fix_all_orphaned_backlinks'):
            self.report("Not removing orphaned backlink %s" % backlink_attr)
            return
        m = ldb.Message()
        m.dn = obj_dn
        m['value'] = ldb.MessageElement(backlink_val, ldb.FLAG_MOD_DELETE, backlink_attr)
        if self.do_modify(m, ["show_recycled:1", "relax:0"],
                          "Failed to fix orphaned backlink %s" % backlink_attr):
            self.report("Fixed orphaned backlink %s" % (backlink_attr))

    def err_recover_forward_links(self, obj, forward_attr, forward_vals):
        '''handle a duplicate links value'''

        self.report("RECHECK: 'Missing/Duplicate/Correct link' lines above for attribute '%s' in '%s'" % (forward_attr, obj.dn))

        if not self.confirm_all("Commit fixes for (missing/duplicate) forward links in attribute '%s'" % forward_attr, 'recover_all_forward_links'):
            self.report("Not fixing corrupted (missing/duplicate) forward links in attribute '%s' of '%s'" % (
                        forward_attr, obj.dn))
            return
        m = ldb.Message()
        m.dn = obj.dn
        m['value'] = ldb.MessageElement(forward_vals, ldb.FLAG_MOD_REPLACE, forward_attr)
        if self.do_modify(m, ["local_oid:1.3.6.1.4.1.7165.4.3.19.2:1"],
                "Failed to fix duplicate links in attribute '%s'" % forward_attr):
            self.report("Fixed duplicate links in attribute '%s'" % (forward_attr))
            duplicate_cache_key = "%s:%s" % (str(obj.dn), forward_attr)
            assert duplicate_cache_key in self.duplicate_link_cache
            self.duplicate_link_cache[duplicate_cache_key] = False

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

        keep_transaction = False
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

    def err_wrong_dn(self, obj, new_dn, rdn_attr, rdn_val, name_val):
        '''handle a wrong dn'''

        new_rdn = ldb.Dn(self.samdb, str(new_dn))
        new_rdn.remove_base_components(len(new_rdn) - 1)
        new_parent = new_dn.parent()

        attributes = ""
        if rdn_val != name_val:
            attributes += "%s=%r " % (rdn_attr, rdn_val)
        attributes += "name=%r" % (name_val)

        self.report("ERROR: wrong dn[%s] %s new_dn[%s]" % (obj.dn, attributes, new_dn))
        if not self.confirm_all("Rename %s to %s?" % (obj.dn, new_dn), 'fix_dn'):
            self.report("Not renaming %s to %s" % (obj.dn, new_dn))
            return

        if self.do_rename(obj.dn, new_rdn, new_parent, ["show_recycled:1", "relax:0"],
                          "Failed to rename object %s into %s" % (obj.dn, new_dn)):
            self.report("Renamed %s into %s" % (obj.dn, new_dn))

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

    def err_short_userParameters(self, obj, attrname, value):
        # This is a truncated userParameters due to a pre 4.1 replication bug
        self.report("ERROR: incorrect userParameters value on object %s.  If you have another working DC that does not give this warning, please run 'samba-tool drs replicate --full-sync --local <destinationDC> <sourceDC> %s'" % (obj.dn, self.samdb.get_nc_root(obj.dn)))

    def err_base64_userParameters(self, obj, attrname, value):
        '''handle a wrong userParameters'''
        self.report("ERROR: wrongly formatted userParameters %s on %s, should not be base64-encoded" % (value, obj.dn))
        if not self.confirm_all('Convert userParameters from base64 encoding on %s?' % (obj.dn), 'fix_base64_userparameters'):
            self.report('Not changing userParameters from base64 encoding on %s' % (obj.dn))
            return

        m = ldb.Message()
        m.dn = obj.dn
        m['value'] = ldb.MessageElement(b64decode(obj[attrname][0]), ldb.FLAG_MOD_REPLACE, 'userParameters')
        if self.do_modify(m, [],
                          "Failed to correct base64-encoded userParameters on %s by converting from base64" % (obj.dn)):
            self.report("Corrected base64-encoded userParameters on %s by converting from base64" % (obj.dn))

    def err_utf8_userParameters(self, obj, attrname, value):
        '''handle a wrong userParameters'''
        self.report("ERROR: wrongly formatted userParameters on %s, should not be psudo-UTF8 encoded" % (obj.dn))
        if not self.confirm_all('Convert userParameters from UTF8 encoding on %s?' % (obj.dn), 'fix_utf8_userparameters'):
            self.report('Not changing userParameters from UTF8 encoding on %s' % (obj.dn))
            return

        m = ldb.Message()
        m.dn = obj.dn
        m['value'] = ldb.MessageElement(obj[attrname][0].decode('utf8').encode('utf-16-le'),
                                        ldb.FLAG_MOD_REPLACE, 'userParameters')
        if self.do_modify(m, [],
                          "Failed to correct psudo-UTF8 encoded userParameters on %s by converting from UTF8" % (obj.dn)):
            self.report("Corrected psudo-UTF8 encoded userParameters on %s by converting from UTF8" % (obj.dn))

    def err_doubled_userParameters(self, obj, attrname, value):
        '''handle a wrong userParameters'''
        self.report("ERROR: wrongly formatted userParameters on %s, should not be double UTF16 encoded" % (obj.dn))
        if not self.confirm_all('Convert userParameters from doubled UTF-16 encoding on %s?' % (obj.dn), 'fix_doubled_userparameters'):
            self.report('Not changing userParameters from doubled UTF-16 encoding on %s' % (obj.dn))
            return

        m = ldb.Message()
        m.dn = obj.dn
        m['value'] = ldb.MessageElement(obj[attrname][0].decode('utf-16-le').decode('utf-16-le').encode('utf-16-le'),
                                        ldb.FLAG_MOD_REPLACE, 'userParameters')
        if self.do_modify(m, [],
                          "Failed to correct doubled-UTF16 encoded userParameters on %s by converting" % (obj.dn)):
            self.report("Corrected doubled-UTF16 encoded userParameters on %s by converting" % (obj.dn))

    def err_odd_userParameters(self, obj, attrname):
        # This is a truncated userParameters due to a pre 4.1 replication bug
        self.report("ERROR: incorrect userParameters value on object %s (odd length).  If you have another working DC that does not give this warning, please run 'samba-tool drs replicate --full-sync --local <destinationDC> <sourceDC> %s'" % (obj.dn, self.samdb.get_nc_root(obj.dn)))

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

    def check_duplicate_links(self, obj, forward_attr, forward_syntax, forward_linkID, backlink_attr):
        '''check a linked values for duplicate forward links'''
        error_count = 0

        duplicate_dict = dict()
        unique_dict = dict()

        # Only forward links can have this problem
        if forward_linkID & 1:
            # If we got the reverse, skip it
            return (error_count, duplicate_dict, unique_dict)

        if backlink_attr is None:
            return (error_count, duplicate_dict, unique_dict)

        duplicate_cache_key = "%s:%s" % (str(obj.dn), forward_attr)
        if duplicate_cache_key not in self.duplicate_link_cache:
            self.duplicate_link_cache[duplicate_cache_key] = False

        for val in obj[forward_attr]:
            dsdb_dn = dsdb_Dn(self.samdb, val, forward_syntax)

            # all DNs should have a GUID component
            guid = dsdb_dn.dn.get_extended_component("GUID")
            if guid is None:
                continue
            guidstr = str(misc.GUID(guid))
            keystr = guidstr + dsdb_dn.prefix
            if keystr not in unique_dict:
                unique_dict[keystr] = dsdb_dn
                continue
            error_count += 1
            if keystr not in duplicate_dict:
                duplicate_dict[keystr] = dict()
                duplicate_dict[keystr]["keep"] = None
                duplicate_dict[keystr]["delete"] = list()

            # Now check for the highest RMD_VERSION
            v1 = int(unique_dict[keystr].dn.get_extended_component("RMD_VERSION"))
            v2 = int(dsdb_dn.dn.get_extended_component("RMD_VERSION"))
            if v1 > v2:
                duplicate_dict[keystr]["keep"] = unique_dict[keystr]
                duplicate_dict[keystr]["delete"].append(dsdb_dn)
                continue
            if v1 < v2:
                duplicate_dict[keystr]["keep"] = dsdb_dn
                duplicate_dict[keystr]["delete"].append(unique_dict[keystr])
                unique_dict[keystr] = dsdb_dn
                continue
            # Fallback to the highest RMD_LOCAL_USN
            u1 = int(unique_dict[keystr].dn.get_extended_component("RMD_LOCAL_USN"))
            u2 = int(dsdb_dn.dn.get_extended_component("RMD_LOCAL_USN"))
            if u1 >= u2:
                duplicate_dict[keystr]["keep"] = unique_dict[keystr]
                duplicate_dict[keystr]["delete"].append(dsdb_dn)
                continue
            duplicate_dict[keystr]["keep"] = dsdb_dn
            duplicate_dict[keystr]["delete"].append(unique_dict[keystr])
            unique_dict[keystr] = dsdb_dn

        if error_count != 0:
            self.duplicate_link_cache[duplicate_cache_key] = True

        return (error_count, duplicate_dict, unique_dict)

    def has_duplicate_links(self, dn, forward_attr, forward_syntax):
        '''check a linked values for duplicate forward links'''
        error_count = 0

        duplicate_cache_key = "%s:%s" % (str(dn), forward_attr)
        if duplicate_cache_key in self.duplicate_link_cache:
            return self.duplicate_link_cache[duplicate_cache_key]

        forward_linkID, backlink_attr = self.get_attr_linkID_and_reverse_name(forward_attr)

        attrs = [forward_attr]
        controls = ["extended_dn:1:1", "reveal_internals:0"]

        # check its the right GUID
        try:
            res = self.samdb.search(base=str(dn), scope=ldb.SCOPE_BASE,
                                    attrs=attrs, controls=controls)
        except ldb.LdbError as e8:
            (enum, estr) = e8.args
            if enum != ldb.ERR_NO_SUCH_OBJECT:
                raise

            return False

        obj = res[0]
        error_count, duplicate_dict, unique_dict = \
            self.check_duplicate_links(obj, forward_attr, forward_syntax, forward_linkID, backlink_attr)

        if duplicate_cache_key in self.duplicate_link_cache:
            return self.duplicate_link_cache[duplicate_cache_key]

        return False

    def find_missing_forward_links_from_backlinks(self, obj,
                                                  forward_attr,
                                                  forward_syntax,
                                                  backlink_attr,
                                                  forward_unique_dict):
        '''Find all backlinks linking to obj_guid_str not already in forward_unique_dict'''
        missing_forward_links = []
        error_count = 0

        if backlink_attr is None:
            return (missing_forward_links, error_count)

        if forward_syntax != ldb.SYNTAX_DN:
            self.report("Not checking for missing forward links for syntax: %s",
                        forward_syntax)
            return (missing_forward_links, error_count)

        if "sortedLinks" in self.compatibleFeatures:
            self.report("Not checking for missing forward links because the db " + \
                        "has the sortedLinks feature")
            return (missing_forward_links, error_count)

        try:
            obj_guid = obj['objectGUID'][0]
            obj_guid_str = str(ndr_unpack(misc.GUID, obj_guid))
            filter = "(%s=<GUID=%s>)" % (backlink_attr, obj_guid_str)

            res = self.samdb.search(expression=filter,
                                    scope=ldb.SCOPE_SUBTREE, attrs=["objectGUID"],
                                    controls=["extended_dn:1:1",
                                              "search_options:1:2",
                                              "paged_results:1:1000"])
        except ldb.LdbError as e9:
            (enum, estr) = e9.args
            raise

        for r in res:
            target_dn = dsdb_Dn(self.samdb, r.dn.extended_str(), forward_syntax)

            guid = target_dn.dn.get_extended_component("GUID")
            guidstr = str(misc.GUID(guid))
            if guidstr in forward_unique_dict:
                continue

            # A valid forward link looks like this:
            #
            #    <GUID=9f92d30a-fc23-11e4-a5f6-30be15454808>;
            #    <RMD_ADDTIME=131607546230000000>;
            #    <RMD_CHANGETIME=131607546230000000>;
            #    <RMD_FLAGS=0>;
            #    <RMD_INVOCID=4e4496a3-7fb8-4f97-8a33-d238db8b5e2d>;
            #    <RMD_LOCAL_USN=3765>;
            #    <RMD_ORIGINATING_USN=3765>;
            #    <RMD_VERSION=1>;
            #    <SID=S-1-5-21-4177067393-1453636373-93818738-1124>;
            #    CN=unsorted-u8,CN=Users,DC=release-4-5-0-pre1,DC=samba,DC=corp
            #
            # Note that versions older than Samba 4.8 create
            # links with RMD_VERSION=0.
            #
            # Try to get the local_usn and time from objectClass
            # if possible and fallback to any other one.
            repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                              obj['replPropertyMetadata'][0])
            for o in repl.ctr.array:
                local_usn = o.local_usn
                t = o.originating_change_time
                if o.attid == drsuapi.DRSUAPI_ATTID_objectClass:
                    break

            # We use a magic invocationID for restoring missing
            # forward links to recover from bug #13228.
            # This should allow some more future magic to fix the
            # problem.
            #
            # It also means it looses the conflict resolution
            # against almost every real invocation, if the
            # version is also 0.
            originating_invocid = misc.GUID("ffffffff-4700-4700-4700-000000b13228")
            originating_usn = 1

            rmd_addtime = t
            rmd_changetime = t
            rmd_flags = 0
            rmd_invocid = originating_invocid
            rmd_originating_usn = originating_usn
            rmd_local_usn = local_usn
            rmd_version = 0

            target_dn.dn.set_extended_component("RMD_ADDTIME", str(rmd_addtime))
            target_dn.dn.set_extended_component("RMD_CHANGETIME", str(rmd_changetime))
            target_dn.dn.set_extended_component("RMD_FLAGS", str(rmd_flags))
            target_dn.dn.set_extended_component("RMD_INVOCID", ndr_pack(rmd_invocid))
            target_dn.dn.set_extended_component("RMD_ORIGINATING_USN", str(rmd_originating_usn))
            target_dn.dn.set_extended_component("RMD_LOCAL_USN", str(rmd_local_usn))
            target_dn.dn.set_extended_component("RMD_VERSION", str(rmd_version))

            error_count += 1
            missing_forward_links.append(target_dn)

        return (missing_forward_links, error_count)

    def check_dn(self, obj, attrname, syntax_oid):
        '''check a DN attribute for correctness'''
        error_count = 0
        obj_guid = obj['objectGUID'][0]

        linkID, reverse_link_name = self.get_attr_linkID_and_reverse_name(attrname)
        if reverse_link_name is not None:
            reverse_syntax_oid = self.samdb_schema.get_syntax_oid_from_lDAPDisplayName(reverse_link_name)
        else:
            reverse_syntax_oid = None

        error_count, duplicate_dict, unique_dict = \
            self.check_duplicate_links(obj, attrname, syntax_oid, linkID, reverse_link_name)

        if len(duplicate_dict) != 0:

            missing_forward_links, missing_error_count = \
                self.find_missing_forward_links_from_backlinks(obj,
                                                         attrname, syntax_oid,
                                                         reverse_link_name,
                                                         unique_dict)
            error_count += missing_error_count

            forward_links = [dn for dn in unique_dict.values()]

            if missing_error_count != 0:
                self.report("ERROR: Missing and duplicate forward link values for attribute '%s' in '%s'" % (
                            attrname, obj.dn))
            else:
                self.report("ERROR: Duplicate forward link values for attribute '%s' in '%s'" % (attrname, obj.dn))
            for m in missing_forward_links:
                self.report("Missing   link '%s'" % (m))
                if not self.confirm_all("Schedule readding missing forward link for attribute %s" % attrname,
                                        'fix_all_missing_forward_links'):
                    self.err_orphaned_backlink(m.dn, reverse_link_name,
                                               obj.dn.extended_str(), obj.dn,
                                               attrname, syntax_oid,
                                               check_duplicates=False)
                    continue
                forward_links += [m]
            for keystr in duplicate_dict.keys():
                d = duplicate_dict[keystr]
                for dd in d["delete"]:
                    self.report("Duplicate link '%s'" % dd)
                self.report("Correct   link '%s'" % d["keep"])

            # We now construct the sorted dn values.
            # They're sorted by the objectGUID of the target
            # See dsdb_Dn.__cmp__()
            vals = [str(dn) for dn in sorted(forward_links)]
            self.err_recover_forward_links(obj, attrname, vals)
            # We should continue with the fixed values
            obj[attrname] = ldb.MessageElement(vals, 0, attrname)

        for val in obj[attrname]:
            dsdb_dn = dsdb_Dn(self.samdb, val, syntax_oid)

            # all DNs should have a GUID component
            guid = dsdb_dn.dn.get_extended_component("GUID")
            if guid is None:
                error_count += 1
                self.err_missing_dn_GUID_component(obj.dn, attrname, val, dsdb_dn,
                    "missing GUID")
                continue

            guidstr = str(misc.GUID(guid))
            attrs = ['isDeleted', 'replPropertyMetaData']

            if (str(attrname).lower() == 'msds-hasinstantiatedncs') and (obj.dn == self.ntds_dsa):
                fixing_msDS_HasInstantiatedNCs = True
                attrs.append("instanceType")
            else:
                fixing_msDS_HasInstantiatedNCs = False

            if reverse_link_name is not None:
                attrs.append(reverse_link_name)

            # check its the right GUID
            try:
                res = self.samdb.search(base="<GUID=%s>" % guidstr, scope=ldb.SCOPE_BASE,
                                        attrs=attrs, controls=["extended_dn:1:1", "show_recycled:1",
                                                               "reveal_internals:0"
                                        ])
            except ldb.LdbError as e3:
                (enum, estr) = e3.args
                if enum != ldb.ERR_NO_SUCH_OBJECT:
                    raise

                # We don't always want to
                error_count += self.err_missing_target_dn_or_GUID(obj.dn,
                                                                  attrname,
                                                                  val,
                                                                  dsdb_dn)
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


            if is_deleted and not obj.dn in self.deleted_objects_containers and linkID:
                # A fully deleted object should not have any linked
                # attributes. (MS-ADTS 3.1.1.5.5.1.1 Tombstone
                # Requirements and 3.1.1.5.5.1.3 Recycled-Object
                # Requirements)
                self.err_undead_linked_attribute(obj, attrname, val)
                error_count += 1
                continue
            elif target_is_deleted and not self.is_deleted_objects_dn(dsdb_dn) and linkID:
                # the target DN is not allowed to be deleted, unless the target DN is the
                # special Deleted Objects container
                error_count += 1
                local_usn = dsdb_dn.dn.get_extended_component("RMD_LOCAL_USN")
                if local_usn:
                    if 'replPropertyMetaData' in res[0]:
                        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                                          str(res[0]['replPropertyMetadata']))
                        found_data = False
                        for o in repl.ctr.array:
                            if o.attid == drsuapi.DRSUAPI_ATTID_isDeleted:
                                deleted_usn = o.local_usn
                                if deleted_usn >= int(local_usn):
                                    # If the object was deleted after the link
                                    # was last modified then, clean it up here
                                    found_data = True
                                    break

                        if found_data:
                            self.err_deleted_dn(obj.dn, attrname,
                                                val, dsdb_dn, res[0].dn, True)
                            continue

                self.err_deleted_dn(obj.dn, attrname, val, dsdb_dn, res[0].dn, False)
                continue

            # We should not check for incorrect
            # components on deleted links, as these are allowed to
            # go stale (we just need the GUID, not the name)
            rmd_blob = dsdb_dn.dn.get_extended_component("RMD_FLAGS")
            rmd_flags = 0
            if rmd_blob is not None:
                rmd_flags = int(rmd_blob)

            # assert the DN matches in string form, where a reverse
            # link exists, otherwise (below) offer to fix it as a non-error.
            # The string form is essentially only kept for forensics,
            # as we always re-resolve by GUID in normal operations.
            if not rmd_flags & 1 and reverse_link_name is not None:
                if str(res[0].dn) != str(dsdb_dn.dn):
                    error_count += 1
                    self.err_dn_component_target_mismatch(obj.dn, attrname, val, dsdb_dn,
                                                          res[0].dn, "string")
                    continue

            if res[0].dn.get_extended_component("GUID") != dsdb_dn.dn.get_extended_component("GUID"):
                error_count += 1
                self.err_dn_component_target_mismatch(obj.dn, attrname, val, dsdb_dn,
                                                      res[0].dn, "GUID")
                continue

            if res[0].dn.get_extended_component("SID") != dsdb_dn.dn.get_extended_component("SID"):
                error_count += 1
                self.err_dn_component_target_mismatch(obj.dn, attrname, val, dsdb_dn,
                                                      res[0].dn, "SID")
                continue

            # Now we have checked the GUID and SID, offer to fix old
            # DN strings as a non-error (for forward links with no
            # backlink).  Samba does not maintain this string
            # otherwise, so we don't increment error_count.
            if reverse_link_name is None:
                if str(res[0].dn) != str(dsdb_dn.dn):
                    self.err_dn_string_component_old(obj.dn, attrname, val, dsdb_dn,
                                                     res[0].dn)
                continue

            # check the reverse_link is correct if there should be one
            match_count = 0
            if reverse_link_name in res[0]:
                for v in res[0][reverse_link_name]:
                    v_dn = dsdb_Dn(self.samdb, v)
                    v_guid = v_dn.dn.get_extended_component("GUID")
                    v_blob = v_dn.dn.get_extended_component("RMD_FLAGS")
                    v_rmd_flags = 0
                    if v_blob is not None:
                        v_rmd_flags = int(v_blob)
                    if v_rmd_flags & 1:
                        continue
                    if v_guid == obj_guid:
                        match_count += 1

            if match_count != 1:
                if syntax_oid == dsdb.DSDB_SYNTAX_BINARY_DN or reverse_syntax_oid == dsdb.DSDB_SYNTAX_BINARY_DN:
                    if not linkID & 1:
                        # Forward binary multi-valued linked attribute
                        forward_count = 0
                        for w in obj[attrname]:
                            w_guid = dsdb_Dn(self.samdb, w).dn.get_extended_component("GUID")
                            if w_guid == guid:
                                forward_count += 1

                        if match_count == forward_count:
                            continue
            expected_count = 0
            for v in obj[attrname]:
                v_dn = dsdb_Dn(self.samdb, v)
                v_guid = v_dn.dn.get_extended_component("GUID")
                v_blob = v_dn.dn.get_extended_component("RMD_FLAGS")
                v_rmd_flags = 0
                if v_blob is not None:
                    v_rmd_flags = int(v_blob)
                if v_rmd_flags & 1:
                    continue
                if v_guid == guid:
                    expected_count += 1

            if match_count == expected_count:
                continue

            diff_count = expected_count - match_count

            if linkID & 1:
                # If there's a backward link on binary multi-valued linked attribute,
                # let the check on the forward link remedy the value.
                # UNLESS, there is no forward link detected.
                if match_count == 0:
                    error_count += 1
                    self.err_orphaned_backlink(obj.dn, attrname,
                                               val, dsdb_dn.dn,
                                               reverse_link_name,
                                               reverse_syntax_oid)
                    continue
                # Only warn here and let the forward link logic fix it.
                self.report("WARNING: Link (back) mismatch for '%s' (%d) on '%s' to '%s' (%d) on '%s'" % (
                            attrname, expected_count, str(obj.dn),
                            reverse_link_name, match_count, str(dsdb_dn.dn)))
                continue

            assert not target_is_deleted

            self.report("ERROR: Link (forward) mismatch for '%s' (%d) on '%s' to '%s' (%d) on '%s'" % (
                        attrname, expected_count, str(obj.dn),
                        reverse_link_name, match_count, str(dsdb_dn.dn)))

            # Loop until the difference between the forward and
            # the backward links is resolved.
            while diff_count != 0:
                error_count += 1
                if diff_count > 0:
                    if match_count > 0 or diff_count > 1:
                        # TODO no method to fix these right now
                        self.report("ERROR: Can't fix missing "
                                    "multi-valued backlinks on %s" % str(dsdb_dn.dn))
                        break
                    self.err_missing_backlink(obj, attrname,
                                              obj.dn.extended_str(),
                                              reverse_link_name,
                                              dsdb_dn.dn)
                    diff_count -= 1
                else:
                    self.err_orphaned_backlink(res[0].dn, reverse_link_name,
                                               obj.dn.extended_str(), obj.dn,
                                               attrname, syntax_oid)
                    diff_count += 1


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

    def process_metadata(self, dn, val):
        '''Read metadata properties and list attributes in it.
           raises KeyError if the attid is unknown.'''

        set_att = set()
        wrong_attids = set()
        list_attid = []
        in_schema_nc = dn.is_child_of(self.schema_dn)

        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob, str(val))
        obj = repl.ctr

        for o in repl.ctr.array:
            att = self.samdb_schema.get_lDAPDisplayName_by_attid(o.attid)
            set_att.add(att.lower())
            list_attid.append(o.attid)
            correct_attid = self.samdb_schema.get_attid_from_lDAPDisplayName(att,
                                                                             is_schema_nc=in_schema_nc)
            if correct_attid != o.attid:
                wrong_attids.add(o.attid)

        return (set_att, list_attid, wrong_attids)


    def fix_metadata(self, obj, attr):
        '''re-write replPropertyMetaData elements for a single attribute for a
        object. This is used to fix missing replPropertyMetaData elements'''
        guid_str = str(ndr_unpack(misc.GUID, obj['objectGUID'][0]))
        dn = ldb.Dn(self.samdb, "<GUID=%s>" % guid_str)
        res = self.samdb.search(base = dn, scope=ldb.SCOPE_BASE, attrs = [attr],
                                controls = ["search_options:1:2",
                                            "show_recycled:1"])
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
        except KeyError as e:
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


    def has_replmetadata_zero_invocationid(self, dn, repl_meta_data):
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          str(repl_meta_data))
        ctr = repl.ctr
        found = False
        for o in ctr.array:
            # Search for a zero invocationID
            if o.originating_invocation_id != misc.GUID("00000000-0000-0000-0000-000000000000"):
                continue

            found = True
            self.report('''ERROR: on replPropertyMetaData of %s, the instanceType on attribute 0x%08x,
                           version %d changed at %s is 00000000-0000-0000-0000-000000000000,
                           but should be non-zero.  Proposed fix is to set to our invocationID (%s).'''
                        % (dn, o.attid, o.version,
                           time.ctime(samba.nttime2unix(o.originating_change_time)),
                           self.samdb.get_invocation_id()))

        return found


    def err_replmetadata_zero_invocationid(self, dn, attr, repl_meta_data):
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          str(repl_meta_data))
        ctr = repl.ctr
        now = samba.unix2nttime(int(time.time()))
        found = False
        for o in ctr.array:
            # Search for a zero invocationID
            if o.originating_invocation_id != misc.GUID("00000000-0000-0000-0000-000000000000"):
                continue

            found = True
            seq = self.samdb.sequence_number(ldb.SEQ_NEXT)
            o.version = o.version + 1
            o.originating_change_time = now
            o.originating_invocation_id = misc.GUID(self.samdb.get_invocation_id())
            o.originating_usn = seq
            o.local_usn = seq

        if found:
            replBlob = ndr_pack(repl)
            msg = ldb.Message()
            msg.dn = dn

            if not self.confirm_all('Fix %s on %s by setting originating_invocation_id on some elements to our invocationID %s?'
                                    % (attr, dn, self.samdb.get_invocation_id()), 'fix_replmetadata_zero_invocationid'):
                self.report('Not fixing zero originating_invocation_id in %s on %s\n' % (attr, dn))
                return

            nmsg = ldb.Message()
            nmsg.dn = dn
            nmsg[attr] = ldb.MessageElement(replBlob, ldb.FLAG_MOD_REPLACE, attr)
            if self.do_modify(nmsg, ["local_oid:%s:0" % dsdb.DSDB_CONTROL_DBCHECK_MODIFY_RO_REPLICA,
                                     "local_oid:1.3.6.1.4.1.7165.4.3.14:0"],
                              "Failed to fix attribute %s" % attr):
                self.report("Fixed attribute '%s' of '%s'\n" % (attr, dn))


    def err_replmetadata_unknown_attid(self, dn, attr, repl_meta_data):
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          str(repl_meta_data))
        ctr = repl.ctr
        for o in ctr.array:
            # Search for an invalid attid
            try:
                att = self.samdb_schema.get_lDAPDisplayName_by_attid(o.attid)
            except KeyError:
                self.report('ERROR: attributeID 0X%0X is not known in our schema, not fixing %s on %s\n' % (o.attid, attr, dn))
                return


    def err_replmetadata_incorrect_attid(self, dn, attr, repl_meta_data, wrong_attids):
        repl = ndr_unpack(drsblobs.replPropertyMetaDataBlob,
                          str(repl_meta_data))
        fix = False

        set_att = set()
        remove_attid = set()
        hash_att = {}

        in_schema_nc = dn.is_child_of(self.schema_dn)

        ctr = repl.ctr
        # Sort the array, except for the last element.  This strange
        # construction, creating a new list, due to bugs in samba's
        # array handling in IDL generated objects.
        ctr.array = sorted(ctr.array[:], key=lambda o: o.attid)
        # Now walk it in reverse, so we see the low (and so incorrect,
        # the correct values are above 0x80000000) values first and
        # remove the 'second' value we see.
        for o in reversed(ctr.array):
            print("%s: 0x%08x" % (dn, o.attid))
            att = self.samdb_schema.get_lDAPDisplayName_by_attid(o.attid)
            if att.lower() in set_att:
                self.report('ERROR: duplicate attributeID values for %s in %s on %s\n' % (att, attr, dn))
                if not self.confirm_all('Fix %s on %s by removing the duplicate value 0x%08x for %s (keeping 0x%08x)?'
                                        % (attr, dn, o.attid, att, hash_att[att].attid),
                                        'fix_replmetadata_duplicate_attid'):
                    self.report('Not fixing duplicate value 0x%08x for %s in %s on %s\n'
                                % (o.attid, att, attr, dn))
                    return
                fix = True
                remove_attid.add(o.attid)
                # We want to set the metadata for the most recent
                # update to have been applied locally, that is the metadata
                # matching the (eg string) value in the attribute
                if o.local_usn > hash_att[att].local_usn:
                    # This is always what we would have sent over DRS,
                    # because the DRS server will have sent the
                    # msDS-IntID, but with the values from both
                    # attribute entries.
                    hash_att[att].version = o.version
                    hash_att[att].originating_change_time = o.originating_change_time
                    hash_att[att].originating_invocation_id = o.originating_invocation_id
                    hash_att[att].originating_usn = o.originating_usn
                    hash_att[att].local_usn = o.local_usn

                # Do not re-add the value to the set or overwrite the hash value
                continue

            hash_att[att] = o
            set_att.add(att.lower())

        # Generate a real list we can sort on properly
        new_list = [o for o in ctr.array if o.attid not in remove_attid]

        if (len(wrong_attids) > 0):
            for o in new_list:
                if o.attid in wrong_attids:
                    att = self.samdb_schema.get_lDAPDisplayName_by_attid(o.attid)
                    correct_attid = self.samdb_schema.get_attid_from_lDAPDisplayName(att, is_schema_nc=in_schema_nc)
                    self.report('ERROR: incorrect attributeID values in %s on %s\n' % (attr, dn))
                    if not self.confirm_all('Fix %s on %s by replacing incorrect value 0x%08x for %s (new 0x%08x)?'
                                            % (attr, dn, o.attid, att, hash_att[att].attid), 'fix_replmetadata_wrong_attid'):
                        self.report('Not fixing incorrect value 0x%08x with 0x%08x for %s in %s on %s\n'
                                    % (o.attid, correct_attid, att, attr, dn))
                        return
                    fix = True
                    o.attid = correct_attid
            if fix:
                # Sort the array, (we changed the value so must re-sort)
                new_list[:] = sorted(new_list[:], key=lambda o: o.attid)

        # If we did not already need to fix it, then ask about sorting
        if not fix:
            self.report('ERROR: unsorted attributeID values in %s on %s\n' % (attr, dn))
            if not self.confirm_all('Fix %s on %s by sorting the attribute list?'
                                    % (attr, dn), 'fix_replmetadata_unsorted_attid'):
                self.report('Not fixing %s on %s\n' % (attr, dn))
                return

            # The actual sort done is done at the top of the function

        ctr.count = len(new_list)
        ctr.array = new_list
        replBlob = ndr_pack(repl)

        nmsg = ldb.Message()
        nmsg.dn = dn
        nmsg[attr] = ldb.MessageElement(replBlob, ldb.FLAG_MOD_REPLACE, attr)
        if self.do_modify(nmsg, ["local_oid:%s:0" % dsdb.DSDB_CONTROL_DBCHECK_MODIFY_RO_REPLICA,
                             "local_oid:1.3.6.1.4.1.7165.4.3.14:0",
                             "local_oid:1.3.6.1.4.1.7165.4.3.25:0"],
                      "Failed to fix attribute %s" % attr):
            self.report("Fixed attribute '%s' of '%s'\n" % (attr, dn))


    def is_deleted_deleted_objects(self, obj):
        faulty = False
        if "description" not in obj:
            self.report("ERROR: description not present on Deleted Objects container %s" % obj.dn)
            faulty = True
        if "showInAdvancedViewOnly" not in obj or obj['showInAdvancedViewOnly'][0].upper() == 'FALSE':
            self.report("ERROR: showInAdvancedViewOnly not present on Deleted Objects container %s" % obj.dn)
            faulty = True
        if "objectCategory" not in obj:
            self.report("ERROR: objectCategory not present on Deleted Objects container %s" % obj.dn)
            faulty = True
        if "isCriticalSystemObject" not in obj or obj['isCriticalSystemObject'][0].upper() == 'FALSE':
            self.report("ERROR: isCriticalSystemObject not present on Deleted Objects container %s" % obj.dn)
            faulty = True
        if "isRecycled" in obj:
            self.report("ERROR: isRecycled present on Deleted Objects container %s" % obj.dn)
            faulty = True
        if "isDeleted" in obj and obj['isDeleted'][0].upper() == 'FALSE':
            self.report("ERROR: isDeleted not set on Deleted Objects container %s" % obj.dn)
            faulty = True
        if "objectClass" not in obj or (len(obj['objectClass']) != 2 or
                                        obj['objectClass'][0] != 'top' or
                                        obj['objectClass'][1] != 'container'):
            self.report("ERROR: objectClass incorrectly set on Deleted Objects container %s" % obj.dn)
            faulty = True
        if "systemFlags" not in obj or obj['systemFlags'][0] != '-1946157056':
            self.report("ERROR: systemFlags incorrectly set on Deleted Objects container %s" % obj.dn)
            faulty = True
        return faulty

    def err_deleted_deleted_objects(self, obj):
        nmsg = ldb.Message()
        nmsg.dn = dn = obj.dn

        if "description" not in obj:
            nmsg["description"] = ldb.MessageElement("Container for deleted objects", ldb.FLAG_MOD_REPLACE, "description")
        if "showInAdvancedViewOnly" not in obj:
            nmsg["showInAdvancedViewOnly"] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_REPLACE, "showInAdvancedViewOnly")
        if "objectCategory" not in obj:
            nmsg["objectCategory"] = ldb.MessageElement("CN=Container,%s" % self.schema_dn, ldb.FLAG_MOD_REPLACE, "objectCategory")
        if "isCriticalSystemObject" not in obj:
            nmsg["isCriticalSystemObject"] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_REPLACE, "isCriticalSystemObject")
        if "isRecycled" in obj:
            nmsg["isRecycled"] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_DELETE, "isRecycled")

        nmsg["isDeleted"] = ldb.MessageElement("TRUE", ldb.FLAG_MOD_REPLACE, "isDeleted")
        nmsg["systemFlags"] = ldb.MessageElement("-1946157056", ldb.FLAG_MOD_REPLACE, "systemFlags")
        nmsg["objectClass"] = ldb.MessageElement(["top", "container"], ldb.FLAG_MOD_REPLACE, "objectClass")

        if not self.confirm_all('Fix Deleted Objects container %s by restoring default attributes?'
                                % (dn), 'fix_deleted_deleted_objects'):
            self.report('Not fixing missing/incorrect attributes on %s\n' % (dn))
            return

        if self.do_modify(nmsg, ["relax:0"],
                          "Failed to fix Deleted Objects container  %s" % dn):
            self.report("Fixed Deleted Objects container '%s'\n" % (dn))

    def err_replica_locations(self, obj, cross_ref, attr):
        nmsg = ldb.Message()
        nmsg.dn = cross_ref
        target = self.samdb.get_dsServiceName()

        if self.samdb.am_rodc():
            self.report('Not fixing %s for the RODC' % (attr, obj.dn))
            return

        if not self.confirm_all('Add yourself to the replica locations for %s?'
                                % (obj.dn), 'fix_replica_locations'):
            self.report('Not fixing missing/incorrect attributes on %s\n' % (obj.dn))
            return

        nmsg[attr] = ldb.MessageElement(target, ldb.FLAG_MOD_ADD, attr)
        if self.do_modify(nmsg, [], "Failed to add %s for %s" % (attr, obj.dn)):
            self.report("Fixed %s for %s" % (attr, obj.dn))

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
            except ldb.LdbError as e4:
                (enum, estr) = e4.args
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

        # If we modify the pass-by-reference attrs variable, then we get a
        # replPropertyMetadata for every object that we check.
        attrs = list(attrs)
        if "dn" in map(str.lower, attrs):
            attrs.append("name")
        if "distinguishedname" in map(str.lower, attrs):
            attrs.append("name")
        if str(dn.get_rdn_name()).lower() in map(str.lower, attrs):
            attrs.append("name")
        if 'name' in map(str.lower, attrs):
            attrs.append(dn.get_rdn_name())
            attrs.append("isDeleted")
            attrs.append("systemFlags")
        need_replPropertyMetaData = False
        if '*' in attrs:
            need_replPropertyMetaData = True
        else:
            for a in attrs:
                linkID, _ = self.get_attr_linkID_and_reverse_name(a)
                if linkID == 0:
                    continue
                if linkID & 1:
                    continue
                need_replPropertyMetaData = True
                break
        if need_replPropertyMetaData:
            attrs.append("replPropertyMetaData")
        attrs.append("objectGUID")

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
                                        "reveal_internals:0",
                                    ],
                                    attrs=attrs)
        except ldb.LdbError as e10:
            (enum, estr) = e10.args
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
        set_attrs_from_md = set()
        set_attrs_seen = set()
        got_repl_property_meta_data = False
        got_objectclass = False

        nc_dn = self.samdb.get_nc_root(obj.dn)
        try:
            deleted_objects_dn = self.samdb.get_wellknown_dn(nc_dn,
                                                             samba.dsdb.DS_GUID_DELETED_OBJECTS_CONTAINER)
        except KeyError:
            # We have no deleted objects DN for schema, and we check for this above for the other
            # NCs
            deleted_objects_dn = None


        object_rdn_attr = None
        object_rdn_val = None
        name_val = None
        isDeleted = False
        systemFlags = 0

        for attrname in obj:
            if attrname == 'dn' or attrname == "distinguishedName":
                continue

            if str(attrname).lower() == 'objectclass':
                got_objectclass = True

            if str(attrname).lower() == "name":
                if len(obj[attrname]) != 1:
                    error_count += 1
                    self.report("ERROR: Not fixing num_values(%d) for '%s' on '%s'" %
                                (len(obj[attrname]), attrname, str(obj.dn)))
                else:
                    name_val = obj[attrname][0]

            if str(attrname).lower() == str(obj.dn.get_rdn_name()).lower():
                object_rdn_attr = attrname
                if len(obj[attrname]) != 1:
                    error_count += 1
                    self.report("ERROR: Not fixing num_values(%d) for '%s' on '%s'" %
                                (len(obj[attrname]), attrname, str(obj.dn)))
                else:
                    object_rdn_val = obj[attrname][0]

            if str(attrname).lower() == 'isdeleted':
                if obj[attrname][0] != "FALSE":
                    isDeleted = True

            if str(attrname).lower() == 'systemflags':
                systemFlags = int(obj[attrname][0])

            if str(attrname).lower() == 'replpropertymetadata':
                if self.has_replmetadata_zero_invocationid(dn, obj[attrname]):
                    error_count += 1
                    self.err_replmetadata_zero_invocationid(dn, attrname, obj[attrname])
                    # We don't continue, as we may also have other fixes for this attribute
                    # based on what other attributes we see.

                try:
                    (set_attrs_from_md, list_attid_from_md, wrong_attids) \
                        = self.process_metadata(dn, obj[attrname])
                except KeyError:
                    error_count += 1
                    self.err_replmetadata_unknown_attid(dn, attrname, obj[attrname])
                    continue

                if len(set_attrs_from_md) < len(list_attid_from_md) \
                   or len(wrong_attids) > 0 \
                   or sorted(list_attid_from_md) != list_attid_from_md:
                    error_count +=1
                    self.err_replmetadata_incorrect_attid(dn, attrname, obj[attrname], wrong_attids)

                else:
                    # Here we check that the first attid is 0
                    # (objectClass).
                    if list_attid_from_md[0] != 0:
                        error_count += 1
                        self.report("ERROR: Not fixing incorrect inital attributeID in '%s' on '%s', it should be objectClass" %
                                    (attrname, str(dn)))

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
                normalised = self.samdb.dsdb_normalise_attributes(self.samdb_schema, attrname, obj[attrname])
                # Do not consider the attribute incorrect if:
                #  - The sorted (alphabetically) list is the same, inclding case
                #  - The first and last elements are the same
                #
                # This avoids triggering an error due to
                # non-determinism in the sort routine in (at least)
                # 4.3 and earlier, and the fact that any AUX classes
                # in these attributes are also not sorted when
                # imported from Windows (they are just in the reverse
                # order of last set)
                if sorted(normalised) != sorted(obj[attrname]) \
                   or normalised[0] != obj[attrname][0] \
                   or normalised[-1] != obj[attrname][-1]:
                    self.err_normalise_mismatch_replace(dn, attrname, list(obj[attrname]))
                    error_count += 1
                continue

            if str(attrname).lower() == 'userparameters':
                if len(obj[attrname][0]) == 1 and obj[attrname][0][0] == '\x20':
                    error_count += 1
                    self.err_short_userParameters(obj, attrname, obj[attrname])
                    continue

                elif obj[attrname][0][:16] == '\x20\x00\x20\x00\x20\x00\x20\x00\x20\x00\x20\x00\x20\x00\x20\x00':
                    # This is the correct, normal prefix
                    continue

                elif obj[attrname][0][:20] == 'IAAgACAAIAAgACAAIAAg':
                    # this is the typical prefix from a windows migration
                    error_count += 1
                    self.err_base64_userParameters(obj, attrname, obj[attrname])
                    continue

                elif obj[attrname][0][1] != '\x00' and obj[attrname][0][3] != '\x00' and obj[attrname][0][5] != '\x00' and obj[attrname][0][7] != '\x00' and obj[attrname][0][9] != '\x00':
                    # This is a prefix that is not in UTF-16 format for the space or munged dialback prefix
                    error_count += 1
                    self.err_utf8_userParameters(obj, attrname, obj[attrname])
                    continue

                elif len(obj[attrname][0]) % 2 != 0:
                    # This is a value that isn't even in length
                    error_count += 1
                    self.err_odd_userParameters(obj, attrname, obj[attrname])
                    continue

                elif obj[attrname][0][1] == '\x00' and obj[attrname][0][2] == '\x00' and obj[attrname][0][3] == '\x00' and obj[attrname][0][4] != '\x00' and obj[attrname][0][5] == '\x00':
                    # This is a prefix that would happen if a SAMR-written value was replicated from a Samba 4.1 server to a working server
                    error_count += 1
                    self.err_doubled_userParameters(obj, attrname, obj[attrname])
                    continue

            if attrname.lower() == 'attributeid' or attrname.lower() == 'governsid':
                if obj[attrname][0] in self.attribute_or_class_ids:
                    error_count += 1
                    self.report('Error: %s %s on %s already exists as an attributeId or governsId'
                                % (attrname, obj.dn, obj[attrname][0]))
                else:
                    self.attribute_or_class_ids.add(obj[attrname][0])

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
            except Exception as msg:
                self.err_unknown_attribute(obj, attrname)
                error_count += 1
                continue

            linkID, reverse_link_name = self.get_attr_linkID_and_reverse_name(attrname)

            flag = self.samdb_schema.get_systemFlags_from_lDAPDisplayName(attrname)
            if (not flag & dsdb.DS_FLAG_ATTR_NOT_REPLICATED
                and not flag & dsdb.DS_FLAG_ATTR_IS_CONSTRUCTED
                and not linkID):
                set_attrs_seen.add(str(attrname).lower())

            if syntax_oid in [ dsdb.DSDB_SYNTAX_BINARY_DN, dsdb.DSDB_SYNTAX_OR_NAME,
                               dsdb.DSDB_SYNTAX_STRING_DN, ldb.SYNTAX_DN ]:
                # it's some form of DN, do specialised checking on those
                error_count += self.check_dn(obj, attrname, syntax_oid)
            else:

                values = set()
                # check for incorrectly normalised attributes
                for val in obj[attrname]:
                    values.add(str(val))

                    normalised = self.samdb.dsdb_normalise_attributes(self.samdb_schema, attrname, [val])
                    if len(normalised) != 1 or normalised[0] != val:
                        self.err_normalise_mismatch(dn, attrname, obj[attrname])
                        error_count += 1
                        break

                if len(obj[attrname]) != len(values):
                    self.err_duplicate_values(dn, attrname, obj[attrname], list(values))
                    error_count += 1
                    break

            if str(attrname).lower() == "instancetype":
                calculated_instancetype = self.calculate_instancetype(dn)
                if len(obj["instanceType"]) != 1 or obj["instanceType"][0] != str(calculated_instancetype):
                    error_count += 1
                    self.err_wrong_instancetype(obj, calculated_instancetype)

        if not got_objectclass and ("*" in attrs or "objectclass" in map(str.lower, attrs)):
            error_count += 1
            self.err_missing_objectclass(dn)

        if ("*" in attrs or "name" in map(str.lower, attrs)):
            if name_val is None:
                error_count += 1
                self.report("ERROR: Not fixing missing 'name' on '%s'" % (str(obj.dn)))
            if object_rdn_attr is None:
                error_count += 1
                self.report("ERROR: Not fixing missing '%s' on '%s'" % (obj.dn.get_rdn_name(), str(obj.dn)))

        if name_val is not None:
            parent_dn = None
            if isDeleted:
                if not (systemFlags & samba.dsdb.SYSTEM_FLAG_DISALLOW_MOVE_ON_DELETE):
                    parent_dn = deleted_objects_dn
            if parent_dn is None:
                parent_dn = obj.dn.parent()
            expected_dn = ldb.Dn(self.samdb, "RDN=RDN,%s" % (parent_dn))
            expected_dn.set_component(0, obj.dn.get_rdn_name(), name_val)

            if obj.dn == deleted_objects_dn:
                expected_dn = obj.dn

            if expected_dn != obj.dn:
                error_count += 1
                self.err_wrong_dn(obj, expected_dn, object_rdn_attr, object_rdn_val, name_val)
            elif obj.dn.get_rdn_value() != object_rdn_val:
                error_count += 1
                self.report("ERROR: Not fixing %s=%r on '%s'" % (object_rdn_attr, object_rdn_val, str(obj.dn)))

        show_dn = True
        if got_repl_property_meta_data:
            if obj.dn == deleted_objects_dn:
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

            for att in set_attrs_seen.difference(set_attrs_from_md):
                if show_dn:
                    self.report("On object %s" % dn)
                    show_dn = False
                error_count += 1
                self.report("ERROR: Attribute %s not present in replication metadata" % att)
                if not self.confirm_all("Fix missing replPropertyMetaData element '%s'" % att, 'fix_all_metadata'):
                    self.report("Not fixing missing replPropertyMetaData element '%s'" % att)
                    continue
                self.fix_metadata(obj, att)

        if self.is_fsmo_role(dn):
            if "fSMORoleOwner" not in obj and ("*" in attrs or "fsmoroleowner" in map(str.lower, attrs)):
                self.err_no_fsmoRoleOwner(obj)
                error_count += 1

        try:
            if dn != self.samdb.get_root_basedn() and str(dn.parent()) not in self.dn_set:
                res = self.samdb.search(base=dn.parent(), scope=ldb.SCOPE_BASE,
                                        controls=["show_recycled:1", "show_deleted:1"])
        except ldb.LdbError as e11:
            (enum, estr) = e11.args
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                self.err_missing_parent(obj)
                error_count += 1
            else:
                raise

        if dn in self.deleted_objects_containers and '*' in attrs:
            if self.is_deleted_deleted_objects(obj):
                self.err_deleted_deleted_objects(obj)
                error_count += 1

        for (dns_part, msg) in self.dns_partitions:
            if dn == dns_part and 'repsFrom' in obj:
                location = "msDS-NC-Replica-Locations"
                if self.samdb.am_rodc():
                    location = "msDS-NC-RO-Replica-Locations"

                if location not in msg:
                    # There are no replica locations!
                    self.err_replica_locations(obj, msg.dn, location)
                    error_count += 1
                    continue

                found = False
                for loc in msg[location]:
                    if loc == self.samdb.get_dsServiceName():
                        found = True
                if not found:
                    # This DC is not in the replica locations
                    self.err_replica_locations(obj, msg.dn, location)
                    error_count += 1

        if dn == self.server_ref_dn:
            # Check we have a valid RID Set
            if "*" in attrs or "rIDSetReferences" in attrs:
                if "rIDSetReferences" not in obj:
                    # NO RID SET reference
                    # We are RID master, allocate it.
                    error_count += 1

                    if self.is_rid_master:
                        # Allocate a RID Set
                        if self.confirm_all('Allocate the missing RID set for RID master?',
                                            'fix_missing_rid_set_master'):

                            # We don't have auto-transaction logic on
                            # extended operations, so we have to do it
                            # here.

                            self.samdb.transaction_start()

                            try:
                                self.samdb.create_own_rid_set()

                            except:
                                self.samdb.transaction_cancel()
                                raise

                            self.samdb.transaction_commit()


                    elif not self.samdb.am_rodc():
                        self.report("No RID Set found for this server: %s, and we are not the RID Master (so can not self-allocate)" % dn)


        # Check some details of our own RID Set
        if dn == self.rid_set_dn:
            res = self.samdb.search(base=self.rid_set_dn, scope=ldb.SCOPE_BASE,
                                    attrs=["rIDAllocationPool",
                                           "rIDPreviousAllocationPool",
                                           "rIDUsedPool",
                                           "rIDNextRID"])
            if "rIDAllocationPool" not in res[0]:
                self.report("No rIDAllocationPool found in %s" % dn)
                error_count += 1
            else:
                next_pool = int(res[0]["rIDAllocationPool"][0])

                high = (0xFFFFFFFF00000000 & next_pool) >> 32
                low = 0x00000000FFFFFFFF & next_pool

                if high <= low:
                    self.report("Invalid RID set %d-%s, %d > %d!" % (low, high, low, high))
                    error_count += 1

                if "rIDNextRID" in res[0]:
                    next_free_rid = int(res[0]["rIDNextRID"][0])
                else:
                    next_free_rid = 0

                if next_free_rid == 0:
                    next_free_rid = low
                else:
                    next_free_rid += 1

                # Check the remainder of this pool for conflicts.  If
                # ridalloc_allocate_rid() moves to a new pool, this
                # will be above high, so we will stop.
                while next_free_rid <= high:
                    sid = "%s-%d" % (self.samdb.get_domain_sid(), next_free_rid)
                    try:
                        res = self.samdb.search(base="<SID=%s>" % sid, scope=ldb.SCOPE_BASE,
                                                attrs=[])
                    except ldb.LdbError as e:
                        (enum, estr) = e.args
                        if enum != ldb.ERR_NO_SUCH_OBJECT:
                            raise
                        res = None
                    if res is not None:
                        self.report("SID %s for %s conflicts with our current RID set in %s" % (sid, res[0].dn, dn))
                        error_count += 1

                        if self.confirm_all('Fix conflict between SID %s and RID pool in %s by allocating a new RID?'
                                            % (sid, dn),
                                            'fix_sid_rid_set_conflict'):
                            self.samdb.transaction_start()

                            # This will burn RIDs, which will move
                            # past the conflict.  We then check again
                            # to see if the new RID conflicts, until
                            # the end of the current pool.  We don't
                            # look at the next pool to avoid burning
                            # all RIDs in one go in some strange
                            # failure case.
                            try:
                                while True:
                                    allocated_rid = self.samdb.allocate_rid()
                                    if allocated_rid >= next_free_rid:
                                        next_free_rid = allocated_rid + 1
                                        break
                            except:
                                self.samdb.transaction_cancel()
                                raise

                            self.samdb.transaction_commit()
                        else:
                            break
                    else:
                        next_free_rid += 1


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
