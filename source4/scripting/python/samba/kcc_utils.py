#!/usr/bin/env python
#
# KCC topology utilities
#
# Copyright (C) Dave Craft 2011
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

import samba, ldb
import uuid

from samba              import dsdb
from samba.dcerpc       import misc
from samba.common       import dsdb_Dn

class NCType:
    (unknown, schema, domain, config, application) = range(0, 5)

class NamingContext:
    """Base class for a naming context.  Holds the DN,
       GUID, SID (if available) and type of the DN.
       Subclasses may inherit from this and specialize
    """

    def __init__(self, nc_dnstr, nc_guid=None, nc_sid=None):
        """Instantiate a NamingContext
            :param nc_dnstr: NC dn string
            :param nc_guid: NC guid string
            :param nc_sid: NC sid
        """
        self.nc_dnstr = nc_dnstr
        self.nc_guid  = nc_guid
        self.nc_sid   = nc_sid
        self.nc_type  = NCType.unknown
        return

    def __str__(self):
        '''Debug dump string output of class'''
        return "%s:\n\tdn=%s\n\tguid=%s\n\ttype=%s" % \
               (self.__class__.__name__, self.nc_dnstr,
                self.nc_guid, self.nc_type)

    def is_schema(self):
        '''Return True if NC is schema'''
        return self.nc_type == NCType.schema

    def is_domain(self):
        '''Return True if NC is domain'''
        return self.nc_type == NCType.domain

    def is_application(self):
        '''Return True if NC is application'''
        return self.nc_type == NCType.application

    def is_config(self):
        '''Return True if NC is config'''
        return self.nc_type == NCType.config

    def identify_by_basedn(self, samdb):
        """Given an NC object, identify what type is is thru
           the samdb basedn strings and NC sid value
        """
        # We check against schema and config because they
        # will be the same for all nTDSDSAs in the forest.
        # That leaves the domain NCs which can be identified
        # by sid and application NCs as the last identified
        if self.nc_dnstr == str(samdb.get_schema_basedn()):
            self.nc_type = NCType.schema
        elif self.nc_dnstr == str(samdb.get_config_basedn()):
            self.nc_type = NCType.config
        elif self.nc_sid != None:
            self.nc_type = NCType.domain
        else:
            self.nc_type = NCType.application
        return

    def identify_by_dsa_attr(self, samdb, attr):
        """Given an NC which has been discovered thru the
           nTDSDSA database object, determine what type of NC
           it is (i.e. schema, config, domain, application) via
           the use of the schema attribute under which the NC
           was found.
            :param attr: attr of nTDSDSA object where NC DN appears
        """
        # If the NC is listed under msDS-HasDomainNCs then
        # this can only be a domain NC and it is our default
        # domain for this dsa
        if attr == "msDS-HasDomainNCs":
            self.nc_type = NCType.domain

        # If the NC is listed under hasPartialReplicaNCs
        # this is only a domain NC
        elif attr == "hasPartialReplicaNCs":
            self.nc_type = NCType.domain

        # NCs listed under hasMasterNCs are either
        # default domain, schema, or config.  We
        # utilize the identify_by_samdb_basedn() to
        # identify those
        elif attr == "hasMasterNCs":
            self.identify_by_basedn(samdb)

        # Still unknown (unlikely) but for completeness
        # and for finally identifying application NCs
        if self.nc_type == NCType.unknown:
            self.identify_by_basedn(samdb)

        return


class NCReplica(NamingContext):
    """Class defines a naming context replica that is relative
       to a specific DSA.  This is a more specific form of
       NamingContext class (inheriting from that class) and it
       identifies unique attributes of the DSA's replica for a NC.
    """

    def __init__(self, dsa_dnstr, dsa_guid, nc_dnstr, \
                 nc_guid=None, nc_sid=None):
        """Instantiate a Naming Context Replica
            :param dsa_guid: GUID of DSA where replica appears
            :param nc_dnstr: NC dn string
            :param nc_guid: NC guid string
            :param nc_sid: NC sid
        """
        self.rep_dsa_dnstr = dsa_dnstr
        self.rep_dsa_guid  = dsa_guid # GUID of DSA where this appears
        self.rep_default   = False # replica for DSA's default domain
        self.rep_partial   = False
        self.rep_ro        = False
        self.rep_flags     = 0

        # The (is present) test is a combination of being
        # enumerated in (hasMasterNCs or msDS-hasFullReplicaNCs or
        # hasPartialReplicaNCs) as well as its replica flags found
        # thru the msDS-HasInstantiatedNCs.  If the NC replica meets
        # the first enumeration test then this flag is set true
        self.rep_present_criteria_one = False

        # Call my super class we inherited from
        NamingContext.__init__(self, nc_dnstr, nc_guid, nc_sid)
        return

    def __str__(self):
        '''Debug dump string output of class'''
        text = "default=%s"  % self.rep_default + \
               ":ro=%s"      % self.rep_ro      + \
               ":partial=%s" % self.rep_partial + \
               ":present=%s" % self.is_present()
        return "%s\n\tdsaguid=%s\n\t%s" % \
               (NamingContext.__str__(self), self.rep_dsa_guid, text)

    def set_replica_flags(self, flags=None):
        '''Set or clear NC replica flags'''
        if (flags == None):
            self.rep_flags = 0
        else:
            self.rep_flags = flags
        return

    def identify_by_dsa_attr(self, samdb, attr):
        """Given an NC which has been discovered thru the
           nTDSDSA database object, determine what type of NC
           replica it is (i.e. partial, read only, default)
            :param attr: attr of nTDSDSA object where NC DN appears
        """
        # If the NC was found under hasPartialReplicaNCs
        # then a partial replica at this dsa
        if attr == "hasPartialReplicaNCs":
            self.rep_partial = True
            self.rep_present_criteria_one = True

        # If the NC is listed under msDS-HasDomainNCs then
        # this can only be a domain NC and it is the DSA's
        # default domain NC
        elif attr == "msDS-HasDomainNCs":
            self.rep_default = True

        # NCs listed under hasMasterNCs are either
        # default domain, schema, or config.  We check
        # against schema and config because they will be
        # the same for all nTDSDSAs in the forest.  That
        # leaves the default domain NC remaining which
        # may be different for each nTDSDSAs (and thus
        # we don't compare agains this samdb's default
        # basedn
        elif attr == "hasMasterNCs":
            self.rep_present_criteria_one = True

            if self.nc_dnstr != str(samdb.get_schema_basedn()) and \
               self.nc_dnstr != str(samdb.get_config_basedn()):
                self.rep_default = True

        # RODC only
        elif attr == "msDS-hasFullReplicaNCs":
            self.rep_present_criteria_one = True
            self.rep_ro = True

        # Not RODC
        elif attr == "msDS-hasMasterNCs":
            self.rep_ro = False

        # Now use this DSA attribute to identify the naming
        # context type by calling the super class method
        # of the same name
        NamingContext.identify_by_dsa_attr(self, samdb, attr)
        return

    def is_default(self):
        """Returns True if this is a default domain NC for the dsa
           that this NC appears on
        """
        return self.rep_default

    def is_ro(self):
        '''Return True if NC replica is read only'''
        return self.rep_ro

    def is_partial(self):
        '''Return True if NC replica is partial'''
        return self.rep_partial

    def is_present(self):
        """Given an NC replica which has been discovered thru the
           nTDSDSA database object and populated with replica flags
           from the msDS-HasInstantiatedNCs; return whether the NC
           replica is present (true) or if the IT_NC_GOING flag is
           set then the NC replica is not present (false)
        """
        if self.rep_present_criteria_one and \
           self.rep_flags & dsdb.INSTANCE_TYPE_NC_GOING == 0:
            return True
        return False


class DirectoryServiceAgent:

    def __init__(self, dsa_dnstr):
        """Initialize DSA class.  Class is subsequently
           fully populated by calling the load_dsa() method
           :param dsa_dnstr:  DN of the nTDSDSA
        """
        self.dsa_dnstr     = dsa_dnstr
        self.dsa_guid      = None
        self.dsa_ivid      = None
        self.dsa_is_ro     = False
        self.dsa_is_gc     = False
        self.dsa_behavior  = 0
        self.default_dnstr = None  # default domain dn string for dsa

        # NCReplicas for this dsa.
        # Indexed by DN string of naming context
        self.rep_table     = {}

        # NTDSConnections for this dsa.
        # Indexed by DN string of connection
        self.connect_table = {}
        return

    def __str__(self):
        '''Debug dump string output of class'''
        text = ""
        if self.dsa_dnstr:
            text = text + "\n\tdn=%s"   % self.dsa_dnstr
        if self.dsa_guid:
            text = text + "\n\tguid=%s" % str(self.dsa_guid)
        if self.dsa_ivid:
            text = text + "\n\tivid=%s" % str(self.dsa_ivid)

        text = text + "\n\tro=%s:gc=%s" % (self.dsa_is_ro, self.dsa_is_gc)
        return "%s:%s\n%s\n%s" % (self.__class__.__name__, text,
                                  self.dumpstr_replica_table(),
                                  self.dumpstr_connect_table())

    def is_ro(self):
        '''Returns True if dsa a read only domain controller'''
        return self.dsa_is_ro

    def is_gc(self):
        '''Returns True if dsa hosts a global catalog'''
        return self.dsa_is_gc

    def is_minimum_behavior(self, version):
        """Is dsa at minimum windows level greater than or
           equal to (version)
           :param version: Windows version to test against
                          (e.g. DS_BEHAVIOR_WIN2008)
        """
        if self.dsa_behavior >= version:
            return True
        return False

    def load_dsa(self, samdb):
        """Method to load a DSA from the samdb.  Prior initialization
           has given us the DN of the DSA that we are to load.  This
           method initializes all other attributes, including loading
           the NC replica table for this DSA.
           Raises an Exception on error.
        """
        controls = [ "extended_dn:1:1" ]
        attrs    = [ "objectGUID",
                     "invocationID",
                     "options",
                     "msDS-isRODC",
                     "msDS-Behavior-Version" ]
        try:
            res = samdb.search(base=self.dsa_dnstr, scope=ldb.SCOPE_BASE,
                               attrs=attrs, controls=controls)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find nTDSDSA for (%s) - (%s)" % \
                            (self.dsa_dnstr, estr))
            return

        msg = res[0]
        self.dsa_guid = misc.GUID(samdb.schema_format_value("objectGUID",
                                  msg["objectGUID"][0]))

        # RODCs don't originate changes and thus have no invocationId,
        # therefore we must check for existence first
        if "invocationId" in msg:
            self.dsa_ivid = misc.GUID(samdb.schema_format_value("objectGUID",
                                      msg["invocationId"][0]))

        if "options" in msg and \
            ((int(msg["options"][0]) & dsdb.DS_NTDSDSA_OPT_IS_GC) != 0):
            self.dsa_is_gc = True
        else:
            self.dsa_is_gc = False

        if "msDS-isRODC" in msg and msg["msDS-isRODC"][0] == "TRUE":
            self.dsa_is_ro = True
        else:
            self.dsa_is_ro = False

        if "msDS-Behavior-Version" in msg:
            self.dsa_behavior = int(msg['msDS-Behavior-Version'][0])

        # Load the NC replicas that are enumerated on this dsa
        self.load_replica_table(samdb)

        # Load the nTDSConnection that are enumerated on this dsa
        self.load_connection_table(samdb)

        return


    def load_replica_table(self, samdb):
        """Method to load the NC replica's listed for DSA object. This
           method queries the samdb for (hasMasterNCs, msDS-hasMasterNCs,
           hasPartialReplicaNCs, msDS-HasDomainNCs, msDS-hasFullReplicaNCs,
           and msDS-HasInstantiatedNCs) to determine complete list of
           NC replicas that are enumerated for the DSA.  Once a NC
           replica is loaded it is identified (schema, config, etc) and
           the other replica attributes (partial, ro, etc) are determined.
           Raises an Exception on error.
           :param samdb: database to query for DSA replica list
        """
        controls = ["extended_dn:1:1"]
        ncattrs = [ # not RODC - default, config, schema (old style)
                    "hasMasterNCs",
                    # not RODC - default, config, schema, app NCs
                    "msDS-hasMasterNCs",
                    # domain NC partial replicas
                    "hasPartialReplicANCs",
                    # default domain NC
                    "msDS-HasDomainNCs",
                    # RODC only - default, config, schema, app NCs
                    "msDS-hasFullReplicaNCs",
                    # Identifies if replica is coming, going, or stable
                    "msDS-HasInstantiatedNCs" ]
        try:
            res = samdb.search(base=self.dsa_dnstr, scope=ldb.SCOPE_BASE,
                               attrs=ncattrs, controls=controls)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find nTDSDSA NCs for (%s) - (%s)" % \
                            (self.dsa_dnstr, estr))
            return

        # The table of NCs for the dsa we are searching
        tmp_table = {}

        # We should get one response to our query here for
        # the ntds that we requested
        if len(res[0]) > 0:

            # Our response will contain a number of elements including
            # the dn of the dsa as well as elements for each
            # attribute (e.g. hasMasterNCs).  Each of these elements
            # is a dictonary list which we retrieve the keys for and
            # then iterate over them
            for k in res[0].keys():
                if k == "dn":
                    continue

                # For each attribute type there will be one or more DNs
                # listed.  For instance DCs normally have 3 hasMasterNCs
                # listed.
                for value in res[0][k]:
                    # Turn dn into a dsdb_Dn so we can use
                    # its methods to parse the extended pieces.
                    # Note we don't really need the exact sid value
                    # but instead only need to know if its present.
                    dsdn  = dsdb_Dn(samdb, value)
                    guid  = dsdn.dn.get_extended_component('GUID')
                    sid   = dsdn.dn.get_extended_component('SID')
                    flags = dsdn.get_binary_integer()
                    dnstr = str(dsdn.dn)

                    if guid is None:
                        raise Exception("Missing GUID for (%s) - (%s: %s)" % \
                                        (self.dsa_dnstr, k, value))
                    else:
                        guidstr = str(misc.GUID(guid))

                    if not dnstr in tmp_table:
                        rep = NCReplica(self.dsa_dnstr, self.dsa_guid,
                                        dnstr, guidstr, sid)
                        tmp_table[dnstr] = rep
                    else:
                        rep = tmp_table[dnstr]

                    if k == "msDS-HasInstantiatedNCs":
                        rep.set_replica_flags(flags)
                        continue

                    rep.identify_by_dsa_attr(samdb, k)

                    # if we've identified the default domain NC
                    # then save its DN string
                    if rep.is_default():
                       self.default_dnstr = dnstr
        else:
            raise Exception("No nTDSDSA NCs for (%s)" % self.dsa_dnstr)
            return

        # Assign our newly built NC replica table to this dsa
        self.rep_table = tmp_table
        return

    def load_connection_table(self, samdb):
        """Method to load the nTDSConnections listed for DSA object.
           Raises an Exception on error.
           :param samdb: database to query for DSA connection list
        """
        try:
            res = samdb.search(base=self.dsa_dnstr,
                               scope=ldb.SCOPE_SUBTREE,
                               expression="(objectClass=nTDSConnection)")

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find nTDSConnection for (%s) - (%s)" % \
                            (self.dsa_dnstr, estr))
            return

        for msg in res:
            dnstr = str(msg.dn)

            # already loaded
            if dnstr in self.connect_table.keys():
                continue

            connect = NTDSConnection(dnstr)

            connect.load_connection(samdb)
            self.connect_table[dnstr] = connect
        return

    def commit_connection_table(self, samdb):
        """Method to commit any uncommitted nTDSConnections
           that are in our table.  These would be newly identified
           connections that are marked as (committed = False)
           :param samdb: database to commit DSA connection list to
        """
        for dnstr, connect in self.connect_table.items():
            connect.commit_connection(samdb)

    def add_connection_by_dnstr(self, dnstr, connect):
        self.connect_table[dnstr] = connect
        return

    def get_connection_by_from_dnstr(self, from_dnstr):
        """Scan DSA nTDSConnection table and return connection
           with a "fromServer" dn string equivalent to method
           input parameter.
           :param from_dnstr: search for this from server entry
        """
        for dnstr, connect in self.connect_table.items():
            if connect.get_from_dnstr() == from_dnstr:
                return connect
        return None

    def dumpstr_replica_table(self):
        '''Debug dump string output of replica table'''
        text=""
        for k in self.rep_table.keys():
            if text:
                text = text + "\n%s" % self.rep_table[k]
            else:
                text = "%s" % self.rep_table[k]
        return text

    def dumpstr_connect_table(self):
        '''Debug dump string output of connect table'''
        text=""
        for k in self.connect_table.keys():
            if text:
                text = text + "\n%s" % self.connect_table[k]
            else:
                text = "%s" % self.connect_table[k]
        return text

class NTDSConnection():
    """Class defines a nTDSConnection found under a DSA
    """
    def __init__(self, dnstr):
        self.dnstr       = dnstr
        self.enabled     = False
        self.committed   = False # appears in database
        self.options     = 0
        self.flags       = 0
        self.from_dnstr  = None
        self.schedulestr = None
        return

    def __str__(self):
        '''Debug dump string output of NTDSConnection object'''
        text = "%s: %s" % (self.__class__.__name__, self.dnstr)
        text = text + "\n\tenabled: %s" % self.enabled
        text = text + "\n\tcommitted: %s" % self.committed
        text = text + "\n\toptions: 0x%08X" % self.options
        text = text + "\n\tflags: 0x%08X" % self.flags
        text = text + "\n\tfrom_dn: %s" % self.from_dnstr
        return text

    def load_connection(self, samdb):
        """Given a NTDSConnection object with an prior initialization
           for the object's DN, search for the DN and load attributes
           from the samdb.
           Raises an Exception on error.
        """
        attrs = [ "options",
                  "enabledConnection",
                  "schedule",
                  "fromServer",
                  "systemFlags" ]
        try:
            res = samdb.search(base=self.dnstr, scope=ldb.SCOPE_BASE,
                               attrs=attrs)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find nTDSConnection for (%s) - (%s)" % \
                            (self.dnstr, estr))
            return

        msg = res[0]

        if "options" in msg:
            self.options = int(msg["options"][0])
        if "enabledConnection" in msg:
            if msg["enabledConnection"][0].upper().lstrip().rstrip() == "TRUE":
                self.enabled = True
        if "systemFlags" in msg:
            self.flags = int(msg["systemFlags"][0])
        if "schedule" in msg:
            self.schedulestr = msg["schedule"][0]
        if "fromServer" in msg:
            dsdn = dsdb_Dn(samdb, msg["fromServer"][0])
            self.from_dnstr = str(dsdn.dn)
            assert self.from_dnstr != None

        # Appears as committed in the database
        self.committed = True
        return

    def commit_connection(self, samdb):
        """Given a NTDSConnection object that is not committed in the
           sam database, perform a commit action.
        """
        if self.committed: # nothing to do
            return

        # XXX - not yet written
        return

    def get_from_dnstr(self):
        '''Return fromServer dn string attribute'''
        return self.from_dnstr

class Partition(NamingContext):
    """Class defines a naming context discovered thru the
       Partitions DN of the configuration schema.  This is
       a more specific form of NamingContext class (inheriting
       from that class) and it identifies unique attributes
       enumerated in the Partitions such as which nTDSDSAs
       are cross referenced for replicas
    """
    def __init__(self, partstr):
        self.partstr          = partstr
        self.rw_location_list = []
        self.ro_location_list = []

        # We don't have enough info to properly
        # fill in the naming context yet.  We'll get that
        # fully set up with load_partition().
        NamingContext.__init__(self, None)


    def load_partition(self, samdb):
        """Given a Partition class object that has been initialized
           with its partition dn string, load the partition from the
           sam database, identify the type of the partition (schema,
           domain, etc) and record the list of nTDSDSAs that appear
           in the cross reference attributes msDS-NC-Replica-Locations
           and msDS-NC-RO-Replica-Locations.
           Raises an Exception on error.
           :param samdb: sam database to load partition from
        """
        controls = ["extended_dn:1:1"]
        attrs = [ "nCName",
                  "msDS-NC-Replica-Locations",
                  "msDS-NC-RO-Replica-Locations" ]
        try:
            res = samdb.search(base=self.partstr, scope=ldb.SCOPE_BASE,
                               attrs=attrs, controls=controls)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find partition for (%s) - (%s)" % (
                            self.partstr, estr))
            return

        msg = res[0]
        for k in msg.keys():
            if k == "dn":
                continue

            for value in msg[k]:
                # Turn dn into a dsdb_Dn so we can use
                # its methods to parse the extended pieces.
                # Note we don't really need the exact sid value
                # but instead only need to know if its present.
                dsdn  = dsdb_Dn(samdb, value)
                guid  = dsdn.dn.get_extended_component('GUID')
                sid   = dsdn.dn.get_extended_component('SID')

                if guid is None:
                    raise Exception("Missing GUID for (%s) - (%s: %s)" % \
                                    (self.partstr, k, value))
                else:
                    guidstr = str(misc.GUID(guid))

                if k == "nCName":
                    self.nc_dnstr = str(dsdn.dn)
                    self.nc_guid  = guidstr
                    self.nc_sid   = sid
                    continue

                if k == "msDS-NC-Replica-Locations":
                    self.rw_location_list.append(str(dsdn.dn))
                    continue

                if k == "msDS-NC-RO-Replica-Locations":
                    self.ro_location_list.append(str(dsdn.dn))
                    continue

        # Now identify what type of NC this partition
        # enumerated
        self.identify_by_basedn(samdb)

        return

    def should_be_present(self, target_dsa):
        """Tests whether this partition should have an NC replica
           on the target dsa.  This method returns a tuple of
           needed=True/False, ro=True/False, partial=True/False
           :param target_dsa: should NC be present on target dsa
        """
        needed  = False
        ro      = False
        partial = False

        # If this is the config, schema, or default
        # domain NC for the target dsa then it should
        # be present
        if self.nc_type == NCType.config or \
           self.nc_type == NCType.schema or \
           (self.nc_type == NCType.domain and \
            self.nc_dnstr == target_dsa.default_dnstr):
            needed = True

        # A writable replica of an application NC should be present
        # if there a cross reference to the target DSA exists.  Depending
        # on whether the DSA is ro we examine which type of cross reference
        # to look for (msDS-NC-Replica-Locations or
        # msDS-NC-RO-Replica-Locations
        if self.nc_type == NCType.application:
            if target_dsa.is_ro():
               if target_dsa.dsa_dnstr in self.ro_location_list:
                   needed = True
            else:
               if target_dsa.dsa_dnstr in self.rw_location_list:
                   needed = True

        # If the target dsa is a gc then a partial replica of a
        # domain NC (other than the DSAs default domain) should exist
        # if there is also a cross reference for the DSA
        if target_dsa.is_gc() and \
           self.nc_type == NCType.domain and \
           self.nc_dnstr != target_dsa.default_dnstr and \
           (target_dsa.dsa_dnstr in self.ro_location_list or \
            target_dsa.dsa_dnstr in self.rw_location_list):
            needed  = True
            partial = True

        # partial NCs are always readonly
        if needed and (target_dsa.is_ro() or partial):
            ro = True

        return needed, ro, partial

    def __str__(self):
        '''Debug dump string output of class'''
        text = "%s" % NamingContext.__str__(self)
        text = text + "\n\tpartdn=%s" % self.partstr
        for k in self.rw_location_list:
            text = text + "\n\tmsDS-NC-Replica-Locations=%s" % k
        for k in self.ro_location_list:
            text = text + "\n\tmsDS-NC-RO-Replica-Locations=%s" % k
        return text

class Site:
    def __init__(self, site_dnstr):
        self.site_dnstr   = site_dnstr
        self.site_options = 0
        return

    def load_site(self, samdb):
        """Loads the NTDS Site Settions options attribute for the site
           Raises an Exception on error.
        """
        ssdn = "CN=NTDS Site Settings,%s" % self.site_dnstr
        try:
            res = samdb.search(base=ssdn, scope=ldb.SCOPE_BASE,
                               attrs=["options"])
        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find site settings for (%s) - (%s)" % \
                            (ssdn, estr))
            return

        msg = res[0]
        if "options" in msg:
            self.site_options = int(msg["options"][0])
        return

    def is_same_site(self, target_dsa):
        '''Determine if target dsa is in this site'''
        if self.site_dnstr in target_dsa.dsa_dnstr:
            return True
        return False

    def is_intrasite_topology_disabled(self):
        '''Returns True if intrasite topology is disabled for site'''
        if (self.site_options & \
            dsdb.DS_NTDSSETTINGS_OPT_IS_AUTO_TOPOLOGY_DISABLED) != 0:
            return True
        return False

    def should_detect_stale(self):
        '''Returns True if detect stale is enabled for site'''
        if (self.site_options & \
            dsdb.DS_NTDSSETTINGS_OPT_IS_TOPL_DETECT_STALE_DISABLED) == 0:
            return True
        return False


class GraphNode:
    """This is a graph node describing a set of edges that should be
       directed to it.  Each edge is a connection for a particular
       naming context replica directed from another node in the forest
       to this node.
    """
    def __init__(self, dsa_dnstr, max_node_edges):
        """Instantiate the graph node according to a DSA dn string
           :param max_node_edges: maximum number of edges that should ever
                                  be directed to the node
        """
        self.max_edges = max_node_edges
        self.dsa_dnstr = dsa_dnstr
        self.edge_from = []

    def __str__(self):
        text = "%s: %s" % (self.__class__.__name__, self.dsa_dnstr)
        for edge in self.edge_from:
            text = text + "\n\tedge from: %s" % edge
        return text

    def add_edge_from(self, from_dsa_dnstr):
        """Add an edge from the dsa to our graph nodes edge from list
           :param from_dsa_dnstr: the dsa that the edge emanates from
        """
        assert from_dsa_dnstr != None

        # No edges from myself to myself
        if from_dsa_dnstr == self.dsa_dnstr:
            return False
        # Only one edge from a particular node
        if from_dsa_dnstr in self.edge_from:
            return False
        # Not too many edges
        if len(self.edge_from) >= self.max_edges:
            return False
        self.edge_from.append(from_dsa_dnstr)
        return True

    def add_edges_from_connections(self, dsa):
        """For each nTDSConnection object associated with a particular
           DSA, we test if it implies an edge to this graph node (i.e.
           the "fromServer" attribute).  If it does then we add an
           edge from the server unless we are over the max edges for this
           graph node
           :param dsa: dsa with a dnstr equivalent to his graph node
        """
        for dnstr, connect in dsa.connect_table.items():
            self.add_edge_from(connect.from_dnstr)
        return

    def add_connections_from_edges(self, dsa):
        """For each edge directed to this graph node, ensure there
           is a corresponding nTDSConnection object in the dsa.
        """
        for edge_dnstr in self.edge_from:
            connect = dsa.get_connection_by_from_dnstr(edge_dnstr)

            # For each edge directed to the NC replica that
            # "should be present" on the local DC, the KCC determines
            # whether an object c exists such that:
            #
            #    c is a child of the DC's nTDSDSA object.
            #    c.objectCategory = nTDSConnection
            #
            # Given the NC replica ri from which the edge is directed,
            #    c.fromServer is the dsname of the nTDSDSA object of
            #    the DC on which ri "is present".
            #
            #    c.options does not contain NTDSCONN_OPT_RODC_TOPOLOGY
            if connect and \
               connect.options & dsdb.NTDSCONN_OPT_RODC_TOPOLOGY == 0:
                exists = True
            else:
                exists = False

            # if no such object exists then the KCC adds an object
            # c with the following attributes
            if exists:
                return

            # Generate a new dnstr for this nTDSConnection
            dnstr = "CN=%s," % str(uuid.uuid4()) + self.dsa_dnstr

            connect = NTDSConnection(dnstr)
            connect.enabled    = True
            connect.committed  = False
            connect.from_dnstr = edge_dnstr
            connect.options    = dsdb.NTDSCONN_OPT_IS_GENERATED
            connect.flags      = dsdb.SYSTEM_FLAG_CONFIG_ALLOW_RENAME + \
                                 dsdb.SYSTEM_FLAG_CONFIG_ALLOW_MOVE

            # XXX I need to write the schedule blob

            dsa.add_connection_by_dnstr(dnstr, connect);

        return

    def has_sufficient_edges(self):
        '''Return True if we have met the maximum "from edges" criteria'''
        if len(self.edge_from) >= self.max_edges:
            return True
        return False
