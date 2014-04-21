# KCC topology utilities
#
# Copyright (C) Dave Craft 2011
# Copyright (C) Jelmer Vernooij 2011
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

import ldb
import uuid
import time

from samba import dsdb, unix2nttime
from samba.dcerpc import (
    drsblobs,
    drsuapi,
    misc,
    )
from samba.common import dsdb_Dn
from samba.ndr import (ndr_unpack, ndr_pack)


class NCType(object):
    (unknown, schema, domain, config, application) = range(0, 5)


class NamingContext(object):
    """Base class for a naming context.

    Holds the DN, GUID, SID (if available) and type of the DN.
    Subclasses may inherit from this and specialize
    """

    def __init__(self, nc_dnstr):
        """Instantiate a NamingContext

        :param nc_dnstr: NC dn string
        """
        self.nc_dnstr = nc_dnstr
        self.nc_guid = None
        self.nc_sid = None
        self.nc_type = NCType.unknown

    def __str__(self):
        '''Debug dump string output of class'''
        text = "%s:" % self.__class__.__name__
        text = text + "\n\tnc_dnstr=%s" % self.nc_dnstr
        text = text + "\n\tnc_guid=%s"  % str(self.nc_guid)

        if self.nc_sid is None:
            text = text + "\n\tnc_sid=<absent>"
        else:
            text = text + "\n\tnc_sid=<present>"

        text = text + "\n\tnc_type=%s"  % self.nc_type
        return text

    def load_nc(self, samdb):
        attrs = [ "objectGUID",
                  "objectSid" ]
        try:
            res = samdb.search(base=self.nc_dnstr,
                               scope=ldb.SCOPE_BASE, attrs=attrs)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find naming context (%s)" %
                            (self.nc_dnstr, estr))
        msg = res[0]
        if "objectGUID" in msg:
            self.nc_guid = misc.GUID(samdb.schema_format_value("objectGUID",
                                     msg["objectGUID"][0]))
        if "objectSid" in msg:
            self.nc_sid = msg["objectSid"][0]

        assert self.nc_guid is not None

    def is_schema(self):
        '''Return True if NC is schema'''
        assert self.nc_type != NCType.unknown
        return self.nc_type == NCType.schema

    def is_domain(self):
        '''Return True if NC is domain'''
        assert self.nc_type != NCType.unknown
        return self.nc_type == NCType.domain

    def is_application(self):
        '''Return True if NC is application'''
        assert self.nc_type != NCType.unknown
        return self.nc_type == NCType.application

    def is_config(self):
        '''Return True if NC is config'''
        assert self.nc_type != NCType.unknown
        return self.nc_type == NCType.config

    def identify_by_basedn(self, samdb):
        """Given an NC object, identify what type is is thru
           the samdb basedn strings and NC sid value
        """
        # Invoke loader to initialize guid and more
        # importantly sid value (sid is used to identify
        # domain NCs)
        if self.nc_guid is None:
            self.load_nc(samdb)

        # We check against schema and config because they
        # will be the same for all nTDSDSAs in the forest.
        # That leaves the domain NCs which can be identified
        # by sid and application NCs as the last identified
        if self.nc_dnstr == str(samdb.get_schema_basedn()):
            self.nc_type = NCType.schema
        elif self.nc_dnstr == str(samdb.get_config_basedn()):
            self.nc_type = NCType.config
        elif self.nc_sid is not None:
            self.nc_type = NCType.domain
        else:
            self.nc_type = NCType.application

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
        # utilize the identify_by_basedn() to
        # identify those
        elif attr == "hasMasterNCs":
            self.identify_by_basedn(samdb)

        # Still unknown (unlikely) but for completeness
        # and for finally identifying application NCs
        if self.nc_type == NCType.unknown:
            self.identify_by_basedn(samdb)


class NCReplica(NamingContext):
    """Naming context replica that is relative to a specific DSA.

    This is a more specific form of NamingContext class (inheriting from that
    class) and it identifies unique attributes of the DSA's replica for a NC.
    """

    def __init__(self, dsa_dnstr, dsa_guid, nc_dnstr):
        """Instantiate a Naming Context Replica

        :param dsa_guid: GUID of DSA where replica appears
        :param nc_dnstr: NC dn string
        """
        self.rep_dsa_dnstr = dsa_dnstr
        self.rep_dsa_guid = dsa_guid
        self.rep_default = False # replica for DSA's default domain
        self.rep_partial = False
        self.rep_ro = False
        self.rep_instantiated_flags = 0

        self.rep_fsmo_role_owner = None

        # RepsFromTo tuples
        self.rep_repsFrom = []

        # The (is present) test is a combination of being
        # enumerated in (hasMasterNCs or msDS-hasFullReplicaNCs or
        # hasPartialReplicaNCs) as well as its replica flags found
        # thru the msDS-HasInstantiatedNCs.  If the NC replica meets
        # the first enumeration test then this flag is set true
        self.rep_present_criteria_one = False

        # Call my super class we inherited from
        NamingContext.__init__(self, nc_dnstr)

    def __str__(self):
        '''Debug dump string output of class'''
        text = "%s:" % self.__class__.__name__
        text = text + "\n\tdsa_dnstr=%s"       % self.rep_dsa_dnstr
        text = text + "\n\tdsa_guid=%s"        % str(self.rep_dsa_guid)
        text = text + "\n\tdefault=%s"         % self.rep_default
        text = text + "\n\tro=%s"              % self.rep_ro
        text = text + "\n\tpartial=%s"         % self.rep_partial
        text = text + "\n\tpresent=%s"         % self.is_present()
        text = text + "\n\tfsmo_role_owner=%s" % self.rep_fsmo_role_owner

        for rep in self.rep_repsFrom:
            text = text + "\n%s" % rep

        return "%s\n%s" % (NamingContext.__str__(self), text)

    def set_instantiated_flags(self, flags=None):
        '''Set or clear NC replica instantiated flags'''
        if flags is None:
            self.rep_instantiated_flags = 0
        else:
            self.rep_instantiated_flags = flags

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

    def is_default(self):
        """Whether this is a default domain for the dsa that this NC appears on
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
           self.rep_instantiated_flags & dsdb.INSTANCE_TYPE_NC_GOING == 0:
            return True
        return False

    def load_repsFrom(self, samdb):
        """Given an NC replica which has been discovered thru the nTDSDSA
        database object, load the repsFrom attribute for the local replica.
        held by my dsa.  The repsFrom attribute is not replicated so this
        attribute is relative only to the local DSA that the samdb exists on
        """
        try:
            res = samdb.search(base=self.nc_dnstr, scope=ldb.SCOPE_BASE,
                               attrs=[ "repsFrom" ])

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find NC for (%s) - (%s)" %
                            (self.nc_dnstr, estr))

        msg = res[0]

        # Possibly no repsFrom if this is a singleton DC
        if "repsFrom" in msg:
            for value in msg["repsFrom"]:
                rep = RepsFromTo(self.nc_dnstr,
                                 ndr_unpack(drsblobs.repsFromToBlob, value))
                self.rep_repsFrom.append(rep)

    def commit_repsFrom(self, samdb, ro=False):
        """Commit repsFrom to the database"""

        # XXX - This is not truly correct according to the MS-TECH
        #       docs.  To commit a repsFrom we should be using RPCs
        #       IDL_DRSReplicaAdd, IDL_DRSReplicaModify, and
        #       IDL_DRSReplicaDel to affect a repsFrom change.
        #
        #       Those RPCs are missing in samba, so I'll have to
        #       implement them to get this to more accurately
        #       reflect the reference docs.  As of right now this
        #       commit to the database will work as its what the
        #       older KCC also did
        modify = False
        newreps = []
        delreps = []

        for repsFrom in self.rep_repsFrom:

            # Leave out any to be deleted from
            # replacement list.  Build a list
            # of to be deleted reps which we will
            # remove from rep_repsFrom list below
            if repsFrom.to_be_deleted:
                delreps.append(repsFrom)
                modify = True
                continue

            if repsFrom.is_modified():
                repsFrom.set_unmodified()
                modify = True

            # current (unmodified) elements also get
            # appended here but no changes will occur
            # unless something is "to be modified" or
            # "to be deleted"
            newreps.append(ndr_pack(repsFrom.ndr_blob))

        # Now delete these from our list of rep_repsFrom
        for repsFrom in delreps:
            self.rep_repsFrom.remove(repsFrom)
        delreps = []

        # Nothing to do if no reps have been modified or
        # need to be deleted or input option has informed
        # us to be "readonly" (ro).  Leave database
        # record "as is"
        if not modify or ro:
            return

        m = ldb.Message()
        m.dn = ldb.Dn(samdb, self.nc_dnstr)

        m["repsFrom"] = \
            ldb.MessageElement(newreps, ldb.FLAG_MOD_REPLACE, "repsFrom")

        try:
            samdb.modify(m)

        except ldb.LdbError, estr:
            raise Exception("Could not set repsFrom for (%s) - (%s)" %
                            (self.dsa_dnstr, estr))

    def dumpstr_to_be_deleted(self):
        text=""
        for repsFrom in self.rep_repsFrom:
            if repsFrom.to_be_deleted:
                if text:
                    text = text + "\n%s" % repsFrom
                else:
                    text = "%s" % repsFrom
        return text

    def dumpstr_to_be_modified(self):
        text=""
        for repsFrom in self.rep_repsFrom:
            if repsFrom.is_modified():
                if text:
                    text = text + "\n%s" % repsFrom
                else:
                    text = "%s" % repsFrom
        return text

    def load_fsmo_roles(self, samdb):
        """Given an NC replica which has been discovered thru the nTDSDSA
        database object, load the fSMORoleOwner attribute.
        """
        try:
            res = samdb.search(base=self.nc_dnstr, scope=ldb.SCOPE_BASE,
                               attrs=[ "fSMORoleOwner" ])

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find NC for (%s) - (%s)" %
                            (self.nc_dnstr, estr))

        msg = res[0]

        # Possibly no fSMORoleOwner
        if "fSMORoleOwner" in msg:
            self.rep_fsmo_role_owner = msg["fSMORoleOwner"]

    def is_fsmo_role_owner(self, dsa_dnstr):
        if self.rep_fsmo_role_owner is not None and \
           self.rep_fsmo_role_owner == dsa_dnstr:
            return True
        return False


class DirectoryServiceAgent(object):

    def __init__(self, dsa_dnstr):
        """Initialize DSA class.

        Class is subsequently fully populated by calling the load_dsa() method

        :param dsa_dnstr:  DN of the nTDSDSA
        """
        self.dsa_dnstr = dsa_dnstr
        self.dsa_guid = None
        self.dsa_ivid = None
        self.dsa_is_ro = False
        self.dsa_is_istg = False
        self.dsa_options = 0
        self.dsa_behavior = 0
        self.default_dnstr = None  # default domain dn string for dsa

        # NCReplicas for this dsa that are "present"
        # Indexed by DN string of naming context
        self.current_rep_table = {}

        # NCReplicas for this dsa that "should be present"
        # Indexed by DN string of naming context
        self.needed_rep_table = {}

        # NTDSConnections for this dsa.  These are current
        # valid connections that are committed or pending a commit
        # in the database.  Indexed by DN string of connection
        self.connect_table = {}

    def __str__(self):
        '''Debug dump string output of class'''

        text = "%s:" % self.__class__.__name__
        if self.dsa_dnstr is not None:
            text = text + "\n\tdsa_dnstr=%s" % self.dsa_dnstr
        if self.dsa_guid is not None:
            text = text + "\n\tdsa_guid=%s"  % str(self.dsa_guid)
        if self.dsa_ivid is not None:
            text = text + "\n\tdsa_ivid=%s"  % str(self.dsa_ivid)

        text = text + "\n\tro=%s" % self.is_ro()
        text = text + "\n\tgc=%s" % self.is_gc()
        text = text + "\n\tistg=%s" % self.is_istg()

        text = text + "\ncurrent_replica_table:"
        text = text + "\n%s" % self.dumpstr_current_replica_table()
        text = text + "\nneeded_replica_table:"
        text = text + "\n%s" % self.dumpstr_needed_replica_table()
        text = text + "\nconnect_table:"
        text = text + "\n%s" % self.dumpstr_connect_table()

        return text

    def get_current_replica(self, nc_dnstr):
        if nc_dnstr in self.current_rep_table.keys():
            return self.current_rep_table[nc_dnstr]
        else:
            return None

    def is_istg(self):
        '''Returns True if dsa is intersite topology generator for it's site'''
        # The KCC on an RODC always acts as an ISTG for itself
        return self.dsa_is_istg or self.dsa_is_ro

    def is_ro(self):
        '''Returns True if dsa a read only domain controller'''
        return self.dsa_is_ro

    def is_gc(self):
        '''Returns True if dsa hosts a global catalog'''
        if (self.options & dsdb.DS_NTDSDSA_OPT_IS_GC) != 0:
            return True
        return False

    def is_minimum_behavior(self, version):
        """Is dsa at minimum windows level greater than or equal to (version)

        :param version: Windows version to test against
            (e.g. DS_DOMAIN_FUNCTION_2008)
        """
        if self.dsa_behavior >= version:
            return True
        return False

    def is_translate_ntdsconn_disabled(self):
        """Whether this allows NTDSConnection translation in its options."""
        if (self.options & dsdb.DS_NTDSDSA_OPT_DISABLE_NTDSCONN_XLATE) != 0:
            return True
        return False

    def get_rep_tables(self):
        """Return DSA current and needed replica tables
        """
        return self.current_rep_table, self.needed_rep_table

    def get_parent_dnstr(self):
        """Get the parent DN string of this object."""
        head, sep, tail = self.dsa_dnstr.partition(',')
        return tail

    def load_dsa(self, samdb):
        """Load a DSA from the samdb.

        Prior initialization has given us the DN of the DSA that we are to
        load.  This method initializes all other attributes, including loading
        the NC replica table for this DSA.
        """
        attrs = ["objectGUID",
                 "invocationID",
                 "options",
                 "msDS-isRODC",
                 "msDS-Behavior-Version"]
        try:
            res = samdb.search(base=self.dsa_dnstr, scope=ldb.SCOPE_BASE,
                               attrs=attrs)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find nTDSDSA for (%s) - (%s)" %
                            (self.dsa_dnstr, estr))

        msg = res[0]
        self.dsa_guid = misc.GUID(samdb.schema_format_value("objectGUID",
                                  msg["objectGUID"][0]))

        # RODCs don't originate changes and thus have no invocationId,
        # therefore we must check for existence first
        if "invocationId" in msg:
            self.dsa_ivid = misc.GUID(samdb.schema_format_value("objectGUID",
                                      msg["invocationId"][0]))

        if "options" in msg:
            self.options = int(msg["options"][0])

        if "msDS-isRODC" in msg and msg["msDS-isRODC"][0] == "TRUE":
            self.dsa_is_ro = True
        else:
            self.dsa_is_ro = False

        if "msDS-Behavior-Version" in msg:
            self.dsa_behavior = int(msg['msDS-Behavior-Version'][0])

        # Load the NC replicas that are enumerated on this dsa
        self.load_current_replica_table(samdb)

        # Load the nTDSConnection that are enumerated on this dsa
        self.load_connection_table(samdb)

    def load_current_replica_table(self, samdb):
        """Method to load the NC replica's listed for DSA object.

        This method queries the samdb for (hasMasterNCs, msDS-hasMasterNCs,
        hasPartialReplicaNCs, msDS-HasDomainNCs, msDS-hasFullReplicaNCs, and
        msDS-HasInstantiatedNCs) to determine complete list of NC replicas that
        are enumerated for the DSA.  Once a NC replica is loaded it is
        identified (schema, config, etc) and the other replica attributes
        (partial, ro, etc) are determined.

        :param samdb: database to query for DSA replica list
        """
        ncattrs = [ # not RODC - default, config, schema (old style)
                    "hasMasterNCs",
                    # not RODC - default, config, schema, app NCs
                    "msDS-hasMasterNCs",
                    # domain NC partial replicas
                    "hasPartialReplicaNCs",
                    # default domain NC
                    "msDS-HasDomainNCs",
                    # RODC only - default, config, schema, app NCs
                    "msDS-hasFullReplicaNCs",
                    # Identifies if replica is coming, going, or stable
                    "msDS-HasInstantiatedNCs" ]
        try:
            res = samdb.search(base=self.dsa_dnstr, scope=ldb.SCOPE_BASE,
                               attrs=ncattrs)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find nTDSDSA NCs for (%s) - (%s)" %
                            (self.dsa_dnstr, estr))

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
                    # its methods to parse a binary DN
                    dsdn = dsdb_Dn(samdb, value)
                    flags = dsdn.get_binary_integer()
                    dnstr = str(dsdn.dn)

                    if not dnstr in tmp_table.keys():
                        rep = NCReplica(self.dsa_dnstr, self.dsa_guid, dnstr)
                        tmp_table[dnstr] = rep
                    else:
                        rep = tmp_table[dnstr]

                    if k == "msDS-HasInstantiatedNCs":
                        rep.set_instantiated_flags(flags)
                        continue

                    rep.identify_by_dsa_attr(samdb, k)

                    # if we've identified the default domain NC
                    # then save its DN string
                    if rep.is_default():
                       self.default_dnstr = dnstr
        else:
            raise Exception("No nTDSDSA NCs for (%s)" % self.dsa_dnstr)

        # Assign our newly built NC replica table to this dsa
        self.current_rep_table = tmp_table

    def add_needed_replica(self, rep):
        """Method to add a NC replica that "should be present" to the
        needed_rep_table if not already in the table
        """
        if not rep.nc_dnstr in self.needed_rep_table.keys():
            self.needed_rep_table[rep.nc_dnstr] = rep

    def load_connection_table(self, samdb):
        """Method to load the nTDSConnections listed for DSA object.

        :param samdb: database to query for DSA connection list
        """
        try:
            res = samdb.search(base=self.dsa_dnstr,
                               scope=ldb.SCOPE_SUBTREE,
                               expression="(objectClass=nTDSConnection)")

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find nTDSConnection for (%s) - (%s)" %
                            (self.dsa_dnstr, estr))

        for msg in res:
            dnstr = str(msg.dn)

            # already loaded
            if dnstr in self.connect_table.keys():
                continue

            connect = NTDSConnection(dnstr)

            connect.load_connection(samdb)
            self.connect_table[dnstr] = connect

    def commit_connections(self, samdb, ro=False):
        """Method to commit any uncommitted nTDSConnections
        modifications that are in our table.  These would be
        identified connections that are marked to be added or
        deleted

        :param samdb: database to commit DSA connection list to
        :param ro: if (true) then peform internal operations but
            do not write to the database (readonly)
        """
        delconn = []

        for dnstr, connect in self.connect_table.items():
            if connect.to_be_added:
                connect.commit_added(samdb, ro)

            if connect.to_be_modified:
                connect.commit_modified(samdb, ro)

            if connect.to_be_deleted:
                connect.commit_deleted(samdb, ro)
                delconn.append(dnstr)

        # Now delete the connection from the table
        for dnstr in delconn:
            del self.connect_table[dnstr]

    def add_connection(self, dnstr, connect):
        assert dnstr not in self.connect_table.keys()
        self.connect_table[dnstr] = connect

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

    def dumpstr_current_replica_table(self):
        '''Debug dump string output of current replica table'''
        text=""
        for k in self.current_rep_table.keys():
            if text:
                text = text + "\n%s" % self.current_rep_table[k]
            else:
                text = "%s" % self.current_rep_table[k]
        return text

    def dumpstr_needed_replica_table(self):
        '''Debug dump string output of needed replica table'''
        text=""
        for k in self.needed_rep_table.keys():
            if text:
                text = text + "\n%s" % self.needed_rep_table[k]
            else:
                text = "%s" % self.needed_rep_table[k]
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

    def new_connection(self, options, flags, transport, from_dnstr, sched):
        """Set up a new connection for the DSA based on input
        parameters.  Connection will be added to the DSA
        connect_table and will be marked as "to be added" pending
        a call to commit_connections()
        """
        dnstr = "CN=%s," % str(uuid.uuid4()) + self.dsa_dnstr

        connect = NTDSConnection(dnstr)
        connect.to_be_added = True
        connect.enabled = True
        connect.from_dnstr = from_dnstr
        connect.options = options
        connect.flags = flags

        if transport is not None:
            connect.transport_dnstr = transport.dnstr

        if sched is not None:
            connect.schedule = sched
        else:
            # Create schedule.  Attribute valuse set according to MS-TECH
            # intrasite connection creation document
            connect.schedule = drsblobs.schedule()

            connect.schedule.size = 188
            connect.schedule.bandwidth = 0
            connect.schedule.numberOfSchedules = 1

            header = drsblobs.scheduleHeader()
            header.type = 0
            header.offset = 20

            connect.schedule.headerArray = [ header ]

            # 168 byte instances of the 0x01 value.  The low order 4 bits
            # of the byte equate to 15 minute intervals within a single hour.
            # There are 168 bytes because there are 168 hours in a full week
            # Effectively we are saying to perform replication at the end of
            # each hour of the week
            data = drsblobs.scheduleSlots()
            data.slots = [ 0x01 ] * 168

            connect.schedule.dataArray = [ data ]

        self.add_connection(dnstr, connect);
        return connect


class NTDSConnection(object):
    """Class defines a nTDSConnection found under a DSA
    """
    def __init__(self, dnstr):
        self.dnstr = dnstr
        self.guid = None
        self.enabled = False
        self.whenCreated = 0
        self.to_be_added = False # new connection needs to be added
        self.to_be_deleted = False # old connection needs to be deleted
        self.to_be_modified = False
        self.options = 0
        self.system_flags = 0
        self.transport_dnstr = None
        self.transport_guid = None
        self.from_dnstr = None
        self.schedule = None

    def __str__(self):
        '''Debug dump string output of NTDSConnection object'''

        text = "%s:\n\tdn=%s" % (self.__class__.__name__, self.dnstr)
        text = text + "\n\tenabled=%s" % self.enabled
        text = text + "\n\tto_be_added=%s" % self.to_be_added
        text = text + "\n\tto_be_deleted=%s" % self.to_be_deleted
        text = text + "\n\tto_be_modified=%s" % self.to_be_modified
        text = text + "\n\toptions=0x%08X" % self.options
        text = text + "\n\tsystem_flags=0x%08X" % self.system_flags
        text = text + "\n\twhenCreated=%d" % self.whenCreated
        text = text + "\n\ttransport_dn=%s" % self.transport_dnstr

        if self.guid is not None:
            text = text + "\n\tguid=%s" % str(self.guid)

        if self.transport_guid is not None:
            text = text + "\n\ttransport_guid=%s" % str(self.transport_guid)

        text = text + "\n\tfrom_dn=%s" % self.from_dnstr

        if self.schedule is not None:
            text = text + "\n\tschedule.size=%s" % self.schedule.size
            text = text + "\n\tschedule.bandwidth=%s" % self.schedule.bandwidth
            text = text + "\n\tschedule.numberOfSchedules=%s" % \
                   self.schedule.numberOfSchedules

            for i, header in enumerate(self.schedule.headerArray):
                text = text + "\n\tschedule.headerArray[%d].type=%d" % \
                       (i, header.type)
                text = text + "\n\tschedule.headerArray[%d].offset=%d" % \
                       (i, header.offset)
                text = text + "\n\tschedule.dataArray[%d].slots[ " % i
                for slot in self.schedule.dataArray[i].slots:
                    text = text + "0x%X " % slot
                text = text + "]"

        return text

    def load_connection(self, samdb):
        """Given a NTDSConnection object with an prior initialization
        for the object's DN, search for the DN and load attributes
        from the samdb.
        """
        attrs = [ "options",
                  "enabledConnection",
                  "schedule",
                  "whenCreated",
                  "objectGUID",
                  "transportType",
                  "fromServer",
                  "systemFlags" ]
        try:
            res = samdb.search(base=self.dnstr, scope=ldb.SCOPE_BASE,
                               attrs=attrs)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find nTDSConnection for (%s) - (%s)" %
                            (self.dnstr, estr))

        msg = res[0]

        if "options" in msg:
            self.options = int(msg["options"][0])

        if "enabledConnection" in msg:
            if msg["enabledConnection"][0].upper().lstrip().rstrip() == "TRUE":
                self.enabled = True

        if "systemFlags" in msg:
            self.system_flags = int(msg["systemFlags"][0])

        if "objectGUID" in msg:
            self.guid = \
                misc.GUID(samdb.schema_format_value("objectGUID",
                                                    msg["objectGUID"][0]))

        if "transportType" in msg:
            dsdn = dsdb_Dn(samdb, msg["tranportType"][0])
            self.load_connection_transport(samdb, str(dsdn.dn))

        if "schedule" in msg:
            self.schedule = ndr_unpack(drsblobs.replSchedule, msg["schedule"][0])

        if "whenCreated" in msg:
            self.whenCreated = ldb.string_to_time(msg["whenCreated"][0])

        if "fromServer" in msg:
            dsdn = dsdb_Dn(samdb, msg["fromServer"][0])
            self.from_dnstr = str(dsdn.dn)
            assert self.from_dnstr is not None

    def load_connection_transport(self, samdb, tdnstr):
        """Given a NTDSConnection object which enumerates a transport
        DN, load the transport information for the connection object

        :param tdnstr: transport DN to load
        """
        attrs = [ "objectGUID" ]
        try:
            res = samdb.search(base=tdnstr,
                               scope=ldb.SCOPE_BASE, attrs=attrs)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find transport (%s)" %
                            (tdnstr, estr))

        if "objectGUID" in res[0]:
            msg = res[0]
            self.transport_dnstr = tdnstr
            self.transport_guid = \
                misc.GUID(samdb.schema_format_value("objectGUID",
                                                    msg["objectGUID"][0]))
        assert self.transport_dnstr is not None
        assert self.transport_guid is not None

    def commit_deleted(self, samdb, ro=False):
        """Local helper routine for commit_connections() which
        handles committed connections that are to be deleted from
        the database database
        """
        assert self.to_be_deleted
        self.to_be_deleted = False

        # No database modification requested
        if ro:
            return

        try:
            samdb.delete(self.dnstr)
        except ldb.LdbError, (enum, estr):
            raise Exception("Could not delete nTDSConnection for (%s) - (%s)" %
                            (self.dnstr, estr))

    def commit_added(self, samdb, ro=False):
        """Local helper routine for commit_connections() which
        handles committed connections that are to be added to the
        database
        """
        assert self.to_be_added
        self.to_be_added = False

        # No database modification requested
        if ro:
            return

        # First verify we don't have this entry to ensure nothing
        # is programatically amiss
        found = False
        try:
            msg = samdb.search(base=self.dnstr, scope=ldb.SCOPE_BASE)
            if len(msg) != 0:
                found = True

        except ldb.LdbError, (enum, estr):
            if enum != ldb.ERR_NO_SUCH_OBJECT:
                raise Exception("Unable to search for (%s) - (%s)" %
                                (self.dnstr, estr))
        if found:
            raise Exception("nTDSConnection for (%s) already exists!" %
                            self.dnstr)

        if self.enabled:
            enablestr = "TRUE"
        else:
            enablestr = "FALSE"

        # Prepare a message for adding to the samdb
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, self.dnstr)

        m["objectClass"] = \
            ldb.MessageElement("nTDSConnection", ldb.FLAG_MOD_ADD,
                               "objectClass")
        m["showInAdvancedViewOnly"] = \
            ldb.MessageElement("TRUE", ldb.FLAG_MOD_ADD,
                               "showInAdvancedViewOnly")
        m["enabledConnection"] = \
            ldb.MessageElement(enablestr, ldb.FLAG_MOD_ADD, "enabledConnection")
        m["fromServer"] = \
            ldb.MessageElement(self.from_dnstr, ldb.FLAG_MOD_ADD, "fromServer")
        m["options"] = \
            ldb.MessageElement(str(self.options), ldb.FLAG_MOD_ADD, "options")
        m["systemFlags"] = \
            ldb.MessageElement(str(self.system_flags), ldb.FLAG_MOD_ADD,
                               "systemFlags")

        if self.transport_dnstr is not None:
            m["transportType"] = \
                ldb.MessageElement(str(self.transport_dnstr), ldb.FLAG_MOD_ADD,
                                   "transportType")

        if self.schedule is not None:
            m["schedule"] = \
                ldb.MessageElement(ndr_pack(self.schedule),
                                   ldb.FLAG_MOD_ADD, "schedule")
        try:
            samdb.add(m)
        except ldb.LdbError, (enum, estr):
            raise Exception("Could not add nTDSConnection for (%s) - (%s)" %
                            (self.dnstr, estr))

    def commit_modified(self, samdb, ro=False):
        """Local helper routine for commit_connections() which
        handles committed connections that are to be modified to the
        database
        """
        assert self.to_be_modified
        self.to_be_modified = False

        # No database modification requested
        if ro:
            return

        # First verify we have this entry to ensure nothing
        # is programatically amiss
        try:
            msg = samdb.search(base=self.dnstr, scope=ldb.SCOPE_BASE)
            found = True

        except ldb.LdbError, (enum, estr):
            if enum == ldb.ERR_NO_SUCH_OBJECT:
                found = False
            else:
                raise Exception("Unable to search for (%s) - (%s)" %
                                (self.dnstr, estr))
        if not found:
            raise Exception("nTDSConnection for (%s) doesn't exist!" %
                            self.dnstr)

        if self.enabled:
            enablestr = "TRUE"
        else:
            enablestr = "FALSE"

        # Prepare a message for modifying the samdb
        m = ldb.Message()
        m.dn = ldb.Dn(samdb, self.dnstr)

        m["enabledConnection"] = \
            ldb.MessageElement(enablestr, ldb.FLAG_MOD_REPLACE,
                               "enabledConnection")
        m["fromServer"] = \
            ldb.MessageElement(self.from_dnstr, ldb.FLAG_MOD_REPLACE,
                               "fromServer")
        m["options"] = \
            ldb.MessageElement(str(self.options), ldb.FLAG_MOD_REPLACE,
                               "options")
        m["systemFlags"] = \
            ldb.MessageElement(str(self.system_flags), ldb.FLAG_MOD_REPLACE,
                               "systemFlags")

        if self.transport_dnstr is not None:
            m["transportType"] = \
                ldb.MessageElement(str(self.transport_dnstr),
                                   ldb.FLAG_MOD_REPLACE, "transportType")
        else:
            m["transportType"] = \
                ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "transportType")

        if self.schedule is not None:
            m["schedule"] = \
                ldb.MessageElement(ndr_pack(self.schedule),
                                   ldb.FLAG_MOD_REPLACE, "schedule")
        else:
            m["schedule"] = \
                ldb.MessageElement([], ldb.FLAG_MOD_DELETE, "schedule")
        try:
            samdb.modify(m)
        except ldb.LdbError, (enum, estr):
            raise Exception("Could not modify nTDSConnection for (%s) - (%s)" %
                            (self.dnstr, estr))

    def set_modified(self, truefalse):
        self.to_be_modified = truefalse

    def set_added(self, truefalse):
        self.to_be_added = truefalse

    def set_deleted(self, truefalse):
        self.to_be_deleted = truefalse

    def is_schedule_minimum_once_per_week(self):
        """Returns True if our schedule includes at least one
        replication interval within the week.  False otherwise
        """
        if self.schedule is None or self.schedule.dataArray[0] is None:
            return False

        for slot in self.schedule.dataArray[0].slots:
           if (slot & 0x0F) != 0x0:
               return True
        return False

    def is_equivalent_schedule(self, sched):
        """Returns True if our schedule is equivalent to the input
        comparison schedule.

        :param shed: schedule to compare to
        """
        if self.schedule is not None:
            if sched is None:
               return False
        elif sched is None:
            return True

        if (self.schedule.size != sched.size or
            self.schedule.bandwidth != sched.bandwidth or
            self.schedule.numberOfSchedules != sched.numberOfSchedules):
            return False

        for i, header in enumerate(self.schedule.headerArray):

            if self.schedule.headerArray[i].type != sched.headerArray[i].type:
                return False

            if self.schedule.headerArray[i].offset != \
               sched.headerArray[i].offset:
                return False

            for a, b in zip(self.schedule.dataArray[i].slots,
                            sched.dataArray[i].slots):
                if a != b:
                    return False
        return True

    def convert_schedule_to_repltimes(self):
        """Convert NTDS Connection schedule to replTime schedule.

        NTDS Connection schedule slots are double the size of
        the replTime slots but the top portion of the NTDS
        Connection schedule slot (4 most significant bits in
        uchar) are unused.  The 4 least significant bits have
        the same (15 minute interval) bit positions as replTimes.
        We thus pack two elements of the NTDS Connection schedule
        slots into one element of the replTimes slot
        If no schedule appears in NTDS Connection then a default
        of 0x11 is set in each replTimes slot as per behaviour
        noted in a Windows DC.  That default would cause replication
        within the last 15 minutes of each hour.
        """
        times = [0x11] * 84

        for i, slot in enumerate(times):
            if self.schedule is not None and \
               self.schedule.dataArray[0] is not None:
                slot = (self.schedule.dataArray[0].slots[i*2] & 0xF) << 4 | \
                       (self.schedule.dataArray[0].slots[i*2] & 0xF)
        return times

    def is_rodc_topology(self):
        """Returns True if NTDS Connection specifies RODC
        topology only
        """
        if self.options & dsdb.NTDSCONN_OPT_RODC_TOPOLOGY == 0:
            return False
        return True

    def is_generated(self):
        """Returns True if NTDS Connection was generated by the
        KCC topology algorithm as opposed to set by the administrator
        """
        if self.options & dsdb.NTDSCONN_OPT_IS_GENERATED == 0:
            return False
        return True

    def is_override_notify_default(self):
        """Returns True if NTDS Connection should override notify default
        """
        if self.options & dsdb.NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT == 0:
            return False
        return True

    def is_use_notify(self):
        """Returns True if NTDS Connection should use notify
        """
        if self.options & dsdb.NTDSCONN_OPT_USE_NOTIFY == 0:
            return False
        return True

    def is_twoway_sync(self):
        """Returns True if NTDS Connection should use twoway sync
        """
        if self.options & dsdb.NTDSCONN_OPT_TWOWAY_SYNC == 0:
            return False
        return True

    def is_intersite_compression_disabled(self):
        """Returns True if NTDS Connection intersite compression
        is disabled
        """
        if self.options & dsdb.NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION == 0:
            return False
        return True

    def is_user_owned_schedule(self):
        """Returns True if NTDS Connection has a user owned schedule
        """
        if self.options & dsdb.NTDSCONN_OPT_USER_OWNED_SCHEDULE == 0:
            return False
        return True

    def is_enabled(self):
        """Returns True if NTDS Connection is enabled
        """
        return self.enabled

    def get_from_dnstr(self):
        '''Return fromServer dn string attribute'''
        return self.from_dnstr


class Partition(NamingContext):
    """A naming context discovered thru Partitions DN of the config schema.

    This is a more specific form of NamingContext class (inheriting from that
    class) and it identifies unique attributes enumerated in the Partitions
    such as which nTDSDSAs are cross referenced for replicas
    """
    def __init__(self, partstr):
        self.partstr = partstr
        self.enabled = True
        self.system_flags = 0
        self.rw_location_list = []
        self.ro_location_list = []

        # We don't have enough info to properly
        # fill in the naming context yet.  We'll get that
        # fully set up with load_partition().
        NamingContext.__init__(self, None)


    def load_partition(self, samdb):
        """Given a Partition class object that has been initialized with its
        partition dn string, load the partition from the sam database, identify
        the type of the partition (schema, domain, etc) and record the list of
        nTDSDSAs that appear in the cross reference attributes
        msDS-NC-Replica-Locations and msDS-NC-RO-Replica-Locations.

        :param samdb: sam database to load partition from
        """
        attrs = [ "nCName",
                  "Enabled",
                  "systemFlags",
                  "msDS-NC-Replica-Locations",
                  "msDS-NC-RO-Replica-Locations" ]
        try:
            res = samdb.search(base=self.partstr, scope=ldb.SCOPE_BASE,
                               attrs=attrs)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find partition for (%s) - (%s)" % (
                            self.partstr, estr))

        msg = res[0]
        for k in msg.keys():
            if k == "dn":
                continue

            if k == "Enabled":
                if msg[k][0].upper().lstrip().rstrip() == "TRUE":
                    self.enabled = True
                else:
                    self.enabled = False
                continue

            if k == "systemFlags":
                self.system_flags = int(msg[k][0])
                continue

            for value in msg[k]:
                dsdn = dsdb_Dn(samdb, value)
                dnstr = str(dsdn.dn)

                if k == "nCName":
                    self.nc_dnstr = dnstr
                    continue

                if k == "msDS-NC-Replica-Locations":
                    self.rw_location_list.append(dnstr)
                    continue

                if k == "msDS-NC-RO-Replica-Locations":
                    self.ro_location_list.append(dnstr)
                    continue

        # Now identify what type of NC this partition
        # enumerated
        self.identify_by_basedn(samdb)

    def is_enabled(self):
        """Returns True if partition is enabled
        """
        return self.is_enabled

    def is_foreign(self):
        """Returns True if this is not an Active Directory NC in our
        forest but is instead something else (e.g. a foreign NC)
        """
        if (self.system_flags & dsdb.SYSTEM_FLAG_CR_NTDS_NC) == 0:
            return True
        else:
            return False

    def should_be_present(self, target_dsa):
        """Tests whether this partition should have an NC replica
        on the target dsa.  This method returns a tuple of
        needed=True/False, ro=True/False, partial=True/False

        :param target_dsa: should NC be present on target dsa
        """
        needed = False
        ro = False
        partial = False

        # If this is the config, schema, or default
        # domain NC for the target dsa then it should
        # be present
        if self.nc_type == NCType.config or \
           self.nc_type == NCType.schema or \
           (self.nc_type == NCType.domain and
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
           (target_dsa.dsa_dnstr in self.ro_location_list or
            target_dsa.dsa_dnstr in self.rw_location_list):
            needed = True
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


class Site(object):
    """An individual site object discovered thru the configuration
    naming context.  Contains all DSAs that exist within the site
    """
    def __init__(self, site_dnstr):
        self.site_dnstr = site_dnstr
        self.site_options = 0
        self.site_topo_generator = None
        self.site_topo_failover = 0  # appears to be in minutes
        self.dsa_table = {}

    def load_site(self, samdb):
        """Loads the NTDS Site Settions options attribute for the site
        as well as querying and loading all DSAs that appear within
        the site.
        """
        ssdn = "CN=NTDS Site Settings,%s" % self.site_dnstr
        attrs = ["options",
                 "interSiteTopologyFailover",
                 "interSiteTopologyGenerator"]
        try:
            res = samdb.search(base=ssdn, scope=ldb.SCOPE_BASE,
                               attrs=attrs)
        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find site settings for (%s) - (%s)" %
                            (ssdn, estr))

        msg = res[0]
        if "options" in msg:
            self.site_options = int(msg["options"][0])

        if "interSiteTopologyGenerator" in msg:
            self.site_topo_generator = str(msg["interSiteTopologyGenerator"][0])

        if "interSiteTopologyFailover" in msg:
            self.site_topo_failover = int(msg["interSiteTopologyFailover"][0])

        self.load_all_dsa(samdb)

    def load_all_dsa(self, samdb):
        """Discover all nTDSDSA thru the sites entry and
        instantiate and load the DSAs.  Each dsa is inserted
        into the dsa_table by dn string.
        """
        try:
            res = samdb.search(self.site_dnstr,
                               scope=ldb.SCOPE_SUBTREE,
                               expression="(objectClass=nTDSDSA)")
        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find nTDSDSAs - (%s)" % estr)

        for msg in res:
            dnstr = str(msg.dn)

            # already loaded
            if dnstr in self.dsa_table.keys():
                continue

            dsa = DirectoryServiceAgent(dnstr)

            dsa.load_dsa(samdb)

            # Assign this dsa to my dsa table
            # and index by dsa dn
            self.dsa_table[dnstr] = dsa

    def get_dsa_by_guidstr(self, guidstr):
        for dsa in self.dsa_table.values():
            if str(dsa.dsa_guid) == guidstr:
                return dsa
        return None

    def get_dsa(self, dnstr):
        """Return a previously loaded DSA object by consulting
        the sites dsa_table for the provided DSA dn string

        :return: None if DSA doesn't exist
        """
        if dnstr in self.dsa_table.keys():
            return self.dsa_table[dnstr]
        return None

    def select_istg(self, samdb, mydsa, ro):
        """Determine if my DC should be an intersite topology
        generator.  If my DC is the istg and is both a writeable
        DC and the database is opened in write mode then we perform
        an originating update to set the interSiteTopologyGenerator
        attribute in the NTDS Site Settings object.  An RODC always
        acts as an ISTG for itself.
        """
        # The KCC on an RODC always acts as an ISTG for itself
        if mydsa.dsa_is_ro:
            mydsa.dsa_is_istg = True
            return True

        # Find configuration NC replica for my DSA
        for c_rep in mydsa.current_rep_table.values():
            if c_rep.is_config():
                break

        if c_rep is None:
            raise Exception("Unable to find config NC replica for (%s)" %
                            mydsa.dsa_dnstr)

        # Load repsFrom if not already loaded so we can get the current
        # state of the config replica and whether we are getting updates
        # from the istg
        c_rep.load_repsFrom(samdb)

        # From MS-Tech ISTG selection:
        #     First, the KCC on a writable DC determines whether it acts
        #     as an ISTG for its site
        #
        #     Let s be the object such that s!lDAPDisplayName = nTDSDSA
        #     and classSchema in s!objectClass.
        #
        #     Let D be the sequence of objects o in the site of the local
        #     DC such that o!objectCategory = s. D is sorted in ascending
        #     order by objectGUID.
        #
        # Which is a fancy way of saying "sort all the nTDSDSA objects
        # in the site by guid in ascending order".   Place sorted list
        # in D_sort[]
        D_sort = []
        d_dsa = None

        unixnow = int(time.time())     # seconds since 1970
        ntnow = unix2nttime(unixnow) # double word number of 100 nanosecond
                                       # intervals since 1600s

        for dsa in self.dsa_table.values():
            D_sort.append(dsa)

        D_sort.sort(sort_dsa_by_guid)

        # Let f be the duration o!interSiteTopologyFailover seconds, or 2 hours
        # if o!interSiteTopologyFailover is 0 or has no value.
        #
        # Note: lastSuccess and ntnow are in 100 nanosecond intervals
        #       so it appears we have to turn f into the same interval
        #
        #       interSiteTopologyFailover (if set) appears to be in minutes
        #       so we'll need to convert to senconds and then 100 nanosecond
        #       intervals
        #
        #       10,000,000 is number of 100 nanosecond intervals in a second
        if self.site_topo_failover == 0:
            f = 2 * 60 * 60 * 10000000
        else:
            f = self.site_topo_failover * 60 * 10000000

        # From MS-Tech ISTG selection:
        #     If o != NULL and o!interSiteTopologyGenerator is not the
        #     nTDSDSA object for the local DC and
        #     o!interSiteTopologyGenerator is an element dj of sequence D:
        #
        if self.site_topo_generator is not None and \
           self.site_topo_generator in self.dsa_table.keys():
            d_dsa = self.dsa_table[self.site_topo_generator]
            j_idx = D_sort.index(d_dsa)

        if d_dsa is not None and d_dsa is not mydsa:
           # From MS-Tech ISTG selection:
           #     Let c be the cursor in the replUpToDateVector variable
           #     associated with the NC replica of the config NC such
           #     that c.uuidDsa = dj!invocationId. If no such c exists
           #     (No evidence of replication from current ITSG):
           #         Let i = j.
           #         Let t = 0.
           #
           #     Else if the current time < c.timeLastSyncSuccess - f
           #     (Evidence of time sync problem on current ISTG):
           #         Let i = 0.
           #         Let t = 0.
           #
           #     Else (Evidence of replication from current ITSG):
           #         Let i = j.
           #         Let t = c.timeLastSyncSuccess.
           #
           # last_success appears to be a double word containing
           #     number of 100 nanosecond intervals since the 1600s
           if d_dsa.dsa_ivid != c_rep.source_dsa_invocation_id:
               i_idx = j_idx
               t_time = 0

           elif ntnow < (c_rep.last_success - f):
               i_idx = 0
               t_time = 0
           else:
               i_idx = j_idx
               t_time = c_rep.last_success

        # Otherwise (Nominate local DC as ISTG):
        #     Let i be the integer such that di is the nTDSDSA
        #         object for the local DC.
        #     Let t = the current time.
        else:
            i_idx = D_sort.index(mydsa)
            t_time = ntnow

        # Compute a function that maintains the current ISTG if
        # it is alive, cycles through other candidates if not.
        #
        # Let k be the integer (i + ((current time - t) /
        #     o!interSiteTopologyFailover)) MOD |D|.
        #
        # Note: We don't want to divide by zero here so they must
        #       have meant "f" instead of "o!interSiteTopologyFailover"
        k_idx = (i_idx + ((ntnow - t_time) / f)) % len(D_sort)

        # The local writable DC acts as an ISTG for its site if and
        # only if dk is the nTDSDSA object for the local DC. If the
        # local DC does not act as an ISTG, the KCC skips the
        # remainder of this task.
        d_dsa = D_sort[k_idx]
        d_dsa.dsa_is_istg = True

        # Update if we are the ISTG, otherwise return
        if d_dsa is not mydsa:
            return False

        # Nothing to do
        if self.site_topo_generator == mydsa.dsa_dnstr:
            return True

        self.site_topo_generator = mydsa.dsa_dnstr

        # If readonly database then do not perform a
        # persistent update
        if ro:
            return True

        # Perform update to the samdb
        ssdn = "CN=NTDS Site Settings,%s" % self.site_dnstr

        m = ldb.Message()
        m.dn = ldb.Dn(samdb, ssdn)

        m["interSiteTopologyGenerator"] = \
            ldb.MessageElement(mydsa.dsa_dnstr, ldb.FLAG_MOD_REPLACE,
                               "interSiteTopologyGenerator")
        try:
            samdb.modify(m)

        except ldb.LdbError, estr:
            raise Exception(
                "Could not set interSiteTopologyGenerator for (%s) - (%s)" %
                (ssdn, estr))
        return True

    def is_intrasite_topology_disabled(self):
        '''Returns True if intra-site topology is disabled for site'''
        if (self.site_options &
            dsdb.DS_NTDSSETTINGS_OPT_IS_AUTO_TOPOLOGY_DISABLED) != 0:
            return True
        return False

    def is_intersite_topology_disabled(self):
        '''Returns True if inter-site topology is disabled for site'''
        if (self.site_options &
            dsdb.DS_NTDSSETTINGS_OPT_IS_INTER_SITE_AUTO_TOPOLOGY_DISABLED) != 0:
            return True
        return False

    def is_random_bridgehead_disabled(self):
        '''Returns True if selection of random bridgehead is disabled'''
        if (self.site_options &
            dsdb.DS_NTDSSETTINGS_OPT_IS_RAND_BH_SELECTION_DISABLED) != 0:
            return True
        return False

    def is_detect_stale_disabled(self):
        '''Returns True if detect stale is disabled for site'''
        if (self.site_options &
            dsdb.DS_NTDSSETTINGS_OPT_IS_TOPL_DETECT_STALE_DISABLED) != 0:
            return True
        return False

    def is_cleanup_ntdsconn_disabled(self):
        '''Returns True if NTDS Connection cleanup is disabled for site'''
        if (self.site_options &
            dsdb.DS_NTDSSETTINGS_OPT_IS_TOPL_CLEANUP_DISABLED) != 0:
            return True
        return False

    def same_site(self, dsa):
       '''Return True if dsa is in this site'''
       if self.get_dsa(dsa.dsa_dnstr):
           return True
       return False

    def __str__(self):
        '''Debug dump string output of class'''
        text = "%s:" % self.__class__.__name__
        text = text + "\n\tdn=%s"             % self.site_dnstr
        text = text + "\n\toptions=0x%X"      % self.site_options
        text = text + "\n\ttopo_generator=%s" % self.site_topo_generator
        text = text + "\n\ttopo_failover=%d"  % self.site_topo_failover
        for key, dsa in self.dsa_table.items():
            text = text + "\n%s" % dsa
        return text


class GraphNode(object):
    """A graph node describing a set of edges that should be directed to it.

    Each edge is a connection for a particular naming context replica directed
    from another node in the forest to this node.
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
        text = "%s:" % self.__class__.__name__
        text = text + "\n\tdsa_dnstr=%s" % self.dsa_dnstr
        text = text + "\n\tmax_edges=%d" % self.max_edges

        for i, edge in enumerate(self.edge_from):
            text = text + "\n\tedge_from[%d]=%s" % (i, edge)
        return text

    def add_edge_from(self, from_dsa_dnstr):
        """Add an edge from the dsa to our graph nodes edge from list

        :param from_dsa_dnstr: the dsa that the edge emanates from
        """
        assert from_dsa_dnstr is not None

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
            if connect and not connect.is_rodc_topology():
                exists = True
            else:
                exists = False

            # if no such object exists then the KCC adds an object
            # c with the following attributes
            if exists:
                return

            # Generate a new dnstr for this nTDSConnection
            opt = dsdb.NTDSCONN_OPT_IS_GENERATED
            flags = dsdb.SYSTEM_FLAG_CONFIG_ALLOW_RENAME + \
                     dsdb.SYSTEM_FLAG_CONFIG_ALLOW_MOVE

            dsa.create_connection(opt, flags, None, edge_dnstr, None)

    def has_sufficient_edges(self):
        '''Return True if we have met the maximum "from edges" criteria'''
        if len(self.edge_from) >= self.max_edges:
            return True
        return False


class Transport(object):
    """Class defines a Inter-site transport found under Sites
    """

    def __init__(self, dnstr):
        self.dnstr = dnstr
        self.options = 0
        self.guid = None
        self.name = None
        self.address_attr = None
        self.bridgehead_list = []

    def __str__(self):
        '''Debug dump string output of Transport object'''

        text = "%s:\n\tdn=%s" % (self.__class__.__name__, self.dnstr)
        text = text + "\n\tguid=%s" % str(self.guid)
        text = text + "\n\toptions=%d" % self.options
        text = text + "\n\taddress_attr=%s" % self.address_attr
        text = text + "\n\tname=%s" % self.name
        for dnstr in self.bridgehead_list:
            text = text + "\n\tbridgehead_list=%s" % dnstr

        return text

    def load_transport(self, samdb):
        """Given a Transport object with an prior initialization
        for the object's DN, search for the DN and load attributes
        from the samdb.
        """
        attrs = [ "objectGUID",
                  "options",
                  "name",
                  "bridgeheadServerListBL",
                  "transportAddressAttribute" ]
        try:
            res = samdb.search(base=self.dnstr, scope=ldb.SCOPE_BASE,
                               attrs=attrs)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find Transport for (%s) - (%s)" %
                            (self.dnstr, estr))

        msg = res[0]
        self.guid = misc.GUID(samdb.schema_format_value("objectGUID",
                              msg["objectGUID"][0]))

        if "options" in msg:
            self.options = int(msg["options"][0])

        if "transportAddressAttribute" in msg:
            self.address_attr = str(msg["transportAddressAttribute"][0])

        if "name" in msg:
            self.name = str(msg["name"][0])

        if "bridgeheadServerListBL" in msg:
            for value in msg["bridgeheadServerListBL"]:
                dsdn = dsdb_Dn(samdb, value)
                dnstr = str(dsdn.dn)
                if dnstr not in self.bridgehead_list:
                    self.bridgehead_list.append(dnstr)


class RepsFromTo(object):
    """Class encapsulation of the NDR repsFromToBlob.

    Removes the necessity of external code having to
    understand about other_info or manipulation of
    update flags.
    """
    def __init__(self, nc_dnstr=None, ndr_blob=None):

        self.__dict__['to_be_deleted'] = False
        self.__dict__['nc_dnstr'] = nc_dnstr
        self.__dict__['update_flags'] = 0x0

        # WARNING:
        #
        # There is a very subtle bug here with python
        # and our NDR code.  If you assign directly to
        # a NDR produced struct (e.g. t_repsFrom.ctr.other_info)
        # then a proper python GC reference count is not
        # maintained.
        #
        # To work around this we maintain an internal
        # reference to "dns_name(x)" and "other_info" elements
        # of repsFromToBlob.  This internal reference
        # is hidden within this class but it is why you
        # see statements like this below:
        #
        #   self.__dict__['ndr_blob'].ctr.other_info = \
        #        self.__dict__['other_info'] = drsblobs.repsFromTo1OtherInfo()
        #
        # That would appear to be a redundant assignment but
        # it is necessary to hold a proper python GC reference
        # count.
        if ndr_blob is None:
            self.__dict__['ndr_blob'] = drsblobs.repsFromToBlob()
            self.__dict__['ndr_blob'].version = 0x1
            self.__dict__['dns_name1'] = None
            self.__dict__['dns_name2'] = None

            self.__dict__['ndr_blob'].ctr.other_info = \
                self.__dict__['other_info'] = drsblobs.repsFromTo1OtherInfo()

        else:
            self.__dict__['ndr_blob'] = ndr_blob
            self.__dict__['other_info'] = ndr_blob.ctr.other_info

            if ndr_blob.version == 0x1:
                self.__dict__['dns_name1'] = ndr_blob.ctr.other_info.dns_name
                self.__dict__['dns_name2'] = None
            else:
                self.__dict__['dns_name1'] = ndr_blob.ctr.other_info.dns_name1
                self.__dict__['dns_name2'] = ndr_blob.ctr.other_info.dns_name2

    def __str__(self):
        '''Debug dump string output of class'''

        text = "%s:" % self.__class__.__name__
        text = text + "\n\tdnstr=%s" % self.nc_dnstr
        text = text + "\n\tupdate_flags=0x%X" % self.update_flags

        text = text + "\n\tversion=%d" % self.version
        text = text + "\n\tsource_dsa_obj_guid=%s" % \
               str(self.source_dsa_obj_guid)
        text = text + "\n\tsource_dsa_invocation_id=%s" % \
               str(self.source_dsa_invocation_id)
        text = text + "\n\ttransport_guid=%s" % \
               str(self.transport_guid)
        text = text + "\n\treplica_flags=0x%X" % \
               self.replica_flags
        text = text + "\n\tconsecutive_sync_failures=%d" % \
               self.consecutive_sync_failures
        text = text + "\n\tlast_success=%s" % \
               self.last_success
        text = text + "\n\tlast_attempt=%s" % \
               self.last_attempt
        text = text + "\n\tdns_name1=%s" % \
               str(self.dns_name1)
        text = text + "\n\tdns_name2=%s" % \
               str(self.dns_name2)
        text = text + "\n\tschedule[ "
        for slot in self.schedule:
            text = text + "0x%X " % slot
        text = text + "]"

        return text

    def __setattr__(self, item, value):

        if item in [ 'schedule', 'replica_flags', 'transport_guid',
                     'source_dsa_obj_guid', 'source_dsa_invocation_id',
                     'consecutive_sync_failures', 'last_success',
                     'last_attempt' ]:

            if item in ['replica_flags']:
                self.__dict__['update_flags'] |= drsuapi.DRSUAPI_DRS_UPDATE_FLAGS
            elif item in ['schedule']:
                self.__dict__['update_flags'] |= drsuapi.DRSUAPI_DRS_UPDATE_SCHEDULE

            setattr(self.__dict__['ndr_blob'].ctr, item, value)

        elif item in ['dns_name1']:
            self.__dict__['dns_name1'] = value

            if self.__dict__['ndr_blob'].version == 0x1:
                self.__dict__['ndr_blob'].ctr.other_info.dns_name = \
                    self.__dict__['dns_name1']
            else:
                self.__dict__['ndr_blob'].ctr.other_info.dns_name1 = \
                    self.__dict__['dns_name1']

        elif item in ['dns_name2']:
            self.__dict__['dns_name2'] = value

            if self.__dict__['ndr_blob'].version == 0x1:
                raise AttributeError(item)
            else:
                self.__dict__['ndr_blob'].ctr.other_info.dns_name2 = \
                    self.__dict__['dns_name2']

        elif item in ['nc_dnstr']:
            self.__dict__['nc_dnstr'] = value

        elif item in ['to_be_deleted']:
            self.__dict__['to_be_deleted'] = value

        elif item in ['version']:
            raise AttributeError, "Attempt to set readonly attribute %s" % item
        else:
            raise AttributeError, "Unknown attribute %s" % item

        self.__dict__['update_flags'] |= drsuapi.DRSUAPI_DRS_UPDATE_ADDRESS

    def __getattr__(self, item):
        """Overload of RepsFromTo attribute retrieval.

        Allows external code to ignore substructures within the blob
        """
        if item in [ 'schedule', 'replica_flags', 'transport_guid',
                     'source_dsa_obj_guid', 'source_dsa_invocation_id',
                     'consecutive_sync_failures', 'last_success',
                     'last_attempt' ]:
            return getattr(self.__dict__['ndr_blob'].ctr, item)

        elif item in ['version']:
            return self.__dict__['ndr_blob'].version

        elif item in ['dns_name1']:
            if self.__dict__['ndr_blob'].version == 0x1:
                return self.__dict__['ndr_blob'].ctr.other_info.dns_name
            else:
                return self.__dict__['ndr_blob'].ctr.other_info.dns_name1

        elif item in ['dns_name2']:
            if self.__dict__['ndr_blob'].version == 0x1:
                raise AttributeError(item)
            else:
                return self.__dict__['ndr_blob'].ctr.other_info.dns_name2

        elif item in ['to_be_deleted']:
            return self.__dict__['to_be_deleted']

        elif item in ['nc_dnstr']:
            return self.__dict__['nc_dnstr']

        elif item in ['update_flags']:
            return self.__dict__['update_flags']

        raise AttributeError, "Unknwown attribute %s" % item

    def is_modified(self):
        return (self.update_flags != 0x0)

    def set_unmodified(self):
        self.__dict__['update_flags'] = 0x0


class SiteLink(object):
    """Class defines a site link found under sites
    """

    def __init__(self, dnstr):
        self.dnstr = dnstr
        self.options = 0
        self.system_flags = 0
        self.cost = 0
        self.schedule = None
        self.interval = None
        self.site_list = []

    def __str__(self):
        '''Debug dump string output of Transport object'''

        text = "%s:\n\tdn=%s" % (self.__class__.__name__, self.dnstr)
        text = text + "\n\toptions=%d" % self.options
        text = text + "\n\tsystem_flags=%d" % self.system_flags
        text = text + "\n\tcost=%d" % self.cost
        text = text + "\n\tinterval=%s" % self.interval

        if self.schedule is not None:
            text = text + "\n\tschedule.size=%s" % self.schedule.size
            text = text + "\n\tschedule.bandwidth=%s" % self.schedule.bandwidth
            text = text + "\n\tschedule.numberOfSchedules=%s" % \
                   self.schedule.numberOfSchedules

            for i, header in enumerate(self.schedule.headerArray):
                text = text + "\n\tschedule.headerArray[%d].type=%d" % \
                       (i, header.type)
                text = text + "\n\tschedule.headerArray[%d].offset=%d" % \
                       (i, header.offset)
                text = text + "\n\tschedule.dataArray[%d].slots[ " % i
                for slot in self.schedule.dataArray[i].slots:
                    text = text + "0x%X " % slot
                text = text + "]"

        for dnstr in self.site_list:
            text = text + "\n\tsite_list=%s" % dnstr
        return text

    def load_sitelink(self, samdb):
        """Given a siteLink object with an prior initialization
        for the object's DN, search for the DN and load attributes
        from the samdb.
        """
        attrs = [ "options",
                  "systemFlags",
                  "cost",
                  "schedule",
                  "replInterval",
                  "siteList" ]
        try:
            res = samdb.search(base=self.dnstr, scope=ldb.SCOPE_BASE,
                               attrs=attrs)

        except ldb.LdbError, (enum, estr):
            raise Exception("Unable to find SiteLink for (%s) - (%s)" %
                            (self.dnstr, estr))

        msg = res[0]

        if "options" in msg:
            self.options = int(msg["options"][0])

        if "systemFlags" in msg:
            self.system_flags = int(msg["systemFlags"][0])

        if "cost" in msg:
            self.cost = int(msg["cost"][0])

        if "replInterval" in msg:
            self.interval = int(msg["replInterval"][0])

        if "siteList" in msg:
            for value in msg["siteList"]:
                dsdn = dsdb_Dn(samdb, value)
                dnstr = str(dsdn.dn)
                if dnstr not in self.site_list:
                    self.site_list.append(dnstr)

    def is_sitelink(self, site1_dnstr, site2_dnstr):
        """Given a siteLink object, determine if it is a link
        between the two input site DNs
        """
        if site1_dnstr in self.site_list and site2_dnstr in self.site_list:
            return True
        return False


class VertexColor(object):
    (unknown, white, black, red) = range(0, 4)


class Vertex(object):
    """Class encapsulation of a Site Vertex in the
    intersite topology replication algorithm
    """
    def __init__(self, site, part):
        self.site = site
        self.part = part
        self.color = VertexColor.unknown

    def color_vertex(self):
        """Color each vertex to indicate which kind of NC
        replica it contains
        """
        # IF s contains one or more DCs with full replicas of the
        # NC cr!nCName
        #    SET v.Color to COLOR.RED
        # ELSEIF s contains one or more partial replicas of the NC
        #    SET v.Color to COLOR.BLACK
        #ELSE
        #    SET v.Color to COLOR.WHITE

        # set to minimum (no replica)
        self.color = VertexColor.white

        for dnstr, dsa in self.site.dsa_table.items():
            rep = dsa.get_current_replica(self.part.nc_dnstr)
            if rep is None:
                continue

            # We have a full replica which is the largest
            # value so exit
            if not rep.is_partial():
                self.color = VertexColor.red
                break
            else:
                self.color = VertexColor.black

    def is_red(self):
        assert(self.color != VertexColor.unknown)
        return (self.color == VertexColor.red)

    def is_black(self):
        assert(self.color != VertexColor.unknown)
        return (self.color == VertexColor.black)

    def is_white(self):
        assert(self.color != VertexColor.unknown)
        return (self.color == VertexColor.white)

##################################################
# Global Functions
##################################################
def sort_dsa_by_guid(dsa1, dsa2):
    return cmp(dsa1.dsa_guid, dsa2.dsa_guid)
