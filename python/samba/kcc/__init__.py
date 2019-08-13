# define the KCC object
#
# Copyright (C) Dave Craft 2011
# Copyright (C) Andrew Bartlett 2015
#
# Andrew Bartlett's alleged work performed by his underlings Douglas
# Bagnall and Garming Sam.
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

import random
import uuid

import itertools
from samba import unix2nttime, nttime2unix
from samba import ldb, dsdb, drs_utils
from samba.auth import system_session
from samba.samdb import SamDB
from samba.dcerpc import drsuapi, misc

from samba.kcc.kcc_utils import Site, Partition, Transport, SiteLink
from samba.kcc.kcc_utils import NCReplica, NCType, nctype_lut, GraphNode
from samba.kcc.kcc_utils import RepsFromTo, KCCError, KCCFailedObject
from samba.kcc.graph import convert_schedule_to_repltimes

from samba.ndr import ndr_pack

from samba.kcc.graph_utils import verify_and_dot

from samba.kcc import ldif_import_export
from samba.kcc.graph import setup_graph, get_spanning_tree_edges
from samba.kcc.graph import Vertex

from samba.kcc.debug import DEBUG, DEBUG_FN, logger
from samba.kcc import debug
from samba.compat import cmp_fn


def sort_dsa_by_gc_and_guid(dsa1, dsa2):
    """Helper to sort DSAs by guid global catalog status

    GC DSAs come before non-GC DSAs, other than that, the guids are
    sorted in NDR form.

    :param dsa1: A DSA object
    :param dsa2: Another DSA
    :return: -1, 0, or 1, indicating sort order.
    """
    if dsa1.is_gc() and not dsa2.is_gc():
        return -1
    if not dsa1.is_gc() and dsa2.is_gc():
        return +1
    return cmp_fn(ndr_pack(dsa1.dsa_guid), ndr_pack(dsa2.dsa_guid))


def is_smtp_replication_available():
    """Can the KCC use SMTP replication?

    Currently always returns false because Samba doesn't implement
    SMTP transfer for NC changes between DCs.

    :return: Boolean (always False)
    """
    return False


class KCC(object):
    """The Knowledge Consistency Checker class.

    A container for objects and methods allowing a run of the KCC.  Produces a
    set of connections in the samdb for which the Distributed Replication
    Service can then utilize to replicate naming contexts

    :param unix_now: The putative current time in seconds since 1970.
    :param readonly: Don't write to the database.
    :param verify: Check topological invariants for the generated graphs
    :param debug: Write verbosely to stderr.
    :param dot_file_dir: write diagnostic Graphviz files in this directory
    """
    def __init__(self, unix_now, readonly=False, verify=False, debug=False,
                 dot_file_dir=None):
        """Initializes the partitions class which can hold
        our local DCs partitions or all the partitions in
        the forest
        """
        self.part_table = {}    # partition objects
        self.site_table = {}
        self.ip_transport = None
        self.sitelink_table = {}
        self.dsa_by_dnstr = {}
        self.dsa_by_guid = {}

        self.get_dsa_by_guidstr = self.dsa_by_guid.get
        self.get_dsa = self.dsa_by_dnstr.get

        # TODO: These should be backed by a 'permanent' store so that when
        # calling DRSGetReplInfo with DS_REPL_INFO_KCC_DSA_CONNECT_FAILURES,
        # the failure information can be returned
        self.kcc_failed_links = {}
        self.kcc_failed_connections = set()

        # Used in inter-site topology computation.  A list
        # of connections (by NTDSConnection object) that are
        # to be kept when pruning un-needed NTDS Connections
        self.kept_connections = set()

        self.my_dsa_dnstr = None  # My dsa DN
        self.my_dsa = None  # My dsa object

        self.my_site_dnstr = None
        self.my_site = None

        self.samdb = None

        self.unix_now = unix_now
        self.nt_now = unix2nttime(unix_now)
        self.readonly = readonly
        self.verify = verify
        self.debug = debug
        self.dot_file_dir = dot_file_dir

    def load_ip_transport(self):
        """Loads the inter-site transport objects for Sites

        :return: None
        :raise KCCError: if no IP transport is found
        """
        try:
            res = self.samdb.search("CN=Inter-Site Transports,CN=Sites,%s" %
                                    self.samdb.get_config_basedn(),
                                    scope=ldb.SCOPE_SUBTREE,
                                    expression="(objectClass=interSiteTransport)")
        except ldb.LdbError as e2:
            (enum, estr) = e2.args
            raise KCCError("Unable to find inter-site transports - (%s)" %
                           estr)

        for msg in res:
            dnstr = str(msg.dn)

            transport = Transport(dnstr)

            transport.load_transport(self.samdb)
            if transport.name == 'IP':
                self.ip_transport = transport
            elif transport.name == 'SMTP':
                logger.debug("Samba KCC is ignoring the obsolete "
                             "SMTP transport.")

            else:
                logger.warning("Samba KCC does not support the transport "
                               "called %r." % (transport.name,))

        if self.ip_transport is None:
            raise KCCError("there doesn't seem to be an IP transport")

    def load_all_sitelinks(self):
        """Loads the inter-site siteLink objects

        :return: None
        :raise KCCError: if site-links aren't found
        """
        try:
            res = self.samdb.search("CN=Inter-Site Transports,CN=Sites,%s" %
                                    self.samdb.get_config_basedn(),
                                    scope=ldb.SCOPE_SUBTREE,
                                    expression="(objectClass=siteLink)")
        except ldb.LdbError as e3:
            (enum, estr) = e3.args
            raise KCCError("Unable to find inter-site siteLinks - (%s)" % estr)

        for msg in res:
            dnstr = str(msg.dn)

            # already loaded
            if dnstr in self.sitelink_table:
                continue

            sitelink = SiteLink(dnstr)

            sitelink.load_sitelink(self.samdb)

            # Assign this siteLink to table
            # and index by dn
            self.sitelink_table[dnstr] = sitelink

    def load_site(self, dn_str):
        """Helper for load_my_site and load_all_sites.

        Put all the site's DSAs into the KCC indices.

        :param dn_str: a site dn_str
        :return: the Site object pertaining to the dn_str
        """
        site = Site(dn_str, self.unix_now)
        site.load_site(self.samdb)

        # We avoid replacing the site with an identical copy in case
        # somewhere else has a reference to the old one, which would
        # lead to all manner of confusion and chaos.
        guid = str(site.site_guid)
        if guid not in self.site_table:
            self.site_table[guid] = site
            self.dsa_by_dnstr.update(site.dsa_table)
            self.dsa_by_guid.update((str(x.dsa_guid), x)
                                    for x in site.dsa_table.values())

        return self.site_table[guid]

    def load_my_site(self):
        """Load the Site object for the local DSA.

        :return: None
        """
        self.my_site_dnstr = ("CN=%s,CN=Sites,%s" % (
            self.samdb.server_site_name(),
            self.samdb.get_config_basedn()))

        self.my_site = self.load_site(self.my_site_dnstr)

    def load_all_sites(self):
        """Discover all sites and create Site objects.

        :return: None
        :raise: KCCError if sites can't be found
        """
        try:
            res = self.samdb.search("CN=Sites,%s" %
                                    self.samdb.get_config_basedn(),
                                    scope=ldb.SCOPE_SUBTREE,
                                    expression="(objectClass=site)")
        except ldb.LdbError as e4:
            (enum, estr) = e4.args
            raise KCCError("Unable to find sites - (%s)" % estr)

        for msg in res:
            sitestr = str(msg.dn)
            self.load_site(sitestr)

    def load_my_dsa(self):
        """Discover my nTDSDSA dn thru the rootDSE entry

        :return: None
        :raise: KCCError if DSA can't be found
        """
        dn_query = "<GUID=%s>" % self.samdb.get_ntds_GUID()
        dn = ldb.Dn(self.samdb, dn_query)
        try:
            res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                                    attrs=["objectGUID"])
        except ldb.LdbError as e5:
            (enum, estr) = e5.args
            DEBUG_FN("Search for dn '%s' [from %s] failed: %s. "
                     "This typically happens in --importldif mode due "
                     "to lack of module support." % (dn, dn_query, estr))
            try:
                # We work around the failure above by looking at the
                # dsServiceName that was put in the fake rootdse by
                # the --exportldif, rather than the
                # samdb.get_ntds_GUID(). The disadvantage is that this
                # mode requires we modify the @ROOTDSE dnq to support
                # --forced-local-dsa
                service_name_res = self.samdb.search(base="",
                                                     scope=ldb.SCOPE_BASE,
                                                     attrs=["dsServiceName"])
                dn = ldb.Dn(self.samdb,
                            service_name_res[0]["dsServiceName"][0].decode('utf8'))

                res = self.samdb.search(base=dn, scope=ldb.SCOPE_BASE,
                                        attrs=["objectGUID"])
            except ldb.LdbError as e:
                (enum, estr) = e.args
                raise KCCError("Unable to find my nTDSDSA - (%s)" % estr)

        if len(res) != 1:
            raise KCCError("Unable to find my nTDSDSA at %s" %
                           dn.extended_str())

        ntds_guid = misc.GUID(self.samdb.get_ntds_GUID())
        if misc.GUID(res[0]["objectGUID"][0]) != ntds_guid:
            raise KCCError("Did not find the GUID we expected,"
                           " perhaps due to --importldif")

        self.my_dsa_dnstr = str(res[0].dn)

        self.my_dsa = self.my_site.get_dsa(self.my_dsa_dnstr)

        if self.my_dsa_dnstr not in self.dsa_by_dnstr:
            debug.DEBUG_DARK_YELLOW("my_dsa %s isn't in self.dsas_by_dnstr:"
                                    " it must be RODC.\n"
                                    "Let's add it, because my_dsa is special!"
                                    "\n(likewise for self.dsa_by_guid)" %
                                    self.my_dsa_dnstr)

            self.dsa_by_dnstr[self.my_dsa_dnstr] = self.my_dsa
            self.dsa_by_guid[str(self.my_dsa.dsa_guid)] = self.my_dsa

    def load_all_partitions(self):
        """Discover and load all partitions.

        Each NC is inserted into the part_table by partition
        dn string (not the nCName dn string)

        :return: None
        :raise: KCCError if partitions can't be found
        """
        try:
            res = self.samdb.search("CN=Partitions,%s" %
                                    self.samdb.get_config_basedn(),
                                    scope=ldb.SCOPE_SUBTREE,
                                    expression="(objectClass=crossRef)")
        except ldb.LdbError as e6:
            (enum, estr) = e6.args
            raise KCCError("Unable to find partitions - (%s)" % estr)

        for msg in res:
            partstr = str(msg.dn)

            # already loaded
            if partstr in self.part_table:
                continue

            part = Partition(partstr)

            part.load_partition(self.samdb)
            self.part_table[partstr] = part

    def refresh_failed_links_connections(self, ping=None):
        """Ensure the failed links list is up to date

        Based on MS-ADTS 6.2.2.1

        :param ping: An oracle function of remote site availability
        :return: None
        """
        # LINKS: Refresh failed links
        self.kcc_failed_links = {}
        current, needed = self.my_dsa.get_rep_tables()
        for replica in current.values():
            # For every possible connection to replicate
            for reps_from in replica.rep_repsFrom:
                failure_count = reps_from.consecutive_sync_failures
                if failure_count <= 0:
                    continue

                dsa_guid = str(reps_from.source_dsa_obj_guid)
                time_first_failure = reps_from.last_success
                last_result = reps_from.last_attempt
                dns_name = reps_from.dns_name1

                f = self.kcc_failed_links.get(dsa_guid)
                if f is None:
                    f = KCCFailedObject(dsa_guid, failure_count,
                                        time_first_failure, last_result,
                                        dns_name)
                    self.kcc_failed_links[dsa_guid] = f
                else:
                    f.failure_count = max(f.failure_count, failure_count)
                    f.time_first_failure = min(f.time_first_failure,
                                               time_first_failure)
                    f.last_result = last_result

        # CONNECTIONS: Refresh failed connections
        restore_connections = set()
        if ping is not None:
            DEBUG("refresh_failed_links: checking if links are still down")
            for connection in self.kcc_failed_connections:
                if ping(connection.dns_name):
                    # Failed connection is no longer failing
                    restore_connections.add(connection)
                else:
                    connection.failure_count += 1
        else:
            DEBUG("refresh_failed_links: not checking live links because we\n"
                  "weren't asked to --attempt-live-connections")

        # Remove the restored connections from the failed connections
        self.kcc_failed_connections.difference_update(restore_connections)

    def is_stale_link_connection(self, target_dsa):
        """Check whether a link to a remote DSA is stale

        Used in MS-ADTS 6.2.2.2 Intrasite Connection Creation

        Returns True if the remote seems to have been down for at
        least two hours, otherwise False.

        :param target_dsa: the remote DSA object
        :return: True if link is stale, otherwise False
        """
        failed_link = self.kcc_failed_links.get(str(target_dsa.dsa_guid))
        if failed_link:
            # failure_count should be > 0, but check anyways
            if failed_link.failure_count > 0:
                unix_first_failure = \
                    nttime2unix(failed_link.time_first_failure)
                # TODO guard against future
                if unix_first_failure > self.unix_now:
                    logger.error("The last success time attribute for \
                                 repsFrom is in the future!")

                # Perform calculation in seconds
                if (self.unix_now - unix_first_failure) > 60 * 60 * 2:
                    return True

        # TODO connections.
        # We have checked failed *links*, but we also need to check
        # *connections*

        return False

    # TODO: This should be backed by some form of local database
    def remove_unneeded_failed_links_connections(self):
        # Remove all tuples in kcc_failed_links where failure count = 0
        # In this implementation, this should never happen.

        # Remove all connections which were not used this run or connections
        # that became active during this run.
        pass

    def _ensure_connections_are_loaded(self, connections):
        """Load or fake-load NTDSConnections lacking GUIDs

        New connections don't have GUIDs and created times which are
        needed for sorting. If we're in read-only mode, we make fake
        GUIDs, otherwise we ask SamDB to do it for us.

        :param connections: an iterable of NTDSConnection objects.
        :return: None
        """
        for cn_conn in connections:
            if cn_conn.guid is None:
                if self.readonly:
                    cn_conn.guid = misc.GUID(str(uuid.uuid4()))
                    cn_conn.whenCreated = self.nt_now
                else:
                    cn_conn.load_connection(self.samdb)

    def _mark_broken_ntdsconn(self):
        """Find NTDS Connections that lack a remote

        I'm not sure how they appear. Let's be rid of them by marking
        them with the to_be_deleted attribute.

        :return: None
        """
        for cn_conn in self.my_dsa.connect_table.values():
            s_dnstr = cn_conn.get_from_dnstr()
            if s_dnstr is None:
                DEBUG_FN("%s has phantom connection %s" % (self.my_dsa,
                                                           cn_conn))
                cn_conn.to_be_deleted = True

    def _mark_unneeded_local_ntdsconn(self):
        """Find unneeded intrasite NTDS Connections for removal

        Based on MS-ADTS 6.2.2.4 Removing Unnecessary Connections.
        Every DC removes its own unnecessary intrasite connections.
        This function tags them with the to_be_deleted attribute.

        :return: None
        """
        # XXX should an RODC be regarded as same site? It isn't part
        # of the intrasite ring.

        if self.my_site.is_cleanup_ntdsconn_disabled():
            DEBUG_FN("not doing ntdsconn cleanup for site %s, "
                     "because it is disabled" % self.my_site)
            return

        mydsa = self.my_dsa

        try:
            self._ensure_connections_are_loaded(mydsa.connect_table.values())
        except KCCError:
            # RODC never actually added any connections to begin with
            if mydsa.is_ro():
                return

        local_connections = []

        for cn_conn in mydsa.connect_table.values():
            s_dnstr = cn_conn.get_from_dnstr()
            if s_dnstr in self.my_site.dsa_table:
                removable = not (cn_conn.is_generated() or
                                 cn_conn.is_rodc_topology())
                packed_guid = ndr_pack(cn_conn.guid)
                local_connections.append((cn_conn, s_dnstr,
                                          packed_guid, removable))

        # Avoid "ValueError: r cannot be bigger than the iterable" in
        # for a, b in itertools.permutations(local_connections, 2):
        if (len(local_connections) < 2):
            return

        for a, b in itertools.permutations(local_connections, 2):
            cn_conn, s_dnstr, packed_guid, removable = a
            cn_conn2, s_dnstr2, packed_guid2, removable2 = b
            if (removable and
                s_dnstr == s_dnstr2 and
                cn_conn.whenCreated < cn_conn2.whenCreated or
                (cn_conn.whenCreated == cn_conn2.whenCreated and
                 packed_guid < packed_guid2)):
                cn_conn.to_be_deleted = True

    def _mark_unneeded_intersite_ntdsconn(self):
        """find unneeded intersite NTDS Connections for removal

        Based on MS-ADTS 6.2.2.4 Removing Unnecessary Connections. The
        intersite topology generator removes links for all DCs in its
        site. Here we just tag them with the to_be_deleted attribute.

        :return: None
        """
        # TODO Figure out how best to handle the RODC case
        # The RODC is ISTG, but shouldn't act on anyone's behalf.
        if self.my_dsa.is_ro():
            return

        # Find the intersite connections
        local_dsas = self.my_site.dsa_table
        connections_and_dsas = []
        for dsa in local_dsas.values():
            for cn in dsa.connect_table.values():
                if cn.to_be_deleted:
                    continue
                s_dnstr = cn.get_from_dnstr()
                if s_dnstr is None:
                    continue
                if s_dnstr not in local_dsas:
                    from_dsa = self.get_dsa(s_dnstr)
                    # Samba ONLY: ISTG removes connections to dead DCs
                    if from_dsa is None or '\\0ADEL' in s_dnstr:
                        logger.info("DSA appears deleted, removing connection %s"
                                    % s_dnstr)
                        cn.to_be_deleted = True
                        continue
                    connections_and_dsas.append((cn, dsa, from_dsa))

        self._ensure_connections_are_loaded(x[0] for x in connections_and_dsas)
        for cn, to_dsa, from_dsa in connections_and_dsas:
            if not cn.is_generated() or cn.is_rodc_topology():
                continue

            # If the connection is in the kept_connections list, we
            # only remove it if an endpoint seems down.
            if (cn in self.kept_connections and
                not (self.is_bridgehead_failed(to_dsa, True) or
                     self.is_bridgehead_failed(from_dsa, True))):
                continue

            # this one is broken and might be superseded by another.
            # But which other? Let's just say another link to the same
            # site can supersede.
            from_dnstr = from_dsa.dsa_dnstr
            for site in self.site_table.values():
                if from_dnstr in site.rw_dsa_table:
                    for cn2, to_dsa2, from_dsa2 in connections_and_dsas:
                        if (cn is not cn2 and
                            from_dsa2 in site.rw_dsa_table):
                            cn.to_be_deleted = True

    def _commit_changes(self, dsa):
        if dsa.is_ro() or self.readonly:
            for connect in dsa.connect_table.values():
                if connect.to_be_deleted:
                    logger.info("TO BE DELETED:\n%s" % connect)
                if connect.to_be_added:
                    logger.info("TO BE ADDED:\n%s" % connect)
                if connect.to_be_modified:
                    logger.info("TO BE MODIFIED:\n%s" % connect)

            # Peform deletion from our tables but perform
            # no database modification
            dsa.commit_connections(self.samdb, ro=True)
        else:
            # Commit any modified connections
            dsa.commit_connections(self.samdb)

    def remove_unneeded_ntdsconn(self, all_connected):
        """Remove unneeded NTDS Connections once topology is calculated

        Based on MS-ADTS 6.2.2.4 Removing Unnecessary Connections

        :param all_connected: indicates whether all sites are connected
        :return: None
        """
        self._mark_broken_ntdsconn()
        self._mark_unneeded_local_ntdsconn()
        # if we are not the istg, we're done!
        # if we are the istg, but all_connected is False, we also do nothing.
        if self.my_dsa.is_istg() and all_connected:
            self._mark_unneeded_intersite_ntdsconn()

        for dsa in self.my_site.dsa_table.values():
            self._commit_changes(dsa)

    def modify_repsFrom(self, n_rep, t_repsFrom, s_rep, s_dsa, cn_conn):
        """Update an repsFrom object if required.

        Part of MS-ADTS 6.2.2.5.

        Update t_repsFrom if necessary to satisfy requirements. Such
        updates are typically required when the IDL_DRSGetNCChanges
        server has moved from one site to another--for example, to
        enable compression when the server is moved from the
        client's site to another site.

        The repsFrom.update_flags bit field may be modified
        auto-magically if any changes are made here. See
        kcc_utils.RepsFromTo for gory details.


        :param n_rep: NC replica we need
        :param t_repsFrom: repsFrom tuple to modify
        :param s_rep: NC replica at source DSA
        :param s_dsa: source DSA
        :param cn_conn: Local DSA NTDSConnection child

        :return: None
        """
        s_dnstr = s_dsa.dsa_dnstr
        same_site = s_dnstr in self.my_site.dsa_table

        # if schedule doesn't match then update and modify
        times = convert_schedule_to_repltimes(cn_conn.schedule)
        if times != t_repsFrom.schedule:
            t_repsFrom.schedule = times

        # Bit DRS_ADD_REF is set in replicaFlags unconditionally
        # Samba ONLY:
        if ((t_repsFrom.replica_flags &
             drsuapi.DRSUAPI_DRS_ADD_REF) == 0x0):
            t_repsFrom.replica_flags |= drsuapi.DRSUAPI_DRS_ADD_REF

        # Bit DRS_PER_SYNC is set in replicaFlags if and only
        # if nTDSConnection schedule has a value v that specifies
        # scheduled replication is to be performed at least once
        # per week.
        if cn_conn.is_schedule_minimum_once_per_week():

            if ((t_repsFrom.replica_flags &
                 drsuapi.DRSUAPI_DRS_PER_SYNC) == 0x0):
                t_repsFrom.replica_flags |= drsuapi.DRSUAPI_DRS_PER_SYNC

        # Bit DRS_INIT_SYNC is set in t.replicaFlags if and only
        # if the source DSA and the local DC's nTDSDSA object are
        # in the same site or source dsa is the FSMO role owner
        # of one or more FSMO roles in the NC replica.
        if same_site or n_rep.is_fsmo_role_owner(s_dnstr):

            if ((t_repsFrom.replica_flags &
                 drsuapi.DRSUAPI_DRS_INIT_SYNC) == 0x0):
                t_repsFrom.replica_flags |= drsuapi.DRSUAPI_DRS_INIT_SYNC

        # If bit NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT is set in
        # cn!options, bit DRS_NEVER_NOTIFY is set in t.replicaFlags
        # if and only if bit NTDSCONN_OPT_USE_NOTIFY is clear in
        # cn!options. Otherwise, bit DRS_NEVER_NOTIFY is set in
        # t.replicaFlags if and only if s and the local DC's
        # nTDSDSA object are in different sites.
        if ((cn_conn.options &
             dsdb.NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT) != 0x0):

            if (cn_conn.options & dsdb.NTDSCONN_OPT_USE_NOTIFY) == 0x0:
                # WARNING
                #
                # it LOOKS as if this next test is a bit silly: it
                # checks the flag then sets it if it not set; the same
                # effect could be achieved by unconditionally setting
                # it. But in fact the repsFrom object has special
                # magic attached to it, and altering replica_flags has
                # side-effects. That is bad in my opinion, but there
                # you go.
                if ((t_repsFrom.replica_flags &
                     drsuapi.DRSUAPI_DRS_NEVER_NOTIFY) == 0x0):
                    t_repsFrom.replica_flags |= \
                        drsuapi.DRSUAPI_DRS_NEVER_NOTIFY

        elif not same_site:

            if ((t_repsFrom.replica_flags &
                 drsuapi.DRSUAPI_DRS_NEVER_NOTIFY) == 0x0):
                t_repsFrom.replica_flags |= drsuapi.DRSUAPI_DRS_NEVER_NOTIFY

        # Bit DRS_USE_COMPRESSION is set in t.replicaFlags if
        # and only if s and the local DC's nTDSDSA object are
        # not in the same site and the
        # NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION bit is
        # clear in cn!options
        if (not same_site and
            (cn_conn.options &
             dsdb.NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION) == 0x0):

            if ((t_repsFrom.replica_flags &
                 drsuapi.DRSUAPI_DRS_USE_COMPRESSION) == 0x0):
                t_repsFrom.replica_flags |= drsuapi.DRSUAPI_DRS_USE_COMPRESSION

        # Bit DRS_TWOWAY_SYNC is set in t.replicaFlags if and only
        # if bit NTDSCONN_OPT_TWOWAY_SYNC is set in cn!options.
        if (cn_conn.options & dsdb.NTDSCONN_OPT_TWOWAY_SYNC) != 0x0:

            if ((t_repsFrom.replica_flags &
                 drsuapi.DRSUAPI_DRS_TWOWAY_SYNC) == 0x0):
                t_repsFrom.replica_flags |= drsuapi.DRSUAPI_DRS_TWOWAY_SYNC

        # Bits DRS_DISABLE_AUTO_SYNC and DRS_DISABLE_PERIODIC_SYNC are
        # set in t.replicaFlags if and only if cn!enabledConnection = false.
        if not cn_conn.is_enabled():

            if ((t_repsFrom.replica_flags &
                 drsuapi.DRSUAPI_DRS_DISABLE_AUTO_SYNC) == 0x0):
                t_repsFrom.replica_flags |= \
                    drsuapi.DRSUAPI_DRS_DISABLE_AUTO_SYNC

            if ((t_repsFrom.replica_flags &
                 drsuapi.DRSUAPI_DRS_DISABLE_PERIODIC_SYNC) == 0x0):
                t_repsFrom.replica_flags |= \
                    drsuapi.DRSUAPI_DRS_DISABLE_PERIODIC_SYNC

        # If s and the local DC's nTDSDSA object are in the same site,
        # cn!transportType has no value, or the RDN of cn!transportType
        # is CN=IP:
        #
        #     Bit DRS_MAIL_REP in t.replicaFlags is clear.
        #
        #     t.uuidTransport = NULL GUID.
        #
        #     t.uuidDsa = The GUID-based DNS name of s.
        #
        # Otherwise:
        #
        #     Bit DRS_MAIL_REP in t.replicaFlags is set.
        #
        #     If x is the object with dsname cn!transportType,
        #     t.uuidTransport = x!objectGUID.
        #
        #     Let a be the attribute identified by
        #     x!transportAddressAttribute. If a is
        #     the dNSHostName attribute, t.uuidDsa = the GUID-based
        #      DNS name of s. Otherwise, t.uuidDsa = (s!parent)!a.
        #
        # It appears that the first statement i.e.
        #
        #     "If s and the local DC's nTDSDSA object are in the same
        #      site, cn!transportType has no value, or the RDN of
        #      cn!transportType is CN=IP:"
        #
        # could be a slightly tighter statement if it had an "or"
        # between each condition.  I believe this should
        # be interpreted as:
        #
        #     IF (same-site) OR (no-value) OR (type-ip)
        #
        # because IP should be the primary transport mechanism
        # (even in inter-site) and the absense of the transportType
        # attribute should always imply IP no matter if its multi-site
        #
        # NOTE MS-TECH INCORRECT:
        #
        #     All indications point to these statements above being
        #     incorrectly stated:
        #
        #         t.uuidDsa = The GUID-based DNS name of s.
        #
        #         Let a be the attribute identified by
        #         x!transportAddressAttribute. If a is
        #         the dNSHostName attribute, t.uuidDsa = the GUID-based
        #         DNS name of s. Otherwise, t.uuidDsa = (s!parent)!a.
        #
        #     because the uuidDSA is a GUID and not a GUID-base DNS
        #     name.  Nor can uuidDsa hold (s!parent)!a if not
        #     dNSHostName.  What should have been said is:
        #
        #         t.naDsa = The GUID-based DNS name of s
        #
        #     That would also be correct if transportAddressAttribute
        #     were "mailAddress" because (naDsa) can also correctly
        #     hold the SMTP ISM service address.
        #
        nastr = "%s._msdcs.%s" % (s_dsa.dsa_guid, self.samdb.forest_dns_name())

        if ((t_repsFrom.replica_flags &
             drsuapi.DRSUAPI_DRS_MAIL_REP) != 0x0):
            t_repsFrom.replica_flags &= ~drsuapi.DRSUAPI_DRS_MAIL_REP

        t_repsFrom.transport_guid = misc.GUID()

        # See (NOTE MS-TECH INCORRECT) above

        # NOTE: it looks like these conditionals are pointless,
        # because the state will end up as `t_repsFrom.dns_name1 ==
        # nastr` in either case, BUT the repsFrom thing is magic and
        # assigning to it alters some flags. So we try not to update
        # it unless necessary.
        if t_repsFrom.dns_name1 != nastr:
            t_repsFrom.dns_name1 = nastr

        if t_repsFrom.version > 0x1 and t_repsFrom.dns_name2 != nastr:
            t_repsFrom.dns_name2 = nastr

        if t_repsFrom.is_modified():
            DEBUG_FN("modify_repsFrom(): %s" % t_repsFrom)

    def get_dsa_for_implied_replica(self, n_rep, cn_conn):
        """If a connection imply a replica, find the relevant DSA

        Given a NC replica and NTDS Connection, determine if the
        connection implies a repsFrom tuple should be present from the
        source DSA listed in the connection to the naming context. If
        it should be, return the DSA; otherwise return None.

        Based on part of MS-ADTS 6.2.2.5

        :param n_rep: NC replica
        :param cn_conn: NTDS Connection
        :return: source DSA or None
        """
        # XXX different conditions for "implies" than MS-ADTS 6.2.2
        # preamble.

        # It boils down to: we want an enabled, non-FRS connections to
        # a valid remote DSA with a non-RO replica corresponding to
        # n_rep.

        if not cn_conn.is_enabled() or cn_conn.is_rodc_topology():
            return None

        s_dnstr = cn_conn.get_from_dnstr()
        s_dsa = self.get_dsa(s_dnstr)

        # No DSA matching this source DN string?
        if s_dsa is None:
            return None

        s_rep = s_dsa.get_current_replica(n_rep.nc_dnstr)

        if (s_rep is not None and
            s_rep.is_present() and
            (not s_rep.is_ro() or n_rep.is_partial())):
            return s_dsa
        return None

    def translate_ntdsconn(self, current_dsa=None):
        """Adjust repsFrom to match NTDSConnections

        This function adjusts values of repsFrom abstract attributes of NC
        replicas on the local DC to match those implied by
        nTDSConnection objects.

        Based on [MS-ADTS] 6.2.2.5

        :param current_dsa: optional DSA on whose behalf we are acting.
        :return: None
        """
        ro = False
        if current_dsa is None:
            current_dsa = self.my_dsa

        if current_dsa.is_ro():
            ro = True

        if current_dsa.is_translate_ntdsconn_disabled():
            DEBUG_FN("skipping translate_ntdsconn() "
                     "because disabling flag is set")
            return

        DEBUG_FN("translate_ntdsconn(): enter")

        current_rep_table, needed_rep_table = current_dsa.get_rep_tables()

        # Filled in with replicas we currently have that need deleting
        delete_reps = set()

        # We're using the MS notation names here to allow
        # correlation back to the published algorithm.
        #
        # n_rep      - NC replica (n)
        # t_repsFrom - tuple (t) in n!repsFrom
        # s_dsa      - Source DSA of the replica. Defined as nTDSDSA
        #              object (s) such that (s!objectGUID = t.uuidDsa)
        #              In our IDL representation of repsFrom the (uuidDsa)
        #              attribute is called (source_dsa_obj_guid)
        # cn_conn    - (cn) is nTDSConnection object and child of the local
        #               DC's nTDSDSA object and (cn!fromServer = s)
        # s_rep      - source DSA replica of n
        #
        # If we have the replica and its not needed
        # then we add it to the "to be deleted" list.
        for dnstr in current_rep_table:
            # If we're on the RODC, hardcode the update flags
            if ro:
                c_rep = current_rep_table[dnstr]
                c_rep.load_repsFrom(self.samdb)
                for t_repsFrom in c_rep.rep_repsFrom:
                    replica_flags = (drsuapi.DRSUAPI_DRS_INIT_SYNC |
                                     drsuapi.DRSUAPI_DRS_PER_SYNC |
                                     drsuapi.DRSUAPI_DRS_ADD_REF |
                                     drsuapi.DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING |
                                     drsuapi.DRSUAPI_DRS_NONGC_RO_REP)
                    if t_repsFrom.replica_flags != replica_flags:
                        t_repsFrom.replica_flags = replica_flags
                c_rep.commit_repsFrom(self.samdb, ro=self.readonly)
            else:
                if dnstr not in needed_rep_table:
                    delete_reps.add(dnstr)

        DEBUG_FN('current %d needed %d delete %d' % (len(current_rep_table),
                 len(needed_rep_table), len(delete_reps)))

        if delete_reps:
            # TODO Must delete repsFrom/repsTo for these replicas
            DEBUG('deleting these reps: %s' % delete_reps)
            for dnstr in delete_reps:
                del current_rep_table[dnstr]

        # HANDLE REPS-FROM
        #
        # Now perform the scan of replicas we'll need
        # and compare any current repsFrom against the
        # connections
        for n_rep in needed_rep_table.values():

            # load any repsFrom and fsmo roles as we'll
            # need them during connection translation
            n_rep.load_repsFrom(self.samdb)
            n_rep.load_fsmo_roles(self.samdb)

            # Loop thru the existing repsFrom tuples (if any)
            # XXX This is a list and could contain duplicates
            #     (multiple load_repsFrom calls)
            for t_repsFrom in n_rep.rep_repsFrom:

                # for each tuple t in n!repsFrom, let s be the nTDSDSA
                # object such that s!objectGUID = t.uuidDsa
                guidstr = str(t_repsFrom.source_dsa_obj_guid)
                s_dsa = self.get_dsa_by_guidstr(guidstr)

                # Source dsa is gone from config (strange)
                # so cleanup stale repsFrom for unlisted DSA
                if s_dsa is None:
                    logger.warning("repsFrom source DSA guid (%s) not found" %
                                   guidstr)
                    t_repsFrom.to_be_deleted = True
                    continue

                # Find the connection that this repsFrom would use. If
                # there isn't a good one (i.e. non-RODC_TOPOLOGY,
                # meaning non-FRS), we delete the repsFrom.
                s_dnstr = s_dsa.dsa_dnstr
                connections = current_dsa.get_connection_by_from_dnstr(s_dnstr)
                for cn_conn in connections:
                    if not cn_conn.is_rodc_topology():
                        break
                else:
                    # no break means no non-rodc_topology connection exists
                    t_repsFrom.to_be_deleted = True
                    continue

                # KCC removes this repsFrom tuple if any of the following
                # is true:
                #     No NC replica of the NC "is present" on DSA that
                #     would be source of replica
                #
                #     A writable replica of the NC "should be present" on
                #     the local DC, but a partial replica "is present" on
                #     the source DSA
                s_rep = s_dsa.get_current_replica(n_rep.nc_dnstr)

                if s_rep is None or not s_rep.is_present() or \
                   (not n_rep.is_ro() and s_rep.is_partial()):

                    t_repsFrom.to_be_deleted = True
                    continue

                # If the KCC did not remove t from n!repsFrom, it updates t
                self.modify_repsFrom(n_rep, t_repsFrom, s_rep, s_dsa, cn_conn)

            # Loop thru connections and add implied repsFrom tuples
            # for each NTDSConnection under our local DSA if the
            # repsFrom is not already present
            for cn_conn in current_dsa.connect_table.values():

                s_dsa = self.get_dsa_for_implied_replica(n_rep, cn_conn)
                if s_dsa is None:
                    continue

                # Loop thru the existing repsFrom tuples (if any) and
                # if we already have a tuple for this connection then
                # no need to proceed to add.  It will have been changed
                # to have the correct attributes above
                for t_repsFrom in n_rep.rep_repsFrom:
                    guidstr = str(t_repsFrom.source_dsa_obj_guid)
                    if s_dsa is self.get_dsa_by_guidstr(guidstr):
                        s_dsa = None
                        break

                if s_dsa is None:
                    continue

                # Create a new RepsFromTo and proceed to modify
                # it according to specification
                t_repsFrom = RepsFromTo(n_rep.nc_dnstr)

                t_repsFrom.source_dsa_obj_guid = s_dsa.dsa_guid

                s_rep = s_dsa.get_current_replica(n_rep.nc_dnstr)

                self.modify_repsFrom(n_rep, t_repsFrom, s_rep, s_dsa, cn_conn)

                # Add to our NC repsFrom as this is newly computed
                if t_repsFrom.is_modified():
                    n_rep.rep_repsFrom.append(t_repsFrom)

            if self.readonly or ro:
                # Display any to be deleted or modified repsFrom
                text = n_rep.dumpstr_to_be_deleted()
                if text:
                    logger.info("TO BE DELETED:\n%s" % text)
                text = n_rep.dumpstr_to_be_modified()
                if text:
                    logger.info("TO BE MODIFIED:\n%s" % text)

                # Peform deletion from our tables but perform
                # no database modification
                n_rep.commit_repsFrom(self.samdb, ro=True)
            else:
                # Commit any modified repsFrom to the NC replica
                n_rep.commit_repsFrom(self.samdb)

        # HANDLE REPS-TO:
        #
        # Now perform the scan of replicas we'll need
        # and compare any current repsTo against the
        # connections

        # RODC should never push to anybody (should we check this?)
        if ro:
            return

        for n_rep in needed_rep_table.values():

            # load any repsTo and fsmo roles as we'll
            # need them during connection translation
            n_rep.load_repsTo(self.samdb)

            # Loop thru the existing repsTo tuples (if any)
            # XXX This is a list and could contain duplicates
            #     (multiple load_repsTo calls)
            for t_repsTo in n_rep.rep_repsTo:

                # for each tuple t in n!repsTo, let s be the nTDSDSA
                # object such that s!objectGUID = t.uuidDsa
                guidstr = str(t_repsTo.source_dsa_obj_guid)
                s_dsa = self.get_dsa_by_guidstr(guidstr)

                # Source dsa is gone from config (strange)
                # so cleanup stale repsTo for unlisted DSA
                if s_dsa is None:
                    logger.warning("repsTo source DSA guid (%s) not found" %
                                   guidstr)
                    t_repsTo.to_be_deleted = True
                    continue

                # Find the connection that this repsTo would use. If
                # there isn't a good one (i.e. non-RODC_TOPOLOGY,
                # meaning non-FRS), we delete the repsTo.
                s_dnstr = s_dsa.dsa_dnstr
                if '\\0ADEL' in s_dnstr:
                    logger.warning("repsTo source DSA guid (%s) appears deleted" %
                                   guidstr)
                    t_repsTo.to_be_deleted = True
                    continue

                connections = s_dsa.get_connection_by_from_dnstr(self.my_dsa_dnstr)
                if len(connections) > 0:
                    # Then this repsTo is tentatively valid
                    continue
                else:
                    # There is no plausible connection for this repsTo
                    t_repsTo.to_be_deleted = True

            if self.readonly:
                # Display any to be deleted or modified repsTo
                for rt in n_rep.rep_repsTo:
                    if rt.to_be_deleted:
                        logger.info("REMOVING REPS-TO: %s" % rt)

                # Peform deletion from our tables but perform
                # no database modification
                n_rep.commit_repsTo(self.samdb, ro=True)
            else:
                # Commit any modified repsTo to the NC replica
                n_rep.commit_repsTo(self.samdb)

        # TODO Remove any duplicate repsTo values. This should never happen in
        # any normal situations.

    def merge_failed_links(self, ping=None):
        """Merge of kCCFailedLinks and kCCFailedLinks from bridgeheads.

        The KCC on a writable DC attempts to merge the link and connection
        failure information from bridgehead DCs in its own site to help it
        identify failed bridgehead DCs.

        Based on MS-ADTS 6.2.2.3.2 "Merge of kCCFailedLinks and kCCFailedLinks
        from Bridgeheads"

        :param ping: An oracle of current bridgehead availability
        :return: None
        """
        # 1. Queries every bridgehead server in your site (other than yourself)
        # 2. For every ntDSConnection that references a server in a different
        #    site merge all the failure info
        #
        # XXX - not implemented yet
        if ping is not None:
            debug.DEBUG_RED("merge_failed_links() is NOT IMPLEMENTED")
        else:
            DEBUG_FN("skipping merge_failed_links() because it requires "
                     "real network connections\n"
                     "and we weren't asked to --attempt-live-connections")

    def setup_graph(self, part):
        """Set up an intersite graph

        An intersite graph has a Vertex for each site object, a
        MultiEdge for each SiteLink object, and a MutliEdgeSet for
        each siteLinkBridge object (or implied siteLinkBridge). It
        reflects the intersite topology in a slightly more abstract
        graph form.

        Roughly corresponds to MS-ADTS 6.2.2.3.4.3

        :param part: a Partition object
        :returns: an InterSiteGraph object
        """
        # If 'Bridge all site links' is enabled and Win2k3 bridges required
        # is not set
        # NTDSTRANSPORT_OPT_BRIDGES_REQUIRED 0x00000002
        # No documentation for this however, ntdsapi.h appears to have:
        # NTDSSETTINGS_OPT_W2K3_BRIDGES_REQUIRED = 0x00001000
        bridges_required = self.my_site.site_options & 0x00001002 != 0
        transport_guid = str(self.ip_transport.guid)

        g = setup_graph(part, self.site_table, transport_guid,
                        self.sitelink_table, bridges_required)

        if self.verify or self.dot_file_dir is not None:
            dot_edges = []
            for edge in g.edges:
                for a, b in itertools.combinations(edge.vertices, 2):
                    dot_edges.append((a.site.site_dnstr, b.site.site_dnstr))
            verify_properties = ()
            name = 'site_edges_%s' % part.partstr
            verify_and_dot(name, dot_edges, directed=False,
                           label=self.my_dsa_dnstr,
                           properties=verify_properties, debug=DEBUG,
                           verify=self.verify,
                           dot_file_dir=self.dot_file_dir)

        return g

    def get_bridgehead(self, site, part, transport, partial_ok, detect_failed):
        """Get a bridghead DC for a site.

        Part of MS-ADTS 6.2.2.3.4.4

        :param site: site object representing for which a bridgehead
            DC is desired.
        :param part: crossRef for NC to replicate.
        :param transport: interSiteTransport object for replication
            traffic.
        :param partial_ok: True if a DC containing a partial
            replica or a full replica will suffice, False if only
            a full replica will suffice.
        :param detect_failed: True to detect failed DCs and route
            replication traffic around them, False to assume no DC
            has failed.
        :return: dsa object for the bridgehead DC or None
        """

        bhs = self.get_all_bridgeheads(site, part, transport,
                                       partial_ok, detect_failed)
        if not bhs:
            debug.DEBUG_MAGENTA("get_bridgehead FAILED:\nsitedn = %s" %
                                site.site_dnstr)
            return None

        debug.DEBUG_GREEN("get_bridgehead:\n\tsitedn = %s\n\tbhdn = %s" %
                          (site.site_dnstr, bhs[0].dsa_dnstr))
        return bhs[0]

    def get_all_bridgeheads(self, site, part, transport,
                            partial_ok, detect_failed):
        """Get all bridghead DCs on a site satisfying the given criteria

        Part of MS-ADTS 6.2.2.3.4.4

        :param site: site object representing the site for which
            bridgehead DCs are desired.
        :param part: partition for NC to replicate.
        :param transport: interSiteTransport object for
            replication traffic.
        :param partial_ok: True if a DC containing a partial
            replica or a full replica will suffice, False if
            only a full replica will suffice.
        :param detect_failed: True to detect failed DCs and route
            replication traffic around them, FALSE to assume
            no DC has failed.
        :return: list of dsa object for available bridgehead DCs
        """
        bhs = []

        if transport.name != "IP":
            raise KCCError("get_all_bridgeheads has run into a "
                           "non-IP transport! %r"
                           % (transport.name,))

        DEBUG_FN(site.rw_dsa_table)
        for dsa in site.rw_dsa_table.values():

            pdnstr = dsa.get_parent_dnstr()

            # IF t!bridgeheadServerListBL has one or more values and
            # t!bridgeheadServerListBL does not contain a reference
            # to the parent object of dc then skip dc
            if ((len(transport.bridgehead_list) != 0 and
                 pdnstr not in transport.bridgehead_list)):
                continue

            # IF dc is in the same site as the local DC
            #    IF a replica of cr!nCName is not in the set of NC replicas
            #    that "should be present" on dc or a partial replica of the
            #    NC "should be present" but partialReplicasOkay = FALSE
            #        Skip dc
            if self.my_site.same_site(dsa):
                needed, ro, partial = part.should_be_present(dsa)
                if not needed or (partial and not partial_ok):
                    continue
                rep = dsa.get_current_replica(part.nc_dnstr)

            # ELSE
            #     IF an NC replica of cr!nCName is not in the set of NC
            #     replicas that "are present" on dc or a partial replica of
            #     the NC "is present" but partialReplicasOkay = FALSE
            #          Skip dc
            else:
                rep = dsa.get_current_replica(part.nc_dnstr)
                if rep is None or (rep.is_partial() and not partial_ok):
                    continue

            # IF AmIRODC() and cr!nCName corresponds to default NC then
            #     Let dsaobj be the nTDSDSA object of the dc
            #     IF  dsaobj.msDS-Behavior-Version < DS_DOMAIN_FUNCTION_2008
            #         Skip dc
            if self.my_dsa.is_ro() and rep is not None and rep.is_default():
                if not dsa.is_minimum_behavior(dsdb.DS_DOMAIN_FUNCTION_2008):
                    continue

            # IF BridgeheadDCFailed(dc!objectGUID, detectFailedDCs) = TRUE
            #     Skip dc
            if self.is_bridgehead_failed(dsa, detect_failed):
                DEBUG("bridgehead is failed")
                continue

            DEBUG_FN("found a bridgehead: %s" % dsa.dsa_dnstr)
            bhs.append(dsa)

        # IF bit NTDSSETTINGS_OPT_IS_RAND_BH_SELECTION_DISABLED is set in
        # s!options
        #    SORT bhs such that all GC servers precede DCs that are not GC
        #    servers, and otherwise by ascending objectGUID
        # ELSE
        #    SORT bhs in a random order
        if site.is_random_bridgehead_disabled():
            bhs.sort(sort_dsa_by_gc_and_guid)
        else:
            random.shuffle(bhs)
        debug.DEBUG_YELLOW(bhs)
        return bhs

    def is_bridgehead_failed(self, dsa, detect_failed):
        """Determine whether a given DC is known to be in a failed state

        :param dsa: the bridgehead to test
        :param detect_failed: True to really check, False to assume no failure
        :return: True if and only if the DC should be considered failed

        Here we DEPART from the pseudo code spec which appears to be
        wrong. It says, in full:

    /***** BridgeheadDCFailed *****/
    /* Determine whether a given DC is known to be in a failed state.
     * IN: objectGUID - objectGUID of the DC's nTDSDSA object.
     * IN: detectFailedDCs - TRUE if and only failed DC detection is
     *     enabled.
     * RETURNS: TRUE if and only if the DC should be considered to be in a
     *          failed state.
     */
    BridgeheadDCFailed(IN GUID objectGUID, IN bool detectFailedDCs) : bool
    {
        IF bit NTDSSETTINGS_OPT_IS_TOPL_DETECT_STALE_DISABLED is set in
        the options attribute of the site settings object for the local
        DC's site
            RETURN FALSE
        ELSEIF a tuple z exists in the kCCFailedLinks or
        kCCFailedConnections variables such that z.UUIDDsa =
        objectGUID, z.FailureCount > 1, and the current time -
        z.TimeFirstFailure > 2 hours
            RETURN TRUE
        ELSE
            RETURN detectFailedDCs
        ENDIF
    }

        where you will see detectFailedDCs is not behaving as
        advertised -- it is acting as a default return code in the
        event that a failure is not detected, not a switch turning
        detection on or off. Elsewhere the documentation seems to
        concur with the comment rather than the code.
        """
        if not detect_failed:
            return False

        # NTDSSETTINGS_OPT_IS_TOPL_DETECT_STALE_DISABLED = 0x00000008
        # When DETECT_STALE_DISABLED, we can never know of if
        # it's in a failed state
        if self.my_site.site_options & 0x00000008:
            return False

        return self.is_stale_link_connection(dsa)

    def create_connection(self, part, rbh, rsite, transport,
                          lbh, lsite, link_opt, link_sched,
                          partial_ok, detect_failed):
        """Create an nTDSConnection object as specified if it doesn't exist.

        Part of MS-ADTS 6.2.2.3.4.5

        :param part: crossRef object for the NC to replicate.
        :param rbh: nTDSDSA object for DC to act as the
            IDL_DRSGetNCChanges server (which is in a site other
            than the local DC's site).
        :param rsite: site of the rbh
        :param transport: interSiteTransport object for the transport
            to use for replication traffic.
        :param lbh: nTDSDSA object for DC to act as the
            IDL_DRSGetNCChanges client (which is in the local DC's site).
        :param lsite: site of the lbh
        :param link_opt: Replication parameters (aggregated siteLink options,
                                                 etc.)
        :param link_sched: Schedule specifying the times at which
            to begin replicating.
        :partial_ok: True if bridgehead DCs containing partial
            replicas of the NC are acceptable.
        :param detect_failed: True to detect failed DCs and route
            replication traffic around them, FALSE to assume no DC
            has failed.
        """
        rbhs_all = self.get_all_bridgeheads(rsite, part, transport,
                                            partial_ok, False)
        rbh_table = dict((x.dsa_dnstr, x) for x in rbhs_all)

        debug.DEBUG_GREY("rbhs_all: %s %s" % (len(rbhs_all),
                                              [x.dsa_dnstr for x in rbhs_all]))

        # MS-TECH says to compute rbhs_avail but then doesn't use it
        # rbhs_avail = self.get_all_bridgeheads(rsite, part, transport,
        #                                        partial_ok, detect_failed)

        lbhs_all = self.get_all_bridgeheads(lsite, part, transport,
                                            partial_ok, False)
        if lbh.is_ro():
            lbhs_all.append(lbh)

        debug.DEBUG_GREY("lbhs_all: %s %s" % (len(lbhs_all),
                                              [x.dsa_dnstr for x in lbhs_all]))

        # MS-TECH says to compute lbhs_avail but then doesn't use it
        # lbhs_avail = self.get_all_bridgeheads(lsite, part, transport,
        #                                       partial_ok, detect_failed)

        # FOR each nTDSConnection object cn such that the parent of cn is
        # a DC in lbhsAll and cn!fromServer references a DC in rbhsAll
        for ldsa in lbhs_all:
            for cn in ldsa.connect_table.values():

                rdsa = rbh_table.get(cn.from_dnstr)
                if rdsa is None:
                    continue

                debug.DEBUG_DARK_YELLOW("rdsa is %s" % rdsa.dsa_dnstr)
                # IF bit NTDSCONN_OPT_IS_GENERATED is set in cn!options and
                # NTDSCONN_OPT_RODC_TOPOLOGY is clear in cn!options and
                # cn!transportType references t
                if ((cn.is_generated() and
                     not cn.is_rodc_topology() and
                     cn.transport_guid == transport.guid)):

                    # IF bit NTDSCONN_OPT_USER_OWNED_SCHEDULE is clear in
                    # cn!options and cn!schedule != sch
                    #     Perform an originating update to set cn!schedule to
                    #     sched
                    if ((not cn.is_user_owned_schedule() and
                         not cn.is_equivalent_schedule(link_sched))):
                        cn.schedule = link_sched
                        cn.set_modified(True)

                    # IF bits NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT and
                    # NTDSCONN_OPT_USE_NOTIFY are set in cn
                    if cn.is_override_notify_default() and \
                       cn.is_use_notify():

                        # IF bit NTDSSITELINK_OPT_USE_NOTIFY is clear in
                        # ri.Options
                        #    Perform an originating update to clear bits
                        #    NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT and
                        #    NTDSCONN_OPT_USE_NOTIFY in cn!options
                        if (link_opt & dsdb.NTDSSITELINK_OPT_USE_NOTIFY) == 0:
                            cn.options &= \
                                ~(dsdb.NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT |
                                  dsdb.NTDSCONN_OPT_USE_NOTIFY)
                            cn.set_modified(True)

                    # ELSE
                    else:

                        # IF bit NTDSSITELINK_OPT_USE_NOTIFY is set in
                        # ri.Options
                        #     Perform an originating update to set bits
                        #     NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT and
                        #     NTDSCONN_OPT_USE_NOTIFY in cn!options
                        if (link_opt & dsdb.NTDSSITELINK_OPT_USE_NOTIFY) != 0:
                            cn.options |= \
                                (dsdb.NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT |
                                 dsdb.NTDSCONN_OPT_USE_NOTIFY)
                            cn.set_modified(True)

                    # IF bit NTDSCONN_OPT_TWOWAY_SYNC is set in cn!options
                    if cn.is_twoway_sync():

                        # IF bit NTDSSITELINK_OPT_TWOWAY_SYNC is clear in
                        # ri.Options
                        #     Perform an originating update to clear bit
                        #     NTDSCONN_OPT_TWOWAY_SYNC in cn!options
                        if (link_opt & dsdb.NTDSSITELINK_OPT_TWOWAY_SYNC) == 0:
                            cn.options &= ~dsdb.NTDSCONN_OPT_TWOWAY_SYNC
                            cn.set_modified(True)

                    # ELSE
                    else:

                        # IF bit NTDSSITELINK_OPT_TWOWAY_SYNC is set in
                        # ri.Options
                        #     Perform an originating update to set bit
                        #     NTDSCONN_OPT_TWOWAY_SYNC in cn!options
                        if (link_opt & dsdb.NTDSSITELINK_OPT_TWOWAY_SYNC) != 0:
                            cn.options |= dsdb.NTDSCONN_OPT_TWOWAY_SYNC
                            cn.set_modified(True)

                    # IF bit NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION is set
                    # in cn!options
                    if cn.is_intersite_compression_disabled():

                        # IF bit NTDSSITELINK_OPT_DISABLE_COMPRESSION is clear
                        # in ri.Options
                        #     Perform an originating update to clear bit
                        #     NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION in
                        #     cn!options
                        if ((link_opt &
                             dsdb.NTDSSITELINK_OPT_DISABLE_COMPRESSION) == 0):
                            cn.options &= \
                                ~dsdb.NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION
                            cn.set_modified(True)

                    # ELSE
                    else:
                        # IF bit NTDSSITELINK_OPT_DISABLE_COMPRESSION is set in
                        # ri.Options
                        #     Perform an originating update to set bit
                        #     NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION in
                        #     cn!options
                        if ((link_opt &
                             dsdb.NTDSSITELINK_OPT_DISABLE_COMPRESSION) != 0):
                            cn.options |= \
                                dsdb.NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION
                            cn.set_modified(True)

                    # Display any modified connection
                    if self.readonly or ldsa.is_ro():
                        if cn.to_be_modified:
                            logger.info("TO BE MODIFIED:\n%s" % cn)

                        ldsa.commit_connections(self.samdb, ro=True)
                    else:
                        ldsa.commit_connections(self.samdb)
        # ENDFOR

        valid_connections = 0

        # FOR each nTDSConnection object cn such that cn!parent is
        # a DC in lbhsAll and cn!fromServer references a DC in rbhsAll
        for ldsa in lbhs_all:
            for cn in ldsa.connect_table.values():

                rdsa = rbh_table.get(cn.from_dnstr)
                if rdsa is None:
                    continue

                debug.DEBUG_DARK_YELLOW("round 2: rdsa is %s" % rdsa.dsa_dnstr)

                # IF (bit NTDSCONN_OPT_IS_GENERATED is clear in cn!options or
                # cn!transportType references t) and
                # NTDSCONN_OPT_RODC_TOPOLOGY is clear in cn!options
                if (((not cn.is_generated() or
                      cn.transport_guid == transport.guid) and
                     not cn.is_rodc_topology())):

                    # LET rguid be the objectGUID of the nTDSDSA object
                    # referenced by cn!fromServer
                    # LET lguid be (cn!parent)!objectGUID

                    # IF BridgeheadDCFailed(rguid, detectFailedDCs) = FALSE and
                    # BridgeheadDCFailed(lguid, detectFailedDCs) = FALSE
                    #     Increment cValidConnections by 1
                    if ((not self.is_bridgehead_failed(rdsa, detect_failed) and
                         not self.is_bridgehead_failed(ldsa, detect_failed))):
                        valid_connections += 1

                    # IF keepConnections does not contain cn!objectGUID
                    #     APPEND cn!objectGUID to keepConnections
                    self.kept_connections.add(cn)

        # ENDFOR
        debug.DEBUG_RED("valid connections %d" % valid_connections)
        DEBUG("kept_connections:\n%s" % (self.kept_connections,))
        # IF cValidConnections = 0
        if valid_connections == 0:

            # LET opt be NTDSCONN_OPT_IS_GENERATED
            opt = dsdb.NTDSCONN_OPT_IS_GENERATED

            # IF bit NTDSSITELINK_OPT_USE_NOTIFY is set in ri.Options
            #     SET bits NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT and
            #     NTDSCONN_OPT_USE_NOTIFY in opt
            if (link_opt & dsdb.NTDSSITELINK_OPT_USE_NOTIFY) != 0:
                opt |= (dsdb.NTDSCONN_OPT_OVERRIDE_NOTIFY_DEFAULT |
                        dsdb.NTDSCONN_OPT_USE_NOTIFY)

            # IF bit NTDSSITELINK_OPT_TWOWAY_SYNC is set in ri.Options
            #     SET bit NTDSCONN_OPT_TWOWAY_SYNC opt
            if (link_opt & dsdb.NTDSSITELINK_OPT_TWOWAY_SYNC) != 0:
                opt |= dsdb.NTDSCONN_OPT_TWOWAY_SYNC

            # IF bit NTDSSITELINK_OPT_DISABLE_COMPRESSION is set in
            # ri.Options
            #     SET bit NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION in opt
            if ((link_opt &
                 dsdb.NTDSSITELINK_OPT_DISABLE_COMPRESSION) != 0):
                opt |= dsdb.NTDSCONN_OPT_DISABLE_INTERSITE_COMPRESSION

            # Perform an originating update to create a new nTDSConnection
            # object cn that is a child of lbh, cn!enabledConnection = TRUE,
            # cn!options = opt, cn!transportType is a reference to t,
            # cn!fromServer is a reference to rbh, and cn!schedule = sch
            DEBUG_FN("new connection, KCC dsa: %s" % self.my_dsa.dsa_dnstr)
            system_flags = (dsdb.SYSTEM_FLAG_CONFIG_ALLOW_RENAME |
                            dsdb.SYSTEM_FLAG_CONFIG_ALLOW_MOVE)

            cn = lbh.new_connection(opt, system_flags, transport,
                                    rbh.dsa_dnstr, link_sched)

            # Display any added connection
            if self.readonly or lbh.is_ro():
                if cn.to_be_added:
                    logger.info("TO BE ADDED:\n%s" % cn)

                lbh.commit_connections(self.samdb, ro=True)
            else:
                lbh.commit_connections(self.samdb)

            # APPEND cn!objectGUID to keepConnections
            self.kept_connections.add(cn)

    def add_transports(self, vertex, local_vertex, graph, detect_failed):
        """Build a Vertex's transport lists

        Each vertex has accept_red_red and accept_black lists that
        list what transports they accept under various conditions. The
        only transport that is ever accepted is IP, and a dummy extra
        transport called "EDGE_TYPE_ALL".

        Part of MS-ADTS 6.2.2.3.4.3 -- ColorVertices

        :param vertex: the remote vertex we are thinking about
        :param local_vertex: the vertex relating to the local site.
        :param graph: the intersite graph
        :param detect_failed: whether to detect failed links
        :return: True if some bridgeheads were not found
        """
        # The docs ([MS-ADTS] 6.2.2.3.4.3) say to use local_vertex
        # here, but using vertex seems to make more sense. That is,
        # the docs want this:
        #
        # bh = self.get_bridgehead(local_vertex.site, vertex.part, transport,
        #                         local_vertex.is_black(), detect_failed)
        #
        # TODO WHY?????

        vertex.accept_red_red = []
        vertex.accept_black = []
        found_failed = False

        if vertex in graph.connected_vertices:
            t_guid = str(self.ip_transport.guid)

            bh = self.get_bridgehead(vertex.site, vertex.part,
                                     self.ip_transport,
                                     vertex.is_black(), detect_failed)
            if bh is None:
                if vertex.site.is_rodc_site():
                    vertex.accept_red_red.append(t_guid)
                else:
                    found_failed = True
            else:
                vertex.accept_red_red.append(t_guid)
                vertex.accept_black.append(t_guid)

        # Add additional transport to ensure another run of Dijkstra
        vertex.accept_red_red.append("EDGE_TYPE_ALL")
        vertex.accept_black.append("EDGE_TYPE_ALL")

        return found_failed

    def create_connections(self, graph, part, detect_failed):
        """Create intersite NTDSConnections as needed by a partition

        Construct an NC replica graph for the NC identified by
        the given crossRef, then create any additional nTDSConnection
        objects required.

        :param graph: site graph.
        :param part: crossRef object for NC.
        :param detect_failed:  True to detect failed DCs and route
            replication traffic around them, False to assume no DC
            has failed.

        Modifies self.kept_connections by adding any connections
        deemed to be "in use".

        :return: (all_connected, found_failed_dc)
        (all_connected) True if the resulting NC replica graph
            connects all sites that need to be connected.
        (found_failed_dc) True if one or more failed DCs were
            detected.
        """
        all_connected = True
        found_failed = False

        DEBUG_FN("create_connections(): enter\n"
                 "\tpartdn=%s\n\tdetect_failed=%s" %
                 (part.nc_dnstr, detect_failed))

        # XXX - This is a highly abbreviated function from the MS-TECH
        #       ref.  It creates connections between bridgeheads to all
        #       sites that have appropriate replicas.  Thus we are not
        #       creating a minimum cost spanning tree but instead
        #       producing a fully connected tree.  This should produce
        #       a full (albeit not optimal cost) replication topology.

        my_vertex = Vertex(self.my_site, part)
        my_vertex.color_vertex()

        for v in graph.vertices:
            v.color_vertex()
            if self.add_transports(v, my_vertex, graph, detect_failed):
                found_failed = True

        # No NC replicas for this NC in the site of the local DC,
        # so no nTDSConnection objects need be created
        if my_vertex.is_white():
            return all_connected, found_failed

        edge_list, n_components = get_spanning_tree_edges(graph,
                                                          self.my_site,
                                                          label=part.partstr)

        DEBUG_FN("%s Number of components: %d" %
                 (part.nc_dnstr, n_components))
        if n_components > 1:
            all_connected = False

        # LET partialReplicaOkay be TRUE if and only if
        # localSiteVertex.Color = COLOR.BLACK
        partial_ok = my_vertex.is_black()

        # Utilize the IP transport only for now
        transport = self.ip_transport

        DEBUG("edge_list %s" % edge_list)
        for e in edge_list:
            # XXX more accurate comparison?
            if e.directed and e.vertices[0].site is self.my_site:
                continue

            if e.vertices[0].site is self.my_site:
                rsite = e.vertices[1].site
            else:
                rsite = e.vertices[0].site

            # We don't make connections to our own site as that
            # is intrasite topology generator's job
            if rsite is self.my_site:
                DEBUG("rsite is my_site")
                continue

            # Determine bridgehead server in remote site
            rbh = self.get_bridgehead(rsite, part, transport,
                                      partial_ok, detect_failed)
            if rbh is None:
                continue

            # RODC acts as an BH for itself
            # IF AmIRODC() then
            #     LET lbh be the nTDSDSA object of the local DC
            # ELSE
            #     LET lbh be the result of GetBridgeheadDC(localSiteVertex.ID,
            #     cr, t, partialReplicaOkay, detectFailedDCs)
            if self.my_dsa.is_ro():
                lsite = self.my_site
                lbh = self.my_dsa
            else:
                lsite = self.my_site
                lbh = self.get_bridgehead(lsite, part, transport,
                                          partial_ok, detect_failed)
            # TODO
            if lbh is None:
                debug.DEBUG_RED("DISASTER! lbh is None")
                return False, True

            DEBUG_FN("lsite: %s\nrsite: %s" % (lsite, rsite))
            DEBUG_FN("vertices %s" % (e.vertices,))
            debug.DEBUG_BLUE("bridgeheads\n%s\n%s\n%s" % (lbh, rbh, "-" * 70))

            sitelink = e.site_link
            if sitelink is None:
                link_opt = 0x0
                link_sched = None
            else:
                link_opt = sitelink.options
                link_sched = sitelink.schedule

            self.create_connection(part, rbh, rsite, transport,
                                   lbh, lsite, link_opt, link_sched,
                                   partial_ok, detect_failed)

        return all_connected, found_failed

    def create_intersite_connections(self):
        """Create NTDSConnections as necessary for all partitions.

        Computes an NC replica graph for each NC replica that "should be
        present" on the local DC or "is present" on any DC in the same site
        as the local DC. For each edge directed to an NC replica on such a
        DC from an NC replica on a DC in another site, the KCC creates an
        nTDSConnection object to imply that edge if one does not already
        exist.

        Modifies self.kept_connections - A set of nTDSConnection
        objects for edges that are directed
        to the local DC's site in one or more NC replica graphs.

        :return: True if spanning trees were created for all NC replica
                 graphs, otherwise False.
        """
        all_connected = True
        self.kept_connections = set()

        # LET crossRefList be the set containing each object o of class
        # crossRef such that o is a child of the CN=Partitions child of the
        # config NC

        # FOR each crossRef object cr in crossRefList
        #    IF cr!enabled has a value and is false, or if FLAG_CR_NTDS_NC
        #        is clear in cr!systemFlags, skip cr.
        #    LET g be the GRAPH return of SetupGraph()

        for part in self.part_table.values():

            if not part.is_enabled():
                continue

            if part.is_foreign():
                continue

            graph = self.setup_graph(part)

            # Create nTDSConnection objects, routing replication traffic
            # around "failed" DCs.
            found_failed = False

            connected, found_failed = self.create_connections(graph,
                                                              part, True)

            DEBUG("with detect_failed: connected %s Found failed %s" %
                  (connected, found_failed))
            if not connected:
                all_connected = False

                if found_failed:
                    # One or more failed DCs preclude use of the ideal NC
                    # replica graph. Add connections for the ideal graph.
                    self.create_connections(graph, part, False)

        return all_connected

    def intersite(self, ping):
        """Generate the inter-site KCC replica graph and nTDSConnections

        As per MS-ADTS 6.2.2.3.

        If self.readonly is False, the connections are added to self.samdb.

        Produces self.kept_connections which is a set of NTDS
        Connections that should be kept during subsequent pruning
        process.

        After this has run, all sites should be connected in a minimum
        spanning tree.

        :param ping: An oracle function of remote site availability
        :return (True or False):  (True) if the produced NC replica
            graph connects all sites that need to be connected
        """

        # Retrieve my DSA
        mydsa = self.my_dsa
        mysite = self.my_site
        all_connected = True

        DEBUG_FN("intersite(): enter")

        # Determine who is the ISTG
        if self.readonly:
            mysite.select_istg(self.samdb, mydsa, ro=True)
        else:
            mysite.select_istg(self.samdb, mydsa, ro=False)

        # Test whether local site has topology disabled
        if mysite.is_intersite_topology_disabled():
            DEBUG_FN("intersite(): exit disabled all_connected=%d" %
                     all_connected)
            return all_connected

        if not mydsa.is_istg():
            DEBUG_FN("intersite(): exit not istg all_connected=%d" %
                     all_connected)
            return all_connected

        self.merge_failed_links(ping)

        # For each NC with an NC replica that "should be present" on the
        # local DC or "is present" on any DC in the same site as the
        # local DC, the KCC constructs a site graph--a precursor to an NC
        # replica graph. The site connectivity for a site graph is defined
        # by objects of class interSiteTransport, siteLink, and
        # siteLinkBridge in the config NC.

        all_connected = self.create_intersite_connections()

        DEBUG_FN("intersite(): exit all_connected=%d" % all_connected)
        return all_connected

    # This function currently does no actions. The reason being that we cannot
    # perform modifies in this way on the RODC.
    def update_rodc_connection(self, ro=True):
        """Updates the RODC NTFRS connection object.

        If the local DSA is not an RODC, this does nothing.
        """
        if not self.my_dsa.is_ro():
            return

        # Given an nTDSConnection object cn1, such that cn1.options contains
        # NTDSCONN_OPT_RODC_TOPOLOGY, and another nTDSConnection object cn2,
        # does not contain NTDSCONN_OPT_RODC_TOPOLOGY, modify cn1 to ensure
        # that the following is true:
        #
        #     cn1.fromServer = cn2.fromServer
        #     cn1.schedule = cn2.schedule
        #
        # If no such cn2 can be found, cn1 is not modified.
        # If no such cn1 can be found, nothing is modified by this task.

        all_connections = self.my_dsa.connect_table.values()
        ro_connections = [x for x in all_connections if x.is_rodc_topology()]
        rw_connections = [x for x in all_connections
                          if x not in ro_connections]

        # XXX here we are dealing with multiple RODC_TOPO connections,
        # if they exist. It is not clear whether the spec means that
        # or if it ever arises.
        if rw_connections and ro_connections:
            for con in ro_connections:
                cn2 = rw_connections[0]
                con.from_dnstr = cn2.from_dnstr
                con.schedule = cn2.schedule
                con.to_be_modified = True

            self.my_dsa.commit_connections(self.samdb, ro=ro)

    def intrasite_max_node_edges(self, node_count):
        """Find the maximum number of edges directed to an intrasite node

        The KCC does not create more than 50 edges directed to a
        single DC. To optimize replication, we compute that each node
        should have n+2 total edges directed to it such that (n) is
        the smallest non-negative integer satisfying
        (node_count <= 2*(n*n) + 6*n + 7)

        (If the number of edges is m (i.e. n + 2), that is the same as
        2 * m*m - 2 * m + 3). We think in terms of n because that is
        the number of extra connections over the double directed ring
        that exists by default.

        edges  n   nodecount
          2    0    7
          3    1   15
          4    2   27
          5    3   43
                  ...
         50   48 4903

        :param node_count: total number of nodes in the replica graph

        The intention is that there should be no more than 3 hops
        between any two DSAs at a site. With up to 7 nodes the 2 edges
        of the ring are enough; any configuration of extra edges with
        8 nodes will be enough. It is less clear that the 3 hop
        guarantee holds at e.g. 15 nodes in degenerate cases, but
        those are quite unlikely given the extra edges are randomly
        arranged.

        :param node_count: the number of nodes in the site
        "return: The desired maximum number of connections
        """
        n = 0
        while True:
            if node_count <= (2 * (n * n) + (6 * n) + 7):
                break
            n = n + 1
        n = n + 2
        if n < 50:
            return n
        return 50

    def construct_intrasite_graph(self, site_local, dc_local,
                                  nc_x, gc_only, detect_stale):
        """Create an intrasite graph using given parameters

        This might be called a number of times per site with different
        parameters.

        Based on [MS-ADTS] 6.2.2.2

        :param site_local: site for which we are working
        :param dc_local: local DC that potentially needs a replica
        :param nc_x:  naming context (x) that we are testing if it
                    "should be present" on the local DC
        :param gc_only: Boolean - only consider global catalog servers
        :param detect_stale: Boolean - check whether links seems down
        :return: None
        """
        # We're using the MS notation names here to allow
        # correlation back to the published algorithm.
        #
        # nc_x     - naming context (x) that we are testing if it
        #            "should be present" on the local DC
        # f_of_x   - replica (f) found on a DC (s) for NC (x)
        # dc_s     - DC where f_of_x replica was found
        # dc_local - local DC that potentially needs a replica
        #            (f_of_x)
        # r_list   - replica list R
        # p_of_x   - replica (p) is partial and found on a DC (s)
        #            for NC (x)
        # l_of_x   - replica (l) is the local replica for NC (x)
        #            that should appear on the local DC
        # r_len = is length of replica list |R|
        #
        # If the DSA doesn't need a replica for this
        # partition (NC x) then continue
        needed, ro, partial = nc_x.should_be_present(dc_local)

        debug.DEBUG_YELLOW("construct_intrasite_graph(): enter" +
                           "\n\tgc_only=%d" % gc_only +
                           "\n\tdetect_stale=%d" % detect_stale +
                           "\n\tneeded=%s" % needed +
                           "\n\tro=%s" % ro +
                           "\n\tpartial=%s" % partial +
                           "\n%s" % nc_x)

        if not needed:
            debug.DEBUG_RED("%s lacks 'should be present' status, "
                            "aborting construct_intrasite_graph!" %
                            nc_x.nc_dnstr)
            return

        # Create a NCReplica that matches what the local replica
        # should say.  We'll use this below in our r_list
        l_of_x = NCReplica(dc_local, nc_x.nc_dnstr)

        l_of_x.identify_by_basedn(self.samdb)

        l_of_x.rep_partial = partial
        l_of_x.rep_ro = ro

        # Add this replica that "should be present" to the
        # needed replica table for this DSA
        dc_local.add_needed_replica(l_of_x)

        # Replica list
        #
        # Let R be a sequence containing each writable replica f of x
        # such that f "is present" on a DC s satisfying the following
        # criteria:
        #
        #  * s is a writable DC other than the local DC.
        #
        #  * s is in the same site as the local DC.
        #
        #  * If x is a read-only full replica and x is a domain NC,
        #    then the DC's functional level is at least
        #    DS_BEHAVIOR_WIN2008.
        #
        #  * Bit NTDSSETTINGS_OPT_IS_TOPL_DETECT_STALE_DISABLED is set
        #    in the options attribute of the site settings object for
        #    the local DC's site, or no tuple z exists in the
        #    kCCFailedLinks or kCCFailedConnections variables such
        #    that z.UUIDDsa is the objectGUID of the nTDSDSA object
        #    for s, z.FailureCount > 0, and the current time -
        #    z.TimeFirstFailure > 2 hours.

        r_list = []

        # We'll loop thru all the DSAs looking for
        # writeable NC replicas that match the naming
        # context dn for (nc_x)
        #
        for dc_s in self.my_site.dsa_table.values():
            # If this partition (nc_x) doesn't appear as a
            # replica (f_of_x) on (dc_s) then continue
            if nc_x.nc_dnstr not in dc_s.current_rep_table:
                continue

            # Pull out the NCReplica (f) of (x) with the dn
            # that matches NC (x) we are examining.
            f_of_x = dc_s.current_rep_table[nc_x.nc_dnstr]

            # Replica (f) of NC (x) must be writable
            if f_of_x.is_ro():
                continue

            # Replica (f) of NC (x) must satisfy the
            # "is present" criteria for DC (s) that
            # it was found on
            if not f_of_x.is_present():
                continue

            # DC (s) must be a writable DSA other than
            # my local DC.  In other words we'd only replicate
            # from other writable DC
            if dc_s.is_ro() or dc_s is dc_local:
                continue

            # Certain replica graphs are produced only
            # for global catalogs, so test against
            # method input parameter
            if gc_only and not dc_s.is_gc():
                continue

            # DC (s) must be in the same site as the local DC
            # as this is the intra-site algorithm. This is
            # handled by virtue of placing DSAs in per
            # site objects (see enclosing for() loop)

            # If NC (x) is intended to be read-only full replica
            # for a domain NC on the target DC then the source
            # DC should have functional level at minimum WIN2008
            #
            # Effectively we're saying that in order to replicate
            # to a targeted RODC (which was introduced in Windows 2008)
            # then we have to replicate from a DC that is also minimally
            # at that level.
            #
            # You can also see this requirement in the MS special
            # considerations for RODC which state that to deploy
            # an RODC, at least one writable domain controller in
            # the domain must be running Windows Server 2008
            if ro and not partial and nc_x.nc_type == NCType.domain:
                if not dc_s.is_minimum_behavior(dsdb.DS_DOMAIN_FUNCTION_2008):
                    continue

            # If we haven't been told to turn off stale connection
            # detection and this dsa has a stale connection then
            # continue
            if detect_stale and self.is_stale_link_connection(dc_s):
                continue

            # Replica meets criteria.  Add it to table indexed
            # by the GUID of the DC that it appears on
            r_list.append(f_of_x)

        # If a partial (not full) replica of NC (x) "should be present"
        # on the local DC, append to R each partial replica (p of x)
        # such that p "is present" on a DC satisfying the same
        # criteria defined above for full replica DCs.
        #
        # XXX This loop and the previous one differ only in whether
        # the replica is partial or not. here we only accept partial
        # (because we're partial); before we only accepted full. Order
        # doen't matter (the list is sorted a few lines down) so these
        # loops could easily be merged. Or this could be a helper
        # function.

        if partial:
            # Now we loop thru all the DSAs looking for
            # partial NC replicas that match the naming
            # context dn for (NC x)
            for dc_s in self.my_site.dsa_table.values():

                # If this partition NC (x) doesn't appear as a
                # replica (p) of NC (x) on the dsa DC (s) then
                # continue
                if nc_x.nc_dnstr not in dc_s.current_rep_table:
                    continue

                # Pull out the NCReplica with the dn that
                # matches NC (x) we are examining.
                p_of_x = dc_s.current_rep_table[nc_x.nc_dnstr]

                # Replica (p) of NC (x) must be partial
                if not p_of_x.is_partial():
                    continue

                # Replica (p) of NC (x) must satisfy the
                # "is present" criteria for DC (s) that
                # it was found on
                if not p_of_x.is_present():
                    continue

                # DC (s) must be a writable DSA other than
                # my DSA.  In other words we'd only replicate
                # from other writable DSA
                if dc_s.is_ro() or dc_s is dc_local:
                    continue

                # Certain replica graphs are produced only
                # for global catalogs, so test against
                # method input parameter
                if gc_only and not dc_s.is_gc():
                    continue

                # If we haven't been told to turn off stale connection
                # detection and this dsa has a stale connection then
                # continue
                if detect_stale and self.is_stale_link_connection(dc_s):
                    continue

                # Replica meets criteria.  Add it to table indexed
                # by the GUID of the DSA that it appears on
                r_list.append(p_of_x)

        # Append to R the NC replica that "should be present"
        # on the local DC
        r_list.append(l_of_x)

        r_list.sort(key=lambda rep: ndr_pack(rep.rep_dsa_guid))
        r_len = len(r_list)

        max_node_edges = self.intrasite_max_node_edges(r_len)

        # Add a node for each r_list element to the replica graph
        graph_list = []
        for rep in r_list:
            node = GraphNode(rep.rep_dsa_dnstr, max_node_edges)
            graph_list.append(node)

        # For each r(i) from (0 <= i < |R|-1)
        i = 0
        while i < (r_len - 1):
            # Add an edge from r(i) to r(i+1) if r(i) is a full
            # replica or r(i+1) is a partial replica
            if not r_list[i].is_partial() or r_list[i +1].is_partial():
                graph_list[i + 1].add_edge_from(r_list[i].rep_dsa_dnstr)

            # Add an edge from r(i+1) to r(i) if r(i+1) is a full
            # replica or ri is a partial replica.
            if not r_list[i + 1].is_partial() or r_list[i].is_partial():
                graph_list[i].add_edge_from(r_list[i + 1].rep_dsa_dnstr)
            i = i + 1

        # Add an edge from r|R|-1 to r0 if r|R|-1 is a full replica
        # or r0 is a partial replica.
        if not r_list[r_len - 1].is_partial() or r_list[0].is_partial():
            graph_list[0].add_edge_from(r_list[r_len - 1].rep_dsa_dnstr)

        # Add an edge from r0 to r|R|-1 if r0 is a full replica or
        # r|R|-1 is a partial replica.
        if not r_list[0].is_partial() or r_list[r_len -1].is_partial():
            graph_list[r_len - 1].add_edge_from(r_list[0].rep_dsa_dnstr)

        DEBUG("r_list is length %s" % len(r_list))
        DEBUG('\n'.join(str((x.rep_dsa_guid, x.rep_dsa_dnstr))
                        for x in r_list))

        do_dot_files = self.dot_file_dir is not None and self.debug
        if self.verify or do_dot_files:
            dot_edges = []
            dot_vertices = set()
            for v1 in graph_list:
                dot_vertices.add(v1.dsa_dnstr)
                for v2 in v1.edge_from:
                    dot_edges.append((v2, v1.dsa_dnstr))
                    dot_vertices.add(v2)

            verify_properties = ('connected',)
            verify_and_dot('intrasite_pre_ntdscon', dot_edges, dot_vertices,
                           label='%s__%s__%s' % (site_local.site_dnstr,
                                                 nctype_lut[nc_x.nc_type],
                                                 nc_x.nc_dnstr),
                           properties=verify_properties, debug=DEBUG,
                           verify=self.verify,
                           dot_file_dir=self.dot_file_dir,
                           directed=True)

            rw_dot_vertices = set(x for x in dot_vertices
                                  if not self.get_dsa(x).is_ro())
            rw_dot_edges = [(a, b) for a, b in dot_edges if
                            a in rw_dot_vertices and b in rw_dot_vertices]
            rw_verify_properties = ('connected',
                                    'directed_double_ring_or_small')
            verify_and_dot('intrasite_rw_pre_ntdscon', rw_dot_edges,
                           rw_dot_vertices,
                           label='%s__%s__%s' % (site_local.site_dnstr,
                                                 nctype_lut[nc_x.nc_type],
                                                 nc_x.nc_dnstr),
                           properties=rw_verify_properties, debug=DEBUG,
                           verify=self.verify,
                           dot_file_dir=self.dot_file_dir,
                           directed=True)

        # For each existing nTDSConnection object implying an edge
        # from rj of R to ri such that j != i, an edge from rj to ri
        # is not already in the graph, and the total edges directed
        # to ri is less than n+2, the KCC adds that edge to the graph.
        for vertex in graph_list:
            dsa = self.my_site.dsa_table[vertex.dsa_dnstr]
            for connect in dsa.connect_table.values():
                remote = connect.from_dnstr
                if remote in self.my_site.dsa_table:
                    vertex.add_edge_from(remote)

        DEBUG('reps are:  %s' % '   '.join(x.rep_dsa_dnstr for x in r_list))
        DEBUG('dsas are:  %s' % '   '.join(x.dsa_dnstr for x in graph_list))

        for tnode in graph_list:
            # To optimize replication latency in sites with many NC
            # replicas, the KCC adds new edges directed to ri to bring
            # the total edges to n+2, where the NC replica rk of R
            # from which the edge is directed is chosen at random such
            # that k != i and an edge from rk to ri is not already in
            # the graph.
            #
            # Note that the KCC tech ref does not give a number for
            # the definition of "sites with many NC replicas". At a
            # bare minimum to satisfy n+2 edges directed at a node we
            # have to have at least three replicas in |R| (i.e. if n
            # is zero then at least replicas from two other graph
            # nodes may direct edges to us).
            if r_len >= 3 and not tnode.has_sufficient_edges():
                candidates = [x for x in graph_list if
                              (x is not tnode and
                               x.dsa_dnstr not in tnode.edge_from)]

                debug.DEBUG_BLUE("looking for random link for %s. r_len %d, "
                                 "graph len %d candidates %d"
                                 % (tnode.dsa_dnstr, r_len, len(graph_list),
                                    len(candidates)))

                DEBUG("candidates %s" % [x.dsa_dnstr for x in candidates])

                while candidates and not tnode.has_sufficient_edges():
                    other = random.choice(candidates)
                    DEBUG("trying to add candidate %s" % other.dsa_dnstr)
                    if not tnode.add_edge_from(other.dsa_dnstr):
                        debug.DEBUG_RED("could not add %s" % other.dsa_dnstr)
                    candidates.remove(other)
            else:
                DEBUG_FN("not adding links to %s: nodes %s, links is %s/%s" %
                         (tnode.dsa_dnstr, r_len, len(tnode.edge_from),
                          tnode.max_edges))

            # Print the graph node in debug mode
            DEBUG_FN("%s" % tnode)

            # For each edge directed to the local DC, ensure a nTDSConnection
            # points to us that satisfies the KCC criteria

            if tnode.dsa_dnstr == dc_local.dsa_dnstr:
                tnode.add_connections_from_edges(dc_local, self.ip_transport)

        if self.verify or do_dot_files:
            dot_edges = []
            dot_vertices = set()
            for v1 in graph_list:
                dot_vertices.add(v1.dsa_dnstr)
                for v2 in v1.edge_from:
                    dot_edges.append((v2, v1.dsa_dnstr))
                    dot_vertices.add(v2)

            verify_properties = ('connected',)
            verify_and_dot('intrasite_post_ntdscon', dot_edges, dot_vertices,
                           label='%s__%s__%s' % (site_local.site_dnstr,
                                                 nctype_lut[nc_x.nc_type],
                                                 nc_x.nc_dnstr),
                           properties=verify_properties, debug=DEBUG,
                           verify=self.verify,
                           dot_file_dir=self.dot_file_dir,
                           directed=True)

            rw_dot_vertices = set(x for x in dot_vertices
                                  if not self.get_dsa(x).is_ro())
            rw_dot_edges = [(a, b) for a, b in dot_edges if
                            a in rw_dot_vertices and b in rw_dot_vertices]
            rw_verify_properties = ('connected',
                                    'directed_double_ring_or_small')
            verify_and_dot('intrasite_rw_post_ntdscon', rw_dot_edges,
                           rw_dot_vertices,
                           label='%s__%s__%s' % (site_local.site_dnstr,
                                                 nctype_lut[nc_x.nc_type],
                                                 nc_x.nc_dnstr),
                           properties=rw_verify_properties, debug=DEBUG,
                           verify=self.verify,
                           dot_file_dir=self.dot_file_dir,
                           directed=True)

    def intrasite(self):
        """Generate the intrasite KCC connections

        As per MS-ADTS 6.2.2.2.

        If self.readonly is False, the connections are added to self.samdb.

        After this call, all DCs in each site with more than 3 DCs
        should be connected in a bidirectional ring. If a site has 2
        DCs, they will bidirectionally connected. Sites with many DCs
        may have arbitrary extra connections.

        :return: None
        """
        mydsa = self.my_dsa

        DEBUG_FN("intrasite(): enter")

        # Test whether local site has topology disabled
        mysite = self.my_site
        if mysite.is_intrasite_topology_disabled():
            return

        detect_stale = (not mysite.is_detect_stale_disabled())
        for connect in mydsa.connect_table.values():
            if connect.to_be_added:
                debug.DEBUG_CYAN("TO BE ADDED:\n%s" % connect)

        # Loop thru all the partitions, with gc_only False
        for partdn, part in self.part_table.items():
            self.construct_intrasite_graph(mysite, mydsa, part, False,
                                           detect_stale)
            for connect in mydsa.connect_table.values():
                if connect.to_be_added:
                    debug.DEBUG_BLUE("TO BE ADDED:\n%s" % connect)

        # If the DC is a GC server, the KCC constructs an additional NC
        # replica graph (and creates nTDSConnection objects) for the
        # config NC as above, except that only NC replicas that "are present"
        # on GC servers are added to R.
        for connect in mydsa.connect_table.values():
            if connect.to_be_added:
                debug.DEBUG_YELLOW("TO BE ADDED:\n%s" % connect)

        # Do it again, with gc_only True
        for partdn, part in self.part_table.items():
            if part.is_config():
                self.construct_intrasite_graph(mysite, mydsa, part, True,
                                               detect_stale)

        # The DC repeats the NC replica graph computation and nTDSConnection
        # creation for each of the NC replica graphs, this time assuming
        # that no DC has failed. It does so by re-executing the steps as
        # if the bit NTDSSETTINGS_OPT_IS_TOPL_DETECT_STALE_DISABLED were
        # set in the options attribute of the site settings object for
        # the local DC's site.  (ie. we set "detec_stale" flag to False)
        for connect in mydsa.connect_table.values():
            if connect.to_be_added:
                debug.DEBUG_BLUE("TO BE ADDED:\n%s" % connect)

        # Loop thru all the partitions.
        for partdn, part in self.part_table.items():
            self.construct_intrasite_graph(mysite, mydsa, part, False,
                                           False)  # don't detect stale

        # If the DC is a GC server, the KCC constructs an additional NC
        # replica graph (and creates nTDSConnection objects) for the
        # config NC as above, except that only NC replicas that "are present"
        # on GC servers are added to R.
        for connect in mydsa.connect_table.values():
            if connect.to_be_added:
                debug.DEBUG_RED("TO BE ADDED:\n%s" % connect)

        for partdn, part in self.part_table.items():
            if part.is_config():
                self.construct_intrasite_graph(mysite, mydsa, part, True,
                                               False)  # don't detect stale

        self._commit_changes(mydsa)

    def list_dsas(self):
        """Compile a comprehensive list of DSA DNs

        These are all the DSAs on all the sites that KCC would be
        dealing with.

        This method is not idempotent and may not work correctly in
        sequence with KCC.run().

        :return: a list of DSA DN strings.
        """
        self.load_my_site()
        self.load_my_dsa()

        self.load_all_sites()
        self.load_all_partitions()
        self.load_ip_transport()
        self.load_all_sitelinks()
        dsas = []
        for site in self.site_table.values():
            dsas.extend([dsa.dsa_dnstr.replace('CN=NTDS Settings,', '', 1)
                         for dsa in site.dsa_table.values()])
        return dsas

    def load_samdb(self, dburl, lp, creds, force=False):
        """Load the database using an url, loadparm, and credentials

        If force is False, the samdb won't be reloaded if it already
        exists.

        :param dburl: a database url.
        :param lp: a loadparm object.
        :param creds: a Credentials object.
        :param force: a boolean indicating whether to overwrite.

        """
        if force or self.samdb is None:
            try:
                self.samdb = SamDB(url=dburl,
                                   session_info=system_session(),
                                   credentials=creds, lp=lp)
            except ldb.LdbError as e1:
                (num, msg) = e1.args
                raise KCCError("Unable to open sam database %s : %s" %
                               (dburl, msg))

    def plot_all_connections(self, basename, verify_properties=()):
        """Helper function to plot and verify NTDSConnections

        :param basename: an identifying string to use in filenames and logs.
        :param verify_properties: properties to verify (default empty)
        """
        verify = verify_properties and self.verify
        if not verify and self.dot_file_dir is None:
            return

        dot_edges = []
        dot_vertices = []
        edge_colours = []
        vertex_colours = []

        for dsa in self.dsa_by_dnstr.values():
            dot_vertices.append(dsa.dsa_dnstr)
            if dsa.is_ro():
                vertex_colours.append('#cc0000')
            else:
                vertex_colours.append('#0000cc')
            for con in dsa.connect_table.values():
                if con.is_rodc_topology():
                    edge_colours.append('red')
                else:
                    edge_colours.append('blue')
                dot_edges.append((con.from_dnstr, dsa.dsa_dnstr))

        verify_and_dot(basename, dot_edges, vertices=dot_vertices,
                       label=self.my_dsa_dnstr,
                       properties=verify_properties, debug=DEBUG,
                       verify=verify, dot_file_dir=self.dot_file_dir,
                       directed=True, edge_colors=edge_colours,
                       vertex_colors=vertex_colours)

    def run(self, dburl, lp, creds, forced_local_dsa=None,
            forget_local_links=False, forget_intersite_links=False,
            attempt_live_connections=False):
        """Perform a KCC run, possibly updating repsFrom topology

        :param dburl: url of the database to work with.
        :param lp: a loadparm object.
        :param creds: a Credentials object.
        :param forced_local_dsa: pretend to be on the DSA with this dn_str
        :param forget_local_links: calculate as if no connections existed
               (boolean, default False)
        :param forget_intersite_links: calculate with only intrasite connection
               (boolean, default False)
        :param attempt_live_connections: attempt to connect to remote DSAs to
               determine link availability (boolean, default False)
        :return: 1 on error, 0 otherwise
        """
        if self.samdb is None:
            DEBUG_FN("samdb is None; let's load it from %s" % (dburl,))
            self.load_samdb(dburl, lp, creds, force=False)

        if forced_local_dsa:
            self.samdb.set_ntds_settings_dn("CN=NTDS Settings,%s" %
                                            forced_local_dsa)

        try:
            # Setup
            self.load_my_site()
            self.load_my_dsa()

            self.load_all_sites()
            self.load_all_partitions()
            self.load_ip_transport()
            self.load_all_sitelinks()

            if self.verify or self.dot_file_dir is not None:
                guid_to_dnstr = {}
                for site in self.site_table.values():
                    guid_to_dnstr.update((str(dsa.dsa_guid), dnstr)
                                         for dnstr, dsa
                                         in site.dsa_table.items())

                self.plot_all_connections('dsa_initial')

                dot_edges = []
                current_reps, needed_reps = self.my_dsa.get_rep_tables()
                for dnstr, c_rep in current_reps.items():
                    DEBUG("c_rep %s" % c_rep)
                    dot_edges.append((self.my_dsa.dsa_dnstr, dnstr))

                verify_and_dot('dsa_repsFrom_initial', dot_edges,
                               directed=True, label=self.my_dsa_dnstr,
                               properties=(), debug=DEBUG, verify=self.verify,
                               dot_file_dir=self.dot_file_dir)

                dot_edges = []
                for site in self.site_table.values():
                    for dsa in site.dsa_table.values():
                        current_reps, needed_reps = dsa.get_rep_tables()
                        for dn_str, rep in current_reps.items():
                            for reps_from in rep.rep_repsFrom:
                                DEBUG("rep %s" % rep)
                                dsa_guid = str(reps_from.source_dsa_obj_guid)
                                dsa_dn = guid_to_dnstr[dsa_guid]
                                dot_edges.append((dsa.dsa_dnstr, dsa_dn))

                verify_and_dot('dsa_repsFrom_initial_all', dot_edges,
                               directed=True, label=self.my_dsa_dnstr,
                               properties=(), debug=DEBUG, verify=self.verify,
                               dot_file_dir=self.dot_file_dir)

                dot_edges = []
                dot_colours = []
                for link in self.sitelink_table.values():
                    from hashlib import md5
                    tmp_str = link.dnstr.encode('utf8')
                    colour = '#' + md5(tmp_str).hexdigest()[:6]
                    for a, b in itertools.combinations(link.site_list, 2):
                        dot_edges.append((a[1], b[1]))
                        dot_colours.append(colour)
                properties = ('connected',)
                verify_and_dot('dsa_sitelink_initial', dot_edges,
                               directed=False,
                               label=self.my_dsa_dnstr, properties=properties,
                               debug=DEBUG, verify=self.verify,
                               dot_file_dir=self.dot_file_dir,
                               edge_colors=dot_colours)

            if forget_local_links:
                for dsa in self.my_site.dsa_table.values():
                    dsa.connect_table = dict((k, v) for k, v in
                                             dsa.connect_table.items()
                                             if v.is_rodc_topology() or
                                             (v.from_dnstr not in
                                              self.my_site.dsa_table))
                self.plot_all_connections('dsa_forgotten_local')

            if forget_intersite_links:
                for site in self.site_table.values():
                    for dsa in site.dsa_table.values():
                        dsa.connect_table = dict((k, v) for k, v in
                                                 dsa.connect_table.items()
                                                 if site is self.my_site and
                                                 v.is_rodc_topology())

                self.plot_all_connections('dsa_forgotten_all')

            if attempt_live_connections:
                # Encapsulates lp and creds in a function that
                # attempts connections to remote DSAs.
                def ping(self, dnsname):
                    try:
                        drs_utils.drsuapi_connect(dnsname, self.lp, self.creds)
                    except drs_utils.drsException:
                        return False
                    return True
            else:
                ping = None
            # These are the published steps (in order) for the
            # MS-TECH description of the KCC algorithm ([MS-ADTS] 6.2.2)

            # Step 1
            self.refresh_failed_links_connections(ping)

            # Step 2
            self.intrasite()

            # Step 3
            all_connected = self.intersite(ping)

            # Step 4
            self.remove_unneeded_ntdsconn(all_connected)

            # Step 5
            self.translate_ntdsconn()

            # Step 6
            self.remove_unneeded_failed_links_connections()

            # Step 7
            self.update_rodc_connection()

            if self.verify or self.dot_file_dir is not None:
                self.plot_all_connections('dsa_final',
                                          ('connected',))

                debug.DEBUG_MAGENTA("there are %d dsa guids" %
                                    len(guid_to_dnstr))

                dot_edges = []
                edge_colors = []
                my_dnstr = self.my_dsa.dsa_dnstr
                current_reps, needed_reps = self.my_dsa.get_rep_tables()
                for dnstr, n_rep in needed_reps.items():
                    for reps_from in n_rep.rep_repsFrom:
                        guid_str = str(reps_from.source_dsa_obj_guid)
                        dot_edges.append((my_dnstr, guid_to_dnstr[guid_str]))
                        edge_colors.append('#' + str(n_rep.nc_guid)[:6])

                verify_and_dot('dsa_repsFrom_final', dot_edges, directed=True,
                               label=self.my_dsa_dnstr,
                               properties=(), debug=DEBUG, verify=self.verify,
                               dot_file_dir=self.dot_file_dir,
                               edge_colors=edge_colors)

                dot_edges = []

                for site in self.site_table.values():
                    for dsa in site.dsa_table.values():
                        current_reps, needed_reps = dsa.get_rep_tables()
                        for n_rep in needed_reps.values():
                            for reps_from in n_rep.rep_repsFrom:
                                dsa_guid = str(reps_from.source_dsa_obj_guid)
                                dsa_dn = guid_to_dnstr[dsa_guid]
                                dot_edges.append((dsa.dsa_dnstr, dsa_dn))

                verify_and_dot('dsa_repsFrom_final_all', dot_edges,
                               directed=True, label=self.my_dsa_dnstr,
                               properties=(), debug=DEBUG, verify=self.verify,
                               dot_file_dir=self.dot_file_dir)

        except:
            raise

        return 0

    def import_ldif(self, dburl, lp, ldif_file, forced_local_dsa=None):
        """Import relevant objects and attributes from an LDIF file.

        The point of this function is to allow a programmer/debugger to
        import an LDIF file with non-security relevent information that
        was previously extracted from a DC database.  The LDIF file is used
        to create a temporary abbreviated database.  The KCC algorithm can
        then run against this abbreviated database for debug or test
        verification that the topology generated is computationally the
        same between different OSes and algorithms.

        :param dburl: path to the temporary abbreviated db to create
        :param lp: a loadparm object.
        :param ldif_file: path to the ldif file to import
        :param forced_local_dsa: perform KCC from this DSA's point of view
        :return: zero on success, 1 on error
        """
        try:
            self.samdb = ldif_import_export.ldif_to_samdb(dburl, lp, ldif_file,
                                                          forced_local_dsa)
        except ldif_import_export.LdifError as e:
            logger.critical(e)
            return 1
        return 0

    def export_ldif(self, dburl, lp, creds, ldif_file):
        """Save KCC relevant details to an ldif file

        The point of this function is to allow a programmer/debugger to
        extract an LDIF file with non-security relevent information from
        a DC database.  The LDIF file can then be used to "import" via
        the import_ldif() function this file into a temporary abbreviated
        database.  The KCC algorithm can then run against this abbreviated
        database for debug or test verification that the topology generated
        is computationally the same between different OSes and algorithms.

        :param dburl: LDAP database URL to extract info from
        :param lp: a loadparm object.
        :param cred: a Credentials object.
        :param ldif_file: output LDIF file name to create
        :return: zero on success, 1 on error
        """
        try:
            ldif_import_export.samdb_to_ldif_file(self.samdb, dburl, lp, creds,
                                                  ldif_file)
        except ldif_import_export.LdifError as e:
            logger.critical(e)
            return 1
        return 0
