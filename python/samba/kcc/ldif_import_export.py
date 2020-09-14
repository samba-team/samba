# LDIF helper functions for the samba_kcc tool
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

import os

from samba import Ldb, ldb, read_and_sub_file
from samba.auth import system_session
from samba.samdb import SamDB, dsdb_Dn


class LdifError(Exception):
    pass


def write_search_result(samdb, f, res):
    for msg in res:
        lstr = samdb.write_ldif(msg, ldb.CHANGETYPE_NONE)
        f.write("%s" % lstr)


def ldif_to_samdb(dburl, lp, ldif_file, forced_local_dsa=None):
    """Routine to import all objects and attributes that are relevent
    to the KCC algorithms from a previously exported LDIF file.

    The point of this function is to allow a programmer/debugger to
    import an LDIF file with non-security relevent information that
    was previously extracted from a DC database.  The LDIF file is used
    to create a temporary abbreviated database.  The KCC algorithm can
    then run against this abbreviated database for debug or test
    verification that the topology generated is computationally the
    same between different OSes and algorithms.

    :param dburl: path to the temporary abbreviated db to create
    :param ldif_file: path to the ldif file to import
    """
    if os.path.exists(dburl):
        raise LdifError("Specify a database (%s) that doesn't already exist." %
                        dburl)

    # Use ["modules:"] as we are attempting to build a sam
    # database as opposed to start it here.
    tmpdb = Ldb(url=dburl, session_info=system_session(),
                lp=lp, options=["modules:"])

    tmpdb.transaction_start()
    try:
        data = read_and_sub_file(ldif_file, None)
        tmpdb.add_ldif(data, None)
        if forced_local_dsa:
            tmpdb.modify_ldif("""dn: @ROOTDSE
changetype: modify
replace: dsServiceName
dsServiceName: CN=NTDS Settings,%s
            """ % forced_local_dsa)

        tmpdb.add_ldif("""dn: @MODULES
@LIST: rootdse,extended_dn_in,extended_dn_out_ldb,objectguid
-
""")

    except Exception as estr:
        tmpdb.transaction_cancel()
        raise LdifError("Failed to import %s: %s" % (ldif_file, estr))

    tmpdb.transaction_commit()

    # We have an abbreviated list of options here because we have built
    # an abbreviated database.  We use the rootdse and extended-dn
    # modules only during this re-open
    samdb = SamDB(url=dburl, session_info=system_session(), lp=lp)
    return samdb


def samdb_to_ldif_file(samdb, dburl, lp, creds, ldif_file):
    """Routine to extract all objects and attributes that are relevent
    to the KCC algorithms from a DC database.

    The point of this function is to allow a programmer/debugger to
    extract an LDIF file with non-security relevent information from
    a DC database.  The LDIF file can then be used to "import" via
    the import_ldif() function this file into a temporary abbreviated
    database.  The KCC algorithm can then run against this abbreviated
    database for debug or test verification that the topology generated
    is computationally the same between different OSes and algorithms.

    :param dburl: LDAP database URL to extract info from
    :param ldif_file: output LDIF file name to create
    """
    try:
        samdb = SamDB(url=dburl,
                      session_info=system_session(),
                      credentials=creds, lp=lp)
    except ldb.LdbError as e:
        (enum, estr) = e.args
        raise LdifError("Unable to open sam database (%s) : %s" %
                        (dburl, estr))

    if os.path.exists(ldif_file):
        raise LdifError("Specify a file (%s) that doesn't already exist." %
                        ldif_file)

    try:
        f = open(ldif_file, "w")
    except IOError as ioerr:
        raise LdifError("Unable to open (%s) : %s" % (ldif_file, str(ioerr)))

    try:
        # Query Partitions
        attrs = ["objectClass",
                 "objectGUID",
                 "cn",
                 "whenChanged",
                 "objectSid",
                 "Enabled",
                 "systemFlags",
                 "dnsRoot",
                 "nCName",
                 "msDS-NC-Replica-Locations",
                 "msDS-NC-RO-Replica-Locations"]

        sstr = "CN=Partitions,%s" % samdb.get_config_basedn()
        res = samdb.search(base=sstr, scope=ldb.SCOPE_SUBTREE,
                           attrs=attrs,
                           expression="(objectClass=crossRef)")

        # Write partitions output
        write_search_result(samdb, f, res)

        # Query cross reference container
        attrs = ["objectClass",
                 "objectGUID",
                 "cn",
                 "whenChanged",
                 "fSMORoleOwner",
                 "systemFlags",
                 "msDS-Behavior-Version",
                 "msDS-EnabledFeature"]

        sstr = "CN=Partitions,%s" % samdb.get_config_basedn()
        res = samdb.search(base=sstr, scope=ldb.SCOPE_SUBTREE,
                           attrs=attrs,
                           expression="(objectClass=crossRefContainer)")

        # Write cross reference container output
        write_search_result(samdb, f, res)

        # Query Sites
        attrs = ["objectClass",
                 "objectGUID",
                 "cn",
                 "whenChanged",
                 "systemFlags"]

        sstr = "CN=Sites,%s" % samdb.get_config_basedn()
        sites = samdb.search(base=sstr, scope=ldb.SCOPE_SUBTREE,
                             attrs=attrs,
                             expression="(objectClass=site)")

        # Write sites output
        write_search_result(samdb, f, sites)

        # Query NTDS Site Settings
        for msg in sites:
            sitestr = str(msg.dn)

            attrs = ["objectClass",
                     "objectGUID",
                     "cn",
                     "whenChanged",
                     "interSiteTopologyGenerator",
                     "interSiteTopologyFailover",
                     "schedule",
                     "options"]

            sstr = "CN=NTDS Site Settings,%s" % sitestr
            res = samdb.search(base=sstr, scope=ldb.SCOPE_BASE,
                               attrs=attrs)

            # Write Site Settings output
            write_search_result(samdb, f, res)

        # Naming context list
        nclist = []

        # Query Directory Service Agents
        for msg in sites:
            sstr = str(msg.dn)

            ncattrs = ["hasMasterNCs",
                       "msDS-hasMasterNCs",
                       "hasPartialReplicaNCs",
                       "msDS-HasDomainNCs",
                       "msDS-hasFullReplicaNCs",
                       "msDS-HasInstantiatedNCs"]
            attrs = ["objectClass",
                     "objectGUID",
                     "cn",
                     "whenChanged",
                     "invocationID",
                     "options",
                     "msDS-isRODC",
                     "msDS-Behavior-Version"]

            res = samdb.search(base=sstr, scope=ldb.SCOPE_SUBTREE,
                               attrs=attrs + ncattrs,
                               expression="(objectClass=nTDSDSA)")

            # Spin thru all the DSAs looking for NC replicas
            # and build a list of all possible Naming Contexts
            # for subsequent retrieval below
            for msg in res:
                for k in msg.keys():
                    if k in ncattrs:
                        for value in msg[k]:
                            # Some of these have binary DNs so
                            # use dsdb_Dn to split out relevent parts
                            dsdn = dsdb_Dn(samdb, value.decode('utf8'))
                            dnstr = str(dsdn.dn)
                            if dnstr not in nclist:
                                nclist.append(dnstr)

            # Write DSA output
            write_search_result(samdb, f, res)

        # Query NTDS Connections
        for msg in sites:
            sstr = str(msg.dn)

            attrs = ["objectClass",
                     "objectGUID",
                     "cn",
                     "whenChanged",
                     "options",
                     "whenCreated",
                     "enabledConnection",
                     "schedule",
                     "transportType",
                     "fromServer",
                     "systemFlags"]

            res = samdb.search(base=sstr, scope=ldb.SCOPE_SUBTREE,
                               attrs=attrs,
                               expression="(objectClass=nTDSConnection)")
            # Write NTDS Connection output
            write_search_result(samdb, f, res)

        # Query Intersite transports
        attrs = ["objectClass",
                 "objectGUID",
                 "cn",
                 "whenChanged",
                 "options",
                 "name",
                 "bridgeheadServerListBL",
                 "transportAddressAttribute"]

        sstr = "CN=Inter-Site Transports,CN=Sites,%s" % \
               samdb.get_config_basedn()
        res = samdb.search(sstr, scope=ldb.SCOPE_SUBTREE,
                           attrs=attrs,
                           expression="(objectClass=interSiteTransport)")

        # Write inter-site transport output
        write_search_result(samdb, f, res)

        # Query siteLink
        attrs = ["objectClass",
                 "objectGUID",
                 "cn",
                 "whenChanged",
                 "systemFlags",
                 "options",
                 "schedule",
                 "replInterval",
                 "siteList",
                 "cost"]

        sstr = "CN=Sites,%s" % \
               samdb.get_config_basedn()
        res = samdb.search(sstr, scope=ldb.SCOPE_SUBTREE,
                           attrs=attrs,
                           expression="(objectClass=siteLink)",
                           controls=['extended_dn:0'])

        # Write siteLink output
        write_search_result(samdb, f, res)

        # Query siteLinkBridge
        attrs = ["objectClass",
                 "objectGUID",
                 "cn",
                 "whenChanged",
                 "siteLinkList"]

        sstr = "CN=Sites,%s" % samdb.get_config_basedn()
        res = samdb.search(sstr, scope=ldb.SCOPE_SUBTREE,
                           attrs=attrs,
                           expression="(objectClass=siteLinkBridge)")

        # Write siteLinkBridge output
        write_search_result(samdb, f, res)

        # Query servers containers
        # Needed for samdb.server_site_name()
        attrs = ["objectClass",
                 "objectGUID",
                 "cn",
                 "whenChanged",
                 "systemFlags"]

        sstr = "CN=Sites,%s" % samdb.get_config_basedn()
        res = samdb.search(sstr, scope=ldb.SCOPE_SUBTREE,
                           attrs=attrs,
                           expression="(objectClass=serversContainer)")

        # Write servers container output
        write_search_result(samdb, f, res)

        # Query servers
        # Needed because some transport interfaces refer back to
        # attributes found in the server object.   Also needed
        # so extended-dn will be happy with dsServiceName in rootDSE
        attrs = ["objectClass",
                 "objectGUID",
                 "cn",
                 "whenChanged",
                 "systemFlags",
                 "dNSHostName",
                 "mailAddress"]

        sstr = "CN=Sites,%s" % samdb.get_config_basedn()
        res = samdb.search(sstr, scope=ldb.SCOPE_SUBTREE,
                           attrs=attrs,
                           expression="(objectClass=server)")

        # Write server output
        write_search_result(samdb, f, res)

        # Query Naming Context replicas
        attrs = ["objectClass",
                 "objectGUID",
                 "cn",
                 "whenChanged",
                 "objectSid",
                 "fSMORoleOwner",
                 "msDS-Behavior-Version",
                 "repsFrom",
                 "repsTo"]

        for sstr in nclist:
            res = samdb.search(sstr, scope=ldb.SCOPE_BASE,
                               attrs=attrs)

            # Write naming context output
            write_search_result(samdb, f, res)

        # Query rootDSE replicas
        attrs = ["objectClass",
                 "objectGUID",
                 "cn",
                 "whenChanged",
                 "rootDomainNamingContext",
                 "configurationNamingContext",
                 "schemaNamingContext",
                 "defaultNamingContext",
                 "dsServiceName"]

        sstr = ""
        res = samdb.search(sstr, scope=ldb.SCOPE_BASE,
                           attrs=attrs)

        # Record the rootDSE object as a dn as it
        # would appear in the base ldb file.  We have
        # to save it this way because we are going to
        # be importing as an abbreviated database.
        res[0].dn = ldb.Dn(samdb, "@ROOTDSE")

        # Write rootdse output
        write_search_result(samdb, f, res)

    except ldb.LdbError as e1:
        (enum, estr) = e1.args
        raise LdifError("Error processing (%s) : %s" % (sstr, estr))

    f.close()
