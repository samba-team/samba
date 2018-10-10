# Samba4 Domain update checker
#
# Copyright (C) Andrew Bartlett <abartlet@samba.org> 2017
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
import samba
from base64 import b64encode
from samba import sd_utils
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import security
from samba.dcerpc.security import SECINFO_DACL
from samba.descriptor import (
    get_managed_service_accounts_descriptor,
)
from samba.dsdb import (
    DS_DOMAIN_FUNCTION_2008,
    DS_DOMAIN_FUNCTION_2008_R2,
    DS_DOMAIN_FUNCTION_2012,
    DS_DOMAIN_FUNCTION_2012_R2,
    DS_DOMAIN_FUNCTION_2016,
)

MIN_UPDATE = 75
MAX_UPDATE = 81

update_map = {
    # Missing updates from 2008 R2 - version 5
    75: "5e1574f6-55df-493e-a671-aaeffca6a100",
    76: "d262aae8-41f7-48ed-9f35-56bbb677573d",
    77: "82112ba0-7e4c-4a44-89d9-d46c9612bf91",
    # Windows Server 2012 - version 9
    78: "c3c927a6-cc1d-47c0-966b-be8f9b63d991",
    79: "54afcfb9-637a-4251-9f47-4d50e7021211",
    80: "f4728883-84dd-483c-9897-274f2ebcf11e",
    81: "ff4f9d27-7157-4cb0-80a9-5d6f2b14c8ff",
    # Windows Server 2012 R2 - version 10
    # No updates
}

functional_level_to_max_update = {
    DS_DOMAIN_FUNCTION_2008: 74,
    DS_DOMAIN_FUNCTION_2008_R2: 77,
    DS_DOMAIN_FUNCTION_2012: 81,
    DS_DOMAIN_FUNCTION_2012_R2: 81,
    DS_DOMAIN_FUNCTION_2016: 88,
}

functional_level_to_version = {
    DS_DOMAIN_FUNCTION_2008: 3,
    DS_DOMAIN_FUNCTION_2008_R2: 5,
    DS_DOMAIN_FUNCTION_2012: 9,
    DS_DOMAIN_FUNCTION_2012_R2: 10,
    DS_DOMAIN_FUNCTION_2016: 15,
}

# No update numbers have been skipped over
missing_updates = []


class DomainUpdateException(Exception):
    pass


class DomainUpdate(object):
    """Check and update a SAM database for domain updates"""

    def __init__(self, samdb, fix=False,
                 add_update_container=True):
        """
        :param samdb: LDB database
        :param fix: Apply the update if the container is missing
        :param add_update_container: Add the container at the end of the change
        :raise DomainUpdateException:
        """
        self.samdb = samdb
        self.fix = fix
        self.add_update_container = add_update_container
        # TODO: In future we should check for inconsistencies when it claims it has been done
        self.check_update_applied = False

        self.config_dn = self.samdb.get_config_basedn()
        self.domain_dn = self.samdb.domain_dn()
        self.schema_dn = self.samdb.get_schema_basedn()

        self.sd_utils = sd_utils.SDUtils(samdb)
        self.domain_sid = security.dom_sid(samdb.get_domain_sid())

        self.domainupdate_container = self.samdb.get_root_basedn()
        if not self.domainupdate_container.add_child("CN=Operations,CN=DomainUpdates,CN=System"):
            raise DomainUpdateException("Failed to add domain update container child")

        self.revision_object = self.samdb.get_root_basedn()
        if not self.revision_object.add_child("CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System"):
            raise DomainUpdateException("Failed to add revision object child")

    def check_updates_functional_level(self, functional_level,
                                       old_functional_level=None,
                                       update_revision=False):
        """
        Apply all updates for a given old and new functional level
        :param functional_level: constant
        :param old_functional_level: constant
        :param update_revision: modify the stored version
        :raise DomainUpdateException:
        """
        res = self.samdb.search(base=self.revision_object,
                                attrs=["revision"], scope=ldb.SCOPE_BASE)

        expected_update = functional_level_to_max_update[functional_level]

        if old_functional_level:
            min_update = functional_level_to_max_update[old_functional_level]
            min_update += 1
        else:
            min_update = MIN_UPDATE

        self.check_updates_range(min_update, expected_update)

        expected_version = functional_level_to_version[functional_level]
        found_version = int(res[0]['revision'][0])
        if update_revision and found_version < expected_version:
            if not self.fix:
                raise DomainUpdateException("Revision is not high enough. Fix is set to False."
                                            "\nExpected: %dGot: %d" % (expected_version,
                                                                       found_version))
            self.samdb.modify_ldif("""dn: %s
changetype: modify
replace: revision
revision: %d
""" % (str(self.revision_object), expected_version))

    def check_updates_iterator(self, iterator):
        """
        Apply a list of updates which must be within the valid range of updates
        :param iterator: Iterable specifying integer update numbers to apply
        :raise DomainUpdateException:
        """
        for op in iterator:
            if op < MIN_UPDATE or op > MAX_UPDATE:
                raise DomainUpdateException("Update number invalid.")

            # No LDIF file exists for the change
            getattr(self, "operation_%d" % op)(op)

    def check_updates_range(self, start=0, end=0):
        """
        Apply a range of updates which must be within the valid range of updates
        :param start: integer update to begin
        :param end: integer update to end (inclusive)
        :raise DomainUpdateException:
        """
        op = start
        if start < MIN_UPDATE or start > end or end > MAX_UPDATE:
            raise DomainUpdateException("Update number invalid.")
        while op <= end:
            if op not in missing_updates:
                # No LDIF file exists for the change
                getattr(self, "operation_%d" % op)(op)

            op += 1

    def update_exists(self, op):
        """
        :param op: Integer update number
        :return: True if update exists else False
        """
        try:
            res = self.samdb.search(base=self.domainupdate_container,
                                    expression="(CN=%s)" % update_map[op])
        except ldb.LdbError:
            return False

        return len(res) == 1

    def update_add(self, op):
        """
        Add the corresponding container object for the given update
        :param op: Integer update
        """
        self.samdb.add_ldif("""dn: CN=%s,%s
objectClass: container
""" % (update_map[op], str(self.domainupdate_container)))

    def insert_ace_into_dacl(self, dn, existing_sddl, ace):
        """
        Add an ACE to a DACL, checking if it already exists with a simple string search.

        :param dn: DN to modify
        :param existing_sddl: existing sddl as string
        :param ace: string ace to insert
        :return: True if modified else False
        """
        index = existing_sddl.rfind("S:")
        if index != -1:
            new_sddl = existing_sddl[:index] + ace + existing_sddl[index:]
        else:
            # Insert it at the end if no S: section
            new_sddl = existing_sddl + ace

        if ace in existing_sddl:
            return False

        self.sd_utils.modify_sd_on_dn(dn, new_sddl,
                                      controls=["sd_flags:1:%d" % SECINFO_DACL])

        return True

    def insert_ace_into_string(self, dn, ace, attr):
        """
        Insert an ACE into a string attribute like defaultSecurityDescriptor.
        This also checks if it already exists using a simple string search.

        :param dn: DN to modify
        :param ace: string ace to insert
        :param attr: attribute to modify
        :return: True if modified else False
        """
        msg = self.samdb.search(base=dn,
                                attrs=[attr],
                                controls=["search_options:1:2"])

        assert len(msg) == 1
        existing_sddl = msg[0][attr][0]
        index = existing_sddl.rfind("S:")
        if index != -1:
            new_sddl = existing_sddl[:index] + ace + existing_sddl[index:]
        else:
            # Insert it at the end if no S: section
            new_sddl = existing_sddl + ace

        if ace in existing_sddl:
            return False

        m = ldb.Message()
        m.dn = dn
        m[attr] = ldb.MessageElement(new_sddl, ldb.FLAG_MOD_REPLACE,
                                     attr)

        self.samdb.modify(m, controls=["relax:0"])

        return True

    def raise_if_not_fix(self, op):
        """
        Raises an exception if not set to fix.
        :param op: Integer operation
        :raise DomainUpdateException:
        """
        if not self.fix:
            raise DomainUpdateException("Missing operation %d. Fix is currently set to False" % op)

    # Create a new object CN=TPM Devices in the Domain partition.
    def operation_78(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        self.samdb.add_ldif("""dn: CN=TPM Devices,%s
objectClass: top
objectClass: msTPM-InformationObjectsContainer
""" % self.domain_dn,
                            controls=["relax:0", "provision:0"])

        if self.add_update_container:
            self.update_add(op)

    # Created an access control entry for the TPM service.
    def operation_79(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        ace = "(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)"

        res = self.samdb.search(expression="(objectClass=samDomain)",
                                attrs=["nTSecurityDescriptor"],
                                controls=["search_options:1:2"])
        for msg in res:
            existing_sd = ndr_unpack(security.descriptor,
                                     msg["nTSecurityDescriptor"][0])
            existing_sddl = existing_sd.as_sddl(self.domain_sid)

            self.insert_ace_into_dacl(msg.dn, existing_sddl, ace)

        res = self.samdb.search(expression="(objectClass=domainDNS)",
                                attrs=["nTSecurityDescriptor"],
                                controls=["search_options:1:2"])
        for msg in res:
            existing_sd = ndr_unpack(security.descriptor,
                                     msg["nTSecurityDescriptor"][0])
            existing_sddl = existing_sd.as_sddl(self.domain_sid)

            self.insert_ace_into_dacl(msg.dn, existing_sddl, ace)

        if self.add_update_container:
            self.update_add(op)

    # Grant "Clone DC" extended right to Cloneable Domain Controllers group
    def operation_80(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        ace = "(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;%s-522)" % str(self.domain_sid)

        res = self.samdb.search(base=self.domain_dn,
                                scope=ldb.SCOPE_BASE,
                                attrs=["nTSecurityDescriptor"],
                                controls=["search_options:1:2",
                                          "sd_flags:1:%d" % SECINFO_DACL])
        msg = res[0]

        existing_sd = ndr_unpack(security.descriptor,
                                 msg["nTSecurityDescriptor"][0])
        existing_sddl = existing_sd.as_sddl(self.domain_sid)

        self.insert_ace_into_dacl(msg.dn, existing_sddl, ace)

        if self.add_update_container:
            self.update_add(op)

    # Grant ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity to Principal Self
    # on all objects
    def operation_81(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        ace = "(OA;CIOI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)"

        res = self.samdb.search(expression="(objectClass=samDomain)",
                                attrs=["nTSecurityDescriptor"],
                                controls=["search_options:1:2"])
        for msg in res:
            existing_sd = ndr_unpack(security.descriptor,
                                     msg["nTSecurityDescriptor"][0])
            existing_sddl = existing_sd.as_sddl(self.domain_sid)

            self.insert_ace_into_dacl(msg.dn, existing_sddl, ace)

        res = self.samdb.search(expression="(objectClass=domainDNS)",
                                attrs=["nTSecurityDescriptor"],
                                controls=["search_options:1:2"])

        for msg in res:
            existing_sd = ndr_unpack(security.descriptor,
                                     msg["nTSecurityDescriptor"][0])
            existing_sddl = existing_sd.as_sddl(self.domain_sid)

            self.insert_ace_into_dacl(msg.dn, existing_sddl, ace)

        if self.add_update_container:
            self.update_add(op)

    #
    # THE FOLLOWING ARE MISSING UPDATES FROM 2008 R2
    #

    # Add Managed Service Accounts container
    def operation_75(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        descriptor = get_managed_service_accounts_descriptor(self.domain_sid)
        managedservice_descr = b64encode(descriptor).decode('utf8')
        managed_service_dn = "CN=Managed Service Accounts,%s" % \
            str(self.domain_dn)

        self.samdb.modify_ldif("""dn: %s
changetype: add
objectClass: container
description: Default container for managed service accounts
showInAdvancedViewOnly: FALSE
nTSecurityDescriptor:: %s""" % (managed_service_dn, managedservice_descr),
                               controls=["relax:0", "provision:0"])

        if self.add_update_container:
            self.update_add(op)

    # Add the otherWellKnownObjects reference to MSA
    def operation_76(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        managed_service_dn = "CN=Managed Service Accounts,%s" % \
            str(self.domain_dn)

        self.samdb.modify_ldif("""dn: %s
changetype: modify
add: otherWellKnownObjects
otherWellKnownObjects: B:32:1EB93889E40C45DF9F0C64D23BBB6237:%s
""" % (str(self.domain_dn), managed_service_dn), controls=["relax:0",
                                                           "provision:0"])

        if self.add_update_container:
            self.update_add(op)

    # Add the PSPs object in the System container
    def operation_77(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        self.samdb.add_ldif("""dn: CN=PSPs,CN=System,%s
objectClass: top
objectClass: msImaging-PSPs
""" % str(self.domain_dn), controls=["relax:0", "provision:0"])

        if self.add_update_container:
            self.update_add(op)
