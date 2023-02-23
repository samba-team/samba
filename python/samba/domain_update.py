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
MAX_UPDATE = 89

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
    # Windows Server 2016 - version 15
    82: "83c53da7-427e-47a4-a07a-a324598b88f7",
    # from the documentation and a fresh installtion
    # 83 is this:
    # c81fc9cc-0130-4fd1-b272-634d74818133
    # adprep will use this on the wire:
    # c81fc9cc-0130-f4d1-b272-634d74818133
    83: "c81fc9cc-0130-4fd1-b272-634d74818133",
    84: "e5f9e791-d96d-4fc9-93c9-d53e1dc439ba",
    85: "e6d5fd00-385d-4e65-b02d-9da3493ed850",
    86: "3a6b3fbf-3168-4312-a10d-dd5b3393952d",
    87: "7f950403-0ab3-47f9-9730-5d7b0269f9bd",
    88: "434bb40d-dbc9-4fe7-81d4-d57229f7b080",
    # Windows Server 2016 - version 16
    89: "a0c238ba-9e30-4ee6-80a6-43f731e9a5cd",
}


functional_level_to_max_update = {
    DS_DOMAIN_FUNCTION_2008: 74,
    DS_DOMAIN_FUNCTION_2008_R2: 77,
    DS_DOMAIN_FUNCTION_2012: 81,
    DS_DOMAIN_FUNCTION_2012_R2: 81,
    DS_DOMAIN_FUNCTION_2016: 89,
}

functional_level_to_version = {
    DS_DOMAIN_FUNCTION_2008: 3,
    DS_DOMAIN_FUNCTION_2008_R2: 5,
    DS_DOMAIN_FUNCTION_2012: 9,
    DS_DOMAIN_FUNCTION_2012_R2: 10,
    DS_DOMAIN_FUNCTION_2016: 16,
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
        try:
            self.domainupdate_container.add_child("CN=Operations,CN=DomainUpdates,CN=System")
        except ldb.LdbError:
            raise DomainUpdateException("Failed to add domain update container child")

        self.revision_object = self.samdb.get_root_basedn()
        try:
            self.revision_object.add_child("CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System")
        except ldb.LdbError:
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
        update_dn = "CN=%s,%s" % (update_map[op], self.domainupdate_container)
        try:
            res = self.samdb.search(base=update_dn,
                                    scope=ldb.SCOPE_BASE,
                                    attrs=[])
        except ldb.LdbError as e:
            (num, msg) = e.args
            if num != ldb.ERR_NO_SUCH_OBJECT:
                raise
            return False

        assert len(res) == 1
        print("Skip Domain Update %u: %s" % (op, update_map[op]))
        return True

    def update_add(self, op):
        """
        Add the corresponding container object for the given update
        :param op: Integer update
        """
        self.samdb.add_ldif("""dn: CN=%s,%s
objectClass: container
""" % (update_map[op], str(self.domainupdate_container)))
        print("Applied Domain Update %u: %s" % (op, update_map[op]))

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

        self.sd_utils.update_aces_in_dacl(self.domain_dn, add_aces=[ace])

        if self.add_update_container:
            self.update_add(op)

    # Grant "Clone DC" extended right to Cloneable Domain Controllers group
    def operation_80(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        ace = "(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;CN)"

        self.sd_utils.update_aces_in_dacl(self.domain_dn, add_aces=[ace])

        if self.add_update_container:
            self.update_add(op)

    # Grant ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity to Principal Self
    # on all objects
    def operation_81(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        ace = "(OA;CIOI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)"

        self.sd_utils.update_aces_in_dacl(self.domain_dn, add_aces=[ace])

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

    ## ## Windows Server 2016: Domain-wide updates
    ##
    ## After the operations that are performed by domainprep in Windows
    ## Server 2016 (operations 82-88) complete, the revision attribute for the
    ## CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System,DC=ForestRootDomain
    ## object is set to 15.

    ## Operation 82: {83c53da7-427e-47a4-a07a-a324598b88f7}
    ##
    ## Create CN=Keys container at root of domain
    ##
    ## - objectClass: container
    ## - description: Default container for key credential objects
    ## - ShowInAdvancedViewOnly: TRUE
    ##
    ## (A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)
    ## (A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)
    ## (A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)
    ## (A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DD)
    ## (A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;ED)
    ##
    def operation_82(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        keys_dn = "CN=Keys,%s" % str(self.domain_dn)

        sddl = "O:DA"
        sddl += "D:"
        sddl += "(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)"
        sddl += "(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)"
        sddl += "(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        sddl += "(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DD)"
        sddl += "(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;ED)"

        ldif = """
dn: %s
objectClass: container
description: Default container for key credential objects
ShowInAdvancedViewOnly: TRUE
nTSecurityDescriptor: %s
""" % (keys_dn, sddl)

        self.samdb.add_ldif(ldif)

        if self.add_update_container:
            self.update_add(op)

    ## Operation 83: {c81fc9cc-0130-4fd1-b272-634d74818133}
    ##
    ## Add Full Control allow aces to CN=Keys container for "domain\Key Admins"
    ## and "rootdomain\Enterprise Key Admins".
    ##
    ## (A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;Key Admins)
    ## (A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;Enterprise Key Admins)
    ##
    def operation_83(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        keys_dn = "CN=Keys,%s" % str(self.domain_dn)

        aces =  ["(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;KA)"]
        aces += ["(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EK)"]

        self.sd_utils.update_aces_in_dacl(keys_dn, add_aces=aces)

        if self.add_update_container:
            self.update_add(op)


    ## Operation 84: {e5f9e791-d96d-4fc9-93c9-d53e1dc439ba}
    ##
    ## Modify otherWellKnownObjects attribute to point to the CN=Keys container.
    ##
    ## - otherWellKnownObjects: B:32:683A24E2E8164BD3AF86AC3C2CF3F981:CN=Keys,%ws
    def operation_84(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        keys_dn = "CN=Keys,%s" % str(self.domain_dn)

        ldif = """
dn: %s
changetype: modify
add: otherWellKnownObjects
otherWellKnownObjects: B:32:683A24E2E8164BD3AF86AC3C2CF3F981:%s
""" % (str(self.domain_dn), keys_dn)

        self.samdb.modify_ldif(ldif)

        if self.add_update_container:
            self.update_add(op)


    ## Operation 85: {e6d5fd00-385d-4e65-b02d-9da3493ed850}
    ##
    ## Modify the domain NC to permit "domain\Key Admins" and
    ## "rootdomain\Enterprise Key Admins"
    ## to modify the msds-KeyCredentialLink attribute.
    ##
    ## (OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;Key Admins)
    ## (OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;Enterprise Key Admins)
    ## in root domain, but in non-root domains resulted in a bogus domain-relative
    ## ACE with a non-resolvable -527 SID
    ##
    def operation_85(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        aces =  ["(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;KA)"]
        # we use an explicit sid in order to replay the windows mistake
        aces += ["(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;%s-527)" %
                 str(self.domain_sid)]

        self.sd_utils.update_aces_in_dacl(self.domain_dn, add_aces=aces)

        if self.add_update_container:
            self.update_add(op)


    ## Operation 86: {3a6b3fbf-3168-4312-a10d-dd5b3393952d}
    ##
    ## Grant the DS-Validated-Write-Computer CAR to creator owner and self
    ##
    ## (OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)
    ## (OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)
    ##
    def operation_86(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        aces  = ["(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;PS)"]
        aces += ["(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;CO)"]

        self.sd_utils.update_aces_in_dacl(self.domain_dn, add_aces=aces)

        if self.add_update_container:
            self.update_add(op)

    ## Operation 87: {7f950403-0ab3-47f9-9730-5d7b0269f9bd}
    ##
    ## Delete the ACE granting Full Control to the incorrect
    ## domain-relative Enterprise Key Admins group, and add
    ## an ACE granting Full Control to Enterprise Key Admins group.
    ##
    ## Delete (A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;Enterprise Key Admins)
    ## Add (A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;Enterprise Key Admins)
    ##
    def operation_87(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        # we use an explicit sid in order to replay the windows mistake
        # note this is also strange for a 2nd reason because it doesn't
        # delete: ["(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;%s-527)"
        # which was added in operation_85, so the del is basically a noop
        # and the result is one additional ace
        del_aces = ["(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;%s-527)" %
                    str(self.domain_sid)]
        add_aces = ["(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EK)"]

        self.sd_utils.update_aces_in_dacl(self.domain_dn,
                                          del_aces=del_aces,
                                          add_aces=add_aces)

        if self.add_update_container:
            self.update_add(op)

    ## Operation 88: {434bb40d-dbc9-4fe7-81d4-d57229f7b080}
    ##
    ## Add "msDS-ExpirePasswordsOnSmartCardOnlyAccounts" on the domain NC object
    ## and set default value to FALSE
    ##
    def operation_88(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        ldif = """
dn: %s
changetype: modify
add: msDS-ExpirePasswordsOnSmartCardOnlyAccounts
msDS-ExpirePasswordsOnSmartCardOnlyAccounts: FALSE
""" % str(self.domain_dn)

        self.samdb.modify_ldif(ldif)

        if self.add_update_container:
            self.update_add(op)

    ## Windows Server 2016 (operation 89) complete, the **revision** attribute for the
    ## CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System,DC=ForestRootDomain object
    ## is set to **16**.
    ##

    ## Operation 89: {a0c238ba-9e30-4ee6-80a6-43f731e9a5cd}
    ##
    ## Delete the ACE granting Full Control to Enterprise Key Admins and
    ## add an ACE granting Enterprise Key Admins Full Control over just
    ## the msdsKeyCredentialLink attribute.
    ##
    ## Delete (A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;Enterprise Key Admins)
    ## Add (OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;Enterprise Key Admins)|
    ##
    def operation_89(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        # Note this only fixes the mistake from operation_87
        # but leaves the mistake of operation_85 if we're
        # not in the root domain...
        del_aces = ["(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EK)"]
        add_aces = ["(OA;CI;RPWP;5b47d60f-6090-40b2-9f37-2a4de88f3063;;EK)"]

        self.sd_utils.update_aces_in_dacl(self.domain_dn,
                                          del_aces=del_aces,
                                          add_aces=add_aces)

        if self.add_update_container:
            self.update_add(op)
