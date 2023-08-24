# Samba4 Forest update checker
#
# Copyright (C) Andrew Bartlett <abarlet@samba.org> 2017
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
from samba import sd_utils
from samba.dcerpc import security
from samba.provision.common import setup_path
from samba.dsdb import (
    DS_DOMAIN_FUNCTION_2008,
    DS_DOMAIN_FUNCTION_2008_R2,
    DS_DOMAIN_FUNCTION_2012,
    DS_DOMAIN_FUNCTION_2012_R2,
    DS_DOMAIN_FUNCTION_2016,
)

MIN_UPDATE = 11
MAX_UPDATE = 142

update_map = {
    # Missing updates from 2008
    11: "27a03717-5963-48fc-ba6f-69faa33e70ed",
    12: "3467dae5-dedd-4648-9066-f48ac186b20a",
    13: "33b7ee33-1386-47cf-baa1-b03e06473253",
    14: "e9ee8d55-c2fb-4723-a333-c80ff4dfbf45",
    15: "ccfae63a-7fb5-454c-83ab-0e8e1214974e",
    16: "ad3c7909-b154-4c16-8bf7-2c3a7870bb3d",
    17: "26ad2ebf-f8f5-44a4-b97c-a616c8b9d09a",
    18: "4444c516-f43a-4c12-9c4b-b5c064941d61",
    19: "436a1a4b-f41a-46e6-ac86-427720ef29f3",
    20: "b2b7fb45-f50d-41bc-a73b-8f580f3b636a",
    21: "1bdf6366-c3db-4d0b-b8cb-f99ba9bce20f",
    22: "63c0f51a-067c-4640-8a4f-044fb33f1049",
    23: "dae441c0-366e-482e-98d9-60a99a1898cc",
    24: "7dd09ca6-f0d6-43bf-b7f8-ef348f435617",
    25: "6b800a81-affe-4a15-8e41-6ea0c7aa89e4",
    26: "dd07182c-3174-4c95-902a-d64fee285bbf",
    27: "ffa5ee3c-1405-476d-b344-7ad37d69cc25",
    28: "099f1587-af70-49c6-ab6c-7b3e82be0fe2",
    29: "1a3f6b15-55f2-4752-ba27-3d38a8232c4d",
    30: "dee21a17-4e8e-4f40-a58c-c0c009b685a7",
    31: "9bd98bb4-4047-4de5-bf4c-7bd1d0f6d21d",
    32: "3fe80fbf-bf39-4773-b5bd-3e5767a30d2d",
    33: "f02915e2-9141-4f73-b8e7-2804662782da",
    34: "39902c52-ef24-4b4b-8033-2c9dfdd173a2",
    35: "20bf09b4-6d0b-4cd1-9c09-4231edf1209b",
    36: "94f238bb-831c-11d6-977b-00c04f613221",
    37: "94f238bc-831c-11d6-977b-00c04f613221",
    38: "94f238bd-831c-11d6-977b-00c04f613221",
    39: "94f238be-831c-11d6-977b-00c04f613221",
    40: "94f238bf-831c-11d6-977b-00c04f613221",
    41: "94f238c0-831c-11d6-977b-00c04f613221",
    42: "eda27b47-e610-11d6-9793-00c04f613221",
    43: "eda27b48-e610-11d6-9793-00c04f613221",
    44: "eda27b49-e610-11d6-9793-00c04f613221",
    45: "eda27b4a-e610-11d6-9793-00c04f613221",
    46: "26d9c510-e61a-11d6-9793-00c04f613221",
    47: "26d9c511-e61a-11d6-9793-00c04f613221",
    48: "ea08c04c-f474-4212-b19e-5e754f9210d4",
    49: "4c0672a2-437c-4944-b953-5db8f111d665",
    50: "4c022fd1-adab-4d84-a7f1-9580f03da856",
    51: "c03b1f37-c240-4910-93c8-1544a452b4b5",
    52: "560cf82d-9572-48a3-9024-6f2b56f1f866",
    53: "abd97102-88dd-4013-a009-0e2c2f967ff6",
    54: "134428a8-0043-48a6-bcda-63310d9ec4dd",
    55: "d668ad1f-cedd-4565-ab02-9385926ce4f5",
    56: "8f86b825-c322-4101-adc4-579f12d445db",
    57: "9fea28ff-387f-4d57-866d-3893c50f373f",
    58: "782370ce-3d38-438d-8b0c-464220a3039d",
    59: "002fb291-0d00-4b0c-8c00-fe7f50ce6f8d",
    60: "dcb3c95d-deb7-4c51-ad13-43a7d5d06fc7",
    61: "ef010a1e-bd88-48c8-a7af-2affd250d77d",
    62: "bd3413c0-9559-469b-9f3d-51d7faabd81a",
    63: "f814097b-3e3d-49ba-8a3a-092c25085f06",
    64: "6eb8eaf9-3403-4ba5-8b4b-ce349a4680ad",
    65: "07e57d28-ad40-44fc-8334-8a0dc119b3f4",
    66: "6fd48655-1698-497a-ac8d-8267ce01c80b",
    67: "10338d31-2423-4dff-b4b5-ef025144b01f",
    68: "a96e2ed5-7a7c-4d5c-9d5d-965eca0051da",
    69: "613bd063-e8e9-4a62-8f4c-cda566f7eb6f",
    70: "2a858903-5696-4364-b4e5-4cac027ca7a6",
    71: "0fc5a978-0059-4b0a-9dc2-9896e8e389a1",
    72: "4d753a29-26ac-4d1a-bc80-311f947e4f0a",
    73: "3b3adbdb-4485-4559-aed8-9811c4bf90e4",
    74: "56040c71-fe93-4037-8fe9-1a4d1a283009",
    75: "caa2bfad-0cca-483b-8d00-347f943292a8",
    76: "2b9e0609-6d75-498a-9727-c9fcc93f0e42",
    77: "96541a16-910a-4b66-acde-720a0dff03c7",
    78: "429a6334-1a00-4515-bf48-676deb55954a",
    # Windows Server 2008 R2 - version 5
    79: "21ae657c-6649-43c4-bbb3-7f184fdf58c1",
    80: "dca8f425-baae-47cd-b424-e3f6c76ed08b",
    81: "a662b036-dbbe-4166-b4ba-21abea17f9cc",
    82: "9d17b863-18c3-497d-9bde-45ddb95fcb65",
    83: "11c39bed-4bee-45f5-b195-8da0e05b573a",
    # Windows Server 2012 - version 11
    84: "4664e973-cb20-4def-b3d5-559d6fe123e0",
    85: "2972d92d-a07a-44ac-9cb0-bf243356f345",
    86: "09a49cb3-6c54-4b83-ab20-8370838ba149",
    87: "77283e65-ce02-4dc3-8c1e-bf99b22527c2",
    88: "0afb7f53-96bd-404b-a659-89e65c269420",
    89: "c7f717ef-fdbe-4b4b-8dfc-fa8b839fbcfa",
    90: "00232167-f3a4-43c6-b503-9acb7a81b01c",
    91: "73a9515b-511c-44d2-822b-444a33d3bd33",
    92: "e0c60003-2ed7-4fd3-8659-7655a7e79397",
    93: "ed0c8cca-80ab-4b6b-ac5a-59b1d317e11f",
    94: "b6a6c19a-afc9-476b-8994-61f5b14b3f05",
    95: "defc28cd-6cb6-4479-8bcb-aabfb41e9713",
    96: "d6bd96d4-e66b-4a38-9c6b-e976ff58c56d",
    97: "bb8efc40-3090-4fa2-8a3f-7cd1d380e695",
    98: "2d6abe1b-4326-489e-920c-76d5337d2dc5",
    99: "6b13dfb5-cecc-4fb8-b28d-0505cea24175",
    100: "92e73422-c68b-46c9-b0d5-b55f9c741410",
    101: "c0ad80b4-8e84-4cc4-9163-2f84649bcc42",
    102: "992fe1d0-6591-4f24-a163-c820fcb7f308",
    103: "ede85f96-7061-47bf-b11b-0c0d999595b5",
    104: "ee0f3271-eb51-414a-bdac-8f9ba6397a39",
    105: "587d52e0-507e-440e-9d67-e6129f33bb68",
    106: "ce24f0f6-237e-43d6-ac04-1e918ab04aac",
    107: "7f77d431-dd6a-434f-ae4d-ce82928e498f",
    108: "ba14e1f6-7cd1-4739-804f-57d0ea74edf4",
    109: "156ffa2a-e07c-46fb-a5c4-fbd84a4e5cce",
    110: "7771d7dd-2231-4470-aa74-84a6f56fc3b6",
    111: "49b2ae86-839a-4ea0-81fe-9171c1b98e83",
    112: "1b1de989-57ec-4e96-b933-8279a8119da4",
    113: "281c63f0-2c9a-4cce-9256-a238c23c0db9",
    114: "4c47881a-f15a-4f6c-9f49-2742f7a11f4b",
    115: "2aea2dc6-d1d3-4f0c-9994-66c1da21de0f",
    116: "ae78240c-43b9-499e-ae65-2b6e0f0e202a",
    117: "261b5bba-3438-4d5c-a3e9-7b871e5f57f0",
    118: "3fb79c05-8ea1-438c-8c7a-81f213aa61c2",
    119: "0b2be39a-d463-4c23-8290-32186759d3b1",
    120: "f0842b44-bc03-46a1-a860-006e8527fccd",
    121: "93efec15-4dd9-4850-bc86-a1f2c8e2ebb9",
    122: "9e108d96-672f-40f0-b6bd-69ee1f0b7ac4",
    123: "1e269508-f862-4c4a-b01f-420d26c4ff8c",
    125: "e1ab17ed-5efb-4691-ad2d-0424592c5755",
    126: "0e848bd4-7c70-48f2-b8fc-00fbaa82e360",
    127: "016f23f7-077d-41fa-a356-de7cfdb01797",
    128: "49c140db-2de3-44c2-a99a-bab2e6d2ba81",
    129: "e0b11c80-62c5-47f7-ad0d-3734a71b8312",
    130: "2ada1a2d-b02f-4731-b4fe-59f955e24f71",
    # Windows Server 2012 R2 - version 15
    131: "b83818c1-01a6-4f39-91b7-a3bb581c3ae3",
    132: "bbbb9db0-4009-4368-8c40-6674e980d3c3",
    133: "f754861c-3692-4a7b-b2c2-d0fa28ed0b0b",
    134: "d32f499f-3026-4af0-a5bd-13fe5a331bd2",
    135: "38618886-98ee-4e42-8cf1-d9a2cd9edf8b",
    # Windows Server 2016 - version 16
    136: "328092fb-16e7-4453-9ab8-7592db56e9c4",
    137: "3a1c887f-df0a-489f-b3f2-2d0409095f6e",
    138: "232e831f-f988-4444-8e3e-8a352e2fd411",
    139: "ddddcf0c-bec9-4a5a-ae86-3cfe6cc6e110",
    140: "a0a45aac-5550-42df-bb6a-3cc5c46b52f2",
    141: "3e7645f3-3ea5-4567-b35a-87630449c70c",
    142: "e634067b-e2c4-4d79-b6e8-73c619324d5e",
}

functional_level_to_max_update = {
    DS_DOMAIN_FUNCTION_2008: 78,
    DS_DOMAIN_FUNCTION_2008_R2: 83,
    DS_DOMAIN_FUNCTION_2012: 130,
    DS_DOMAIN_FUNCTION_2012_R2: 135,
    DS_DOMAIN_FUNCTION_2016: 142,
}

functional_level_to_version = {
    DS_DOMAIN_FUNCTION_2008: 2,
    DS_DOMAIN_FUNCTION_2008_R2: 5,
    DS_DOMAIN_FUNCTION_2012: 11,
    DS_DOMAIN_FUNCTION_2012_R2: 15,
    DS_DOMAIN_FUNCTION_2016: 16,
}

# Documentation says that this update was deprecated
missing_updates = [124]


class ForestUpdateException(Exception):
    pass


class ForestUpdate(object):
    """Check and update a SAM database for forest updates"""

    def __init__(self, samdb, verbose=False, fix=False,
                 add_update_container=True):
        """
        :param samdb: LDB database
        :param verbose: Show the ldif changes
        :param fix: Apply the update if the container is missing
        :param add_update_container: Add the container at the end of the change
        :raise ForestUpdateException:
        """
        from samba.ms_forest_updates_markdown import read_ms_markdown

        self.samdb = samdb
        self.fix = fix
        self.verbose = verbose
        self.add_update_container = add_update_container
        # TODO In future we should check for inconsistencies when it claims it has been done
        self.check_update_applied = False

        self.config_dn = self.samdb.get_config_basedn()
        self.domain_dn = self.samdb.domain_dn()
        self.schema_dn = self.samdb.get_schema_basedn()

        self.sd_utils = sd_utils.SDUtils(samdb)
        self.domain_sid = security.dom_sid(samdb.get_domain_sid())

        self.forestupdate_container = self.samdb.get_config_basedn()
        try:
            self.forestupdate_container.add_child("CN=Operations,CN=ForestUpdates")
        except ldb.LdbError:
            raise ForestUpdateException("Failed to add forest update container child")

        self.revision_object = self.samdb.get_config_basedn()
        try:
            self.revision_object.add_child("CN=ActiveDirectoryUpdate,CN=ForestUpdates")
        except ldb.LdbError:
            raise ForestUpdateException("Failed to add revision object child")

        # Store the result of parsing the markdown in a dictionary
        self.stored_ldif = {}
        read_ms_markdown(setup_path("adprep/WindowsServerDocs/Forest-Wide-Updates.md"),
                         out_dict=self.stored_ldif)

    def check_updates_functional_level(self, functional_level,
                                       old_functional_level=None,
                                       update_revision=False):
        """
        Apply all updates for a given old and new functional level
        :param functional_level: constant
        :param old_functional_level: constant
        :param update_revision: modify the stored version
        :raise ForestUpdateException:
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
                raise ForestUpdateException("Revision is not high enough. Fix is set to False."
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
        :raise ForestUpdateException:
        """
        for op in iterator:
            if op < MIN_UPDATE or op > MAX_UPDATE:
                raise ForestUpdateException("Update number invalid.")

            if 84 <= op <= 87:
                self.operation_ldif(op)
            elif 91 <= op <= 126:
                self.operation_ldif(op)
            elif 131 <= op <= 134:
                self.operation_ldif(op)
            elif 136 <= op <= 142:
                self.operation_ldif(op)
            else:
                # No LDIF file exists for the change
                getattr(self, "operation_%d" % op)(op)

    def check_updates_range(self, start=0, end=0):
        """
        Apply a range of updates which must be within the valid range of updates
        :param start: integer update to begin
        :param end: integer update to end (inclusive)
        :raise ForestUpdateException:
        """
        op = start
        if start < MIN_UPDATE or start > end or end > MAX_UPDATE:
            raise ForestUpdateException("Update number invalid.")
        while op <= end:
            if op in missing_updates:
                pass
            elif 84 <= op <= 87:
                self.operation_ldif(op)
            elif 91 <= op <= 126:
                self.operation_ldif(op)
            elif 131 <= op <= 134:
                self.operation_ldif(op)
            elif 136 <= op <= 142:
                self.operation_ldif(op)
            else:
                # No LDIF file exists for the change
                getattr(self, "operation_%d" % op)(op)

            op += 1

    def update_exists(self, op):
        """
        :param op: Integer update number
        :return: True if update exists else False
        """
        update_dn = "CN=%s,%s" % (update_map[op], self.forestupdate_container)
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
        print("Skip Forest Update %u: %s" % (op, update_map[op]))
        return True

    def update_add(self, op):
        """
        Add the corresponding container object for the given update
        :param op: Integer update
        """
        self.samdb.add_ldif("""dn: CN=%s,%s
objectClass: container
""" % (update_map[op], str(self.forestupdate_container)))
        print("Applied Forest Update %u: %s" % (op, update_map[op]))

    def operation_ldif(self, op):
        if self.update_exists(op):
            # Assume we have applied it (we have no double checks for these)
            return True

        guid = update_map[op]
        if guid in self.stored_ldif:
            ldif = self.stored_ldif[guid]
        elif guid.lower() in self.stored_ldif:
            ldif = self.stored_ldif[guid.lower()]
        elif guid.upper() in self.stored_ldif:
            ldif = self.stored_ldif[guid.upper()]
        else:
            raise ForestUpdateException("OPERATION %d: ldif for %s not found" %
                                        (op, guid))

        sub_ldif = samba.substitute_var(ldif, {"CONFIG_DN":
                                               str(self.config_dn),
                                               "FOREST_ROOT_DOMAIN":
                                               str(self.domain_dn),
                                               "SCHEMA_DN":
                                               str(self.schema_dn)})
        if self.verbose:
            print("UPDATE (LDIF) ------ OPERATION %d" % op)
            print(sub_ldif)

        try:
            self.samdb.modify_ldif(sub_ldif)
        except ldb.LdbError as e:
            (num, msg) = e.args
            if num != ldb.ERR_ATTRIBUTE_OR_VALUE_EXISTS:
                raise e
            pass

        if self.add_update_container:
            self.update_add(op)

    def raise_if_not_fix(self, op):
        """
        Raises an exception if not set to fix.
        :param op: Integer operation
        :raise ForestUpdateException:
        """
        if not self.fix:
            raise ForestUpdateException("Missing operation %d. Fix is currently set to False" % op)

    #
    # Created a new object CN=Sam-Domain in the Schema partition
    #
    # Created the following access control entry (ACE) to grant Write Property
    # to Principal Self on the object: ...
    #
    def operation_88(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        ace = "(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)"

        schema_dn = ldb.Dn(self.samdb, "CN=Sam-Domain,%s" % str(self.schema_dn))

        self.sd_utils.update_aces_in_dacl(schema_dn,
                                          sddl_attr="defaultSecurityDescriptor",
                                          add_aces=[ace])

        if self.add_update_container:
            self.update_add(op)

    #
    # Created a new object CN=Domain-DNS in the Schema partition
    #
    # Created the following access control entry (ACE) to grant Write Property
    # to Principal Self on the object: ...
    #
    def operation_89(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        ace = "(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)"

        schema_dn = ldb.Dn(self.samdb, "CN=Domain-DNS,%s" % str(self.schema_dn))

        self.sd_utils.update_aces_in_dacl(schema_dn,
                                          sddl_attr="defaultSecurityDescriptor",
                                          add_aces=[ace])

        if self.add_update_container:
            self.update_add(op)

    # Update display specifiers
    def operation_90(self, op):
        if self.add_update_container and not self.update_exists(op):
            self.update_add(op)

    # Update display specifiers
    def operation_127(self, op):
        if self.add_update_container and not self.update_exists(op):
            self.update_add(op)

    # Update appears to already be applied in documentation
    def operation_128(self, op):
        if self.add_update_container and not self.update_exists(op):
            self.update_add(op)

    # Grant ACE (OA;CIOI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS) to samDomain
    def operation_129(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        ace = "(OA;CIOI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)"

        schema_dn = ldb.Dn(self.samdb, "CN=Sam-Domain,%s" % str(self.schema_dn))

        self.sd_utils.update_aces_in_dacl(schema_dn,
                                          sddl_attr="defaultSecurityDescriptor",
                                          add_aces=[ace])

        if self.add_update_container:
            self.update_add(op)

    # Grant ACE (OA;CIOI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS) to domainDNS
    def operation_130(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        ace = "(OA;CIOI;RPWP;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;PS)"

        schema_dn = ldb.Dn(self.samdb, "CN=Domain-DNS,%s" % str(self.schema_dn))

        self.sd_utils.update_aces_in_dacl(schema_dn,
                                          sddl_attr="defaultSecurityDescriptor",
                                          add_aces=[ace])

        if self.add_update_container:
            self.update_add(op)

    # Set msDS-ClaimIsValueSpaceRestricted on ad://ext/AuthenticationSilo to FALSE
    def operation_135(self, op):
        if self.update_exists(op):
            return
        self.raise_if_not_fix(op)

        self.samdb.modify_ldif("""dn: CN=ad://ext/AuthenticationSilo,CN=Claim Types,CN=Claims Configuration,CN=Services,%s
changetype: modify
replace: msDS-ClaimIsValueSpaceRestricted
msDS-ClaimIsValueSpaceRestricted: FALSE
""" % self.config_dn,
                               controls=["relax:0", "provision:0"])

        if self.add_update_container:
            self.update_add(op)

    #
    # THE FOLLOWING ARE MISSING UPDATES FROM 2008 + 2008 R2
    #

    def operation_11(self, op):
        if self.add_update_container and not self.update_exists(op):
            self.update_add(op)

    def operation_54(self, op):
        if self.add_update_container and not self.update_exists(op):
            self.update_add(op)

    def operation_79(self, op):
        if self.add_update_container and not self.update_exists(op):
            self.update_add(op)

    def operation_80(self, op):
        if self.add_update_container and not self.update_exists(op):
            self.update_add(op)

    def operation_81(self, op):
        if self.add_update_container and not self.update_exists(op):
            self.update_add(op)

    def operation_82(self, op):
        if self.add_update_container and not self.update_exists(op):
            self.update_add(op)

    def operation_83(self, op):
        if self.add_update_container and not self.update_exists(op):
            self.update_add(op)
