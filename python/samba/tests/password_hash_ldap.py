# Tests for Tests for source4/dsdb/samdb/ldb_modules/password_hash.c
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

"""
Tests for source4/dsdb/samdb/ldb_modules/password_hash.c

These tests are designed to also run against Windows to confirm the values
returned from Windows.

To run against Windows:
Set the following environment variables:
   PASSWORD=Administrator password
   USERNAME=Administrator
   SMB_CONF_PATH=/dev/null
   PYTHONPATH=bin/python
   SERVER=Windows server IP

   /usr/bin/python source4/scripting/bin/subunitrun
       samba.tests.password_hash_ldap.PassWordHashLDAPTests
       -U"Administrator%adminpassword"
"""

from samba.tests.password_hash import (
    PassWordHashTests,
    get_package,
    USER_NAME,
    USER_PASS
)
from samba.samdb import SamDB
from samba.ndr import ndr_unpack
from samba.dcerpc import drsblobs, drsuapi, misc
from samba import drs_utils, net
from samba.credentials import Credentials
from samba.compat import text_type
import binascii
import os


def attid_equal(a1, a2):
    return (a1 & 0xffffffff) == (a2 & 0xffffffff)


class PassWordHashLDAPTests(PassWordHashTests):

    def setUp(self):
        super(PassWordHashLDAPTests, self).setUp()

    # Get the supplemental credentials for the user under test
    def get_supplemental_creds_drs(self):
        binding_str = "ncacn_ip_tcp:%s[seal]" % os.environ["SERVER"]
        dn = "cn=" + USER_NAME + ",cn=users," + self.base_dn
        drs = drsuapi.drsuapi(binding_str, self.get_loadparm(), self.creds)
        (drs_handle, supported_extensions) = drs_utils.drs_DsBind(drs)

        req8 = drsuapi.DsGetNCChangesRequest8()

        null_guid = misc.GUID()
        req8.destination_dsa_guid          = null_guid
        req8.source_dsa_invocation_id      = null_guid
        req8.naming_context                = drsuapi.DsReplicaObjectIdentifier()
        req8.naming_context.dn             = text_type(dn)

        req8.highwatermark = drsuapi.DsReplicaHighWaterMark()
        req8.highwatermark.tmp_highest_usn = 0
        req8.highwatermark.reserved_usn    = 0
        req8.highwatermark.highest_usn     = 0
        req8.uptodateness_vector           = None
        req8.replica_flags                 = (drsuapi.DRSUAPI_DRS_INIT_SYNC |
                                              drsuapi.DRSUAPI_DRS_PER_SYNC |
                                              drsuapi.DRSUAPI_DRS_GET_ANC |
                                              drsuapi.DRSUAPI_DRS_NEVER_SYNCED |
                                              drsuapi.DRSUAPI_DRS_WRIT_REP)
        req8.max_object_count         = 402
        req8.max_ndr_size             = 402116
        req8.extended_op              = drsuapi.DRSUAPI_EXOP_REPL_OBJ
        req8.fsmo_info                = 0
        req8.partial_attribute_set    = None
        req8.partial_attribute_set_ex = None
        req8.mapping_ctr.num_mappings = 0
        req8.mapping_ctr.mappings     = None
        (level, ctr) = drs.DsGetNCChanges(drs_handle, 8, req8)

        obj_item = ctr.first_object
        obj = obj_item.object

        sc_blob = None

        for i in range(0, obj.attribute_ctr.num_attributes):
            attr = obj.attribute_ctr.attributes[i]
            if attid_equal(attr.attid,
                           drsuapi.DRSUAPI_ATTID_supplementalCredentials):
                net_ctx = net.Net(self.creds)
                net_ctx.replicate_decrypt(drs, attr, 0)
                sc_blob = attr.value_ctr.values[0].blob

        sc = ndr_unpack(drsblobs.supplementalCredentialsBlob, sc_blob)
        return sc

    def test_wDigest_supplementalCredentials(self):
        self.creds = Credentials()
        self.creds.set_username(os.environ["USERNAME"])
        self.creds.set_password(os.environ["PASSWORD"])
        self.creds.guess(self.lp)
        ldb = SamDB("ldap://" + os.environ["SERVER"],
                    credentials=self.creds,
                    lp=self.lp)

        self.add_user(ldb=ldb)

        sc = self.get_supplemental_creds_drs()

        (pos, package) = get_package(sc, "Primary:WDigest")
        self.assertEqual("Primary:WDigest", package.name)

        # Check that the WDigest values are correct.
        #
        digests = ndr_unpack(drsblobs.package_PrimaryWDigestBlob,
                             binascii.a2b_hex(package.data))
        self.check_wdigests(digests)
