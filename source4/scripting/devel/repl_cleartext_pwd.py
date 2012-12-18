#!/usr/bin/env python
#
# Copyright Stefan Metzmacher 2011-2012
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
# This is useful to sync passwords from an AD domain.
#
#  $
#  $ source4/scripting/devel/repl_cleartext_pwd.py \
#  	-Uadministrator%A1b2C3d4 \
#  	172.31.9.219 DC=bla,DC=base /tmp/cookie cleartext_utf8 131085 displayName
#  # starting at usn[0]
#  dn: CN=Test User1,CN=Users,DC=bla,DC=base
#  cleartext_utf8: A1b2C3d4
#  displayName:: VABlAHMAdAAgAFUAcwBlAHIAMQA=
#
#  # up to usn[16449]
#  $
#  $ source4/scripting/devel/repl_cleartext_pwd.py \
#  	-Uadministrator%A1b2C3d4
#  	172.31.9.219 DC=bla,DC=base cookie_file cleartext_utf8 131085 displayName
#  # starting at usn[16449]
#  # up to usn[16449]
#  $
#

import sys

# Find right direction when running from source tree
sys.path.insert(0, "bin/python")

import samba.getopt as options
from optparse import OptionParser

from samba.dcerpc import drsuapi, drsblobs, misc
from samba.ndr import ndr_pack, ndr_unpack, ndr_print

import binascii
import hashlib
import Crypto.Cipher.ARC4
import struct
import os

from ldif import LDIFWriter

class globals:
    def __init__(self):
        self.global_objs = {}
        self.ldif = LDIFWriter(sys.stdout)

    def add_attr(self, dn, attname, vals):
        if dn not in self.global_objs:
           self.global_objs[dn] = {}
        self.global_objs[dn][attname] = vals

    def print_all(self):
        for dn, obj in self.global_objs.items():
           self.ldif.unparse(dn, obj)
           continue
        self.global_objs = {}

def attid_equal(a1,a2):
    return (a1 & 0xffffffff) == (a2 & 0xffffffff)

########### main code ###########
if __name__ == "__main__":
    parser = OptionParser("repl_cleartext_pwd.py [options] server dn cookie_file clear_utf8_name [attid attname attmode] [clear_utf16_name")
    sambaopts = options.SambaOptions(parser)
    credopts = options.CredentialsOptions(parser)
    parser.add_option_group(credopts)

    (opts, args) = parser.parse_args()

    if len(args) == 4:
        pass
    elif len(args) == 7:
        pass
    elif len(args) >= 8:
        pass
    else:
        parser.error("more arguments required - given=%d" % (len(args)))

    server = args[0]
    dn = args[1]
    cookie_file = args[2]
    if len(cookie_file) == 0:
        cookie_file = None
    clear_utf8_name = args[3]
    if len(args) >= 7:
        try:
            attid = int(args[4], 16)
        except Exception:
            attid = int(args[4])
        attname = args[5]
        attmode = args[6]
        if attmode not in ["raw", "utf8"]:
            parser.error("attmode should be 'raw' or 'utf8'")
    else:
        attid = -1
        attname = None
        attmode = "raw"
    if len(args) >= 8:
        clear_utf16_name = args[7]
    else:
        clear_utf16_name = None

    lp = sambaopts.get_loadparm()
    creds = credopts.get_credentials(lp)

    if not creds.authentication_requested():
        parser.error("You must supply credentials")

    gls = globals()
    try:
       f = open(cookie_file, 'r')
       store_blob = f.read()
       f.close()

       store_hdr = store_blob[0:28]
       (store_version, \
        store_dn_len, store_dn_ofs, \
        store_hwm_len, store_hwm_ofs, \
        store_utdv_len, store_utdv_ofs) = \
        struct.unpack("<LLLLLLL", store_hdr)

       store_dn = store_blob[store_dn_ofs:store_dn_ofs+store_dn_len]
       store_hwm_blob = store_blob[store_hwm_ofs:store_hwm_ofs+store_hwm_len]
       store_utdv_blob = store_blob[store_utdv_ofs:store_utdv_ofs+store_utdv_len]

       store_hwm = ndr_unpack(drsuapi.DsReplicaHighWaterMark, store_hwm_blob)
       store_utdv = ndr_unpack(drsblobs.replUpToDateVectorBlob, store_utdv_blob)

       assert store_dn == dn
       #print "%s" % ndr_print(store_hwm)
       #print "%s" % ndr_print(store_utdv)
    except Exception:
       store_dn = dn
       store_hwm = drsuapi.DsReplicaHighWaterMark()
       store_hwm.tmp_highest_usn  = 0
       store_hwm.reserved_usn     = 0
       store_hwm.highest_usn      = 0
       store_utdv = None

    binding_str = "ncacn_ip_tcp:%s[spnego,seal]" % server

    drs_conn = drsuapi.drsuapi(binding_str, lp, creds)

    bind_info = drsuapi.DsBindInfoCtr()
    bind_info.length = 28
    bind_info.info = drsuapi.DsBindInfo28()
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_BASE
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_ASYNC_REPLICATION
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_REMOVEAPI
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_MOVEREQ_V2
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHG_COMPRESS
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V1
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_RESTORE_USN_OPTIMIZATION
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_KCC_EXECUTE
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_ADDENTRY_V2
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_LINKED_VALUE_REPLICATION
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V2
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_INSTANCE_TYPE_NOT_REQ_ON_MOD
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_CRYPTO_BIND
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GET_REPL_INFO
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_STRONG_ENCRYPTION
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_DCINFO_V01
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_TRANSITIVE_MEMBERSHIP
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_ADD_SID_HISTORY
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_POST_BETA3
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GET_MEMBERSHIPS2
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V6
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_NONDOMAIN_NCS
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHGREQ_V8
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V5
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V6
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_ADDENTRYREPLY_V3
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_GETCHGREPLY_V7
    bind_info.info.supported_extensions |= drsuapi.DRSUAPI_SUPPORTED_EXTENSION_VERIFY_OBJECT
    (info, drs_handle) = drs_conn.DsBind(misc.GUID(drsuapi.DRSUAPI_DS_BIND_GUID), bind_info)

    null_guid = misc.GUID()

    naming_context = drsuapi.DsReplicaObjectIdentifier()
    naming_context.dn              = dn
    highwatermark                  = store_hwm
    uptodateness_vector            = None
    if store_utdv is not None:
        uptodateness_vector = drsuapi.DsReplicaCursorCtrEx()
        if store_utdv.version == 1:
            uptodateness_vector.cursors = store_utdv.cursors
        elif store_utdv.version == 2:
            cursors = []
            for i in range(0, store_utdv.ctr.count):
                cursor = drsuapi.DsReplicaCursor()
                cursor.source_dsa_invocation_id = store_utdv.ctr.cursors[i].source_dsa_invocation_id
                cursor.highest_usn = store_utdv.ctr.cursors[i].highest_usn
                cursors.append(cursor)
            uptodateness_vector.cursors = cursors

    req8 = drsuapi.DsGetNCChangesRequest8()

    req8.destination_dsa_guid           = null_guid
    req8.source_dsa_invocation_id       = null_guid
    req8.naming_context                 = naming_context
    req8.highwatermark                  = highwatermark
    req8.uptodateness_vector            = uptodateness_vector
    req8.replica_flags                  = (drsuapi.DRSUAPI_DRS_INIT_SYNC |
                                           drsuapi.DRSUAPI_DRS_PER_SYNC |
                                           drsuapi.DRSUAPI_DRS_GET_ANC |
                                           drsuapi.DRSUAPI_DRS_NEVER_SYNCED |
                                           drsuapi.DRSUAPI_DRS_WRIT_REP)
    req8.max_object_count = 402
    req8.max_ndr_size = 402116
    req8.extended_op = 0
    req8.fsmo_info = 0
    req8.partial_attribute_set = None
    req8.partial_attribute_set_ex = None
    req8.mapping_ctr.num_mappings = 0
    req8.mapping_ctr.mappings = None

    user_session_key = drs_conn.user_session_key

    print "# starting at usn[%d]" % (highwatermark.highest_usn)

    while True:
        (level, ctr) = drs_conn.DsGetNCChanges(drs_handle, 8, req8)
        if ctr.first_object == None and ctr.object_count != 0:
            raise RuntimeError("DsGetNCChanges: NULL first_object with object_count=%u" % (ctr.object_count))

        obj_item = ctr.first_object
        while obj_item is not None:
            obj = obj_item.object

            if obj.identifier is None:
                obj_item = obj_item.next_object
                continue

            #print '%s' % obj.identifier.dn

            is_deleted = False
            for i in range(0, obj.attribute_ctr.num_attributes):
                attr = obj.attribute_ctr.attributes[i]
                if attid_equal(attr.attid, drsuapi.DRSUAPI_ATTID_isDeleted):
                    is_deleted = True
            if is_deleted:
                obj_item = obj_item.next_object
                continue

            spl_crypt = None
            attvals = None
            for i in range(0, obj.attribute_ctr.num_attributes):
                attr = obj.attribute_ctr.attributes[i]
                if attid_equal(attr.attid, attid):
                    attvals = []
                    for j in range(0, attr.value_ctr.num_values):
                        assert attr.value_ctr.values[j].blob is not None
                        val_raw = attr.value_ctr.values[j].blob
                        val = None
                        if attmode == "utf8":
                            val_unicode = unicode(val_raw, 'utf-16-le')
                            val = val_unicode.encode('utf-8')
                        elif attmode == "raw":
                            val = val_raw
                        else:
                            assert False, "attmode[%s]" % attmode
                        attvals.append(val)
                if not attid_equal(attr.attid, drsuapi.DRSUAPI_ATTID_supplementalCredentials):
                    continue
                assert attr.value_ctr.num_values <= 1
                if attr.value_ctr.num_values == 0:
                    break
                assert attr.value_ctr.values[0].blob is not None
                spl_crypt = attr.value_ctr.values[0].blob

            if spl_crypt is None:
                obj_item = obj_item.next_object
                continue

            assert len(spl_crypt) >= 20
            confounder = spl_crypt[0:16]
            enc_buffer = spl_crypt[16:]

            m5 = hashlib.md5()
            m5.update(user_session_key)
            m5.update(confounder)
            enc_key = m5.digest()

            rc4 = Crypto.Cipher.ARC4.new(enc_key)
            plain_buffer = rc4.decrypt(enc_buffer)

            (crc32_v) = struct.unpack("<L", plain_buffer[0:4])
            attr_val = plain_buffer[4:]
            crc32_c = binascii.crc32(attr_val) & 0xffffffff
            assert int(crc32_v[0]) == int(crc32_c), "CRC32 0x%08X != 0x%08X" % (crc32_v[0], crc32_c)

            spl = ndr_unpack(drsblobs.supplementalCredentialsBlob, attr_val)

            #print '%s' % ndr_print(spl)

            cleartext_hex = None

            for i in range(0, spl.sub.num_packages):
                pkg = spl.sub.packages[i]
                if pkg.name != "Primary:CLEARTEXT":
                    continue
                cleartext_hex = pkg.data

            if cleartext_hex is not None:
                cleartext_utf16 = binascii.a2b_hex(cleartext_hex)
                if clear_utf16_name is not None:
                    gls.add_attr(obj.identifier.dn, clear_utf16_name, [cleartext_utf16])
                try:
                    cleartext_unicode = unicode(cleartext_utf16, 'utf-16-le')
                    cleartext_utf8 = cleartext_unicode.encode('utf-8')
                    gls.add_attr(obj.identifier.dn, clear_utf8_name, [cleartext_utf8])
                except Exception:
                    pass

                if attvals is not None:
                    gls.add_attr(obj.identifier.dn, attname, attvals)

            krb5_old_hex = None

            for i in range(0, spl.sub.num_packages):
                pkg = spl.sub.packages[i]
                if pkg.name != "Primary:Kerberos":
                    continue
                krb5_old_hex = pkg.data

            if krb5_old_hex is not None:
                krb5_old_raw = binascii.a2b_hex(krb5_old_hex)
                krb5_old = ndr_unpack(drsblobs.package_PrimaryKerberosBlob, krb5_old_raw, allow_remaining=True)

                #print '%s' % ndr_print(krb5_old)

            krb5_new_hex = None

            for i in range(0, spl.sub.num_packages):
                pkg = spl.sub.packages[i]
                if pkg.name != "Primary:Kerberos-Newer-Keys":
                    continue
                krb5_new_hex = pkg.data

            if krb5_new_hex is not None:
                krb5_new_raw = binascii.a2b_hex(krb5_new_hex)
                krb5_new = ndr_unpack(drsblobs.package_PrimaryKerberosBlob, krb5_new_raw, allow_remaining=True)

                #print '%s' % ndr_print(krb5_new)

            obj_item = obj_item.next_object

        gls.print_all()

        if ctr.more_data == 0:
            store_hwm = ctr.new_highwatermark

            store_utdv = drsblobs.replUpToDateVectorBlob()
            store_utdv.version = ctr.uptodateness_vector.version
            store_utdv_ctr = store_utdv.ctr
            store_utdv_ctr.count = ctr.uptodateness_vector.count
            store_utdv_ctr.cursors = ctr.uptodateness_vector.cursors
            store_utdv.ctr = store_utdv_ctr

            #print "%s" % ndr_print(store_hwm)
            #print "%s" % ndr_print(store_utdv)

            store_hwm_blob = ndr_pack(store_hwm)
            store_utdv_blob = ndr_pack(store_utdv)

            #
            # uint32_t version '1'
            # uint32_t dn_str_len
            # uint32_t dn_str_ofs
            # uint32_t hwm_blob_len
            # uint32_t hwm_blob_ofs
            # uint32_t utdv_blob_len
            # uint32_t utdv_blob_ofs
            store_hdr_len = 7 * 4
            dn_ofs = store_hdr_len
            hwm_ofs = dn_ofs + len(dn)
            utdv_ofs = hwm_ofs + len(store_hwm_blob)
            store_blob = struct.pack("<LLLLLLL", 1, \
                                     len(dn), dn_ofs,
                                     len(store_hwm_blob), hwm_ofs, \
                                     len(store_utdv_blob), utdv_ofs) + \
                                     dn + store_hwm_blob + store_utdv_blob

            tmp_file = "%s.tmp" % cookie_file
            f = open(tmp_file, 'wb')
            f.write(store_blob)
            f.close()
            os.rename(tmp_file, cookie_file)

            print "# up to usn[%d]" % (ctr.new_highwatermark.highest_usn)
            break
        print "# up to tmp_usn[%d]" % (ctr.new_highwatermark.highest_usn)
        req8.highwatermark = ctr.new_highwatermark
