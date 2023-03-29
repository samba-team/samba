# Blackbox tests for ndrdump
# Copyright (C) 2008 Andrew Tridgell <tridge@samba.org>
# Copyright (C) 2008 Andrew Bartlett <abartlet@samba.org>
# Copyright (C) 2010 Jelmer Vernooij <jelmer@samba.org>
# based on test_smbclient.sh

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

"""Blackbox tests for ndrdump."""

import os
import re
from samba.tests import BlackboxTestCase, BlackboxProcessError

data_path_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../../source4/librpc/tests"))

class NdrDumpTests(BlackboxTestCase):
    """Blackbox tests for ndrdump."""

    def data_path(self, name):
        return os.path.join(data_path_dir, name)

    def test_ndrdump_with_in(self):
        self.check_run(("ndrdump --debug-stdout samr samr_CreateUser in %s" %
                       (self.data_path("samr-CreateUser-in.dat"))))

    def test_ndrdump_with_out(self):
        self.check_run(("ndrdump --debug-stdout samr samr_CreateUser out %s" %
                       (self.data_path("samr-CreateUser-out.dat"))))

    def test_ndrdump_context_file(self):
        self.check_run(
            ("ndrdump --debug-stdout --context-file %s samr samr_CreateUser out %s" %
                (self.data_path("samr-CreateUser-in.dat"),
                self.data_path("samr-CreateUser-out.dat"))))

    def test_ndrdump_with_validate(self):
        self.check_run(("ndrdump --debug-stdout --validate samr samr_CreateUser in %s" %
                       (self.data_path("samr-CreateUser-in.dat"))))

    def test_ndrdump_with_hex_decode_function(self):
        self.check_run(
            ("ndrdump --debug-stdout dns decode_dns_name_packet in --hex-input %s" %
                self.data_path("dns-decode_dns_name_packet-hex.dat")))

    def test_ndrdump_with_hex_struct_name(self):
        expected = open(self.data_path("dns-decode_dns_name_packet-hex.txt")).read()
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout dns dns_name_packet struct --hex-input %s" %
                self.data_path("dns-decode_dns_name_packet-hex.dat"))
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_with_binary_struct_name(self):
        # Prefix of the expected unparsed PAC data (without times, as
        # these vary by host)
        expected = '''pull returned Success
    PAC_DATA: struct PAC_DATA
        num_buffers              : 0x00000005 (5)
        version                  : 0x00000000 (0)
        buffers: ARRAY(5)'''
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout krb5pac PAC_DATA struct %s" %
                self.data_path("krb5pac-PAC_DATA.dat"))
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual[:len(expected)],
                         expected.encode('utf-8'))
        self.assertTrue(actual.endswith(b"dump OK\n"))

    def test_ndrdump_upn_dns_info_ex(self):
        with open(self.data_path(
                'krb5pac_upn_dns_info_ex.txt')) as f:
            expected = f.read()
        data_path = self.data_path(
            'krb5pac_upn_dns_info_ex.b64.txt')

        try:
            actual = self.check_output(
                'ndrdump --debug-stdout -d0 krb5pac PAC_DATA struct '
                '--validate --base64-input ' + data_path)
        except BlackboxProcessError as e:
            self.fail(e)

        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_upn_dns_info_ex_not_supported(self):
        with open(self.data_path(
                'krb5pac_upn_dns_info_ex_not_supported.txt')) as f:
            expected = f.read()
        data_path = self.data_path(
            'krb5pac_upn_dns_info_ex_not_supported.b64.txt')

        try:
            # This PAC has been edited to remove the
            # PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID bit, so that we can
            # simulate older versions of Samba parsing this structure.
            actual = self.check_output(
                'ndrdump --debug-stdout -d0 krb5pac PAC_DATA struct '
                '--validate --base64-input ' + data_path)
        except BlackboxProcessError as e:
            self.fail(e)

        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_with_binary_struct_number(self):
        expected = '''pull returned Success
    GUID                     : 33323130-3534-3736-3839-616263646566
dump OK
'''
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout misc 0 struct %s" %
                self.data_path("misc-GUID.dat"))
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_with_enum_not_struct(self):
        expected = '''Public structure 'netr_SchannelType' not found
'''
        try:
            actual = self.check_exit_code(
                "ndrdump --debug-stdout misc netr_SchannelType --input=x struct",
                1)
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_input_cmdline_short_struct_name(self):
        expected = '''pull returned Buffer Size Error
'''
        try:
            actual = self.check_exit_code(
                "ndrdump --debug-stdout -d0 misc GUID struct --input=abcdefg", 2)
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_input_cmdline_short_struct_name_dump(self):
        expected = '''pull returned Buffer Size Error
6 bytes consumed
[0000] 61 62 63 64 65 66 67                                abcdefg''' \
        '''
'''
        try:
            actual = self.check_exit_code(
                "ndrdump --debug-stdout -d0 misc GUID struct --input=abcdefg --dump-data", 2)
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_input_cmdline_short_struct_name_print_fail(self):
        expected = '''pull returned Buffer Size Error
6 bytes consumed
[0000] 61 62 63 64 65 66 67                                abcdefg''' \
        '''
WARNING! 1 unread bytes
[0000] 67                                                  g''' \
    '''
WARNING: pull of GUID was incomplete, therefore the parse below may SEGFAULT
    GUID                     : 64636261-6665-0000-0000-000000000000
dump of failed-to-parse GUID complete
'''
        try:
            actual = self.check_exit_code(
                "ndrdump --debug-stdout -d0 misc GUID struct --input=abcdefg --dump-data --print-after-parse-failure", 2)
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_fuzzed_clusapi_QueryAllValues(self):
        expected = b'''pull returned Success
WARNING! 53 unread bytes
[0000] 00 FF 00 00 FF 00 00 00   00 09 00 00 00 08 00 33   ........ .......3
[0010] 33 32 37 36 32 36 39 33   32 37 36 38 34 01 00 00   32762693 27684...
[0020] 80 32 0D FF 00 00 FF 00   00 00 00 08 00 00 00 1C   .2...... ........
[0030] F1 29 08 00 00                                      .)...''' \
        b'''
    clusapi_QueryAllValues: struct clusapi_QueryAllValues
        out: struct clusapi_QueryAllValues
            pcbData                  : *
                pcbData                  : 0x01000000 (16777216)
            ppData                   : *
                ppData: ARRAY(1)
                    ppData                   : NULL
            rpc_status               : *
                rpc_status               : WERR_OK
            result                   : WERR_NOT_ENOUGH_MEMORY
dump OK
'''
        try:
            actual = self.check_output(
                'ndrdump --debug-stdout clusapi clusapi_QueryAllValues out ' +\
                '--base64-input --input=' +\
                'AAAAAQEAAAAAAAAAAAAAAAgAAAAA/wAA/wAAAAAJAAAACAAzMzI3NjI2OTMyNzY4NAEAAIAyDf8AAP8AAAAACAAAABzxKQgAAA==')
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertEqual(actual, expected)

    def test_ndrdump_fuzzed_IOXIDResolver_ResolveOxid(self):
        expected = '''pull returned Character Conversion Error
'''
        try:
            actual = self.check_exit_code(
                'ndrdump --debug-stdout IOXIDResolver ResolveOxid out ' +\
                '--base64-input --input=' +\
                'c87PMf7CBAUAAAAADgQMBASjfPqKw0KPld6DY87PMfQ=',
                2)
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertRegex(actual.decode('utf8'), expected + "$")

    def test_ndrdump_fuzzed_IOXIDResolver_ResolveOxid2(self):
        expected = '''pull returned Buffer Size Error
'''
        try:
            actual = self.check_exit_code(
                'ndrdump --debug-stdout IOXIDResolver ResolveOxid2 out ' +\
                '--base64-input --input=' +\
                'AAAAAQ0K9Q0AAAAAAAAAA6ampqampqampqampqampqampqampqamNAAAAAAtNDQ=',
                2)
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertRegex(actual.decode('utf8'), expected + "$")

    def test_ndrdump_fuzzed_IOXIDResolver_ServerAlive2(self):
        expected = b'''pull returned Success
WARNING! 46 unread bytes
[0000] 0D 36 0A 0A 0A 0A 0A 00   00 00 00 00 00 00 03 00   .6...... ........
[0010] 00 00 01 00 00 33 39 36   31 36 31 37 37 36 38 34   .....396 16177684
[0020] 32 34 FC 85 AC 49 0B 61   87 0A 0A 0A F5 00         24...I.a ......
    ServerAlive: struct ServerAlive
        out: struct ServerAlive
            result                   : DOS code 0x01000000
dump OK
'''
        try:
            actual = self.check_output(
                'ndrdump --debug-stdout IOXIDResolver ServerAlive out ' +\
                '--base64-input --input=' +\
                'AAAAAQ02CgoKCgoAAAAAAAAAAwAAAAEAADM5NjE2MTc3Njg0MjT8haxJC2GHCgoK9QA=')
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertEqual(actual, expected)

    def test_ndrdump_fuzzed_IRemoteActivation_RemoteActivation(self):
        expected = '''pull returned Buffer Size Error
'''
        try:
            actual = self.check_exit_code(
                'ndrdump --debug-stdout IRemoteActivation RemoteActivation out ' +\
                '--base64-input --input=' +\
                'AAAAAQAAAAAAAABKAAD/AAAAAP4AAAAAAAAASgAAAAAAAAABIiIjIiIiIiIiIiIiIiMiAAAAAAD/AAAAAAAA',
                2)
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertRegex(actual.decode('utf8'), expected + "$")

    def test_ndrdump_fuzzed_ntlmsssp_AUTHENTICATE_MESSAGE(self):
        expected = open(self.data_path("fuzzed_ntlmssp-AUTHENTICATE_MESSAGE.txt")).read()
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout ntlmssp AUTHENTICATE_MESSAGE struct --base64-input %s --validate" %
                self.data_path("fuzzed_ntlmssp-AUTHENTICATE_MESSAGE.b64.txt"))
        except BlackboxProcessError as e:
            self.fail(e)
        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_fuzzed_PackagesBlob(self):
        expected = 'ndr_pull_string: ndr_pull_error\\(Buffer Size Error\\):'
        command = (
            "ndrdump --debug-stdout drsblobs package_PackagesBlob struct --input='aw=='"
            " --base64-input")
        try:
            actual = self.check_exit_code(command, 2)
        except BlackboxProcessError as e:
            self.fail(e)
        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertRegex(actual.decode('utf8'), expected)

    def test_ndrdump_fuzzed_drsuapi_DsAddEntry_1(self):
        expected = open(self.data_path("fuzzed_drsuapi_DsAddEntry_1.txt")).read()
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout drsuapi drsuapi_DsAddEntry in --base64-input --validate %s" %
                self.data_path("fuzzed_drsuapi_DsAddEntry_1.b64.txt"))
        except BlackboxProcessError as e:
            self.fail(e)
        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_fuzzed_drsuapi_DsaAddressListItem_V1(self):
        expected = "Maximum Recursion Exceeded"
        try:
            self.check_output(
                "ndrdump --debug-stdout drsuapi 17 out --base64-input %s" %
                self.data_path(
                    "fuzzed_drsuapi_DsaAddressListItem_V1-in.b64.txt"))
            self.fail("Input should have been rejected with %s" % expected)
        except BlackboxProcessError as e:
            if expected not in str(e):
                self.fail(e)

    def test_ndrdump_fuzzed_drsuapi_DsReplicaAttribute(self):
        expected = open(self.data_path("fuzzed_drsuapi_DsReplicaAttribute.txt")).read()
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout drsuapi drsuapi_DsReplicaAttribute struct --base64-input --validate %s" %
                self.data_path("fuzzed_drsuapi_DsReplicaAttribute.b64.txt"))
        except BlackboxProcessError as e:
            self.fail(e)
        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_Krb5ccache(self):
        expected = open(self.data_path("../../../source3/selftest/"
                                       "ktest-krb5_ccache-2.txt")).read()
        try:
            # Specify -d1 to match the generated output file, because ndrdump
            # only outputs some additional info if this parameter is specified,
            # and the --configfile parameter gives us an empty smb.conf to avoid
            # extraneous output.
            actual = self.check_output(
                "ndrdump krb5ccache CCACHE struct "
                "--configfile /dev/null --debug-stdout -d1 --validate " +
                self.data_path("../../../source3/selftest/"
                               "ktest-krb5_ccache-2"))
        except BlackboxProcessError as e:
            self.fail(e)
        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

        expected = open(self.data_path("../../../source3/selftest/"
                                       "ktest-krb5_ccache-3.txt")).read()
        try:
            # Specify -d1 to match the generated output file, because ndrdump
            # only outputs some additional info if this parameter is specified,
            # and the --configfile parameter gives us an empty smb.conf to avoid
            # extraneous output.
            actual = self.check_output(
                "ndrdump krb5ccache CCACHE struct "
                "--configfile /dev/null --debug-stdout -d1 --validate " +
                self.data_path("../../../source3/selftest/"
                               "ktest-krb5_ccache-3"))
        except BlackboxProcessError as e:
            self.fail(e)
        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    # This is a good example of a union with an empty default
    # and no buffers to parse.
    def test_ndrdump_fuzzed_spoolss_EnumForms(self):
        expected_head = b'''pull returned Success
WARNING! 2 unread bytes
[0000] 00 00                                               ..''' b'''
    spoolss_EnumForms: struct spoolss_EnumForms
        out: struct spoolss_EnumForms
            count                    : *
                count                    : 0x00000100 (256)
            info                     : *
                info                     : *
                    info: ARRAY(256)
                        info                     : union spoolss_FormInfo(case 0)
                        info                     : union spoolss_FormInfo(case 0)
'''
        expected_tail = b'''info                     : union spoolss_FormInfo(case 0)
                        info                     : union spoolss_FormInfo(case 0)
                        info                     : union spoolss_FormInfo(case 0)
                        info                     : union spoolss_FormInfo(case 0)
                        info                     : union spoolss_FormInfo(case 0)
                        info                     : union spoolss_FormInfo(case 0)
            needed                   : *
                needed                   : 0x00000000 (0)
            result                   : DOS code 0xa9a9a900
dump OK
'''
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout spoolss spoolss_EnumForms out --base64-input " +\
                "--input AAAAAQAAAAAAAAAAAAEAAACpqakAAA="
                )
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertEqual(actual[:len(expected_head)],
                         expected_head)
        self.assertTrue(actual.endswith(expected_tail))

    # This is a good example of a union with scalars and buffers
    def test_ndrdump_xattr_NTACL(self):

        expected_head =  open(self.data_path("xattr_NTACL.txt")).read().encode('utf8')
        expected_tail = b'''dump OK
'''
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout xattr xattr_NTACL struct --hex-input %s --validate" %
                self.data_path("xattr_NTACL.dat"))
        except BlackboxProcessError as e:
            self.fail(e)

        self.assertEqual(actual[:len(expected_head)],
                         expected_head)
        self.assertTrue(actual.endswith(expected_tail))

    # Confirm parsing of dnsProperty records
    def test_ndrdump_dnsp_DnssrvRpcRecord(self):

        expected = open(self.data_path("dnsp-DnssrvRpcRecord.txt")).read().encode('utf8')
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout dnsp dnsp_DnssrvRpcRecord struct " +\
                "--input BQAPAAXwAAC3AAAAAAADhAAAAAAAAAAAAAoBAAA= "+\
                "--base64-input --validate")
        except BlackboxProcessError as e:
            self.fail(e)

        self.assertEqual(actual, expected)

    # Test a --validate push of a NULL union pointer
    def test_ndrdump_fuzzed_NULL_union_PAC_BUFFER(self):
        expected = b'''pull returned Success
WARNING! 13 unread bytes
[0000] F5 FF 00 3C 3C 25 FF 70   16 1F A0 12 84            ...<<%.p .....
    PAC_BUFFER: struct PAC_BUFFER
        type                     : UNKNOWN_ENUM_VALUE (1094251328)
        _ndr_size                : 0x048792c6 (75993798)
        info                     : NULL
        _pad                     : 0x06000000 (100663296)
push returned Success
pull returned Success
    PAC_BUFFER: struct PAC_BUFFER
        type                     : UNKNOWN_ENUM_VALUE (1094251328)
        _ndr_size                : 0x00000000 (0)
        info                     : NULL
        _pad                     : 0x00000000 (0)
WARNING! orig bytes:29 validated pushed bytes:16
WARNING! orig and validated differ at byte 0x04 (4)
WARNING! orig byte[0x04] = 0xC6 validated byte[0x04] = 0x00
-[0000] 40 F3 38 41 C6 92 87 04   00 00 00 00 00 00 00 06   @.8A.... ........
+[0000] 40 F3 38 41 00 00 00 00   00 00 00 00 00 00 00 00   @.8A.... ........
-[0010] F5 FF 00 3C 3C 25 FF 70   16 1F A0 12 84            ...<<%.p .....
+[0010]                                                     EMPTY   BLOCK
dump OK
'''
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout krb5pac PAC_BUFFER struct --validate --input " +\
                "QPM4QcaShwQAAAAAAAAABvX/ADw8Jf9wFh+gEoQ= --base64-input")
        except BlackboxProcessError as e:
            self.fail(e)

        self.assertEqual(actual, expected)

    # Test a --validate push of a NULL struct pointer
    def test_ndrdump_fuzzed_NULL_struct_ntlmssp_CHALLENGE_MESSAGE(self):
        expected =  open(self.data_path("fuzzed_ntlmssp-CHALLENGE_MESSAGE.txt")).read().encode('utf8')
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout ntlmssp CHALLENGE_MESSAGE struct --validate --input " +\
                "'AAAACwIAAAAAJwIAAAAAAAcAAAAAAAAAAIAbhG8uyk9dAL0mQE73MAAAAAAAAAAA' --base64-input")
        except BlackboxProcessError as e:
            self.fail(e)

        # Filter out the C source file and line number
        regex = rb"\.\./\.\./librpc/ndr/ndr\.c:[0-9]+"
        actual = re.sub(regex, b"", actual)
        expected = re.sub(regex, b"", expected)

        self.assertEqual(actual, expected)

    # Test a print of NULL pointer in manually-written ndr_drsuapi.c
    def test_fuzzed_drsuapi_DsGetNCChanges(self):
        expected =  open(self.data_path("fuzzed_drsuapi_DsGetNCChanges.txt"), 'rb').read()
        try:
            actual = self.check_output(
                "ndrdump --debug-stdout drsuapi 3 out --base64-input --input " +\
                "AQAAAAEAAAAGAKoAAAAGAKoGAAMAAQAAAAYAEwAAAAAAAAAA/wAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAABbAAAAAAAAAAAAAAkRAAABAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPkAAAAAAAABAAD4BgATAAAAAAAAAAD/AAAAAAAAAD8AAAAAAAAAAAAAAAAAAAAAAFsAAAAAAAAAAAAABgAQAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAMAAAABAAAACREAAAEAAAABAAAAAAAAAAYAEAABAAgAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAA=")
        except BlackboxProcessError as e:
            self.fail(e)

        self.assertEqual(actual, expected)

    def test_ndrdump_fuzzed_ndr_compression(self):
        expected = r'ndr_pull_compression_start: ndr_pull_error\(Compression Error\): Bad compression algorithm 204 \(PULL\)'
        command = (
            "ndrdump --debug-stdout drsuapi 3 out --base64-input "
            "--input BwAAAAcAAAAGAAAAAwAgICAgICAJAAAAICAgIAkAAAAgIAAA//////8=")
        try:
            actual = self.check_exit_code(command, 2)
        except BlackboxProcessError as e:
            self.fail(e)
        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertRegex(actual.decode('utf8'), expected)

    def test_ndrdump_short_dnsProperty(self):
        expected = b'''pull returned Success
    dnsp_DnsProperty_short: struct dnsp_DnsProperty_short
        wDataLength              : 0x00000000 (0)
        namelength               : 0x00000000 (0)
        flag                     : 0x00000000 (0)
        version                  : 0x00000001 (1)
        id                       : DSPROPERTY_ZONE_NS_SERVERS_DA (146)
        data                     : union dnsPropertyData(case 0)
        name                     : 0x00000000 (0)
dump OK
'''
        command = (
            "ndrdump --debug-stdout dnsp dnsp_DnsProperty_short struct --base64-input "
            "--input AAAAAAAAAAAAAAAAAQAAAJIAAAAAAAAA")
        try:
            actual = self.check_output(command)
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertEqual(actual, expected)

    # This is compressed with Microsoft's compression, so we can't do a validate
    def test_ndrdump_compressed_claims(self):
        expected =  open(self.data_path("compressed_claims.txt"), 'rb').read()

        try:
            actual = self.check_output(
                "ndrdump --debug-stdout claims CLAIMS_SET_METADATA_NDR struct --hex-input --input " + \
                "01100800cccccccc500200000000000000000200290200000400020004000000282000000000000000000000000000002902000073778788878808880700080007800800060007000700070887770780080088008870070008000808000080000000008070787787770076770867868788000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000007700080080000000870000000000000085070000000000007476800000000000750587000800000066078000000080706677880080008060878708000000008000800000000000800000000000000000000000000000000000000000000000006080080000000070000000000000000000000000000000000000000000000000fd74eaf001add6213aecf4346587eec48c323e3e1a5a32042eecf243669a581e383d2940e80e383c294463b8c0b49024f1def20df819586b086cd2ab98700923386674845663ef57e91718110c1ad4c0ac88912126d2180545e98670ea2aa002052aa54189cc318d26c46b667f18b6876262a9a4985ecdf76e5161033fd457ba020075360c837aaa3aa82749ee8152420999b553c60195be5e5c35c4330557538772972a7d527aeca1fc6b2951ca254ac83960272a930f3194892d4729eff48e48ccfb929329ff501c356c0e8ed18471ec70986c31da86a8090b4022c1db257514fdba4347532146648d4f99f9065e0d9a0d90d80f38389c39cb9ebe6d4e5e681e5a8a5418f591f1dbb7594a3f2aa3220ced1cd18cb49cffcc2ff18eef6caf443663640c5664000012000000")
        except BlackboxProcessError as e:
            self.fail(e)

        self.assertEqual(actual, expected)

    def test_ndrdump_uncompressed_claims(self):
        expected =  open(self.data_path("uncompressed_claims.txt"), 'rb').read()

        try:
            actual = self.check_output(
                "ndrdump --debug-stdout claims CLAIMS_SET_METADATA_NDR struct --hex-input --input " + \
                "01100800cccccccc800100000000000000000200580100000400020000000000580100000000000000000000000000005801000001100800cccccccc480100000000000000000200010000000400020000000000000000000000000001000000010000000300000008000200030000000c000200060006000100000010000200140002000300030003000000180002002800020002000200040000002c0002000b000000000000000b000000370032003000660064003300630033005f00390000000000010000000000000001000000000000000b000000000000000b000000370032003000660064003300630033005f00370000000000030000001c000200200002002400020004000000000000000400000066006f006f0000000400000000000000040000006200610072000000040000000000000004000000620061007a0000000b000000000000000b000000370032003000660064003300630033005f003800000000000400000009000a000000000007000100000000000600010000000000000001000000000000000000")
        except BlackboxProcessError as e:
            self.fail(e)

        self.assertEqual(actual, expected)

    # We can't run --validate here as currently we can't round-trip
    # this data due to uninitialised padding in the sample
    def test_ndrdump_claims_CLAIMS_SET_NDR(self):
        expected =  open(self.data_path("claims_CLAIMS_SET_NDR.txt"), 'rb').read()

        try:
            actual = self.check_output(
                "ndrdump --debug-stdout claims CLAIMS_SET_NDR struct --hex-input " + \
                self.data_path("claims_CLAIMS_SET_NDR.dat"))
        except BlackboxProcessError as e:
            self.fail(e)

        self.assertEqual(actual, expected)
