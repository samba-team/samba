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

from __future__ import print_function
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
        self.check_run(("ndrdump samr samr_CreateUser in %s" %
                       (self.data_path("samr-CreateUser-in.dat"))))

    def test_ndrdump_with_out(self):
        self.check_run(("ndrdump samr samr_CreateUser out %s" %
                       (self.data_path("samr-CreateUser-out.dat"))))

    def test_ndrdump_context_file(self):
        self.check_run(
            ("ndrdump --context-file %s samr samr_CreateUser out %s" %
                (self.data_path("samr-CreateUser-in.dat"),
                self.data_path("samr-CreateUser-out.dat"))))

    def test_ndrdump_with_validate(self):
        self.check_run(("ndrdump --validate samr samr_CreateUser in %s" %
                       (self.data_path("samr-CreateUser-in.dat"))))

    def test_ndrdump_with_hex_decode_function(self):
        self.check_run(
            ("ndrdump dns decode_dns_name_packet in --hex-input %s" %
                self.data_path("dns-decode_dns_name_packet-hex.dat")))

    def test_ndrdump_with_hex_struct_name(self):
        expected = open(self.data_path("dns-decode_dns_name_packet-hex.txt")).read()
        try:
            actual = self.check_output(
                "ndrdump dns dns_name_packet struct --hex-input %s" %
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
                "ndrdump krb5pac PAC_DATA struct %s" %
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
                "ndrdump misc 0 struct %s" %
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
                "ndrdump misc netr_SchannelType --input=x struct",
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
                "ndrdump -d0 misc GUID struct --input=abcdefg", 2)
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_input_cmdline_short_struct_name_dump(self):
        expected = '''pull returned Buffer Size Error
6 bytes consumed
[0000] 61 62 63 64 65 66 67                               abcdefg ''' \
        '''
'''
        try:
            actual = self.check_exit_code(
                "ndrdump -d0 misc GUID struct --input=abcdefg --dump-data", 2)
        except BlackboxProcessError as e:
            self.fail(e)

        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_input_cmdline_short_struct_name_print_fail(self):
        expected = '''pull returned Buffer Size Error
6 bytes consumed
[0000] 61 62 63 64 65 66 67                               abcdefg ''' \
        '''
WARNING! 1 unread bytes
[0000] 67                                                 g ''' \
    '''
WARNING: pull of GUID was incomplete, therefore the parse below may SEGFAULT
    GUID                     : 64636261-6665-0000-0000-000000000000
dump of failed-to-parse GUID complete
'''
        try:
            actual = self.check_exit_code(
                "ndrdump -d0 misc GUID struct --input=abcdefg --dump-data --print-after-parse-failure", 2)
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
[0030] F1 29 08 00 00                                     .)... ''' \
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
                'ndrdump clusapi clusapi_QueryAllValues out ' +\
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
                'ndrdump IOXIDResolver ResolveOxid out ' +\
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
                'ndrdump IOXIDResolver ResolveOxid2 out ' +\
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
                'ndrdump IOXIDResolver ServerAlive out ' +\
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
                'ndrdump IRemoteActivation RemoteActivation out ' +\
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
                "ndrdump ntlmssp AUTHENTICATE_MESSAGE struct --base64-input %s --validate" %
                self.data_path("fuzzed_ntlmssp-AUTHENTICATE_MESSAGE.b64.txt"))
        except BlackboxProcessError as e:
            self.fail(e)
        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertEqual(actual, expected.encode('utf-8'))

    def test_ndrdump_fuzzed_PackagesBlob(self):
        expected = 'ndr_pull_string: ndr_pull_error\\(Buffer Size Error\\):'
        command = (
            "ndrdump drsblobs package_PackagesBlob struct --input='aw=='"
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
                "ndrdump drsuapi drsuapi_DsAddEntry in --base64-input --validate %s" %
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
                "ndrdump drsuapi 17 out --base64-input %s" %
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
                "ndrdump drsuapi drsuapi_DsReplicaAttribute struct --base64-input --validate %s" %
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
                "--configfile /dev/null -d1 --validate " +
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
                "--configfile /dev/null -d1 --validate " +
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
[0000] 00 00                                              .. ''' b'''
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
                "ndrdump spoolss spoolss_EnumForms out --base64-input " +\
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
                "ndrdump xattr xattr_NTACL struct --hex-input %s --validate" %
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
                "ndrdump dnsp dnsp_DnssrvRpcRecord struct " +\
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
dump OK
'''
        try:
            actual = self.check_output(
                "ndrdump krb5pac PAC_BUFFER struct --validate --input " +\
                "QPM4QcaShwQAAAAAAAAABvX/ADw8Jf9wFh+gEoQ= --base64-input")
        except BlackboxProcessError as e:
            self.fail(e)

        self.assertEqual(actual, expected)

    # Test a --validate push of a NULL struct pointer
    def test_ndrdump_fuzzed_NULL_struct_ntlmssp_CHALLENGE_MESSAGE(self):
        expected =  open(self.data_path("fuzzed_ntlmssp-CHALLENGE_MESSAGE.txt")).read().encode('utf8')
        try:
            actual = self.check_exit_code(
                "ndrdump ntlmssp CHALLENGE_MESSAGE struct --validate --input " +\
                "'AAAACwIAAAAAJwIAAAAAAAcAAAAAAAAAAIAbhG8uyk9dAL0mQE73MAAAAAAAAAAA' --base64-input",
                1)
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
                "ndrdump drsuapi 3 out --base64-input --input " +\
                "AQAAAAEAAAAGAKoAAAAGAKoGAAMAAQAAAAYAEwAAAAAAAAAA/wAAAAAAAAA/AAAAAAAAAAAAAAAAAAAAAABbAAAAAAAAAAAAAAkRAAABAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPkAAAAAAAABAAD4BgATAAAAAAAAAAD/AAAAAAAAAD8AAAAAAAAAAAAAAAAAAAAAAFsAAAAAAAAAAAAABgAQAAEAAAABAAAAAQAAAAEAAAABAAAAAQAAAAMAAAABAAAACREAAAEAAAABAAAAAAAAAAYAEAABAAgAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAA=")
        except BlackboxProcessError as e:
            self.fail(e)

        self.assertEqual(actual, expected)

    def test_ndrdump_fuzzed_ndr_compression(self):
        expected = 'pull returned Buffer Size Error'
        command = (
            "ndrdump drsuapi 3 out --base64-input "
            "--input BwAAAAcAAAAGAAAAAwAgICAgICAJAAAAICAgIAkAAAAgIAAA//////8=")
        try:
            actual = self.check_exit_code(command, 2)
        except BlackboxProcessError as e:
            self.fail(e)
        # check_output will return bytes
        # convert expected to bytes for python 3
        self.assertRegex(actual.decode('utf8'), expected + '$')

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
            "ndrdump dnsp dnsp_DnsProperty_short struct --base64-input "
            "--input AAAAAAAAAAAAAAAAAQAAAJIAAAAAAAAA")
        try:
            actual = self.check_output(command)
        except BlackboxProcessError as e:
            self.fail(e)
        self.assertEqual(actual, expected)
