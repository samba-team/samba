/*
   Unix SMB/CIFS implementation.
   test suite for dnsp ndr operations

   Copyright (C) Stefan Metzmacher 2019

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "torture/ndr/ndr.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include "torture/ndr/proto.h"
#include "lib/util/base64.h"

/*
 * base64_decode_data_blob_talloc() => dump_data() gives:
 *
 * [0000] 0C 00 00 00 00 00 00 00   00 00 00 00 01 00 00 00   ........ ........
 * [0010] 81 00 00 00 02 00 00 00   AC 1F 63 21 AC 1F 63 2C   ........ ..c!..c,
 * [0020] 00 00 00 00
 */
static const char *dnsp_dnsProperty_ip4_array_b64 =
	"DAAAAAAAAAAAAAAAAQAAAIEAAAACAAAArB9jIawfYywAAAAA";

static bool dnsp_dnsProperty_ip4_array_check(struct torture_context *tctx,
					     struct dnsp_DnsProperty *r)
{
	/*
	 * NDR_PRINT_DEBUG(dnsp_DnsProperty, r); gave:
	 *
	 *  r: struct dnsp_DnsProperty
	 *     wDataLength              : 0x0000000c (12)
	 *     namelength               : 0x00000000 (0)
	 *     flag                     : 0x00000000 (0)
	 *     version                  : 0x00000001 (1)
	 *     id                       : DSPROPERTY_ZONE_MASTER_SERVERS (129)
	 *     data                     : union dnsPropertyData(case 129)
	 *     master_servers: struct dnsp_ip4_array
	 *         addrCount                : 0x00000002 (2)
	 *         addrArray: ARRAY(2)
	 *             addrArray                : 0x21631fac (560144300)
	 *             addrArray                : 0x2c631fac (744693676)
	 *     name                     : 0x00000000 (0)
	 *
	 */

	torture_assert_int_equal(tctx, r->wDataLength, 12, "wDataLength");
	torture_assert_int_equal(tctx, r->namelength, 0, "namelength");
	torture_assert_int_equal(tctx, r->flag, 0, "flag");
	torture_assert_int_equal(tctx, r->version, 1, "version");
	torture_assert_int_equal(tctx, r->id, DSPROPERTY_ZONE_MASTER_SERVERS, "id");
	torture_assert_int_equal(tctx, r->data.master_servers.addrCount, 2, "addrCount");
	/*
	 * This should be an array of [flag(NDR_BIG_ENDIAN)] ipv4address
	 * instead of uint32!
	 * 0x21631fac is 172.31.99.33
	 * 0x2c631fac is 172.31.99.44
	 */
	torture_assert_int_equal(tctx, r->data.master_servers.addrArray[0], 0x21631fac, "addrArray[0]");
	torture_assert_int_equal(tctx, r->data.master_servers.addrArray[1], 0x2c631fac, "addrArray[1]");
	torture_assert_int_equal(tctx, r->name, 0, "name");

	return true;
}

/*
 * base64_decode_data_blob_talloc() => dump_data() gives:
 *
 * [0000] E0 00 00 00 00 00 00 00   00 00 00 00 01 00 00 00   ........ ........
 * [0010] 91 00 00 00 03 00 00 00   03 00 00 00 00 00 00 00   ........ ........
 * [0020] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
 * [0030] 00 00 00 00 02 00 00 35   AC 1F 63 21 00 00 00 00   .......5 ..c!....
 * [0040] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
 * [0050] 00 00 00 00 10 00 00 00   00 00 00 00 00 00 00 00   ........ ........
 * [0060] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
 * [0070] 00 00 00 00 02 00 00 35   AC 1F 63 2C 00 00 00 00   .......5 ..c,....
 * [0080] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
 * [0090] 00 00 00 00 10 00 00 00   00 00 00 00 00 00 00 00   ........ ........
 * [00A0] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
 * [00B0] 00 00 00 00 17 00 00 35   00 00 00 00 FD 3A AA A3   .......5 .....:..
 * [00C0] EE 87 FF 09 02 00 00 FF   FE 99 FF FF 00 00 00 00   ........ ........
 * [00D0] 00 00 00 00 1C 00 00 00   00 00 00 00 00 00 00 00   ........ ........
 * [00E0] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
 * [00F0] 00 00 00 00 00 00 00 00                             ........
 */
static const char *dnsp_dnsProperty_addr_array_b64 =
	"4AAAAAAAAAAAAAAAAQAAAJEAAAADAAAAAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	"AAAAAAIAADWsH2MhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAA"
	"AAAAAAAAAAAAAAAAAAAAAAAAAAACAAA1rB9jLAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	"AAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFwAANQAAAAD9Oqqj"
	"7of/CQIAAP/+mf//AAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	"AAAAAAAAAAA=DAAAAAAAAAAAAAAAAQAAAIEAAAACAAAArB9jIawfYywAAAAA";

static bool dnsp_dnsProperty_addr_array_check(struct torture_context *tctx,
					      struct dnsp_DnsProperty *r)
{
	const struct dnsp_dns_addr_array *da = NULL;
	const struct dnsp_dns_addr *a0 = NULL;
	const struct dnsp_dns_addr *a1 = NULL;
	const struct dnsp_dns_addr *a2 = NULL;

	/*
	 * NDR_PRINT_DEBUG(dnsp_DnsProperty, r); gave:
	 *
	 * r: struct dnsp_DnsProperty
	 *    wDataLength              : 0x000000e0 (224)
	 *    namelength               : 0x00000000 (0)
	 *    flag                     : 0x00000000 (0)
	 *    version                  : 0x00000001 (1)
	 *    id                       : DSPROPERTY_ZONE_MASTER_SERVERS_DA (145)
	 *    data                     : union dnsPropertyData(case 145)
	 *    z_master_servers: struct dnsp_dns_addr_array
	 *        MaxCount                 : 0x00000003 (3)
	 *        AddrCount                : 0x00000003 (3)
	 *        Tag                      : 0x00000000 (0)
	 *        Family                   : 0x0000 (0)
	 *        Reserved0                : 0x0000 (0)
	 *        Flags                    : 0x00000000 (0)
	 *        MatchFlag                : 0x00000000 (0)
	 *        Reserved1                : 0x00000000 (0)
	 *        Reserved2                : 0x00000000 (0)
	 *        AddrArray: ARRAY(3)
	 *            AddrArray: struct dnsp_dns_addr
	 *                family                   : 0x0002 (2)
	 *                port                     : 0x0035 (53)
	 *                ipv4                     : 172.31.99.33
	 *                ipv6                     : 0000:0000:0000:0000:0000:0000:0000:0000
	 *                pad: ARRAY(8)
	 *                    [0]                      : 0x00 (0)
	 *                    [1]                      : 0x00 (0)
	 *                    [2]                      : 0x00 (0)
	 *                    [3]                      : 0x00 (0)
	 *                    [4]                      : 0x00 (0)
	 *                    [5]                      : 0x00 (0)
	 *                    [6]                      : 0x00 (0)
	 *                    [7]                      : 0x00 (0)
	 *                unused: ARRAY(8)
	 *                    unused                   : 0x00000010 (16)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *            AddrArray: struct dnsp_dns_addr
	 *                family                   : 0x0002 (2)
	 *                port                     : 0x0035 (53)
	 *                ipv4                     : 172.31.99.44
	 *                ipv6                     : 0000:0000:0000:0000:0000:0000:0000:0000
	 *                pad: ARRAY(8)
	 *                    [0]                      : 0x00 (0)
	 *                    [1]                      : 0x00 (0)
	 *                    [2]                      : 0x00 (0)
	 *                    [3]                      : 0x00 (0)
	 *                    [4]                      : 0x00 (0)
	 *                    [5]                      : 0x00 (0)
	 *                    [6]                      : 0x00 (0)
	 *                    [7]                      : 0x00 (0)
	 *                unused: ARRAY(8)
	 *                    unused                   : 0x00000010 (16)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *            AddrArray: struct dnsp_dns_addr
	 *                family                   : 0x0017 (23)
	 *                port                     : 0x0035 (53)
	 *                ipv4                     : 0.0.0.0
	 *                ipv6                     : fd3a:aaa3:ee87:ff09:0200:00ff:fe99:ffff
	 *                pad: ARRAY(8)
	 *                    [0]                      : 0x00 (0)
	 *                    [1]                      : 0x00 (0)
	 *                    [2]                      : 0x00 (0)
	 *                    [3]                      : 0x00 (0)
	 *                    [4]                      : 0x00 (0)
	 *                    [5]                      : 0x00 (0)
	 *                    [6]                      : 0x00 (0)
	 *                    [7]                      : 0x00 (0)
	 *                unused: ARRAY(8)
	 *                    unused                   : 0x0000001c (28)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *                    unused                   : 0x00000000 (0)
	 *    name                     : 0x00000000 (0)
	 *
	 */

	torture_assert_int_equal(tctx, r->wDataLength, 224, "wDataLength");
	torture_assert_int_equal(tctx, r->namelength, 0, "namelength");
	torture_assert_int_equal(tctx, r->flag, 0, "flag");
	torture_assert_int_equal(tctx, r->version, 1, "version");
	torture_assert_int_equal(tctx, r->id, DSPROPERTY_ZONE_MASTER_SERVERS_DA, "id");
	da = &r->data.z_master_servers;
	torture_assert_int_equal(tctx, da->MaxCount, 3, "MaxCount");
	torture_assert_int_equal(tctx, da->AddrCount, 3, "AddrCount");
	torture_assert_int_equal(tctx, da->Tag, 0, "Tag");
	torture_assert_int_equal(tctx, da->Family, 0, "Family");
	torture_assert_int_equal(tctx, da->Reserved0, 0, "Reserved0");
	torture_assert_int_equal(tctx, da->Flags, 0, "Flags");
	torture_assert_int_equal(tctx, da->MatchFlag, 0, "MatchFlag");
	torture_assert_int_equal(tctx, da->Reserved1, 0, "Reserved1");
	torture_assert_int_equal(tctx, da->Reserved2, 0, "Reserved2");
	a0 = &da->AddrArray[0];
	torture_assert_int_equal(tctx, a0->family, 2, "family v4");
	torture_assert_int_equal(tctx, a0->port, 53, "port");
	torture_assert_str_equal(tctx, a0->ipv4, "172.31.99.33", "ipv4");
	torture_assert_str_equal(tctx, a0->ipv6,
				 "0000:0000:0000:0000:0000:0000:0000:0000",
				 "ipv6 (zero)");
	torture_assert_int_equal(tctx, a0->pad[0], 0, "pad[0]");
	torture_assert_int_equal(tctx, a0->pad[1], 0, "pad[1]");
	torture_assert_int_equal(tctx, a0->pad[2], 0, "pad[2]");
	torture_assert_int_equal(tctx, a0->pad[3], 0, "pad[3]");
	torture_assert_int_equal(tctx, a0->pad[4], 0, "pad[4]");
	torture_assert_int_equal(tctx, a0->pad[5], 0, "pad[5]");
	torture_assert_int_equal(tctx, a0->pad[6], 0, "pad[6]");
	torture_assert_int_equal(tctx, a0->pad[7], 0, "pad[7]");
	torture_assert_int_equal(tctx, a0->unused[0], 16, "unused[0]");
	torture_assert_int_equal(tctx, a0->unused[1], 0, "unused[1]");
	torture_assert_int_equal(tctx, a0->unused[2], 0, "unused[2]");
	torture_assert_int_equal(tctx, a0->unused[3], 0, "unused[3]");
	torture_assert_int_equal(tctx, a0->unused[4], 0, "unused[4]");
	torture_assert_int_equal(tctx, a0->unused[5], 0, "unused[5]");
	torture_assert_int_equal(tctx, a0->unused[6], 0, "unused[6]");
	torture_assert_int_equal(tctx, a0->unused[7], 0, "unused[7]");
	a1 = &da->AddrArray[1];
	torture_assert_int_equal(tctx, a1->family, 2, "family v4");
	torture_assert_int_equal(tctx, a1->port, 53, "port");
	torture_assert_str_equal(tctx, a1->ipv4, "172.31.99.44", "ipv4");
	torture_assert_str_equal(tctx, a1->ipv6,
				 "0000:0000:0000:0000:0000:0000:0000:0000",
				 "ipv6 (zero)");
	torture_assert_int_equal(tctx, a1->pad[0], 0, "pad[0]");
	torture_assert_int_equal(tctx, a1->pad[1], 0, "pad[1]");
	torture_assert_int_equal(tctx, a1->pad[2], 0, "pad[2]");
	torture_assert_int_equal(tctx, a1->pad[3], 0, "pad[3]");
	torture_assert_int_equal(tctx, a1->pad[4], 0, "pad[4]");
	torture_assert_int_equal(tctx, a1->pad[5], 0, "pad[5]");
	torture_assert_int_equal(tctx, a1->pad[6], 0, "pad[6]");
	torture_assert_int_equal(tctx, a1->pad[7], 0, "pad[7]");
	torture_assert_int_equal(tctx, a1->unused[0], 16, "unused[0]");
	torture_assert_int_equal(tctx, a1->unused[1], 0, "unused[1]");
	torture_assert_int_equal(tctx, a1->unused[2], 0, "unused[2]");
	torture_assert_int_equal(tctx, a1->unused[3], 0, "unused[3]");
	torture_assert_int_equal(tctx, a1->unused[4], 0, "unused[4]");
	torture_assert_int_equal(tctx, a1->unused[5], 0, "unused[5]");
	torture_assert_int_equal(tctx, a1->unused[6], 0, "unused[6]");
	torture_assert_int_equal(tctx, a1->unused[7], 0, "unused[7]");
	a2 = &da->AddrArray[2];
	torture_assert_int_equal(tctx, a2->family, 23, "family v6");
	torture_assert_int_equal(tctx, a2->port, 53, "port");
	torture_assert_str_equal(tctx, a2->ipv4, "0.0.0.0", "ipv4 (zero)");
	torture_assert_str_equal(tctx, a2->ipv6,
				 "fd3a:aaa3:ee87:ff09:0200:00ff:fe99:ffff",
				 "ipv6");
	torture_assert_int_equal(tctx, a2->pad[0], 0, "pad[0]");
	torture_assert_int_equal(tctx, a2->pad[1], 0, "pad[1]");
	torture_assert_int_equal(tctx, a2->pad[2], 0, "pad[2]");
	torture_assert_int_equal(tctx, a2->pad[3], 0, "pad[3]");
	torture_assert_int_equal(tctx, a2->pad[4], 0, "pad[4]");
	torture_assert_int_equal(tctx, a2->pad[5], 0, "pad[5]");
	torture_assert_int_equal(tctx, a2->pad[6], 0, "pad[6]");
	torture_assert_int_equal(tctx, a2->pad[7], 0, "pad[7]");
	torture_assert_int_equal(tctx, a2->unused[0], 28, "unused[0]");
	torture_assert_int_equal(tctx, a2->unused[1], 0, "unused[1]");
	torture_assert_int_equal(tctx, a2->unused[2], 0, "unused[2]");
	torture_assert_int_equal(tctx, a2->unused[3], 0, "unused[3]");
	torture_assert_int_equal(tctx, a2->unused[4], 0, "unused[4]");
	torture_assert_int_equal(tctx, a2->unused[5], 0, "unused[5]");
	torture_assert_int_equal(tctx, a2->unused[6], 0, "unused[6]");
	torture_assert_int_equal(tctx, a2->unused[7], 0, "unused[7]");
	torture_assert_int_equal(tctx, r->name, 0, "name");

	return true;
}

/*
 * base64_decode_data_blob_talloc() => dump_data() gives:
 *
 * [0000] 26 00 00 00 01 EE C4 71   00 00 00 00 01 00 00 00   &......q ........
 * [0010] 80 00 00 00 77 00 32 00   6B 00 33 00 2D 00 31 00   ....w.2. k.3.-.1.
 * [0020] 39 00 31 00 2E 00 77 00   32 00 6B 00 33 00 2E 00   9.1...w. 2.k.3...
 * [0030] 62 00 61 00 73 00 65 00   00 00 C4 71 EC F3         b.a.s.e. ...q..
 */
static const char *dnsp_dnsProperty_deleted_by_b64 =
	"JgAAAAHuxHEAAAAAAQAAAIAAAAB3ADIAawAzAC0AMQA5ADEALgB3ADIAawAzAC4A"
	"YgBhAHMAZQAAAMRx7PM=";

static bool dnsp_dnsProperty_deleted_by_check(struct torture_context *tctx,
					      struct dnsp_DnsProperty *r)
{
	/*
	 * NDR_PRINT_DEBUG(dnsp_DnsProperty, r); gave:
	 *
	 * r: struct dnsp_DnsProperty
	 *     wDataLength              : 0x00000026 (38)
	 *     namelength               : 0x71c4ee01 (1908731393)
	 *     flag                     : 0x00000000 (0)
	 *     version                  : 0x00000001 (1)
	 *     id                       : DSPROPERTY_ZONE_DELETED_FROM_HOSTNAME (128)
	 *     data                     : union dnsPropertyData(case 128)
	 *     deleted_by_hostname      : 'w2k3-191.w2k3.base'
	 *     name                     : 0xf3ec71c4 (4092359108)
	 *
	 * Note Windows 2003 didn't seem to initialize namelength and name
	 * both are 'Not Used. The value MUST be ignored ...'
	 */

	torture_assert_int_equal(tctx, r->wDataLength, 38, "wDataLength");
	torture_assert_int_equal(tctx, r->namelength, 1908731393, "namelength (random)");
	torture_assert_int_equal(tctx, r->flag, 0, "flag");
	torture_assert_int_equal(tctx, r->version, 1, "version");
	torture_assert_int_equal(tctx, r->id, DSPROPERTY_ZONE_DELETED_FROM_HOSTNAME, "id");
	torture_assert_str_equal(tctx, r->data.deleted_by_hostname, "w2k3-191.w2k3.base", "hostname");
	torture_assert_int_equal(tctx, r->name, 0xf3ec71c4, "name (random)");

	return true;
}

/*
 * Copy of dnsp_dnsProperty_deleted_by_b64 with wDataLength set to 0
 * and no data in the data element.
 * This is a reproducer for https://bugzilla.samba.org/show_bug.cgi?id=14206
 * The dns_property_id was retained so once parsed this structure referenced
 * memory past it's end.
 *
 * [0000] 00 00 00 00 01 EE C4 71   00 00 00 00 01 00 00 00   &......q ........
 * [0010] 80 00 00 00 77 00 32 00   6B 00 33 00 2D 00 31 00   ....w.2. k.3.-.1.
 * [0020] 39 00 31 00 2E 00 77 00   32 00 6B 00 33 00 2E 00   9.1...w. 2.k.3...
 * [0030] 62 00 61 00 73 00 65 00   00 00 C4 71 EC F3         b.a.s.e. ...q..
 */
static const uint8_t dnsp_dnsProperty_deleted_by_zero_wDataLength[] = {
	0x00, 0x00, 0x00, 0x00, 0x01, 0xEE, 0xC4, 0x71, 0x00, 0x00, 0x00,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
	0xC4, 0x71, 0xEC, 0xF3 };

struct torture_suite *ndr_dnsp_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "dnsp");

	torture_suite_add_ndr_pull_validate_test_b64(
		suite,
		dnsp_DnsProperty,
		"ZONE_MASTER_SERVERS",
		dnsp_dnsProperty_ip4_array_b64,
		dnsp_dnsProperty_ip4_array_check);

	torture_suite_add_ndr_pull_validate_test_b64(
		suite,
		dnsp_DnsProperty,
		"ZONE_MASTER_SERVERS_DA",
		dnsp_dnsProperty_addr_array_b64,
		dnsp_dnsProperty_addr_array_check);

	torture_suite_add_ndr_pull_validate_test_b64(
		suite,
		dnsp_DnsProperty,
		"DELETED_FROM_HOSTNAME",
		dnsp_dnsProperty_deleted_by_b64,
		dnsp_dnsProperty_deleted_by_check);

	torture_suite_add_ndr_pull_invalid_data_test(
		suite,
		dnsp_DnsProperty,
		dnsp_dnsProperty_deleted_by_zero_wDataLength,
		NDR_ERR_BUFSIZE);

	return suite;
}
