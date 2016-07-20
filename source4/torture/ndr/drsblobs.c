/*
   Unix SMB/CIFS implementation.
   test suite for drsblobs ndr operations

   Copyright (C) Guenther Deschner 2010

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
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "torture/ndr/proto.h"
#include "lib/util/base64.h"

static const uint8_t forest_trust_info_data_out[] = {
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x3e, 0xca, 0xca, 0x01, 0x00, 0xaf, 0xd5, 0x9b,
	0x00, 0x07, 0x00, 0x00, 0x00, 0x66, 0x32, 0x2e, 0x74, 0x65, 0x73, 0x74,
	0x3a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0xca, 0xca, 0x01,
	0x00, 0xaf, 0xd5, 0x9b, 0x02, 0x18, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x68, 0x4a, 0x64,
	0x28, 0xac, 0x88, 0xa2, 0x74, 0x17, 0x3e, 0x2d, 0x8f, 0x07, 0x00, 0x00,
	0x00, 0x66, 0x32, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x02, 0x00, 0x00, 0x00,
	0x46, 0x32
};

static bool forest_trust_info_check_out(struct torture_context *tctx,
					struct ForestTrustInfo *r)
{
	torture_assert_int_equal(tctx, r->version, 1, "version");
	torture_assert_int_equal(tctx, r->count, 2, "count");
	torture_assert_int_equal(tctx, r->records[0].record_size, 0x00000018, "record size");
	torture_assert_int_equal(tctx, r->records[0].record.flags, 0, "record flags");
	torture_assert_u64_equal(tctx, r->records[0].record.timestamp, 0x9BD5AF0001CACA3EULL, "record timestamp");
	torture_assert_int_equal(tctx, r->records[0].record.type, FOREST_TRUST_TOP_LEVEL_NAME, "record type");
	torture_assert_int_equal(tctx, r->records[0].record.data.name.size, 7, "record name size");
	torture_assert_str_equal(tctx, r->records[0].record.data.name.string, "f2.test", "record name string");
	torture_assert_int_equal(tctx, r->records[1].record_size, 0x0000003a, "record size");
	torture_assert_int_equal(tctx, r->records[1].record.flags, 0, "record flags");
	torture_assert_u64_equal(tctx, r->records[1].record.timestamp, 0x9BD5AF0001CACA3EULL, "record timestamp");
	torture_assert_int_equal(tctx, r->records[1].record.type, FOREST_TRUST_DOMAIN_INFO, "record type");
	torture_assert_int_equal(tctx, r->records[1].record.data.info.sid_size, 0x00000018, "record info sid_size");
	torture_assert_sid_equal(tctx, &r->records[1].record.data.info.sid, dom_sid_parse_talloc(tctx, "S-1-5-21-677661288-1956808876-2402106903"), "record info sid");
	torture_assert_int_equal(tctx, r->records[1].record.data.info.dns_name.size, 7, "record name size");
	torture_assert_str_equal(tctx, r->records[1].record.data.info.dns_name.string, "f2.test", "record info dns_name string");
	torture_assert_int_equal(tctx, r->records[1].record.data.info.netbios_name.size, 2, "record info netbios_name size");
	torture_assert_str_equal(tctx, r->records[1].record.data.info.netbios_name.string, "F2", "record info netbios_name string");

	return true;
}

static const uint8_t trust_domain_passwords_in[] = {
	0x34, 0x1f, 0x6e, 0xcd, 0x5f, 0x14, 0x99, 0xf9, 0xd8, 0x34, 0x9f, 0x1d,
	0x1c, 0xcf, 0x1f, 0x02, 0xb8, 0x30, 0xcc, 0x77, 0x21, 0xc1, 0xf3, 0xe2,
	0xcf, 0x32, 0xe7, 0xf7, 0x86, 0x49, 0x28, 0xa0, 0x57, 0x81, 0xa0, 0x72,
	0x95, 0xd5, 0xa7, 0x49, 0xd7, 0xe7, 0x6f, 0xd1, 0x56, 0x91, 0x44, 0xb7,
	0xe2, 0x4e, 0x48, 0xd2, 0x3e, 0x39, 0xfe, 0x79, 0xd9, 0x1d, 0x4a, 0x92,
	0xc7, 0xbb, 0xe3, 0x65, 0x38, 0x28, 0xb3, 0xb5, 0x6d, 0x1a, 0xfc, 0xf9,
	0xd1, 0xe9, 0xc0, 0x8a, 0x52, 0x5a, 0x86, 0xc1, 0x60, 0x45, 0x85, 0xaa,
	0x20, 0xd8, 0xb4, 0x1f, 0x67, 0x6e, 0xe9, 0xc8, 0xed, 0x52, 0x08, 0x65,
	0xd2, 0x5a, 0x3c, 0xb8, 0xdd, 0x5d, 0xef, 0x59, 0x54, 0x90, 0x75, 0x35,
	0x23, 0x12, 0x92, 0xac, 0xf1, 0x76, 0xb0, 0x16, 0x3d, 0xd8, 0xea, 0x96,
	0xd1, 0xd5, 0x27, 0x37, 0xbe, 0xb8, 0x30, 0x60, 0xab, 0xda, 0x21, 0xc1,
	0x61, 0x66, 0x85, 0xbc, 0x4b, 0xf2, 0x0d, 0x8d, 0x28, 0x1f, 0x02, 0x1c,
	0xcf, 0x39, 0x99, 0x14, 0x6b, 0x1a, 0x59, 0x66, 0x8d, 0x9f, 0x6f, 0x5a,
	0x3d, 0x3d, 0xb4, 0x1e, 0x7d, 0xf4, 0xc3, 0xc6, 0xed, 0xed, 0x87, 0xb1,
	0x35, 0x08, 0xf7, 0x7f, 0x61, 0x00, 0x4b, 0x0d, 0xa7, 0xb7, 0x59, 0x53,
	0xc3, 0x97, 0x55, 0xf9, 0x86, 0x2e, 0x29, 0x6d, 0x00, 0x38, 0xde, 0xe1,
	0x80, 0x37, 0xf4, 0xcb, 0x8d, 0x0d, 0x0d, 0x1f, 0x1c, 0x99, 0xf1, 0x24,
	0x61, 0x14, 0x6b, 0x1a, 0xd9, 0x31, 0xc8, 0x6e, 0xd6, 0x98, 0xab, 0xdb,
	0xb8, 0xaf, 0x99, 0xf9, 0xf4, 0x4c, 0xfe, 0x4b, 0x0d, 0xbb, 0x4f, 0xcc,
	0x63, 0xd3, 0xf0, 0x0c, 0xd1, 0xd6, 0x11, 0x30, 0x68, 0x45, 0x98, 0x07,
	0x44, 0x80, 0xca, 0xa4, 0x7b, 0x10, 0x5b, 0x0b, 0x33, 0xb6, 0x8c, 0xa4,
	0x8f, 0xf1, 0x2b, 0xbf, 0xa2, 0x22, 0xd7, 0xcc, 0x92, 0x34, 0x0b, 0xa0,
	0x05, 0xdf, 0x2f, 0xe3, 0x66, 0x0d, 0x9f, 0x09, 0x84, 0xdb, 0x0b, 0x3a,
	0xfa, 0xd5, 0xa7, 0x1c, 0x46, 0x01, 0xa0, 0x3c, 0x02, 0x8a, 0x6d, 0xec,
	0x97, 0xc1, 0x7c, 0x2f, 0x7e, 0x5d, 0x55, 0x27, 0x37, 0x59, 0x31, 0x64,
	0xe9, 0xc9, 0xd6, 0xfd, 0x8f, 0xf9, 0x59, 0xe7, 0x11, 0x30, 0x4c, 0x76,
	0xb0, 0xe7, 0xee, 0xe9, 0xf7, 0xa2, 0x0f, 0x71, 0x90, 0xdb, 0x1d, 0xb0,
	0xfb, 0xa3, 0x25, 0xf8, 0x0a, 0x6c, 0x69, 0x5c, 0x21, 0xa6, 0xfb, 0x90,
	0x5b, 0x9d, 0x14, 0xe4, 0xea, 0x32, 0xe8, 0xe0, 0x2b, 0x5a, 0x99, 0x0b,
	0xbb, 0x7e, 0x14, 0x6b, 0x36, 0x42, 0x41, 0x0f, 0x44, 0x2f, 0x7f, 0xcf,
	0x1f, 0x89, 0x04, 0xdc, 0x07, 0x2a, 0x57, 0xdf, 0xdd, 0x42, 0x78, 0xf0,
	0x8d, 0x9f, 0x02, 0x1d, 0xaf, 0xff, 0x4f, 0xb2, 0x1e, 0xb4, 0x0b, 0xb2,
	0x4d, 0x7a, 0xdc, 0xf3, 0x7e, 0x81, 0xbb, 0x6b, 0x2e, 0x29, 0x24, 0x61,
	0x93, 0x1e, 0x20, 0x57, 0x66, 0x20, 0xcf, 0x4d, 0x67, 0x76, 0xb0, 0x7b,
	0xd9, 0x9d, 0x30, 0x95, 0xba, 0xb0, 0xcc, 0xf6, 0xcc, 0xff, 0xea, 0x32,
	0x55, 0x15, 0xcd, 0xdf, 0xaf, 0xf6, 0x16, 0xd1, 0x1f, 0x6f, 0xb7, 0xda,
	0x1a, 0x75, 0xc7, 0x4f, 0xb1, 0xeb, 0x1a, 0xe2, 0x17, 0x8b, 0xe8, 0x5f,
	0x41, 0x74, 0x5f, 0x41, 0xe0, 0x46, 0x08, 0x9a, 0xc6, 0x81, 0x19, 0x26,
	0xcd, 0x60, 0xb2, 0x3a, 0x7a, 0x39, 0x2b, 0xee, 0x83, 0x8e, 0xdb, 0x83,
	0x6b, 0x48, 0x24, 0x73, 0x91, 0x31, 0x64, 0xce, 0x2e, 0x43, 0x32, 0xb2,
	0xcd, 0x60, 0x98, 0x87, 0xa9, 0x9b, 0xc3, 0x60, 0x7c, 0xa7, 0x52, 0x3e,
	0xb8, 0x28, 0x4d, 0xcd, 0x5f, 0xaf, 0xe3, 0xe6, 0xa0, 0x06, 0x93, 0xfb,
	0xd9, 0xd4, 0x2b, 0x52, 0xed, 0xec, 0x97, 0x3a, 0x01, 0x00, 0x00, 0x00,
	0x0c, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x4c, 0x6b, 0x41, 0xb6,
	0x7c, 0x16, 0xcb, 0x01, 0x02, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00,
	0xb6, 0xe4, 0x4e, 0xa0, 0xf4, 0xed, 0x90, 0x9d, 0x67, 0xff, 0xda, 0xda,
	0xc7, 0xe5, 0xaf, 0xc7, 0x4d, 0xc1, 0x58, 0xaf, 0x5f, 0x06, 0x5c, 0xe9,
	0x4c, 0x5a, 0x02, 0xfd, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
	0x38, 0x00, 0x00, 0x00, 0x4c, 0x6b, 0x41, 0xb6, 0x7c, 0x16, 0xcb, 0x01,
	0x02, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0xb6, 0xe4, 0x4e, 0xa0,
	0xf4, 0xed, 0x90, 0x9d, 0x67, 0xff, 0xda, 0xda, 0xc7, 0xe5, 0xaf, 0xc7,
	0x4d, 0xc1, 0x58, 0xaf, 0x5f, 0x06, 0x5c, 0xe9, 0x4c, 0x5a, 0x02, 0xfd,
	0x38, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00
};

/* these are taken from the trust objects of a w2k8r2 forest, with a
 * trust relationship between the forest parent and a child domain
 */
static const char *trustAuthIncoming =
"AQAAAAwAAAAcAQAASuQ+RXJdzAECAAAAAAEAAMOWL6UVfVKiJOUsGcT03H"
"jHxr2ACsMMOV5ynM617Tp7idNC+c4egdqk4S9YEpvR2YvHmdZdymL6F7QKm8OkXazYZF2r/gZ/bI+"
"jkWbsn4O8qyAc3OUKQRZwBbf+lxBW+vM4O3ZpUjz5BSKCcFQgM+MY91yVU8Nji3HNnvGnDquobFAZ"
"hxjL+S1l5+QZgkfyfv5mQScGRbU1Lar1xg9G3JznUb7S6pvrBO2nwK8g+KZBfJy5UeULigDH4IWo/"
"JmtaEGkKE2uiKIjdsEQd/uwnkouW26XzRc0ulfJnPFftGnT9KIcShPf7DLj/tstmQAAceRMFHJTY3"
"PmxoowoK8HUyBK5D5Fcl3MAQIAAAAAAQAAw5YvpRV9UqIk5SwZxPTceMfGvYAKwww5XnKczrXtOnu"
"J00L5zh6B2qThL1gSm9HZi8eZ1l3KYvoXtAqbw6RdrNhkXav+Bn9sj6ORZuyfg7yrIBzc5QpBFnAF"
"t/6XEFb68zg7dmlSPPkFIoJwVCAz4xj3XJVTw2OLcc2e8acOq6hsUBmHGMv5LWXn5BmCR/J+/mZBJ"
"wZFtTUtqvXGD0bcnOdRvtLqm+sE7afAryD4pkF8nLlR5QuKAMfghaj8ma1oQaQoTa6IoiN2wRB3+7"
"CeSi5bbpfNFzS6V8mc8V+0adP0ohxKE9/sMuP+2y2ZAABx5EwUclNjc+bGijCgrwdTIA==";

static const char *trustAuthOutgoing =
"AQAAAAwAAAAcAQAASuQ+RXJdzAECAAAAAAEAAMOWL6UVfVKiJOUsGcT03H"
"jHxr2ACsMMOV5ynM617Tp7idNC+c4egdqk4S9YEpvR2YvHmdZdymL6F7QKm8OkXazYZF2r/gZ/bI+"
"jkWbsn4O8qyAc3OUKQRZwBbf+lxBW+vM4O3ZpUjz5BSKCcFQgM+MY91yVU8Nji3HNnvGnDquobFAZ"
"hxjL+S1l5+QZgkfyfv5mQScGRbU1Lar1xg9G3JznUb7S6pvrBO2nwK8g+KZBfJy5UeULigDH4IWo/"
"JmtaEGkKE2uiKIjdsEQd/uwnkouW26XzRc0ulfJnPFftGnT9KIcShPf7DLj/tstmQAAceRMFHJTY3"
"PmxoowoK8HUyBK5D5Fcl3MAQIAAAAAAQAAw5YvpRV9UqIk5SwZxPTceMfGvYAKwww5XnKczrXtOnu"
"J00L5zh6B2qThL1gSm9HZi8eZ1l3KYvoXtAqbw6RdrNhkXav+Bn9sj6ORZuyfg7yrIBzc5QpBFnAF"
"t/6XEFb68zg7dmlSPPkFIoJwVCAz4xj3XJVTw2OLcc2e8acOq6hsUBmHGMv5LWXn5BmCR/J+/mZBJ"
"wZFtTUtqvXGD0bcnOdRvtLqm+sE7afAryD4pkF8nLlR5QuKAMfghaj8ma1oQaQoTa6IoiN2wRB3+7"
"CeSi5bbpfNFzS6V8mc8V+0adP0ohxKE9/sMuP+2y2ZAABx5EwUclNjc+bGijCgrwdTIA==";


static bool trust_domain_passwords_check_in(struct torture_context *tctx,
					    struct trustDomainPasswords *r)
{
	/* torture_assert_mem_equal(tctx, r->confounder, trust_domain_passwords_in, 512, "confounder mismatch"); */

	torture_assert_int_equal(tctx, r->outgoing.count, 1, "outgoing count mismatch");
	torture_assert_int_equal(tctx, r->outgoing.current_offset, 0x0000000c, "outgoing current offset mismatch");
	torture_assert_int_equal(tctx, r->outgoing.previous_offset, 0x00000038, "outgoing previous offset mismatch");

	torture_assert_int_equal(tctx, r->outgoing.current.count, 1, "outgoing current count mismatch");
	torture_assert_int_equal(tctx, r->outgoing.current.array[0].LastUpdateTime, 0xB6416B4C, "outgoing current last update time mismatch");
	torture_assert_int_equal(tctx, r->outgoing.current.array[0].AuthType, TRUST_AUTH_TYPE_CLEAR, "outgoing current auth type mismatch");
	torture_assert_int_equal(tctx, r->outgoing.current.array[0].AuthInfo.clear.size, 0x0000001c, "outgoing current auth info size mismatch");
	torture_assert_mem_equal(tctx, r->outgoing.current.array[0].AuthInfo.clear.password, trust_domain_passwords_in+512+12+8+4+4, 0x0000001c, "outgoing current auth info password mismatch");

	torture_assert_int_equal(tctx, r->outgoing.previous.count, 0, "outgoing previous count mismatch");

	torture_assert_int_equal(tctx, r->incoming.count, 1, "incoming count mismatch");
	torture_assert_int_equal(tctx, r->incoming.current_offset, 0x0000000c, "incoming current offset mismatch");
	torture_assert_int_equal(tctx, r->incoming.previous_offset, 0x00000038, "incoming previous offset mismatch");

	torture_assert_int_equal(tctx, r->incoming.current.count, 1, "incoming current count mismatch");
	torture_assert_int_equal(tctx, r->incoming.current.array[0].LastUpdateTime, 0xB6416B4C, "incoming current last update time mismatch");
	torture_assert_int_equal(tctx, r->incoming.current.array[0].AuthType, TRUST_AUTH_TYPE_CLEAR, "incoming current auth type mismatch");
	torture_assert_int_equal(tctx, r->incoming.current.array[0].AuthInfo.clear.size, 0x0000001c, "incoming current auth info size mismatch");
	torture_assert_mem_equal(tctx, r->incoming.current.array[0].AuthInfo.clear.password, trust_domain_passwords_in+512+12+8+4+4+0x0000001c+12+8+4+4, 0x0000001c, "incoming current auth info password mismatch");

	torture_assert_int_equal(tctx, r->incoming.previous.count, 0, "incoming previous count mismatch");

	torture_assert_int_equal(tctx, r->outgoing_size, 0x00000038, "outgoing size mismatch");
	torture_assert_int_equal(tctx, r->incoming_size, 0x00000038, "incoming size mismatch");

	return true;
}

static const uint8_t supplementalCredentials_empty1[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00
};

static bool supplementalCredentials_empty1_check(struct torture_context *tctx,
					struct supplementalCredentialsBlob *r)
{
	torture_assert_int_equal(tctx, r->unknown1, 0, "unknown1");
	torture_assert_int_equal(tctx, r->__ndr_size, 0, "__ndr_size");
	torture_assert_int_equal(tctx, r->unknown2, 0, "unknown2");
	torture_assert(tctx, r->sub.prefix == NULL, "prefix");
	torture_assert_int_equal(tctx, r->sub.signature, 0, "signature");
	torture_assert_int_equal(tctx, r->sub.num_packages, 0, "num_packages");
	torture_assert_int_equal(tctx, r->unknown3, 0, "unknown3");

	return true;
}

static const uint8_t supplementalCredentials_empty2[] = {
	0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20, 0x00,
	0x20, 0x00, 0x20, 0x00, 0x50, 0x00, 0x00 /* was 0x30 */
	/*
	 * I've changed the last byte as Samba sets it to 0x00
	 * and it's random on Windows.
	 */
};

static bool supplementalCredentials_empty2_check(struct torture_context *tctx,
					struct supplementalCredentialsBlob *r)
{
	torture_assert_int_equal(tctx, r->unknown1, 0, "unknown1");
	torture_assert_int_equal(tctx, r->__ndr_size, 0x62, "__ndr_size");
	torture_assert_int_equal(tctx, r->unknown2, 0, "unknown2");
	torture_assert_str_equal(tctx, r->sub.prefix, SUPPLEMENTAL_CREDENTIALS_PREFIX, "prefix");
	torture_assert_int_equal(tctx, r->sub.signature, SUPPLEMENTAL_CREDENTIALS_SIGNATURE, "signature");
	torture_assert_int_equal(tctx, r->sub.num_packages, 0, "num_packages");
	torture_assert_int_equal(tctx, r->unknown3, 0x00, "unknown3"); /* This is typically not initialized */

	return true;
}

static const char *alpha13_supplementalCredentials =
	"AAAAAPgFAAAAAAAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAg"
	"ACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAI"
	"AAgACAAIAAgACAAUAADACAANAEBAFAAcgBpAG0AYQByAHkAOgBLAGUAcgBiAGUAcgBvAHMAMDMwMD"
	"AwMDAwMjAwMDAwMDNFMDAzRTAwNEMwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDMwMDAwMDAwODAwMDA"
	"wMDhBMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxMDAwMDAwMDgwMDAwMDA5MjAwMDAwMDAwMDAwMDAw"
	"MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA0MTAwNEMwMDUwMDA0ODAwNDEwMDMxMDAzM"
	"zAwMkUwMDUzMDA0MTAwNEQwMDQyMDA0MTAwMkUwMDQzMDA0RjAwNTIwMDUwMDA0MTAwNjQwMDZEMD"
	"A2OTAwNkUwMDY5MDA3MzAwNzQwMDcyMDA2MTAwNzQwMDZGMDA3MjAwMkMwREQ2QzRFQzJGMDhDQjJ"
	"DMERENkM0RUMyRjA4Q0IQAEAAAgBQAGEAYwBrAGEAZwBlAHMANEIwMDY1MDA3MjAwNjIwMDY1MDA3"
	"MjAwNkYwMDczMDAwMDAwNTcwMDQ0MDA2OTAwNjcwMDY1MDA3MzAwNzQwMB4AwAMBAFAAcgBpAG0AY"
	"QByAHkAOgBXAEQAaQBnAGUAcwB0ADMxMDAwMTFEMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDQ1OE"
	"FFNDY1NjY0NkVENUIxRTZCRUQ3NjBGMzZCMUM1RDBEMzRDNDE2MERBOEQ0QzM4M0U1OTQxMzM3MDl"
	"COUQyMDYzMTUxQTI3ODBFODkzMDQ1OTg3N0IyRURGMUU0MDQ1OEFFNDY1NjY0NkVENUIxRTZCRUQ3"
	"NjBGMzZCMUMzOTAyNDNBNENBQUUxNDUzMEVERDMwRTUyRjg1OTREQkEzNDBEMUExQzEyNkQ5QUVDN"
	"kI3MDE3QzEzRTFEODY0NzNDQTk4RUZCOUI2OTRBODFEMjUyNkIwNzc1ODYzNUQ2MUE2MEMxNjIyMD"
	"kxRDE2RDY4NEE1RTk2QzI0QkIwOENBMzQzNjI3M0E3Mzk0NTA1QkZEOUI1NTMzRUMwOUE3M0MyMDF"
	"EQTA5RTVBREZEOUMwMzExRTZEMUJBNEIzNEEzN0FFODMyMUE5RTZFREMyQzA5NERBMDcwRUI4NTgz"
	"QTYxQTYwQzE2MjIwOTFEMTZENjg0QTVFOTZDMjRCQjA4RTgzRENFNUNBOTJERkI4ODNFQTYwNUM4M"
	"jc1OTVGRDE0QjBBM0M2RkRCOTQ2QjM5MkYxMDgzNjEyM0NGQjVFQThFNEZFNjAxNzBFRTA4OTQ2N0"
	"MyNUJEMEY0OTAxMDc3MzYyNTk4RUFGRUI5MjAzNEJFMjEyRDVDNTM5MTdBQzE0RTRDM0RFRTcwQjh"
	"BRDU2QUQ5NUMwNkNGNzU3M0VDOTY5MzlGOTYzNDQzNkFDQzY4QjYzRUFEM0ZDRDQ0QUM2RjY5QzND"
	"MTdDQjlBODA5MDA5M0M0NDQyOERDQTg0ODNERTU5M0JDQUM5NThDNUE0Rjg4NTVDODY5QjAzMTlFR"
	"jVCMUM3OTkyQTc5Q0I4N0I3NjFBMEU0QjUzQkYzNTQ0REQxNTQ0OEUwMTAzREJBMkMyRjZDMUVDNE"
	"IwMjU5REZCODdFQTNDMDVDRjNEMUY2QzIwNkFDQkZGNTZDOUVGRDI3QUY2NTBDRjJGQjgxRThERTA"
	"1QzVGQzE5QjE0QkE4M0UwN0ZCRkM0MUM5RENFQTlFNDY1RTBEODVDNDg2MUZCQTBGQzQyNDI0REEx"
	"OTU4Mzk5REE3QTY3MTE3RUM5NTUxQTI1QzBFMzg1OEM2OUZFREFGRjUwRjUwQ0RFQzA0MTdFMUQ0M"
	"UJFRjlBNzM5QzM0QzBDOTk3NzI5MERGRTIyNzJCQzVDOTMyMTVGMzkwRUE4QzYxRTIzQ0UwMDBDNg"
	"A=";
	
static bool alpha13_supplementalCredentials_check(struct torture_context *tctx,
						  struct supplementalCredentialsBlob *r)
{
	torture_assert_int_equal(tctx, r->unknown1, 0, "unknown1");
	torture_assert_int_equal(tctx, r->__ndr_size, 0x5F8, "__ndr_size");
	torture_assert_int_equal(tctx, r->unknown2, 0, "unknown2");
	torture_assert_str_equal(tctx, r->sub.prefix, SUPPLEMENTAL_CREDENTIALS_PREFIX, "prefix");
	torture_assert_int_equal(tctx, r->sub.signature, SUPPLEMENTAL_CREDENTIALS_SIGNATURE, "signature");
	torture_assert_int_equal(tctx, r->sub.num_packages, 3, "num_packages");
	torture_assert_str_equal(tctx, r->sub.packages[0].name, "Primary:Kerberos", "name of package 0");
	torture_assert_str_equal(tctx, r->sub.packages[1].name, "Packages", "name of package 1");
	torture_assert_str_equal(tctx, r->sub.packages[2].name, "Primary:WDigest", "name of package 2");
	torture_assert_int_equal(tctx, r->unknown3, 0x00, "unknown3"); /* This is typically not initialized */

	return true;
}

static const char *release_4_1_0rc3_supplementalCredentials =
	"AAAAALgIAAAAAAAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAg"
	"ACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAI"
	"AAgACAAIAAgACAAUAAEADYAEAIBAFAAcgBpAG0AYQByAHkAOgBLAGUAcgBiAGUAcgBvAHMALQBOAG"
	"UAdwBlAHIALQBLAGUAeQBzADA0MDAwMDAwMDQwMDAwMDAwMDAwMDAwMDUwMDA1MDAwNzgwMDAwMDA"
	"wMDEwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDEwMDAwMDEyMDAwMDAwMjAwMDAwMDBDODAwMDAwMDAw"
	"MDAwMDAwMDAwMDAwMDAwMDEwMDAwMDExMDAwMDAwMTAwMDAwMDBFODAwMDAwMDAwMDAwMDAwMDAwM"
	"DAwMDAwMDEwMDAwMDAzMDAwMDAwMDgwMDAwMDBGODAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDEwMD"
	"AwMDAxMDAwMDAwMDgwMDAwMDAwMDAxMDAwMDUyMDA0NTAwNEMwMDQ1MDA0MTAwNTMwMDQ1MDAyRDA"
	"wMzQwMDJEMDAzMTAwMkQwMDMwMDA1MjAwNDMwMDMzMDAyRTAwNTMwMDQxMDA0RDAwNDIwMDQxMDAy"
	"RTAwNDMwMDRGMDA1MjAwNTAwMDQxMDA2NDAwNkQwMDY5MDA2RTAwNjkwMDczMDA3NDAwNzIwMDYxM"
	"DA3NDAwNkYwMDcyMDA2MTQzNDMxNERDMjZFNzM0MTBERkQ2OUVENDc1Mjk1QTU1RjJGREUyNEQ2Qj"
	"FEMEMzMzk4QkY2NDI3OUI4REMwNjg0Nzc5ODgzNkUwOTE1NTMwMjYwMDlCMkUzMzBDQjBBNzFBOTQ"
	"xRjdGOEY3OTYyQTcxQTk0MUY3RjhGNzk2MiAAWAEBAFAAcgBpAG0AYQByAHkAOgBLAGUAcgBiAGUA"
	"cgBvAHMAMDMwMDAwMDAwMjAwMDAwMDUwMDA1MDAwNEMwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDMwM"
	"DAwMDAwODAwMDAwMDlDMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxMDAwMDAwMDgwMDAwMDBBNDAwMD"
	"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA1MjAwNDUwMDRDMDA0NTA"
	"wNDEwMDUzMDA0NTAwMkQwMDM0MDAyRDAwMzEwMDJEMDAzMDAwNTIwMDQzMDAzMzAwMkUwMDUzMDA0"
	"MTAwNEQwMDQyMDA0MTAwMkUwMDQzMDA0RjAwNTIwMDUwMDA0MTAwNjQwMDZEMDA2OTAwNkUwMDY5M"
	"DA3MzAwNzQwMDcyMDA2MTAwNzQwMDZGMDA3MjAwQTcxQTk0MUY3RjhGNzk2MkE3MUE5NDFGN0Y4Rj"
	"c5NjIQAJAAAgBQAGEAYwBrAGEAZwBlAHMANEIwMDY1MDA3MjAwNjIwMDY1MDA3MjAwNkYwMDczMDA"
	"yRDAwNEUwMDY1MDA3NzAwNjUwMDcyMDAyRDAwNEIwMDY1MDA3OTAwNzMwMDAwMDA0QjAwNjUwMDcy"
	"MDA2MjAwNjUwMDcyMDA2RjAwNzMwMDAwMDA1NzAwNDQwMDY5MDA2NzAwNjUwMDczMDA3NDAwHgDAA"
	"wEAUAByAGkAbQBhAHIAeQA6AFcARABpAGcAZQBzAHQAMzEwMDAxMUQwMDAwMDAwMDAwMDAwMDAwMD"
	"AwMDAwMDBFNDUwOUQ2MERDRDZERkIxOTlBMDY5QjU4NUUyOTdCMEU0RTgwMzc4QUQxMDhFQjdENUJ"
	"COUQwNjBDMEVFRURBOUNEMzhGQTk3RjBERUJGNkRCMTkxNDA4RkIwQTQ2OThFNDUwOUQ2MERDRDZE"
	"RkIxOTlBMDY5QjU4NUUyOTdCMDg2NjhCREI1QjM4ODg1M0Y5NDc0OTI0RjQzRkYzMEY0NDBFREJEN"
	"UU3MUU0Mjg4QjNFRkYyRUFEQUQyQjcwMTNBRTEwODQ0MjlCQTc4RTUwRkYyMTAxRkFEQzEwMEI1Mz"
	"NGODYwNzYyQzc1OTU0MTNEMENCRUNEODNDODJDRUE3Njk3MjgxQjI5QTU5M0U3MzRFQUQzMEZBMkE"
	"3N0EzQkVERjA4MjEzMDNGMTUwOThFMUM1RkMzNjhDQzY2MTZEMTI1MDU4NzQ4RTUyRkMzM0YzQ0ZC"
	"MUE0NUIzMzNEMUJDM0Y4NjA3NjJDNzU5NTQxM0QwQ0JFQ0Q4M0M4MkNFQTczNDk4MDNFN0FEODUyN"
	"zEyMTlBNzEyMEQ4MkE4NjA2RDlERUQxMDA2NDk2MTkyQjZEQTM0RkQxMDdGOThDMjdDOTUyQzMwND"
	"Q0MUFDODcwMTYwODdGNDU0ODUwMTRCQ0Q1QTNDNUU4NjBFQ0Y5RTQzMzJCODI1OTUyOTJFODYxNkF"
	"DREU1RUJERjFFMkIzNDZCNTcyRUE2RjM4MkQyOTJCNkE4MDk3NzY1RDMyMTI0M0Y4QjFCRjAzNEFB"
	"MjZGNEI3ODYwRUJGMzY4NDc5MTExRjQzRkMyRTVFQkUzQkNGRkE3N0RDOTdEQTJBQ0I0ODQ1NjIwQ"
	"zg3QkNFMTYwQkE3RTEyOTFFQ0MwODdFQkE4Qzg1QkNDQjc4MzVGRTYyRUU4RTA0QTBBNzQwOENDQT"
	"MxRkVDRjdFQTQ0MjI4QjJCRjVFQjg5MEQ2QjBEODgwNzVEMzhFREYxQzc5NEY1MDgxNUE2MzcxNTM"
	"5QURCQTEyNkFDODc0Q0EyNzNBMzgwRTM0NjRFQkZERDE4MTgzRDY1MDlDOTJEQzVCQzhCNTg4M0Iy"
	"QTlGRTcyMUQ0RkQ0MEQ3QkI0QzlENjcxOTYxNTRFRTQ4QkIzMDkxNEE3QkREODcyOTMyMjc1M0JDR"
	"Dk2QkI5QzY1MzdFQjc1ODg3MUZDQzhGMEUxQjkyRTgyNEIxQTBDMjU1NjE2QURCMzYyMDc5NTQ5OT"
	"Q5MUJCRTY5NTA0AA==";

static bool release_4_1_0rc3_supplementalCredentials_check(struct torture_context *tctx,
						  struct supplementalCredentialsBlob *r)
{
	torture_assert_int_equal(tctx, r->unknown1, 0, "unknown1");
	torture_assert_int_equal(tctx, r->__ndr_size, 0x8b8, "__ndr_size");
	torture_assert_int_equal(tctx, r->unknown2, 0, "unknown2");
	torture_assert_str_equal(tctx, r->sub.prefix, SUPPLEMENTAL_CREDENTIALS_PREFIX, "prefix");
	torture_assert_int_equal(tctx, r->sub.signature, SUPPLEMENTAL_CREDENTIALS_SIGNATURE, "signature");
	torture_assert_int_equal(tctx, r->sub.num_packages, 4, "num_packages");
	torture_assert_str_equal(tctx, r->sub.packages[0].name, "Primary:Kerberos-Newer-Keys", "name of package 0");
	torture_assert_str_equal(tctx, r->sub.packages[1].name, "Primary:Kerberos", "name of package 0");
	torture_assert_str_equal(tctx, r->sub.packages[2].name, "Packages", "name of package 1");
	torture_assert_str_equal(tctx, r->sub.packages[3].name, "Primary:WDigest", "name of package 2");
	torture_assert_int_equal(tctx, r->unknown3, 0x00, "unknown3"); /* This is typically not initialized */

	return true;
}

struct torture_suite *ndr_drsblobs_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "drsblobs");
	struct torture_suite *empty1_suite = torture_suite_create(ctx, "empty1");
	struct torture_suite *empty2_suite = torture_suite_create(ctx, "empty2");
	struct torture_suite *alpha13_suite = torture_suite_create(ctx, "alpha13");
	struct torture_suite *release_4_1_0rc3_suite = torture_suite_create(ctx, "release-4-1-0rc3");
	torture_suite_add_suite(suite, empty1_suite);
	torture_suite_add_suite(suite, empty2_suite);
	torture_suite_add_suite(suite, alpha13_suite);
	torture_suite_add_suite(suite, release_4_1_0rc3_suite);
	
	torture_suite_add_ndr_pull_test(suite, ForestTrustInfo, forest_trust_info_data_out, forest_trust_info_check_out);
	torture_suite_add_ndr_pull_test(suite, trustDomainPasswords, trust_domain_passwords_in, trust_domain_passwords_check_in);

	torture_suite_add_ndr_pull_validate_test(suite,
					    trustAuthInOutBlob,
					    base64_decode_data_blob_talloc(suite, trustAuthIncoming),
					    NULL);

	torture_suite_add_ndr_pull_validate_test(suite,
					    trustAuthInOutBlob,
					    base64_decode_data_blob_talloc(suite, trustAuthOutgoing),
					    NULL);

	torture_suite_add_ndr_pull_validate_test(empty1_suite, supplementalCredentialsBlob,
					data_blob_const(supplementalCredentials_empty1,
						sizeof(supplementalCredentials_empty1)),
					supplementalCredentials_empty1_check);

	torture_suite_add_ndr_pull_validate_test(empty2_suite, supplementalCredentialsBlob,
					data_blob_const(supplementalCredentials_empty2,
						sizeof(supplementalCredentials_empty2)),
					supplementalCredentials_empty2_check);

	torture_suite_add_ndr_pull_validate_test(alpha13_suite,
						 supplementalCredentialsBlob,
						 base64_decode_data_blob_talloc(suite, alpha13_supplementalCredentials),
						 alpha13_supplementalCredentials_check);

	torture_suite_add_ndr_pull_validate_test(release_4_1_0rc3_suite,
						 supplementalCredentialsBlob,
						 base64_decode_data_blob_talloc(suite, release_4_1_0rc3_supplementalCredentials),
						 release_4_1_0rc3_supplementalCredentials_check);

	return suite;
}
