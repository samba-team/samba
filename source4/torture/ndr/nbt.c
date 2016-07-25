/*
   Unix SMB/CIFS implementation.
   test suite for nbt ndr operations

   Copyright (C) Guenther Deschner 2010-2012

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
#include "librpc/gen_ndr/ndr_nbt.h"
#include "torture/ndr/proto.h"

static const uint8_t netlogon_logon_request_req_data[] = {
	0x00, 0x00, 0x57, 0x49, 0x4e, 0x39, 0x38, 0x00, 0x47, 0x44, 0x00, 0x5c,
	0x4d, 0x41, 0x49, 0x4c, 0x53, 0x4c, 0x4f, 0x54, 0x5c, 0x54, 0x45, 0x4d,
	0x50, 0x5c, 0x4e, 0x45, 0x54, 0x4c, 0x4f, 0x47, 0x4f, 0x4e, 0x00, 0x01,
	0x01, 0x00, 0xff, 0xff
};

static bool netlogon_logon_request_req_check(struct torture_context *tctx,
					     struct nbt_netlogon_packet *r)
{
	torture_assert_int_equal(tctx, r->command, LOGON_REQUEST, "command");
	torture_assert_str_equal(tctx, r->req.logon0.computer_name, "WIN98", "computer name");
	torture_assert_str_equal(tctx, r->req.logon0.user_name, "GD", "user_name");
	torture_assert_str_equal(tctx, r->req.logon0.mailslot_name, "\\MAILSLOT\\TEMP\\NETLOGON", "mailslot_name");
	torture_assert_int_equal(tctx, r->req.logon0.request_count, 1, "request_count");
	torture_assert_int_equal(tctx, r->req.logon0.lmnt_token, 1, "lmnt_token");
	torture_assert_int_equal(tctx, r->req.logon0.lm20_token, 0xffff, "lm20_token");

	return true;
}

static const uint8_t netlogon_logon_request_resp_data[] = {
	0x06, 0x00, 0x5c, 0x5c, 0x4d, 0x54, 0x48, 0x45, 0x4c, 0x45, 0x4e, 0x41,
	0x00, 0xff, 0xff
};

static bool netlogon_logon_request_resp_check(struct torture_context *tctx,
					      struct nbt_netlogon_response2 *r)
{
	torture_assert_int_equal(tctx, r->command, LOGON_RESPONSE2, "command");
	torture_assert_str_equal(tctx, r->pdc_name, "\\\\MTHELENA", "pdc_name");
	torture_assert_int_equal(tctx, r->lm20_token, 0xffff, "lm20_token");

	return true;
}

static const uint8_t netlogon_samlogon_response_data[] = {
/*	0x04, 0x74, 0x17, 0x00, 0x00, 0x00, 0xfd, 0x33, 0x00, 0x00, 0x03, 0x13, */
	            0x17, 0x00, 0x00, 0x00, 0xfd, 0x33, 0x00, 0x00, 0x03, 0x13,
	0x44, 0xcd, 0x1c, 0x00, 0x4c, 0x46, 0xa6, 0x21, 0xe9, 0xd6, 0xb9, 0xb1,
	0x2f, 0xe9, 0x07, 0x77, 0x32, 0x6b, 0x38, 0x64, 0x6f, 0x6d, 0x03, 0x62,
	0x65, 0x72, 0x06, 0x72, 0x65, 0x64, 0x68, 0x61, 0x74, 0x03, 0x63, 0x6f,
	0x6d, 0x00, 0xc0, 0x18, 0x08, 0x67, 0x64, 0x77, 0x32, 0x6b, 0x38, 0x72,
	0x32, 0xc0, 0x18, 0x07, 0x57, 0x32, 0x4b, 0x38, 0x44, 0x4f, 0x4d, 0x00,
	0x08, 0x47, 0x44, 0x57, 0x32, 0x4b, 0x38, 0x52, 0x32, 0x00, 0x00, 0x17,
	0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2d, 0x46, 0x69, 0x72, 0x73,
	0x74, 0x2d, 0x53, 0x69, 0x74, 0x65, 0x2d, 0x4e, 0x61, 0x6d, 0x65, 0x00,
	0xc0, 0x51, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
};

static bool netlogon_samlogon_response_check(struct torture_context *tctx,
					     struct netlogon_samlogon_response *r)
{
	struct GUID guid;
	torture_assert_ntstatus_ok(tctx, GUID_from_string("cd441303-001c-464c-a621-e9d6b9b12fe9", &guid), "");

	torture_assert_int_equal(tctx, r->ntver, 5, "ntver");
	torture_assert_int_equal(tctx, r->data.nt5_ex.command, LOGON_SAM_LOGON_RESPONSE_EX, "command");
	torture_assert_int_equal(tctx, r->data.nt5_ex.sbz, 0, "sbz");
	torture_assert_int_equal(tctx, r->data.nt5_ex.server_type, 0x000033fd, "server_type");
	torture_assert_guid_equal(tctx, r->data.nt5_ex.domain_uuid, guid, "domain_uuid");
	torture_assert_str_equal(tctx, r->data.nt5_ex.forest, "w2k8dom.ber.redhat.com", "forest");
	torture_assert_str_equal(tctx, r->data.nt5_ex.dns_domain, "w2k8dom.ber.redhat.com", "dns_domain");
	torture_assert_str_equal(tctx, r->data.nt5_ex.pdc_dns_name, "gdw2k8r2.w2k8dom.ber.redhat.com", "pdc_dns_name");
	torture_assert_str_equal(tctx, r->data.nt5_ex.domain_name, "W2K8DOM", "domain_name");
	torture_assert_str_equal(tctx, r->data.nt5_ex.pdc_name, "GDW2K8R2", "pdc_name");
	torture_assert_str_equal(tctx, r->data.nt5_ex.user_name, "", "user_name");
	torture_assert_str_equal(tctx, r->data.nt5_ex.server_site, "Default-First-Site-Name", "server_site");
	torture_assert_str_equal(tctx, r->data.nt5_ex.client_site, "Default-First-Site-Name", "client_site");
	torture_assert_int_equal(tctx, r->data.nt5_ex.sockaddr_size, 0, "sockaddr_size");
	/* sockaddr: struct nbt_sockaddr
	 *             sockaddr_family          : 0x00000000 (0)
	 *             pdc_ip                   : (null)
	 *             remaining                : DATA_BLOB length=0 */
	torture_assert_int_equal(tctx, r->data.nt5_ex.nt_version, 5, "nt_version");
	/* next_closest_site NULL */
	torture_assert_int_equal(tctx, r->data.nt5_ex.lmnt_token, 0xffff, "lmnt_token");
	torture_assert_int_equal(tctx, r->data.nt5_ex.lm20_token, 0xffff, "lm20_token");

	return true;
}

static const uint8_t nbt_netlogon_packet_data[] = {
	0x12, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x45, 0x00, 0x4e, 0x00, 0x4e, 0x00,
	0x59, 0x00, 0x00, 0x00, 0x4c, 0x00, 0x45, 0x00, 0x4e, 0x00, 0x4e, 0x00,
	0x59, 0x00, 0x24, 0x00, 0x00, 0x00, 0x5c, 0x4d, 0x41, 0x49, 0x4c, 0x53,
	0x4c, 0x4f, 0x54, 0x5c, 0x4e, 0x45, 0x54, 0x5c, 0x47, 0x45, 0x54, 0x44,
	0x43, 0x35, 0x32, 0x45, 0x41, 0x41, 0x38, 0x43, 0x30, 0x00, 0x80, 0x00,
	0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0x9c, 0x4e, 0x59, 0xff,
	0xe1, 0xa0, 0x39, 0xac, 0x29, 0xa6, 0xe2, 0xda, 0x01, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff
};

static bool nbt_netlogon_packet_check(struct torture_context *tctx,
				      struct nbt_netlogon_packet *r)
{
	torture_assert_int_equal(tctx, r->command, LOGON_SAM_LOGON_REQUEST, "command");
	torture_assert_int_equal(tctx, r->req.logon.request_count, 0, "request_count");
	torture_assert_str_equal(tctx, r->req.logon.computer_name, "LENNY", "computer_name");
	torture_assert_str_equal(tctx, r->req.logon.user_name, "LENNY$", "user_name");
	torture_assert_str_equal(tctx, r->req.logon.mailslot_name, "\\MAILSLOT\\NET\\GETDC52EAA8C0", "mailslot_name");
	torture_assert_int_equal(tctx, r->req.logon.acct_control, 0x00000080, "acct_control");
	torture_assert_int_equal(tctx, r->req.logon.sid_size, 24, "sid_size");
	torture_assert_int_equal(tctx, r->req.logon._pad.length, 2, "_pad.length");
	torture_assert_sid_equal(tctx, &r->req.logon.sid, dom_sid_parse_talloc(tctx, "S-1-5-21-4284042908-2889457889-3672286761"), "sid");
	torture_assert_int_equal(tctx, r->req.logon.nt_version, NETLOGON_NT_VERSION_1, "nt_version");
	torture_assert_int_equal(tctx, r->req.logon.lmnt_token, 0xffff, "lmnt_token");
	torture_assert_int_equal(tctx, r->req.logon.lm20_token, 0xffff, "lm20_token");

	return true;
}

static const uint8_t nbt_netlogon_packet_logon_primary_query_data[] = {
	0x07, 0x00, 0x58, 0x50, 0x44, 0x41, 0x54, 0x45, 0x56, 0x2d, 0x50, 0x52,
	0x4f, 0x00, 0x5c, 0x4d, 0x41, 0x49, 0x4c, 0x53, 0x4c, 0x4f, 0x54, 0x5c,
	0x4e, 0x45, 0x54, 0x5c, 0x47, 0x45, 0x54, 0x44, 0x43, 0x38, 0x31, 0x37,
	0x00, 0x00, 0x58, 0x00, 0x50, 0x00, 0x44, 0x00, 0x41, 0x00, 0x54, 0x00,
	0x45, 0x00, 0x56, 0x00, 0x2d, 0x00, 0x50, 0x00, 0x52, 0x00, 0x4f, 0x00,
	0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

static bool nbt_netlogon_packet_logon_primary_query_check(struct torture_context *tctx,
							  struct nbt_netlogon_packet *r)
{
	torture_assert_int_equal(tctx, r->command, LOGON_PRIMARY_QUERY, "command");
	torture_assert_str_equal(tctx, r->req.pdc.computer_name, "XPDATEV-PRO", "computer_name");
	torture_assert_str_equal(tctx, r->req.pdc.mailslot_name, "\\MAILSLOT\\NET\\GETDC817", "mailslot_name");
	torture_assert_int_equal(tctx, r->req.pdc._pad.length, 1, "_pad.length");
	torture_assert_int_equal(tctx, r->req.pdc._pad.data[0], 0, "_pad.data");
	torture_assert_str_equal(tctx, r->req.pdc.unicode_name, "XPDATEV-PRO", "unicode_name");
	torture_assert_int_equal(tctx, r->req.pdc.nt_version, 0x0000000b, "nt_version");
	torture_assert_int_equal(tctx, r->req.pdc.lmnt_token, 0xffff, "lmnt_token");
	torture_assert_int_equal(tctx, r->req.pdc.lm20_token, 0xffff, "lm20_token");

	return true;
}

static const uint8_t netlogon_samlogon_response_data2[] = {
/*	0x04, 0x77, 0x17, 0x00, 0x00, 0x00, 0xfd, 0x33, 0x00, 0x00, 0x55, 0xaf,*/
	            0x17, 0x00, 0x00, 0x00, 0xfd, 0x33, 0x00, 0x00, 0x55, 0xaf,
	0x8d, 0x13, 0x8c, 0x91, 0x70, 0x41, 0x9d, 0x46, 0xd4, 0xd5, 0x04, 0x90,
	0xaa, 0x13, 0x03, 0x62, 0x6c, 0x61, 0x04, 0x62, 0x61, 0x73, 0x65, 0x00,
	0xc0, 0x18, 0x0a, 0x57, 0x32, 0x4b, 0x38, 0x52, 0x32, 0x2d, 0x32, 0x31,
	0x39, 0xc0, 0x18, 0x03, 0x42, 0x4c, 0x41, 0x00, 0x0a, 0x57, 0x32, 0x4b,
	0x38, 0x52, 0x32, 0x2d, 0x32, 0x31, 0x39, 0x00, 0x0a, 0x77, 0x32, 0x30,
	0x31, 0x32, 0x72, 0x32, 0x2d, 0x6c, 0x36, 0x05, 0x62, 0x61, 0x73, 0x65,
	0x2e, 0x00, 0x17, 0x44, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x2d, 0x46,
	0x69, 0x72, 0x73, 0x74, 0x2d, 0x53, 0x69, 0x74, 0x65, 0x2d, 0x4e, 0x61,
	0x6d, 0x65, 0x00, 0xc0, 0x54, 0x05, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
	0xff
};

static bool netlogon_samlogon_response_check2(struct torture_context *tctx,
					      struct netlogon_samlogon_response *r)
{
	struct GUID guid;
	torture_assert_ntstatus_ok(tctx, GUID_from_string("138daf55-918c-4170-9d46-d4d50490aa13", &guid), "");

	torture_assert_int_equal(tctx, r->ntver, 5, "ntver");
	torture_assert_int_equal(tctx, r->data.nt5_ex.command, LOGON_SAM_LOGON_RESPONSE_EX, "command");
	torture_assert_int_equal(tctx, r->data.nt5_ex.sbz, 0, "sbz");
	torture_assert_int_equal(tctx, r->data.nt5_ex.server_type, 0x000033fd, "server_type");
	torture_assert_guid_equal(tctx, r->data.nt5_ex.domain_uuid, guid, "domain_uuid");
	torture_assert_str_equal(tctx, r->data.nt5_ex.forest, "bla.base", "forest");
	torture_assert_str_equal(tctx, r->data.nt5_ex.dns_domain, "bla.base", "dns_domain");
	torture_assert_str_equal(tctx, r->data.nt5_ex.pdc_dns_name, "W2K8R2-219.bla.base", "pdc_dns_name");
	torture_assert_str_equal(tctx, r->data.nt5_ex.domain_name, "BLA", "domain_name");
	torture_assert_str_equal(tctx, r->data.nt5_ex.pdc_name, "W2K8R2-219", "pdc_name");
	torture_assert_str_equal(tctx, r->data.nt5_ex.user_name, "w2012r2-l6.base.", "user_name");
	torture_assert_str_equal(tctx, r->data.nt5_ex.server_site, "Default-First-Site-Name", "server_site");
	torture_assert_str_equal(tctx, r->data.nt5_ex.client_site, "Default-First-Site-Name", "client_site");
	torture_assert_int_equal(tctx, r->data.nt5_ex.sockaddr_size, 0, "sockaddr_size");
	/*
	 * sockaddr: struct nbt_sockaddr
	 *             sockaddr_family          : 0x00000000 (0)
	 *             pdc_ip                   : (null)
	 *             remaining                : DATA_BLOB length=0
	 */
	torture_assert_int_equal(tctx, r->data.nt5_ex.nt_version, 5, "nt_version");
	/* next_closest_site NULL */
	torture_assert_int_equal(tctx, r->data.nt5_ex.lmnt_token, 0xffff, "lmnt_token");
	torture_assert_int_equal(tctx, r->data.nt5_ex.lm20_token, 0xffff, "lm20_token");

	return true;
}


struct torture_suite *ndr_nbt_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "nbt");

	torture_suite_add_ndr_pull_test(suite, nbt_netlogon_packet, netlogon_logon_request_req_data, netlogon_logon_request_req_check);

	torture_suite_add_ndr_pull_test(suite,
					nbt_netlogon_packet,
					nbt_netlogon_packet_logon_primary_query_data,
					nbt_netlogon_packet_logon_primary_query_check);

	torture_suite_add_ndr_pull_test(suite, nbt_netlogon_response2, netlogon_logon_request_resp_data, netlogon_logon_request_resp_check);

	torture_suite_add_ndr_pull_test(suite,
					netlogon_samlogon_response,
					netlogon_samlogon_response_data,
					netlogon_samlogon_response_check);

	torture_suite_add_ndr_pull_validate_test(suite,
					    netlogon_samlogon_response,
					    netlogon_samlogon_response_data,
					    netlogon_samlogon_response_check);

	torture_suite_add_ndr_pull_validate_test(suite,
					    nbt_netlogon_packet,
					    nbt_netlogon_packet_data,
					    nbt_netlogon_packet_check);

	torture_suite_add_ndr_pull_validate_test(suite,
					    nbt_netlogon_packet,
					    nbt_netlogon_packet_logon_primary_query_data,
					    nbt_netlogon_packet_logon_primary_query_check);

	torture_suite_add_ndr_pull_validate_test(suite,
					    netlogon_samlogon_response,
					    netlogon_samlogon_response_data2,
					    netlogon_samlogon_response_check2);

	return suite;
}
