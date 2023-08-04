/*
   Unix SMB/CIFS implementation.
   test suite for dcerpc ndr operations

   Copyright (C) Stefan Metzmacher 2023

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
#include "librpc/gen_ndr/ndr_dcerpc.h"
#include "torture/ndr/proto.h"

/*
 *  ncacn_packet: struct ncacn_packet
 *      rpc_vers                 : 0x05 (5)
 *      rpc_vers_minor           : 0x00 (0)
 *      ptype                    : DCERPC_PKT_CO_CANCEL (18)
 *      pfc_flags                : 0x06 (6)
 *             0: DCERPC_PFC_FLAG_FIRST
 *             1: DCERPC_PFC_FLAG_LAST
 *             1: DCERPC_PFC_FLAG_PENDING_CANCEL_OR_HDR_SIGNING
 *             0: DCERPC_PFC_FLAG_CONC_MPX
 *             0: DCERPC_PFC_FLAG_DID_NOT_EXECUTE
 *             0: DCERPC_PFC_FLAG_MAYBE
 *             0: DCERPC_PFC_FLAG_OBJECT_UUID
 *      drep: ARRAY(4)
 *          [0]                      : 0x10 (16)
 *          [1]                      : 0x00 (0)
 *          [2]                      : 0x00 (0)
 *          [3]                      : 0x00 (0)
 *      frag_length              : 0x0010 (16)
 *      auth_length              : 0x0000 (0)
 *      call_id                  : 0x00000001 (1)
 *      u                        : union dcerpc_payload(case 18)
 *      co_cancel: struct dcerpc_co_cancel
 *          auth_info                : DATA_BLOB length=0
 */
static const uint8_t ncacn_packet_co_cancel_data[] = {
	0x05, 0x00, 0x12, 0x06, 0x10, 0x00, 0x00, 0x00,
	0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
};

static bool ncacn_packet_co_cancel_check(struct torture_context *tctx,
					 struct ncacn_packet *pkt)
{
	torture_assert_int_equal(tctx, pkt->rpc_vers, 5, "rpc_vers");
	torture_assert_int_equal(tctx, pkt->rpc_vers_minor, 0, "rpc_vers_minor");
	torture_assert_int_equal(tctx, pkt->ptype, DCERPC_PKT_CO_CANCEL, "ptype");
	torture_assert_int_equal(tctx, pkt->pfc_flags,
				 DCERPC_PFC_FLAG_LAST |
				 DCERPC_PFC_FLAG_PENDING_CANCEL_OR_HDR_SIGNING,
				 "pfc_flags");
	torture_assert_int_equal(tctx, pkt->drep[0], DCERPC_DREP_LE, "drep[0]");
	torture_assert_int_equal(tctx, pkt->drep[1], 0, "drep[1]");
	torture_assert_int_equal(tctx, pkt->drep[2], 0, "drep[2]");
	torture_assert_int_equal(tctx, pkt->drep[3], 0, "drep[3]");
	torture_assert_int_equal(tctx, pkt->frag_length, 16, "frag_length");
	torture_assert_int_equal(tctx, pkt->auth_length, 0, "auth_length");
	torture_assert_int_equal(tctx, pkt->call_id, 1, "call_id");
	torture_assert_int_equal(tctx, pkt->u.co_cancel.auth_info.length, 0,
				 "co_cancel.auth_info.length");
	return true;
}

/*
 *  ncacn_packet: struct ncacn_packet
 *      rpc_vers                 : 0x05 (5)
 *      rpc_vers_minor           : 0x00 (0)
 *      ptype                    : DCERPC_PKT_ORPHANED (19)
 *      pfc_flags                : 0x03 (3)
 *             1: DCERPC_PFC_FLAG_FIRST
 *             1: DCERPC_PFC_FLAG_LAST
 *             0: DCERPC_PFC_FLAG_PENDING_CANCEL_OR_HDR_SIGNING
 *             0: DCERPC_PFC_FLAG_CONC_MPX
 *             0: DCERPC_PFC_FLAG_DID_NOT_EXECUTE
 *             0: DCERPC_PFC_FLAG_MAYBE
 *             0: DCERPC_PFC_FLAG_OBJECT_UUID
 *      drep: ARRAY(4)
 *          [0]                      : 0x10 (16)
 *          [1]                      : 0x00 (0)
 *          [2]                      : 0x00 (0)
 *          [3]                      : 0x00 (0)
 *      frag_length              : 0x0010 (16)
 *      auth_length              : 0x0000 (0)
 *      call_id                  : 0x00000008 (8)
 *      u                        : union dcerpc_payload(case 19)
 *      orphaned: struct dcerpc_orphaned
 *          auth_info                : DATA_BLOB length=0
 */
static const uint8_t ncacn_packet_orphaned_data[] = {
	0x05, 0x00, 0x13, 0x03, 0x10, 0x00, 0x00, 0x00,
	0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
};

static bool ncacn_packet_orphaned_check(struct torture_context *tctx,
					struct ncacn_packet *pkt)
{
	torture_assert_int_equal(tctx, pkt->rpc_vers, 5, "rpc_vers");
	torture_assert_int_equal(tctx, pkt->rpc_vers_minor, 0, "rpc_vers_minor");
	torture_assert_int_equal(tctx, pkt->ptype, DCERPC_PKT_ORPHANED, "ptype");
	torture_assert_int_equal(tctx, pkt->pfc_flags,
				 DCERPC_PFC_FLAG_FIRST|DCERPC_PFC_FLAG_LAST,
				 "pfc_flags");
	torture_assert_int_equal(tctx, pkt->drep[0], DCERPC_DREP_LE, "drep[0]");
	torture_assert_int_equal(tctx, pkt->drep[1], 0, "drep[1]");
	torture_assert_int_equal(tctx, pkt->drep[2], 0, "drep[2]");
	torture_assert_int_equal(tctx, pkt->drep[3], 0, "drep[3]");
	torture_assert_int_equal(tctx, pkt->frag_length, 16, "frag_length");
	torture_assert_int_equal(tctx, pkt->auth_length, 0, "auth_length");
	torture_assert_int_equal(tctx, pkt->call_id, 8, "call_id");
	torture_assert_int_equal(tctx, pkt->u.orphaned.auth_info.length, 0,
				 "orphaned.auth_info.length");
	return true;
}

struct torture_suite *ndr_dcerpc_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "dcerpc");
	struct torture_suite *co_cancel = torture_suite_create(ctx, "co_cancel");
	struct torture_suite *orphaned = torture_suite_create(ctx, "orphaned");

	torture_suite_add_suite(suite, co_cancel);
	torture_suite_add_ndr_pull_validate_test(co_cancel,
					ncacn_packet,
					ncacn_packet_co_cancel_data,
					ncacn_packet_co_cancel_check);

	torture_suite_add_suite(suite, orphaned);
	torture_suite_add_ndr_pull_validate_test(orphaned,
					ncacn_packet,
					ncacn_packet_orphaned_data,
					ncacn_packet_orphaned_check);

	return suite;
}
