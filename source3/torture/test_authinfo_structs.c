/*
   Unix SMB/CIFS implementation.
   Test conversion form struct lsa_TrustDomainInfoAuthInfo to
   struct trustAuthInOutBlob and back
   Copyright (C) Sumit Bose 2011

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
#include "torture/proto.h"
#include "librpc/gen_ndr/lsa.h"
#include "libcli/lsarpc/util_lsarpc.h"

static bool cmp_TrustDomainInfoBuffer(struct lsa_TrustDomainInfoBuffer a,
				      struct lsa_TrustDomainInfoBuffer b)
{
	if (a.last_update_time != b. last_update_time ||
	    a.AuthType != b.AuthType ||
	    a.data.size != b.data.size ||
	    memcmp(a.data.data, b.data.data, a.data.size) !=0) {
		return false;
	}

	return true;
}

static bool cmp_auth_info(struct lsa_TrustDomainInfoAuthInfo *a,
			  struct lsa_TrustDomainInfoAuthInfo *b)
{
	size_t c;

	if (a->incoming_count != b->incoming_count ||
	    a->outgoing_count != b->outgoing_count) {
		return false;
	}

	for (c = 0; c < a->incoming_count; c++) {
		if (!cmp_TrustDomainInfoBuffer(a->incoming_current_auth_info[c],
					       b->incoming_current_auth_info[c])) {
			return false;
		}

		if (a->incoming_previous_auth_info != NULL &&
		    b->incoming_previous_auth_info != NULL) {
			if (!cmp_TrustDomainInfoBuffer(a->incoming_previous_auth_info[c],
						       b->incoming_previous_auth_info[c])) {
				return false;
			}
		} else if (a->incoming_previous_auth_info == NULL &&
			   b->incoming_previous_auth_info == NULL) {
			continue;
		} else {
			return false;
		}
	}

	for (c = 0; c < a->outgoing_count; c++) {
		if (!cmp_TrustDomainInfoBuffer(a->outgoing_current_auth_info[c],
					       b->outgoing_current_auth_info[c])) {
			return false;
		}

		if (a->outgoing_previous_auth_info != NULL &&
		    b->outgoing_previous_auth_info != NULL) {
			if (!cmp_TrustDomainInfoBuffer(a->outgoing_previous_auth_info[c],
						       b->outgoing_previous_auth_info[c])) {
				return false;
			}
		} else if (a->outgoing_previous_auth_info == NULL &&
			   b->outgoing_previous_auth_info == NULL) {
			continue;
		} else {
			return false;
		}
	}

	return true;
}

static bool covert_and_compare(struct lsa_TrustDomainInfoAuthInfo *auth_info)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;
	DATA_BLOB incoming;
	DATA_BLOB outgoing;
	struct lsa_TrustDomainInfoAuthInfo auth_info_out;
	bool result = false;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return false;
	}

	status = auth_info_2_auth_blob(tmp_ctx, auth_info, &incoming, &outgoing);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return false;
	}

	status = auth_blob_2_auth_info(tmp_ctx, incoming, outgoing,
				       &auth_info_out);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return false;
	}

	result = cmp_auth_info(auth_info, &auth_info_out);
	talloc_free(tmp_ctx);

	return result;
}

bool run_local_conv_auth_info(int dummy)
{
	struct lsa_TrustDomainInfoAuthInfo auth_info;
	struct lsa_TrustDomainInfoBuffer ic[1];
	struct lsa_TrustDomainInfoBuffer ip[1];
	struct lsa_TrustDomainInfoBuffer oc[2];
	struct lsa_TrustDomainInfoBuffer op[2];
	uint32_t version = 3;

	ic[0].last_update_time = 12345;
	ic[0].AuthType = TRUST_AUTH_TYPE_CLEAR;
	ic[0].data.size = strlen("iPaSsWoRd");
	ic[0].data.data = discard_const_p(uint8_t, "iPaSsWoRd");

	ip[0].last_update_time = 67890;
	ip[0].AuthType = TRUST_AUTH_TYPE_CLEAR;
	ip[0].data.size = strlen("OlDiPaSsWoRd");
	ip[0].data.data = discard_const_p(uint8_t, "OlDiPaSsWoRd");

	oc[0].last_update_time = 24580;
	oc[0].AuthType = TRUST_AUTH_TYPE_CLEAR;
	oc[0].data.size = strlen("oPaSsWoRd");
	oc[0].data.data = discard_const_p(uint8_t, "oPaSsWoRd");
	oc[1].last_update_time = 24580;
	oc[1].AuthType = TRUST_AUTH_TYPE_VERSION;
	oc[1].data.size = 4;
	oc[1].data.data = (uint8_t *) &version;

	op[0].last_update_time = 13579;
	op[0].AuthType = TRUST_AUTH_TYPE_CLEAR;
	op[0].data.size = strlen("OlDoPaSsWoRd");
	op[0].data.data = discard_const_p(uint8_t, "OlDoPaSsWoRd");
	op[1].last_update_time = 24580;
	op[1].AuthType = TRUST_AUTH_TYPE_VERSION;
	op[1].data.size = 4;
	op[1].data.data = (uint8_t *) &version;

	auth_info.incoming_count = 0;
	auth_info.incoming_current_auth_info = NULL;
	auth_info.incoming_previous_auth_info = NULL;
	auth_info.outgoing_count = 0;
	auth_info.outgoing_current_auth_info = NULL;
	auth_info.outgoing_previous_auth_info = NULL;

	if (!covert_and_compare(&auth_info)) {
		return false;
	}

	auth_info.incoming_count = 1;
	auth_info.incoming_current_auth_info = ic;
	auth_info.incoming_previous_auth_info = NULL;
	auth_info.outgoing_count = 0;
	auth_info.outgoing_current_auth_info = NULL;
	auth_info.outgoing_previous_auth_info = NULL;

	if (!covert_and_compare(&auth_info)) {
		return false;
	}

	auth_info.incoming_count = 0;
	auth_info.incoming_current_auth_info = NULL;
	auth_info.incoming_previous_auth_info = NULL;
	auth_info.outgoing_count = 2;
	auth_info.outgoing_current_auth_info = oc;
	auth_info.outgoing_previous_auth_info = NULL;

	if (!covert_and_compare(&auth_info)) {
		return false;
	}

	auth_info.incoming_count = 1;
	auth_info.incoming_current_auth_info = ic;
	auth_info.incoming_previous_auth_info = NULL;
	auth_info.outgoing_count = 2;
	auth_info.outgoing_current_auth_info = oc;
	auth_info.outgoing_previous_auth_info = NULL;

	if (!covert_and_compare(&auth_info)) {
		return false;
	}

	auth_info.incoming_count = 1;
	auth_info.incoming_current_auth_info = ic;
	auth_info.incoming_previous_auth_info = ip;
	auth_info.outgoing_count = 2;
	auth_info.outgoing_current_auth_info = oc;
	auth_info.outgoing_previous_auth_info = op;

	if (!covert_and_compare(&auth_info)) {
		return false;
	}

	return true;
}
