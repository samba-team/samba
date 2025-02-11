/*
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Sumit Bose 2010

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
#include "lib/util/dns_cmp.h"
#include "../librpc/gen_ndr/ndr_drsblobs.h"
#include "../librpc/gen_ndr/ndr_lsa.h"
#include "libcli/lsarpc/util_lsarpc.h"
#include "libcli/security/dom_sid.h"

static NTSTATUS ai_array_2_trust_domain_info_buffer(TALLOC_CTX *mem_ctx,
				uint32_t count,
				struct AuthenticationInformationArray *ai,
				struct lsa_TrustDomainInfoBuffer **_b)
{
	NTSTATUS status;
	struct lsa_TrustDomainInfoBuffer *b;
	int i;

	b = talloc_array(mem_ctx, struct lsa_TrustDomainInfoBuffer, count);
	if (b == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for(i = 0; i < count; i++) {
		size_t size = 0;
		b[i].last_update_time = ai->array[i].LastUpdateTime;
		b[i].AuthType = ai->array[i].AuthType;
		switch(ai->array[i].AuthType) {
			case TRUST_AUTH_TYPE_NONE:
				b[i].data.size = 0;
				b[i].data.data = NULL;
				break;
			case TRUST_AUTH_TYPE_NT4OWF:
				if (ai->array[i].AuthInfo.nt4owf.size != 16) {
					status = NT_STATUS_INVALID_PARAMETER;
					goto fail;
				}
				b[i].data.data = (uint8_t *)talloc_memdup(b,
				    &ai->array[i].AuthInfo.nt4owf.password.hash,
				    16);
				if (b[i].data.data == NULL) {
					status = NT_STATUS_NO_MEMORY;
					goto fail;
				}
				break;
			case TRUST_AUTH_TYPE_CLEAR:
				if (!convert_string_talloc(b,
							   CH_UTF16LE, CH_UNIX,
							   ai->array[i].AuthInfo.clear.password,
							   ai->array[i].AuthInfo.clear.size,
							   &b[i].data.data,
							   &size)) {
					status = NT_STATUS_INVALID_PARAMETER;
					goto fail;
				}
				b[i].data.size = size;
				break;
			case TRUST_AUTH_TYPE_VERSION:
				if (ai->array[i].AuthInfo.version.size != 4) {
					status = NT_STATUS_INVALID_PARAMETER;
					goto fail;
				}
				b[i].data.size = 4;
				b[i].data.data = (uint8_t *)talloc_memdup(b,
				     &ai->array[i].AuthInfo.version.version, 4);
				if (b[i].data.data == NULL) {
					status = NT_STATUS_NO_MEMORY;
					goto fail;
				}
				break;
			default:
				status = NT_STATUS_INVALID_PARAMETER;
				goto fail;
		}
	}

	*_b = b;

	return NT_STATUS_OK;

fail:
	talloc_free(b);
	return status;
}

static NTSTATUS trustauth_inout_blob_2_auth_info(TALLOC_CTX *mem_ctx,
				    DATA_BLOB *inout_blob,
				    uint32_t *count,
				    struct lsa_TrustDomainInfoBuffer **current,
				    struct lsa_TrustDomainInfoBuffer **previous)
{
	NTSTATUS status;
	struct trustAuthInOutBlob iopw;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ndr_err = ndr_pull_struct_blob(inout_blob, tmp_ctx, &iopw,
			      (ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	*count = iopw.count;

	status = ai_array_2_trust_domain_info_buffer(mem_ctx, iopw.count,
						      &iopw.current, current);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (iopw.previous.count > 0) {
		status = ai_array_2_trust_domain_info_buffer(mem_ctx, iopw.count,
							     &iopw.previous, previous);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	} else {
		*previous = NULL;
	}

	status = NT_STATUS_OK;

done:
	talloc_free(tmp_ctx);
	return status;
}

NTSTATUS auth_blob_2_auth_info(TALLOC_CTX *mem_ctx,
			       DATA_BLOB incoming, DATA_BLOB outgoing,
			       struct lsa_TrustDomainInfoAuthInfo *auth_info)
{
	NTSTATUS status;

	if (incoming.length != 0) {
		status = trustauth_inout_blob_2_auth_info(mem_ctx,
					&incoming,
					&auth_info->incoming_count,
					&auth_info->incoming_current_auth_info,
					&auth_info->incoming_previous_auth_info);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		auth_info->incoming_count = 0;
		auth_info->incoming_current_auth_info = NULL;
		auth_info->incoming_previous_auth_info = NULL;
	}

	if (outgoing.length != 0) {
		status = trustauth_inout_blob_2_auth_info(mem_ctx,
					&outgoing,
					&auth_info->outgoing_count,
					&auth_info->outgoing_current_auth_info,
					&auth_info->outgoing_previous_auth_info);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		auth_info->outgoing_count = 0;
		auth_info->outgoing_current_auth_info = NULL;
		auth_info->outgoing_previous_auth_info = NULL;
	}

	return NT_STATUS_OK;
}

static NTSTATUS trust_domain_info_buffer_2_ai_array(TALLOC_CTX *mem_ctx,
						    uint32_t count,
						    struct lsa_TrustDomainInfoBuffer *b,
						    struct AuthenticationInformationArray *ai)
{
	NTSTATUS status;
	int i;

	ai->count = count;
	ai->array = talloc_zero_array(mem_ctx, struct AuthenticationInformation,
				      count);
	if (ai->array == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for(i = 0; i < count; i++) {
		size_t size = 0;
		ai->array[i].LastUpdateTime = b[i].last_update_time;
		ai->array[i].AuthType = b[i].AuthType;
		switch(ai->array[i].AuthType) {
			case TRUST_AUTH_TYPE_NONE:
				ai->array[i].AuthInfo.none.size = 0;
				break;
			case TRUST_AUTH_TYPE_NT4OWF:
				if (b[i].data.size != 16) {
					status = NT_STATUS_INVALID_PARAMETER;
					goto fail;
				}
				memcpy(&ai->array[i].AuthInfo.nt4owf.password.hash,
				       b[i].data.data, 16);
				break;
			case TRUST_AUTH_TYPE_CLEAR:
				if (!convert_string_talloc(ai->array,
							   CH_UNIX, CH_UTF16,
							   b[i].data.data,
							   b[i].data.size,
							   &ai->array[i].AuthInfo.clear.password,
							   &size)) {
					status = NT_STATUS_INVALID_PARAMETER;
					goto fail;
				}
				ai->array[i].AuthInfo.clear.size = size;
				break;
			case TRUST_AUTH_TYPE_VERSION:
				if (b[i].data.size != 4) {
					status = NT_STATUS_INVALID_PARAMETER;
					goto fail;
				}
				ai->array[i].AuthInfo.version.size = 4;
				memcpy(&ai->array[i].AuthInfo.version.version,
				       b[i].data.data, 4);
				break;
			default:
				status = NT_STATUS_INVALID_PARAMETER;
				goto fail;
		}
	}

	return NT_STATUS_OK;

fail:
	talloc_free(ai->array);
	return status;
}

NTSTATUS auth_info_2_trustauth_inout(TALLOC_CTX *mem_ctx,
				     uint32_t count,
				     struct lsa_TrustDomainInfoBuffer *current,
				     struct lsa_TrustDomainInfoBuffer *previous,
				     struct trustAuthInOutBlob **iopw_out)
{
	NTSTATUS status;
	struct trustAuthInOutBlob *iopw;

	iopw = talloc_zero(mem_ctx, struct trustAuthInOutBlob);
	if (iopw == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	iopw->count = count;
	status = trust_domain_info_buffer_2_ai_array(iopw, count, current,
						     &iopw->current);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (previous != NULL) {
		status = trust_domain_info_buffer_2_ai_array(iopw, count,
							     previous,
							     &iopw->previous);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
	} else {
		iopw->previous.count = 0;
		iopw->previous.array = NULL;
	}

	*iopw_out = iopw;

	status = NT_STATUS_OK;

done:
	return status;
}

static NTSTATUS auth_info_2_trustauth_inout_blob(TALLOC_CTX *mem_ctx,
				     uint32_t count,
				     struct lsa_TrustDomainInfoBuffer *current,
				     struct lsa_TrustDomainInfoBuffer *previous,
				     DATA_BLOB *inout_blob)
{
	NTSTATUS status;
	struct trustAuthInOutBlob *iopw = NULL;
	enum ndr_err_code ndr_err;

	status = auth_info_2_trustauth_inout(mem_ctx, count, current, previous, &iopw);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	ndr_err = ndr_push_struct_blob(inout_blob, mem_ctx,
			      iopw,
			      (ndr_push_flags_fn_t)ndr_push_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = NT_STATUS_OK;

done:
	talloc_free(iopw);
	return status;
}

NTSTATUS auth_info_2_auth_blob(TALLOC_CTX *mem_ctx,
			       struct lsa_TrustDomainInfoAuthInfo *auth_info,
			       DATA_BLOB *incoming, DATA_BLOB *outgoing)
{
	NTSTATUS status;

	if (auth_info->incoming_count == 0) {
		incoming->length = 0;
		incoming->data = NULL;
	} else {
		status = auth_info_2_trustauth_inout_blob(mem_ctx,
					 auth_info->incoming_count,
					 auth_info->incoming_current_auth_info,
					 auth_info->incoming_previous_auth_info,
					 incoming);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (auth_info->outgoing_count == 0) {
		outgoing->length = 0;
		outgoing->data = NULL;
	} else {
		status = auth_info_2_trustauth_inout_blob(mem_ctx,
					 auth_info->outgoing_count,
					 auth_info->outgoing_current_auth_info,
					 auth_info->outgoing_previous_auth_info,
					 outgoing);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS trust_forest_record_from_lsa(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustRecord2 *lftr,
				struct ForestTrustInfoRecord *ftr)
{
	struct ForestTrustString *str = NULL;
	const struct lsa_StringLarge *lstr = NULL;
	const struct lsa_ForestTrustDomainInfo *linfo = NULL;
	struct ForestTrustDataDomainInfo *info = NULL;

	if (lftr == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	ftr->flags = lftr->flags;
	ftr->timestamp = lftr->time;

	switch (lftr->type) {
	case LSA_FOREST_TRUST_TOP_LEVEL_NAME:
		ftr->type = FOREST_TRUST_TOP_LEVEL_NAME;

		lstr = &lftr->forest_trust_data.top_level_name;
		str = &ftr->data.name;

		str->string = talloc_strdup(mem_ctx, lstr->string);
		if (str->string == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
		ftr->type = FOREST_TRUST_TOP_LEVEL_NAME_EX;

		lstr = &lftr->forest_trust_data.top_level_name_ex;
		str = &ftr->data.name;

		str->string = talloc_strdup(mem_ctx, lstr->string);
		if (str->string == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_DOMAIN_INFO:
		ftr->type = FOREST_TRUST_DOMAIN_INFO;

		linfo = &lftr->forest_trust_data.domain_info;
		info = &ftr->data.info;

		if (linfo->domain_sid == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		info->sid = *linfo->domain_sid;

		lstr = &linfo->dns_domain_name;
		str = &info->dns_name;
		str->string = talloc_strdup(mem_ctx, lstr->string);
		if (str->string == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		lstr = &linfo->netbios_domain_name;
		str = &info->netbios_name;
		str->string = talloc_strdup(mem_ctx, lstr->string);
		if (str->string == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_BINARY_DATA:
	case LSA_FOREST_TRUST_SCANNER_INFO:
		/* TODO */
		break;
	}

	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS trust_forest_record_lsa_1to2(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustRecord *lftr,
				struct lsa_ForestTrustRecord2 *lftr2)
{
	if (lftr == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	lftr2->flags = lftr->flags;
	lftr2->time = lftr->time;

	switch (lftr->type) {
	case LSA_FOREST_TRUST_TOP_LEVEL_NAME:
		lftr2->type = LSA_FOREST_TRUST_TOP_LEVEL_NAME;
		lftr2->forest_trust_data.top_level_name =
			lftr->forest_trust_data.top_level_name;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
		lftr2->type = LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX;
		lftr2->forest_trust_data.top_level_name_ex =
			lftr->forest_trust_data.top_level_name_ex;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_DOMAIN_INFO:
		lftr2->type = LSA_FOREST_TRUST_DOMAIN_INFO;
		lftr2->forest_trust_data.domain_info =
			lftr->forest_trust_data.domain_info;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_BINARY_DATA:
		lftr2->type = LSA_FOREST_TRUST_BINARY_DATA;
		lftr2->forest_trust_data.data =
			lftr->forest_trust_data.data;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_SCANNER_INFO:
		/* TODO */
		break;
	}

	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS trust_forest_info_from_lsa(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustInformation *lfti,
				struct ForestTrustInfo **_fti)
{
	struct ForestTrustInfo *fti;
	uint32_t i;

	*_fti = NULL;

	fti = talloc_zero(mem_ctx, struct ForestTrustInfo);
	if (fti == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fti->version = 1;
	fti->count = lfti->count;
	fti->records = talloc_zero_array(fti,
					 struct ForestTrustInfoRecordArmor,
					 fti->count);
	if (fti->records == NULL) {
		TALLOC_FREE(fti);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < fti->count; i++) {
		const struct lsa_ForestTrustRecord *lftr = lfti->entries[i];
		struct lsa_ForestTrustRecord2 lftr2 = { .flags = 0, };
		struct ForestTrustInfoRecord *ftr = &fti->records[i].record;
		TALLOC_CTX *frame = talloc_stackframe();
		NTSTATUS status;

		status = trust_forest_record_lsa_1to2(frame,
						      lftr,
						      &lftr2);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			TALLOC_FREE(fti);
			return status;
		}

		status = trust_forest_record_from_lsa(fti->records,
						      &lftr2,
						      ftr);
		TALLOC_FREE(frame);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(fti);
			return status;
		}
	}

	*_fti = fti;
	return NT_STATUS_OK;
}

static NTSTATUS trust_forest_record_to_lsa(TALLOC_CTX *mem_ctx,
					const struct ForestTrustInfoRecord *ftr,
					struct lsa_ForestTrustRecord2 *lftr)
{
	const struct ForestTrustString *str = NULL;
	struct lsa_StringLarge *lstr = NULL;
	const struct ForestTrustDataDomainInfo *info = NULL;
	struct lsa_ForestTrustDomainInfo *linfo = NULL;

	lftr->flags = ftr->flags;
	lftr->time = ftr->timestamp;

	switch (ftr->type) {
	case FOREST_TRUST_TOP_LEVEL_NAME:
		lftr->type = LSA_FOREST_TRUST_TOP_LEVEL_NAME;

		lstr = &lftr->forest_trust_data.top_level_name;
		str = &ftr->data.name;

		lstr->string = talloc_strdup(mem_ctx, str->string);
		if (lstr->string == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		return NT_STATUS_OK;

	case FOREST_TRUST_TOP_LEVEL_NAME_EX:
		lftr->type = LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX;

		lstr = &lftr->forest_trust_data.top_level_name_ex;
		str = &ftr->data.name;

		lstr->string = talloc_strdup(mem_ctx, str->string);
		if (lstr->string == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		return NT_STATUS_OK;

	case FOREST_TRUST_DOMAIN_INFO:
		lftr->type = LSA_FOREST_TRUST_DOMAIN_INFO;

		linfo = &lftr->forest_trust_data.domain_info;
		info = &ftr->data.info;

		linfo->domain_sid = dom_sid_dup(mem_ctx, &info->sid);
		if (linfo->domain_sid == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		lstr = &linfo->dns_domain_name;
		str = &info->dns_name;
		lstr->string = talloc_strdup(mem_ctx, str->string);
		if (lstr->string == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		lstr = &linfo->netbios_domain_name;
		str = &info->netbios_name;
		lstr->string = talloc_strdup(mem_ctx, str->string);
		if (lstr->string == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		return NT_STATUS_OK;

	case FOREST_TRUST_BINARY_DATA:
	case FOREST_TRUST_SCANNER_INFO:
		/* TODO */
		break;
	}

	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS trust_forest_record_lsa_2to1(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustRecord2 *lftr2,
				struct lsa_ForestTrustRecord *lftr)
{
	if (lftr2 == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	lftr->flags = lftr2->flags;
	lftr->time = lftr2->time;

	switch (lftr2->type) {
	case LSA_FOREST_TRUST_TOP_LEVEL_NAME:
		lftr->type = LSA_FOREST_TRUST_TOP_LEVEL_NAME;
		lftr->forest_trust_data.top_level_name =
			lftr2->forest_trust_data.top_level_name;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
		lftr->type = LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX;
		lftr->forest_trust_data.top_level_name_ex =
			lftr2->forest_trust_data.top_level_name_ex;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_DOMAIN_INFO:
		lftr->type = LSA_FOREST_TRUST_DOMAIN_INFO;
		lftr->forest_trust_data.domain_info =
			lftr2->forest_trust_data.domain_info;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_BINARY_DATA:
		lftr->type = LSA_FOREST_TRUST_BINARY_DATA;
		lftr->forest_trust_data.data =
			lftr2->forest_trust_data.data;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_SCANNER_INFO:
		/* TODO */
		break;
	}

	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS trust_forest_info_to_lsa(TALLOC_CTX *mem_ctx,
				  const struct ForestTrustInfo *fti,
				  struct lsa_ForestTrustInformation **_lfti)
{
	struct lsa_ForestTrustInformation *lfti;
	uint32_t i;

	*_lfti = NULL;

	if (fti->version != 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	lfti = talloc_zero(mem_ctx, struct lsa_ForestTrustInformation);
	if (lfti == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	lfti->count = fti->count;
	lfti->entries = talloc_zero_array(mem_ctx,
					  struct lsa_ForestTrustRecord *,
					  lfti->count);
	if (lfti->entries == NULL) {
		TALLOC_FREE(lfti);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < fti->count; i++) {
		struct ForestTrustInfoRecord *ftr = &fti->records[i].record;
		struct lsa_ForestTrustRecord2 lftr2 = { .flags = 0, };
		struct lsa_ForestTrustRecord *lftr = NULL;
		NTSTATUS status;

		lftr = talloc_zero(lfti->entries,
				   struct lsa_ForestTrustRecord);
		if (lftr == NULL) {
			TALLOC_FREE(lfti);
			return NT_STATUS_NO_MEMORY;
		}

		status = trust_forest_record_to_lsa(lftr, ftr, &lftr2);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(lfti);
			return NT_STATUS_NO_MEMORY;
		}

		status = trust_forest_record_lsa_2to1(lftr, &lftr2, lftr);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(lfti);
			return NT_STATUS_NO_MEMORY;
		}

		lfti->entries[i] = lftr;
	}

	*_lfti = lfti;
	return NT_STATUS_OK;
}

static int trust_forest_info_tln_match_internal(
		const struct lsa_ForestTrustInformation *info,
		enum lsa_ForestTrustRecordType type,
		uint32_t disable_mask,
		const char *tln)
{
	uint32_t i;

	for (i = 0; i < info->count; i++) {
		struct lsa_ForestTrustRecord *e = info->entries[i];
		struct lsa_StringLarge *t = NULL;
		int cmp;

		if (e == NULL) {
			continue;
		}

		if (e->type != type) {
			continue;
		}

		if (e->flags & disable_mask) {
			continue;
		}

		switch (type) {
		case LSA_FOREST_TRUST_TOP_LEVEL_NAME:
			t = &e->forest_trust_data.top_level_name;
			break;
		case LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
			t = &e->forest_trust_data.top_level_name_ex;
			break;
		default:
			break;
		}

		if (t == NULL) {
			continue;
		}

		cmp = dns_cmp(tln, t->string);
		switch (cmp) {
		case DNS_CMP_MATCH:
		case DNS_CMP_FIRST_IS_CHILD:
			return i;
		}
	}

	return -1;
}

bool trust_forest_info_tln_match(
		const struct lsa_ForestTrustInformation *info,
		const char *tln)
{
	int m;

	m = trust_forest_info_tln_match_internal(info,
					LSA_FOREST_TRUST_TOP_LEVEL_NAME,
					LSA_TLN_DISABLED_MASK,
					tln);
	if (m != -1) {
		return true;
	}

	return false;
}

bool trust_forest_info_tln_ex_match(
		const struct lsa_ForestTrustInformation *info,
		const char *tln)
{
	int m;

	m = trust_forest_info_tln_match_internal(info,
					LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX,
					0,
					tln);
	if (m != -1) {
		return true;
	}

	return false;
}
