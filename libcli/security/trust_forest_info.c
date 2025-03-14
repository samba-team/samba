/*
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Stefan Metzmacher 2018,2025

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

#include "replace.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/bytearray.h"
#include "lib/util/dns_cmp.h"

static NTSTATUS trust_forest_record_from_lsa(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustRecord2 *lftr,
				struct ForestTrustInfoRecord *ftr)
{
	struct ForestTrustString *str = NULL;
	const struct lsa_StringLarge *lstr = NULL;
	const struct lsa_ForestTrustDomainInfo *linfo = NULL;
	struct ForestTrustDataDomainInfo *info = NULL;
	DATA_BLOB blob = { .length = 0, };

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
		ftr->type = FOREST_TRUST_BINARY_DATA;

		blob = data_blob_talloc_named(mem_ctx,
					      lftr->forest_trust_data.data.data,
					      lftr->forest_trust_data.data.length,
					      "BINARY_DATA");
		if (blob.length != lftr->forest_trust_data.data.length) {
			return NT_STATUS_NO_MEMORY;
		}
		ftr->data.binary.data = blob.data;
		ftr->data.binary.size = blob.length;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_SCANNER_INFO:
		ftr->type = FOREST_TRUST_SCANNER_INFO;

		linfo = &lftr->forest_trust_data.scanner_info;
		info = &ftr->data.scanner_info.info;

		ftr->data.scanner_info.sub_type = FOREST_TRUST_SCANNER_INFO;

		if (linfo->domain_sid != NULL) {
			info->sid = *linfo->domain_sid;
		} else {
			info->sid = (struct dom_sid) { .sid_rev_num = 0, };
		}

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
	}

	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS trust_forest_record_lsa_resolve_binary(TALLOC_CTX *mem_ctx,
				uint32_t flags,
				NTTIME time,
				const struct lsa_ForestTrustBinaryData *binary,
				struct lsa_ForestTrustRecord2 *lftr2)
{
	enum ForestTrustInfoRecordType sub_type = FOREST_TRUST_BINARY_DATA;
	DATA_BLOB blob = { .length = 0, };

	if (binary == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/*
	 * Note 'binary' may points to
	 * lftr2->forest_trust_data.data
	 *
	 * So we remember the relevant
	 * information in blob and clear
	 * the binary pointer in order
	 * to avoid touching it again.
	 *
	 * Because we likely change
	 * the lftr2->forest_trust_data union
	 */
	blob.data = binary->data;
	blob.length = binary->length;
	binary = NULL;

	/*
	 * We need at least size and subtype
	 */
	if (blob.length < 5) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	sub_type = PULL_LE_U8(blob.data, 4);

	/*
	 * Only levels above LSA_FOREST_TRUST_DOMAIN_INFO
	 * are handled as binary.
	 */
	if (sub_type <= FOREST_TRUST_BINARY_DATA) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	lftr2->flags = flags;
	lftr2->time = time;

	/*
	 * Depending if the sub_type is wellknown the information is upgraded,
	 * currently only for the LSA_FOREST_TRUST_SCANNER_INFO records.
	 */

	if (sub_type == FOREST_TRUST_SCANNER_INFO) {
		struct lsa_ForestTrustDomainInfo *d_sdi = NULL;
		union ForestTrustData fta = { .unknown = { .size = 0, }, };
		const struct ForestTrustDataDomainInfo *s_sdi = NULL;
		enum ndr_err_code ndr_err;

		ndr_err = ndr_pull_union_blob(&blob,
					      mem_ctx,
					      &fta,
					      FOREST_TRUST_SCANNER_INFO,
					      (ndr_pull_flags_fn_t)ndr_pull_ForestTrustData);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return ndr_map_error2ntstatus(ndr_err);
		}

		if (fta.scanner_info.sub_type != FOREST_TRUST_SCANNER_INFO) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		s_sdi = &fta.scanner_info.info;
		d_sdi = &lftr2->forest_trust_data.scanner_info;

		d_sdi->dns_domain_name.string = s_sdi->dns_name.string;
		d_sdi->netbios_domain_name.string = s_sdi->netbios_name.string;

		if (s_sdi->sid_size != 0) {
			d_sdi->domain_sid = dom_sid_dup(mem_ctx,
							&s_sdi->sid);
			if (d_sdi->domain_sid == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		} else {
			d_sdi->domain_sid = NULL;
		}

		lftr2->type = LSA_FOREST_TRUST_SCANNER_INFO;

		return NT_STATUS_OK;
	}

	/*
	 * In all other cases lftr->type is downgraded to
	 * LSA_FOREST_TRUST_BINARY_DATA.
	 */

	lftr2->type = LSA_FOREST_TRUST_BINARY_DATA;
	lftr2->forest_trust_data.data.data = blob.data;
	lftr2->forest_trust_data.data.length = blob.length;

	return NT_STATUS_OK;
}

static NTSTATUS trust_forest_record_lsa_1to2(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustRecord *lftr,
				struct lsa_ForestTrustRecord2 *lftr2)
{
	const struct lsa_ForestTrustBinaryData *binary = NULL;

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
	case LSA_FOREST_TRUST_SCANNER_INFO:
		/* just to avoid the missing enum switch warning */
		break;
	}

	/*
	 * All levels above LSA_FOREST_TRUST_DOMAIN_INFO are handled as binary.
	 *
	 * Depending if the sub_type is wellknown the information is upgraded,
	 * currently only for the LSA_FOREST_TRUST_SCANNER_INFO records.
	 *
	 * In all other cases lftr->type is downgraded to
	 * LSA_FOREST_TRUST_BINARY_DATA.
	 */

	binary = &lftr->forest_trust_data.data;

	return trust_forest_record_lsa_resolve_binary(mem_ctx,
						      lftr->flags,
						      lftr->time,
						      binary,
						      lftr2);
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
	DATA_BLOB blob = { .length = 0, };

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
		lftr->type = LSA_FOREST_TRUST_BINARY_DATA;

		blob = data_blob_talloc_named(mem_ctx,
					      ftr->data.binary.data,
					      ftr->data.binary.size,
					      "BINARY_DATA");
		if (blob.length != ftr->data.binary.size) {
			return NT_STATUS_NO_MEMORY;
		}

		lftr->forest_trust_data.data.data = blob.data;
		lftr->forest_trust_data.data.length = blob.length;

		return NT_STATUS_OK;

	case FOREST_TRUST_SCANNER_INFO:
		lftr->type = LSA_FOREST_TRUST_SCANNER_INFO;

		linfo = &lftr->forest_trust_data.scanner_info;
		info = &ftr->data.scanner_info.info;

		if (info->sid_size != 0) {
			linfo->domain_sid = dom_sid_dup(mem_ctx,
							&info->sid);
			if (linfo->domain_sid == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		} else {
			linfo->domain_sid = NULL;
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
	}

	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS trust_forest_record_lsa_2to1(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustRecord2 *lftr2,
				struct lsa_ForestTrustRecord *lftr)
{
	const struct lsa_ForestTrustDomainInfo *s_sdi = NULL;
	union ForestTrustData fta = { .unknown = { .size = 0, }, };
	struct ForestTrustDataDomainInfo *d_sdi = NULL;
	enum ndr_err_code ndr_err;
	DATA_BLOB blob = { .length = 0, };

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
		fta.scanner_info.sub_type = FOREST_TRUST_SCANNER_INFO;
		s_sdi = &lftr2->forest_trust_data.scanner_info;
		d_sdi = &fta.scanner_info.info;

		if (s_sdi->domain_sid != NULL) {
			d_sdi->sid = *s_sdi->domain_sid;
		} else {
			d_sdi->sid = (struct dom_sid) { .sid_rev_num = 0, };
		}

		d_sdi->dns_name.string = s_sdi->dns_domain_name.string;
		d_sdi->netbios_name.string = s_sdi->netbios_domain_name.string;

		ndr_err = ndr_push_union_blob(&blob,
					      mem_ctx,
					      &fta,
					      FOREST_TRUST_SCANNER_INFO,
					      (ndr_push_flags_fn_t)ndr_push_ForestTrustData);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			return ndr_map_error2ntstatus(ndr_err);
		}

		lftr->type = LSA_FOREST_TRUST_SCANNER_INFO;
		lftr->forest_trust_data.data.data = blob.data;
		lftr->forest_trust_data.data.length = blob.length;

		return NT_STATUS_OK;
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

static NTSTATUS trust_forest_record_lsa_2to2(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustRecord2 *in,
				struct lsa_ForestTrustRecord2 *out)
{
	const struct lsa_ForestTrustBinaryData *binary = NULL;

	if (in == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	out->flags = in->flags;
	out->time = in->time;

	switch (in->type) {
	case LSA_FOREST_TRUST_TOP_LEVEL_NAME:
		out->type = LSA_FOREST_TRUST_TOP_LEVEL_NAME;
		out->forest_trust_data.top_level_name =
			in->forest_trust_data.top_level_name;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX:
		out->type = LSA_FOREST_TRUST_TOP_LEVEL_NAME_EX;
		out->forest_trust_data.top_level_name_ex =
			in->forest_trust_data.top_level_name_ex;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_DOMAIN_INFO:
		out->type = LSA_FOREST_TRUST_DOMAIN_INFO;
		out->forest_trust_data.domain_info =
			in->forest_trust_data.domain_info;

		return NT_STATUS_OK;

	case LSA_FOREST_TRUST_BINARY_DATA:
		binary = &in->forest_trust_data.data;

		return trust_forest_record_lsa_resolve_binary(mem_ctx,
							      in->flags,
							      in->time,
							      binary,
							      out);

	case LSA_FOREST_TRUST_SCANNER_INFO:
		out->type = LSA_FOREST_TRUST_SCANNER_INFO;
		out->forest_trust_data.domain_info =
			in->forest_trust_data.domain_info;

		return NT_STATUS_OK;
	}

	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS trust_forest_info_from_lsa2(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustInformation2 *lfti,
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
		const struct lsa_ForestTrustRecord2 *lftr2 = lfti->entries[i];
		struct lsa_ForestTrustRecord2 _lftr2 = { .flags = 0, };
		struct ForestTrustInfoRecord *ftr = &fti->records[i].record;
		TALLOC_CTX *frame = talloc_stackframe();
		NTSTATUS status;

		status = trust_forest_record_lsa_2to2(frame,
						      lftr2,
						      &_lftr2);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			TALLOC_FREE(fti);
			return status;
		}

		status = trust_forest_record_from_lsa(fti->records,
						      &_lftr2,
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

NTSTATUS trust_forest_info_to_lsa2(TALLOC_CTX *mem_ctx,
				   const struct ForestTrustInfo *fti,
				   struct lsa_ForestTrustInformation2 **_lfti)
{
	struct lsa_ForestTrustInformation2 *lfti;
	uint32_t i;

	*_lfti = NULL;

	if (fti->version != 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	lfti = talloc_zero(mem_ctx, struct lsa_ForestTrustInformation2);
	if (lfti == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	lfti->count = fti->count;
	lfti->entries = talloc_zero_array(mem_ctx,
					  struct lsa_ForestTrustRecord2 *,
					  lfti->count);
	if (lfti->entries == NULL) {
		TALLOC_FREE(lfti);
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < fti->count; i++) {
		struct ForestTrustInfoRecord *ftr = &fti->records[i].record;
		struct lsa_ForestTrustRecord2 *lftr2 = NULL;
		NTSTATUS status;

		lftr2 = talloc_zero(lfti->entries,
				    struct lsa_ForestTrustRecord2);
		if (lftr2 == NULL) {
			TALLOC_FREE(lfti);
			return NT_STATUS_NO_MEMORY;
		}

		status = trust_forest_record_to_lsa(lftr2, ftr, lftr2);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(lfti);
			return NT_STATUS_NO_MEMORY;
		}

		lfti->entries[i] = lftr2;
	}

	*_lfti = lfti;
	return NT_STATUS_OK;
}

NTSTATUS trust_forest_info_lsa_1to2(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustInformation *lfti,
				struct lsa_ForestTrustInformation2 **_lfti2)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct ForestTrustInfo *fti = NULL;
	struct lsa_ForestTrustInformation2 *lfti2 = NULL;
	NTSTATUS status;

	status = trust_forest_info_from_lsa(frame, lfti, &fti);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = trust_forest_info_to_lsa2(mem_ctx,
					   fti,
					   &lfti2);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	*_lfti2 = lfti2;
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

NTSTATUS trust_forest_info_lsa_2to1(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustInformation2 *lfti2,
				struct lsa_ForestTrustInformation **_lfti)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct ForestTrustInfo *fti = NULL;
	struct lsa_ForestTrustInformation *lfti = NULL;
	NTSTATUS status;

	status = trust_forest_info_from_lsa2(frame, lfti2, &fti);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = trust_forest_info_to_lsa(mem_ctx,
					  fti,
					  &lfti);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	*_lfti = lfti;
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

NTSTATUS trust_forest_info_lsa_2to2(TALLOC_CTX *mem_ctx,
				const struct lsa_ForestTrustInformation2 *in,
				struct lsa_ForestTrustInformation2 **_out)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct ForestTrustInfo *fti = NULL;
	struct lsa_ForestTrustInformation2 *out = NULL;
	NTSTATUS status;

	status = trust_forest_info_from_lsa2(frame, in, &fti);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = trust_forest_info_to_lsa2(mem_ctx,
					   fti,
					   &out);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	*_out = out;
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static int trust_forest_info_tln_match_internal(
		const struct lsa_ForestTrustInformation2 *info,
		enum lsa_ForestTrustRecordType type,
		uint32_t disable_mask,
		const char *tln)
{
	uint32_t i;

	for (i = 0; i < info->count; i++) {
		struct lsa_ForestTrustRecord2 *e = info->entries[i];
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
		const struct lsa_ForestTrustInformation2 *info,
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
		const struct lsa_ForestTrustInformation2 *info,
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

bool trust_forest_info_match_tln_namespace(
		const struct lsa_ForestTrustInformation2 *info,
		const char *tln)
{
	bool match;

	match = trust_forest_info_tln_ex_match(info, tln);
	if (match) {
		return false;
	}

	match = trust_forest_info_tln_match(info, tln);
	if (!match) {
		return false;
	}

	return true;
}
