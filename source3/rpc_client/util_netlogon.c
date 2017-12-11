/*
   Unix SMB/CIFS implementation.
   Authentication utility functions
   Copyright (C) Volker Lendecke 2010

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
#include "../librpc/gen_ndr/netlogon.h"
#include "../libcli/security/security.h"
#include "rpc_client/util_netlogon.h"

#define COPY_LSA_STRING(mem_ctx, in, out, name) do { \
	if (in->name.string) { \
		out->name.string = talloc_strdup(mem_ctx, in->name.string); \
		NT_STATUS_HAVE_NO_MEMORY(out->name.string); \
	} \
} while (0)

NTSTATUS copy_netr_SamBaseInfo(TALLOC_CTX *mem_ctx,
			       const struct netr_SamBaseInfo *in,
			       struct netr_SamBaseInfo *out)
{
	/* first copy all, then realloc pointers */
	*out = *in;

	COPY_LSA_STRING(mem_ctx, in, out, account_name);
	COPY_LSA_STRING(mem_ctx, in, out, full_name);
	COPY_LSA_STRING(mem_ctx, in, out, logon_script);
	COPY_LSA_STRING(mem_ctx, in, out, profile_path);
	COPY_LSA_STRING(mem_ctx, in, out, home_directory);
	COPY_LSA_STRING(mem_ctx, in, out, home_drive);

	if (in->groups.count) {
		out->groups.rids = (struct samr_RidWithAttribute *)
			talloc_memdup(mem_ctx, in->groups.rids,
				(sizeof(struct samr_RidWithAttribute) *
					in->groups.count));
		NT_STATUS_HAVE_NO_MEMORY(out->groups.rids);
	}

	COPY_LSA_STRING(mem_ctx, in, out, logon_server);
	COPY_LSA_STRING(mem_ctx, in, out, logon_domain);

	if (in->domain_sid) {
		out->domain_sid = dom_sid_dup(mem_ctx, in->domain_sid);
		NT_STATUS_HAVE_NO_MEMORY(out->domain_sid);
	}

	return NT_STATUS_OK;
}

#undef RET_NOMEM

#define RET_NOMEM(ptr) do { \
	if (!ptr) { \
		TALLOC_FREE(info3); \
		return NULL; \
	} } while(0)

struct netr_SamInfo3 *copy_netr_SamInfo3(TALLOC_CTX *mem_ctx,
					 const struct netr_SamInfo3 *orig)
{
	struct netr_SamInfo3 *info3;
	unsigned int i;
	NTSTATUS status;

	info3 = talloc_zero(mem_ctx, struct netr_SamInfo3);
	if (!info3) return NULL;

	status = copy_netr_SamBaseInfo(info3, &orig->base, &info3->base);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(info3);
		return NULL;
	}

	if (orig->sidcount) {
		info3->sidcount = orig->sidcount;
		info3->sids = talloc_array(info3, struct netr_SidAttr,
					   orig->sidcount);
		RET_NOMEM(info3->sids);
		for (i = 0; i < orig->sidcount; i++) {
			info3->sids[i].sid = dom_sid_dup(info3->sids,
							    orig->sids[i].sid);
			RET_NOMEM(info3->sids[i].sid);
			info3->sids[i].attributes =
				orig->sids[i].attributes;
		}
	}

	return info3;
}

NTSTATUS map_validation_to_info3(TALLOC_CTX *mem_ctx,
				 uint16_t validation_level,
				 union netr_Validation *validation,
				 struct netr_SamInfo3 **info3_p)
{
	struct netr_SamInfo3 *info3;
	struct netr_SamInfo6 *info6 = NULL;
	NTSTATUS status;

	if (validation == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (validation_level) {
	case 3:
		if (validation->sam3 == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		info3 = copy_netr_SamInfo3(mem_ctx, validation->sam3);
		if (info3 == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		break;
	case 6:
		if (validation->sam6 == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		info6 = validation->sam6;

		info3 = talloc_zero(mem_ctx, struct netr_SamInfo3);
		if (info3 == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = copy_netr_SamBaseInfo(info3,
					       &info6->base,
					       &info3->base);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(info3);
			return status;
		}

		if (validation->sam6->sidcount > 0) {
			int i;

			info3->sidcount = info6->sidcount;

			info3->sids = talloc_array(info3,
						   struct netr_SidAttr,
						   info3->sidcount);
			if (info3->sids == NULL) {
				TALLOC_FREE(info3);
				return NT_STATUS_NO_MEMORY;
			}

			for (i = 0; i < info3->sidcount; i++) {
				info3->sids[i].sid = dom_sid_dup(
					info3->sids, info6->sids[i].sid);
				if (info3->sids[i].sid == NULL) {
					TALLOC_FREE(info3);
					return NT_STATUS_NO_MEMORY;
				}
				info3->sids[i].attributes =
					info6->sids[i].attributes;
			}
		}
		break;
	default:
		return NT_STATUS_BAD_VALIDATION_CLASS;
	}

	*info3_p = info3;

	return NT_STATUS_OK;
}

NTSTATUS map_info3_to_validation(TALLOC_CTX *mem_ctx,
				 struct netr_SamInfo3 *info3,
				 uint16_t *_validation_level,
				 union netr_Validation **_validation)
{
	union netr_Validation *validation = NULL;

	validation = talloc_zero(mem_ctx, union netr_Validation);
	if (validation == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	validation->sam3 = copy_netr_SamInfo3(mem_ctx, info3);
	if (validation->sam3 == NULL) {
		TALLOC_FREE(validation);
		return NT_STATUS_NO_MEMORY;
	}

	* _validation_level = 3;
	*_validation = validation;
	return NT_STATUS_OK;
}
