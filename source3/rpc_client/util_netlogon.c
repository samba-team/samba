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

NTSTATUS copy_netr_SamInfo3(TALLOC_CTX *mem_ctx,
			    const struct netr_SamInfo3 *in,
			    struct netr_SamInfo3 **pout)
{
	struct netr_SamInfo3 *info3 = NULL;
	unsigned int i;
	NTSTATUS status;

	info3 = talloc_zero(mem_ctx, struct netr_SamInfo3);
	if (info3 == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	status = copy_netr_SamBaseInfo(info3, &in->base, &info3->base);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (in->sidcount) {
		info3->sidcount = in->sidcount;
		info3->sids = talloc_array(info3, struct netr_SidAttr,
					   in->sidcount);
		if (info3->sids == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		for (i = 0; i < in->sidcount; i++) {
			info3->sids[i].sid = dom_sid_dup(info3->sids,
							 in->sids[i].sid);
			if (info3->sids[i].sid == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto out;
			}
			info3->sids[i].attributes = in->sids[i].attributes;
		}
	}

	*pout = info3;
	info3 = NULL;

	status = NT_STATUS_OK;
out:
	TALLOC_FREE(info3);
	return status;
}

NTSTATUS map_validation_to_info3(TALLOC_CTX *mem_ctx,
				 uint16_t validation_level,
				 union netr_Validation *validation,
				 struct netr_SamInfo3 **info3_p)
{
	struct netr_SamInfo3 *info3 = NULL;
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

		status = copy_netr_SamInfo3(mem_ctx,
					    validation->sam3,
					    &info3);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
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

NTSTATUS copy_netr_SamInfo6(TALLOC_CTX *mem_ctx,
			    const struct netr_SamInfo6 *in,
			    struct netr_SamInfo6 **pout)
{
	struct netr_SamInfo6 *info6 = NULL;
	unsigned int i;
	NTSTATUS status;

	info6 = talloc_zero(mem_ctx, struct netr_SamInfo6);
	if (info6 == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	status = copy_netr_SamBaseInfo(info6, &in->base, &info6->base);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (in->sidcount) {
		info6->sidcount = in->sidcount;
		info6->sids = talloc_array(info6, struct netr_SidAttr,
					   in->sidcount);
		if (info6->sids == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}

		for (i = 0; i < in->sidcount; i++) {
			info6->sids[i].sid = dom_sid_dup(info6->sids,
							 in->sids[i].sid);
			if (info6->sids[i].sid == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto out;
			}
			info6->sids[i].attributes = in->sids[i].attributes;
		}
	}

	if (in->dns_domainname.string != NULL) {
		info6->dns_domainname.string = talloc_strdup(info6,
						in->dns_domainname.string);
		if (info6->dns_domainname.string == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	if (in->principal_name.string != NULL) {
		info6->principal_name.string = talloc_strdup(info6,
						in->principal_name.string);
		if (info6->principal_name.string == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}

	*pout = info6;
	info6 = NULL;

	status = NT_STATUS_OK;
out:
	TALLOC_FREE(info6);
	return status;
}

NTSTATUS map_validation_to_info6(TALLOC_CTX *mem_ctx,
				 uint16_t validation_level,
				 union netr_Validation *validation,
				 struct netr_SamInfo6 **info6_p)
{
	struct netr_SamInfo3 *info3 = NULL;
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
		info3 = validation->sam3;

		info6 = talloc_zero(mem_ctx, struct netr_SamInfo6);
		if (info6 == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		status = copy_netr_SamBaseInfo(info6,
					       &info3->base,
					       &info6->base);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(info6);
			return status;
		}

		if (validation->sam3->sidcount > 0) {
			int i;

			info6->sidcount = info3->sidcount;

			info6->sids = talloc_array(info6,
						   struct netr_SidAttr,
						   info6->sidcount);
			if (info6->sids == NULL) {
				TALLOC_FREE(info6);
				return NT_STATUS_NO_MEMORY;
			}

			for (i = 0; i < info6->sidcount; i++) {
				info6->sids[i].sid = dom_sid_dup(
					info6->sids, info3->sids[i].sid);
				if (info6->sids[i].sid == NULL) {
					TALLOC_FREE(info6);
					return NT_STATUS_NO_MEMORY;
				}
				info6->sids[i].attributes =
					info3->sids[i].attributes;
			}
		}
		break;
	case 6:
		if (validation->sam6 == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		status = copy_netr_SamInfo6(mem_ctx,
					    validation->sam6,
					    &info6);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		break;
	default:
		return NT_STATUS_BAD_VALIDATION_CLASS;
	}

	*info6_p = info6;

	return NT_STATUS_OK;
}

NTSTATUS map_info3_to_validation(TALLOC_CTX *mem_ctx,
				 struct netr_SamInfo3 *info3,
				 uint16_t *_validation_level,
				 union netr_Validation **_validation)
{
	union netr_Validation *validation = NULL;
	NTSTATUS status;

	validation = talloc_zero(mem_ctx, union netr_Validation);
	if (validation == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = copy_netr_SamInfo3(mem_ctx,
				    info3,
				    &validation->sam3);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(validation);
		return status;
	}

	* _validation_level = 3;
	*_validation = validation;
	return NT_STATUS_OK;
}

NTSTATUS map_info6_to_validation(TALLOC_CTX *mem_ctx,
				 const struct netr_SamInfo6 *info6,
				 uint16_t *_validation_level,
				 union netr_Validation **_validation)
{
	union netr_Validation *validation = NULL;
	NTSTATUS status;

	validation = talloc_zero(mem_ctx, union netr_Validation);
	if (validation == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = copy_netr_SamInfo6(mem_ctx,
				    info6,
				    &validation->sam6);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(validation);
		return status;
	}

	* _validation_level = 6;
	*_validation = validation;
	return NT_STATUS_OK;
}
