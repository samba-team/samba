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
#include "../librpc/gen_ndr/ndr_drsblobs.h"
#include "../librpc/gen_ndr/ndr_lsa.h"
#include "libcli/lsarpc/util_lsarpc.h"

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
