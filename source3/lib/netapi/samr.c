/*
 *  Unix SMB/CIFS implementation.
 *  NetApi Samr Support
 *  Copyright (C) Guenther Deschner 2008
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

/****************************************************************
****************************************************************/

WERROR libnetapi_samr_open_domain(TALLOC_CTX *mem_ctx,
				  struct rpc_pipe_client *pipe_cli,
				  uint32_t connect_mask,
				  uint32_t domain_mask,
				  struct policy_handle *connect_handle,
				  struct policy_handle *domain_handle,
				  struct dom_sid2 **domain_sid)
{
	NTSTATUS status;
	WERROR werr;
	uint32_t resume_handle = 0;
	uint32_t num_entries = 0;
	struct samr_SamArray *sam = NULL;
	const char *domain_name = NULL;
	struct lsa_String lsa_domain_name;
	bool domain_found = true;
	int i;

	if (!is_valid_policy_hnd(connect_handle)) {
		status = rpccli_try_samr_connects(pipe_cli, mem_ctx,
						  connect_mask,
						  connect_handle);
		if (!NT_STATUS_IS_OK(status)) {
			werr = ntstatus_to_werror(status);
			goto done;
		}
	}

	status = rpccli_samr_EnumDomains(pipe_cli, mem_ctx,
					 connect_handle,
					 &resume_handle,
					 &sam,
					 0xffffffff,
					 &num_entries);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	for (i=0; i<num_entries; i++) {

		domain_name = sam->entries[i].name.string;

		if (strequal(domain_name, builtin_domain_name())) {
			continue;
		}

		domain_found = true;
		break;
	}

	if (!domain_found) {
		werr = WERR_NO_SUCH_DOMAIN;
		goto done;
	}

	init_lsa_String(&lsa_domain_name, domain_name);

	status = rpccli_samr_LookupDomain(pipe_cli, mem_ctx,
					  connect_handle,
					  &lsa_domain_name,
					  domain_sid);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	status = rpccli_samr_OpenDomain(pipe_cli, mem_ctx,
					connect_handle,
					domain_mask,
					*domain_sid,
					domain_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = WERR_OK;

 done:
	return werr;
}

/****************************************************************
****************************************************************/

WERROR libnetapi_samr_open_builtin_domain(TALLOC_CTX *mem_ctx,
					  struct rpc_pipe_client *pipe_cli,
					  uint32_t connect_mask,
					  uint32_t builtin_mask,
					  struct policy_handle *connect_handle,
					  struct policy_handle *builtin_handle)
{
	NTSTATUS status;
	WERROR werr;

	if (!is_valid_policy_hnd(connect_handle)) {
		status = rpccli_try_samr_connects(pipe_cli, mem_ctx,
						  connect_mask,
						  connect_handle);
		if (!NT_STATUS_IS_OK(status)) {
			werr = ntstatus_to_werror(status);
			goto done;
		}
	}

	status = rpccli_samr_OpenDomain(pipe_cli, mem_ctx,
					connect_handle,
					builtin_mask,
					CONST_DISCARD(DOM_SID *, &global_sid_Builtin),
					builtin_handle);
	if (!NT_STATUS_IS_OK(status)) {
		werr = ntstatus_to_werror(status);
		goto done;
	}

	werr = WERR_OK;

 done:
	return werr;
}

/****************************************************************
****************************************************************/

void libnetapi_samr_close_domain_handle(struct libnetapi_ctx *ctx,
					struct policy_handle *handle)
{
	struct libnetapi_private_ctx *priv;

	if (!is_valid_policy_hnd(handle)) {
		return;
	}

	priv = talloc_get_type_abort(ctx->private_data,
		struct libnetapi_private_ctx);

	if (!policy_hnd_equal(handle, &priv->samr.domain_handle)) {
		return;
	}

	rpccli_samr_Close(priv->samr.cli, ctx, handle);

	ZERO_STRUCT(priv->samr.domain_handle);
}

/****************************************************************
****************************************************************/

void libnetapi_samr_close_connect_handle(struct libnetapi_ctx *ctx,
					 struct policy_handle *handle)
{
	struct libnetapi_private_ctx *priv;

	if (!is_valid_policy_hnd(handle)) {
		return;
	}

	priv = talloc_get_type_abort(ctx->private_data,
		struct libnetapi_private_ctx);

	if (!policy_hnd_equal(handle, &priv->samr.connect_handle)) {
		return;
	}

	rpccli_samr_Close(priv->samr.cli, ctx, handle);

	ZERO_STRUCT(priv->samr.connect_handle);
}
