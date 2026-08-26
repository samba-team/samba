/*
   Unix SMB/CIFS implementation.

   GKDI implementation

   Copyright (C) Catalyst IT 2026

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
#include "lib/crypto/gkdi.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/gkdi.h"
#include "librpc/gen_ndr/ndr_gkdi.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "dsdb/gkdi/gkdi.h"
#include "libcli/security/session.h"
#include "auth/auth.h"

#undef strcasecmp

#define DCESRV_INTERFACE_GKDI_BIND(context, iface) \
	dcesrv_interface_gkdi_bind(context, iface)
static NTSTATUS dcesrv_interface_gkdi_bind(
	struct dcesrv_connection_context *context,
	const struct dcesrv_interface *iface)
{
	return dcesrv_interface_bind_require_privacy(context, iface);
}

/*
  gkdi_GetKey
*/
static HRESULT dcesrv_gkdi_GetKey(struct dcesrv_call_state *dce_call,
				  TALLOC_CTX *mem_ctx,
				  struct gkdi_GetKey *r)
{
	TALLOC_CTX *tmp_ctx = NULL;
	DATA_BLOB target_sd = {};
	struct security_descriptor security_descriptor;
	struct Gkid requested_gkid = invalid_gkid;
	enum GkidType gkid_type = GKID_DEFAULT;
	NTTIME current_time = 0;
	struct Gkid current_gkid = invalid_gkid;
	struct Gkid gkid = invalid_gkid;
	struct auth_session_info *session_info = dcesrv_call_session_info(
		dce_call);
	uint32_t access_granted = 0;
	struct ldb_context *sam_ctx = NULL;
	struct GUID root_key_id;
	const struct ldb_message *root_key_msg = NULL;
	const struct ProvRootKey *root_key = NULL;
	uint8_t *l2_key = NULL;
	uint8_t *l1_key = NULL;
	const char *domain_name = NULL;
	const char *forest_name = NULL;
	const struct GroupKeyEnvelope *gke = NULL;
	DATA_BLOB gke_blob = {};
	bool root_key_specified = false;
	HRESULT hres = HRES_OK;
	enum ndr_err_code ndr_err = NDR_ERR_SUCCESS;
	NTSTATUS status = NT_STATUS_OK;
	int ret = LDB_SUCCESS;
	bool ok = true;

	ZERO_STRUCT(r->out);

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		hres = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}

	r->out.out = talloc_zero(mem_ctx, uint8_t *);
	if (r->out.out == NULL) {
		hres = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}

	r->out.out_len = talloc_zero(mem_ctx, uint32_t);
	if (r->out.out_len == NULL) {
		hres = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}

	/*
	 * Validate that the target security descriptor is a valid
	 * security descriptor in self‐relative format.
	 */

	target_sd = data_blob_const(r->in.target_sd, r->in.target_sd_len);

	ndr_err = ndr_pull_struct_blob_all(
		&target_sd,
		tmp_ctx,
		&security_descriptor,
		(ndr_pull_flags_fn_t)ndr_pull_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = ndr_map_error2ntstatus(ndr_err);
		hres = HRESULT_FROM_NT(status);
		goto out;
	}

	if (!(security_descriptor.type & SEC_DESC_SELF_RELATIVE)) {
		hres = HRES_E_INVALIDARG;
		goto out;
	}

	/* Verify the given GKID. */
	requested_gkid = Gkid(r->in.l0_key_id,
			      r->in.l1_key_id,
			      r->in.l2_key_id);
	if (!gkid_is_valid(requested_gkid)) {
		hres = HRES_E_INVALIDARG;
		goto out;
	}

	gkid_type = gkid_key_type(requested_gkid);
	if (gkid_type != GKID_L2_SEED_KEY) {
		hres = HRES_E_INVALIDARG;
		goto out;
	}

	ok = gkdi_current_time(&current_time);
	if (!ok) {
		hres = HRES_RPC_E_UNEXPECTED;
		goto out;
	}

	current_gkid = gkdi_get_interval_id(current_time);

	if (gkid_type != GKID_DEFAULT) {
		/* Ensure the key being requested is not from the future. */
		ok = gkid_start_time_valid(requested_gkid, current_time);
		if (!ok) {
			hres = HRES_E_INVALIDARG;
			goto out;
		}
	}

	root_key_specified = r->in.root_key_id != NULL;
	if (gkid_type == GKID_DEFAULT) {
		gkid = current_gkid;
	} else if (!root_key_specified) {
		gkid = requested_gkid;
	} else if (requested_gkid.l0_idx < current_gkid.l0_idx) {
		gkid = Gkid(requested_gkid.l0_idx, 31, 31);
	} else {
		gkid = current_gkid;
	}

	status = sec_access_check_ds(&security_descriptor,
				     session_info->security_token,
				     SEC_FILE_READ_DATA | SEC_FILE_WRITE_DATA,
				     &access_granted,
				     NULL,
				     NULL);
	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		/* The client is not authorized to access seed keys. */

		if (gkid_type != GKID_DEFAULT) {
			hres = HRESULT_FROM_NT(status);
			goto out;
		}

		status = sec_access_check_ds(&security_descriptor,
					     session_info->security_token,
					     SEC_FILE_WRITE_DATA,
					     &access_granted,
					     NULL,
					     NULL);
		if (!NT_STATUS_IS_OK(status)) {
			hres = HRESULT_FROM_NT(status);
			goto out;
		}

		/*
		 * The client is authorized only to access public keys.
		 */
	} else if (!NT_STATUS_IS_OK(status)) {
		hres = HRESULT_FROM_NT(status);
		goto out;
	} else {
		/* The client is authorized to access seed keys. */
	}

	/* Connect as system so that we can access root key material. */
	sam_ctx = dcesrv_samdb_connect_as_system(tmp_ctx, dce_call);
	if (sam_ctx == NULL) {
		hres = HRES_RPC_E_UNEXPECTED;
		goto out;
	}

	if (root_key_specified) {
		root_key_id = *r->in.root_key_id;

		ret = gkdi_root_key_from_id(tmp_ctx,
					    sam_ctx,
					    &root_key_id,
					    &root_key_msg);
		if (ret) {
			/* No such root key exists. */
			hres = HRES_NTE_NO_KEY;
			goto out;
		}
	} else if (gkid_type == GKID_DEFAULT) {
		hres = HRES_RPC_E_UNEXPECTED;
		goto out;
	} else {
		NTTIME key_start_time;

		ok = gkdi_get_key_start_time(gkid, &key_start_time);
		if (!ok) {
			hres = HRES_RPC_E_UNEXPECTED;
			goto out;
		}

		ret = gkdi_most_recently_created_root_key(tmp_ctx,
							  sam_ctx,
							  current_time,
							  key_start_time,
							  &root_key_id,
							  &root_key_msg);
		if (ret) {
			/* No root keys exist at the specified time. */
			hres = HRES_NTE_NO_KEY;
			goto out;
		}
	}

	status = gkdi_root_key_from_msg(mem_ctx,
					root_key_id,
					root_key_msg,
					&root_key);
	if (!NT_STATUS_IS_OK(status)) {
		hres = HRESULT_FROM_NT(status);
		goto out;
	}

	/* Verify root key data is the correct length. */
	if (root_key->data.length != GKDI_KEY_LEN) {
		hres = HRES_NTE_BAD_KEY;
		goto out;
	}

	if (root_key->use_start_time == 0) {
		/* Root key effective time is zero. */
		hres = HRES_NTE_BAD_KEY;
		goto out;
	}

	if (root_key_specified) {
		const NTTIME one_interval = gkdi_key_cycle_duration +
					    gkdi_max_clock_skew;
		NTTIME gkid_start_nt_time;

		ok = gkdi_get_key_start_time(gkid, &gkid_start_nt_time);
		if (!ok) {
			hres = HRES_E_INVALIDARG;
			goto out;
		}

		if (root_key->use_start_time < one_interval ||
		    gkid_start_nt_time <
			    root_key->use_start_time - one_interval)
		{
			/* Root key is not yet valid. */
			hres = HRES_E_INVALIDARG;
			goto out;
		}
	}

	if (gkid.l2_idx == 31) {
		l1_key = talloc_array(tmp_ctx, uint8_t, GKDI_KEY_LEN);
		if (l1_key == NULL) {
			hres = HRES_RPC_E_OUT_OF_RESOURCES;
			goto out;
		}

		status = compute_seed_key(tmp_ctx,
					  target_sd,
					  root_key,
					  Gkid(gkid.l0_idx, gkid.l1_idx, -1),
					  l1_key);
		if (!NT_STATUS_IS_OK(status)) {
			hres = HRESULT_FROM_NT(status);
			goto out;
		}
	} else {
		if (gkid.l1_idx != 0) {
			l1_key = talloc_array(tmp_ctx, uint8_t, GKDI_KEY_LEN);
			if (l1_key == NULL) {
				hres = HRES_RPC_E_OUT_OF_RESOURCES;
				goto out;
			}

			status = compute_seed_key(tmp_ctx,
						  target_sd,
						  root_key,
						  Gkid(gkid.l0_idx,
						       gkid.l1_idx - 1,
						       -1),
						  l1_key);
			if (!NT_STATUS_IS_OK(status)) {
				hres = HRESULT_FROM_NT(status);
				goto out;
			}
		}

		l2_key = talloc_array(tmp_ctx, uint8_t, GKDI_KEY_LEN);
		if (l2_key == NULL) {
			hres = HRES_RPC_E_OUT_OF_RESOURCES;
			goto out;
		}

		status = compute_seed_key(
			tmp_ctx, target_sd, root_key, gkid, l2_key);
		if (!NT_STATUS_IS_OK(status)) {
			hres = HRESULT_FROM_NT(status);
			goto out;
		}
	}

	domain_name = samdb_default_domain_name(sam_ctx, tmp_ctx);
	if (domain_name == NULL) {
		hres = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}

	forest_name = samdb_forest_name(sam_ctx, tmp_ctx);
	if (forest_name == NULL) {
		hres = HRES_RPC_E_OUT_OF_RESOURCES;
		goto out;
	}

	status = GroupKeyEnvelope(tmp_ctx,
				  gkid,
				  root_key,
				  l1_key,
				  talloc_array_length(l1_key),
				  l2_key,
				  talloc_array_length(l2_key),
				  domain_name,
				  forest_name,
				  &gke);
	if (!NT_STATUS_IS_OK(status)) {
		hres = HRESULT_FROM_NT(status);
		goto out;
	}

	ndr_err = ndr_push_struct_blob(&gke_blob,
				       mem_ctx,
				       gke,
				       (ndr_push_flags_fn_t)
					       ndr_push_GroupKeyEnvelope);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		hres = HRES_RPC_E_SERVER_CANTMARSHAL_DATA;
		goto out;
	}

	*r->out.out = gke_blob.data;
	*r->out.out_len = gke_blob.length;

out:
	talloc_free(tmp_ctx);
	return hres;
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_gkdi_s.c"
