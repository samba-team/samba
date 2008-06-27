/*
 *  Unix SMB/CIFS implementation.
 *  libnet Support
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

struct dssync_context;

typedef NTSTATUS (*dssync_processing_fn_t)(TALLOC_CTX *,
					   struct drsuapi_DsReplicaObjectListItemEx *,
					   struct drsuapi_DsReplicaOIDMapping_Ctr *,
					   bool,
					   struct dssync_context *ctx);

struct dssync_context {
	const char *domain_name;
	const char *dns_domain_name;
	struct rpc_pipe_client *cli;
	const char *nc_dn;
	struct policy_handle bind_handle;
	DATA_BLOB session_key;
	const char *output_filename;

	dssync_processing_fn_t processing_fn;

	char *result_message;
	char *error_message;
};

NTSTATUS libnet_dssync_dump_keytab(TALLOC_CTX *mem_ctx,
				   struct drsuapi_DsReplicaObjectListItemEx *cur,
				   struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr,
				   bool last_query,
				   struct dssync_context *ctx);
