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


enum net_samsync_mode {
	NET_SAMSYNC_MODE_FETCH_PASSDB = 0,
	NET_SAMSYNC_MODE_FETCH_LDIF = 1,
	NET_SAMSYNC_MODE_FETCH_KEYTAB = 2,
	NET_SAMSYNC_MODE_DUMP = 3
};

struct samsync_context;

typedef NTSTATUS (*samsync_delta_fn_t)(TALLOC_CTX *,
				       enum netr_SamDatabaseID,
				       struct netr_DELTA_ENUM_ARRAY *,
				       bool,
				       struct samsync_context *);

struct samsync_context {
	enum net_samsync_mode mode;
	const struct dom_sid *domain_sid;
	const char *domain_sid_str;
	const char *domain_name;
	const char *output_filename;

	const char *username;
	const char *password;

	char *result_message;
	char *error_message;

	struct rpc_pipe_client *cli;
	samsync_delta_fn_t delta_fn;
	void *private_data;
};

NTSTATUS fetch_sam_entries_ldif(TALLOC_CTX *mem_ctx,
				enum netr_SamDatabaseID database_id,
				struct netr_DELTA_ENUM_ARRAY *r,
				bool last_query,
				struct samsync_context *ctx);
NTSTATUS fetch_sam_entries(TALLOC_CTX *mem_ctx,
			   enum netr_SamDatabaseID database_id,
			   struct netr_DELTA_ENUM_ARRAY *r,
			   bool last_query,
			   struct samsync_context *ctx);
NTSTATUS display_sam_entries(TALLOC_CTX *mem_ctx,
			     enum netr_SamDatabaseID database_id,
			     struct netr_DELTA_ENUM_ARRAY *r,
			     bool last_query,
			     struct samsync_context *ctx);
NTSTATUS fetch_sam_entries_keytab(TALLOC_CTX *mem_ctx,
				  enum netr_SamDatabaseID database_id,
				  struct netr_DELTA_ENUM_ARRAY *r,
				  bool last_query,
				  struct samsync_context *ctx);
