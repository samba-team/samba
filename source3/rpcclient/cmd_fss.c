/*
 * Unix SMB/CIFS implementation.
 *
 * File Server Remote VSS Protocol (FSRVP) client
 *
 * Copyright (C) David Disseldorp 2012
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "rpcclient.h"
#include "../librpc/gen_ndr/ndr_fsrvp.h"
#include "../librpc/gen_ndr/ndr_fsrvp_c.h"
#include "../libcli/util/hresult.h"

static const struct {
	uint32_t error_code;
	const char *error_str;
} fss_errors[] = {
	{
		FSRVP_E_BAD_STATE,
		"A method call was invalid because of the state of the server."
	},
	{
		FSRVP_E_SHADOW_COPY_SET_IN_PROGRESS,
		"A call was made to either \'SetContext\' or \'StartShadowCopySet\' while the creation of another shadow copy set is in progress."
	},
	{
		FSRVP_E_NOT_SUPPORTED,
		"The file store which contains the share to be shadow copied is not supported by the server."
	},
	{
		FSRVP_E_WAIT_TIMEOUT,
		"The wait for a shadow copy commit or expose operation has timed out."
	},
	{
		FSRVP_E_WAIT_FAILED,
		"The wait for a shadow copy commit expose operation has failed."
	},
	{
		FSRVP_E_OBJECT_NOT_FOUND,
		"The specified object does not exist."
	},
	{
		FSRVP_E_UNSUPPORTED_CONTEXT,
		"The specified context value is invalid."
	}
};

struct fss_context_map {
	uint32_t ctx_val;
	const char *ctx_str;
	const char *ctx_desc;
};
struct fss_context_map ctx_map[] = {
	{
		.ctx_val = FSRVP_CTX_BACKUP,
		.ctx_str = "backup",
		.ctx_desc = "auto-release, non-persistent shadow-copy.",
	},
	{
		.ctx_val = FSRVP_CTX_FILE_SHARE_BACKUP,
		.ctx_str = "file_share_backup",
		.ctx_desc = "auto-release, non-persistent shadow-copy created "
			    "without writer involvement.",
	},
	{
		.ctx_val = FSRVP_CTX_NAS_ROLLBACK,
		.ctx_str = "nas_rollback",
		.ctx_desc = "non-auto-release, persistent shadow-copy created "
			    "without writer involvement.",
	},
	{
		.ctx_val = FSRVP_CTX_APP_ROLLBACK,
		.ctx_str = "app_rollback",
		.ctx_desc = "non-auto-release, persistent shadow-copy.",
	},
	{ 0, NULL, NULL },
};

static const char *get_error_str(uint32_t code)
{
	static const char *default_err = "Unknown Error";
	const char *result = default_err;
	int i;
	for (i = 0; i < ARRAY_SIZE(fss_errors); ++i) {
		if (code == fss_errors[i].error_code) {
			result = fss_errors[i].error_str;
			break;
		}
	}
	/* error isn't specific fsrvp one, check hresult errors */
	if (result == default_err) {
		const char *hres_err = hresult_errstr_const(HRES_ERROR(code));
		if (hres_err) {
			result = hres_err;
		}
	}
	return result;
};

static bool map_fss_ctx_str(const char *ctx_str,
			    uint32_t *ctx_val)
{
	int i;

	for (i = 0; ctx_map[i].ctx_str != NULL; i++) {
		if (!strcmp(ctx_map[i].ctx_str, ctx_str)) {
			*ctx_val = ctx_map[i].ctx_val;
			return true;
		}
	}
	return false;
}

static void cmd_fss_is_path_sup_usage(const char *script_name)
{
	printf("usage: %s [share_name]\n", script_name);
}

static NTSTATUS cmd_fss_is_path_sup(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx, int argc,
				    const char **argv)
{
	NTSTATUS status;
	struct fss_IsPathSupported r;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc != 2) {
		cmd_fss_is_path_sup_usage(argv[0]);
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCT(r);
	r.in.ShareName = talloc_asprintf(mem_ctx, "%s\\%s\\",
					 cli->srv_name_slash, argv[1]);
	if (r.in.ShareName == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_fss_IsPathSupported_r(b, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("IsPathSupported failed with UNC %s\n",
			  r.in.ShareName));
		return NT_STATUS_UNSUCCESSFUL;
	} else if (r.out.result) {
		DEBUG(0, ("failed IsPathSupported response: 0x%x - \"%s\"\n",
			  r.out.result, get_error_str(r.out.result)));
		return NT_STATUS_UNSUCCESSFUL;
	}
	printf("UNC %s %s shadow copy requests\n", r.in.ShareName,
	       *r.out.SupportedByThisProvider ? "supports" : "does not support");

	return NT_STATUS_OK;
}

static void cmd_fss_get_sup_version_usage(const char *script_name)
{
	printf("usage: %s\n", script_name);
}

static NTSTATUS cmd_fss_get_sup_version(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx, int argc,
				    const char **argv)
{
	NTSTATUS status;
	struct fss_GetSupportedVersion r;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc != 1) {
		cmd_fss_get_sup_version_usage(argv[0]);
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCT(r);
	status = dcerpc_fss_GetSupportedVersion_r(b, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) || (r.out.result != 0)) {
		DEBUG(0, ("GetSupportedVersion failed: %s result: 0x%x\n",
			  nt_errstr(status), r.out.result));
		return NT_STATUS_UNSUCCESSFUL;
	}
	printf("server %s supports FSRVP versions from %u to %u\n",
	       cli->desthost, *r.out.MinVersion, *r.out.MaxVersion);

	return NT_STATUS_OK;
}

static void cmd_fss_create_expose_usage(const char *script_name)
{
	int i;

	printf("usage: %s [fss_context] [ro|rw] [share1] <share2> ...\n"
	       "[fss_context] values:\n", script_name);
	for (i = 0; ctx_map[i].ctx_str != NULL; i++) {
		printf("\t%s: %s\n", ctx_map[i].ctx_str, ctx_map[i].ctx_desc);
	}
}

static NTSTATUS cmd_fss_create_expose_parse(TALLOC_CTX *mem_ctx, int argc,
					    const char **argv,
					    const char *desthost,
					    uint32_t *fss_ctx_val,
					    int *num_maps,
					 struct fssagent_share_mapping_1 **maps)
{
	int num_non_share_args = 3;
	int num_share_args;
	int i;
	struct fssagent_share_mapping_1 *map_array;

	if (argc < 4) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!map_fss_ctx_str(argv[1], fss_ctx_val)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!strcmp(argv[2], "rw")) {
		/* shadow-copy is created as read-write */
		*fss_ctx_val |= ATTR_AUTO_RECOVERY;
	} else if (strcmp(argv[2], "ro")) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	num_share_args = argc - num_non_share_args;
	map_array = talloc_array(mem_ctx, struct fssagent_share_mapping_1,
				 num_share_args);
	if (map_array == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i = 0; i < num_share_args; i++) {
		/*
		 * A trailing slash should to be present in the request UNC,
		 * otherwise Windows Server 2012 FSRVP servers don't append
		 * a '$' to exposed hidden share shadow-copies. E.g.
		 *   AddToShadowCopySet(UNC=\\server\hidden$)
		 *   CommitShadowCopySet()
		 *   ExposeShadowCopySet()
		 *   -> new share = \\server\hidden$@{ShadowCopy.ShadowCopyId}
		 * But...
		 *   AddToShadowCopySet(UNC=\\server\hidden$\)
		 *   CommitShadowCopySet()
		 *   ExposeShadowCopySet()
		 *   -> new share = \\server\hidden$@{ShadowCopy.ShadowCopyId}$
		 */
		map_array[i].ShareNameUNC = talloc_asprintf(mem_ctx,
							    "\\\\%s\\%s\\",
							    desthost,
						argv[i + num_non_share_args]);
		if (map_array[i].ShareNameUNC == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	*num_maps = num_share_args;
	*maps = map_array;

	return NT_STATUS_OK;
}

static NTSTATUS cmd_fss_abort(TALLOC_CTX *mem_ctx,
			      struct dcerpc_binding_handle *b,
			      struct GUID *sc_set_id)
{
	NTSTATUS status;
	struct fss_AbortShadowCopySet r_scset_abort;

	ZERO_STRUCT(r_scset_abort);
	r_scset_abort.in.ShadowCopySetId = *sc_set_id;
	status = dcerpc_fss_AbortShadowCopySet_r(b, mem_ctx, &r_scset_abort);
	if (!NT_STATUS_IS_OK(status) || (r_scset_abort.out.result != 0)) {
		DEBUG(0, ("AbortShadowCopySet failed: %s result: 0x%x\n",
			  nt_errstr(status), r_scset_abort.out.result));
		return NT_STATUS_UNSUCCESSFUL;
	}
	return NT_STATUS_OK;
}

static NTSTATUS cmd_fss_create_expose(struct rpc_pipe_client *cli,
				     TALLOC_CTX *mem_ctx, int argc,
				     const char **argv)
{
	NTSTATUS status;
	struct fss_GetSupportedVersion r_version_get;
	struct fss_SetContext r_context_set;
	struct fss_StartShadowCopySet r_scset_start;
	struct fss_PrepareShadowCopySet r_scset_prep;
	struct fss_CommitShadowCopySet r_scset_commit;
	struct fss_ExposeShadowCopySet r_scset_expose;
	struct dcerpc_binding_handle *b = cli->binding_handle;
	time_t start_time;
	TALLOC_CTX *tmp_ctx;
	uint32_t fss_ctx_val;
	int num_maps;
	struct fssagent_share_mapping_1 *req_maps;
	int i;

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = cmd_fss_create_expose_parse(tmp_ctx, argc, argv, cli->desthost,
					    &fss_ctx_val, &num_maps, &req_maps);
	if (!NT_STATUS_IS_OK(status)) {
		cmd_fss_create_expose_usage(argv[0]);
		goto err_out;
	}

	/*
	 * PrepareShadowCopySet & CommitShadowCopySet often exceed the default
	 * 60 second dcerpc request timeout against Windows Server "8" Beta.
	 * ACHTUNG! dcerpc_binding_handle_set_timeout() value is interpreted as
	 * seconds on a source4 transport and as msecs here.
	 */
	dcerpc_binding_handle_set_timeout(b, 240 * 1000);

	for (i = 0; i < num_maps; i++) {
		struct fss_IsPathSupported r_pathsupport_get;
		r_pathsupport_get.in.ShareName = req_maps[i].ShareNameUNC;
		status = dcerpc_fss_IsPathSupported_r(b, tmp_ctx, &r_pathsupport_get);
		if (!NT_STATUS_IS_OK(status) || (r_pathsupport_get.out.result != 0)) {
			DEBUG(0, ("IsPathSupported failed: %s result: 0x%x\n",
				  nt_errstr(status), r_pathsupport_get.out.result));
			goto err_out;
		}
		if (!r_pathsupport_get.out.SupportedByThisProvider) {
			printf("path %s does not supported shadow-copies\n",
			       req_maps[i].ShareNameUNC);
			status = NT_STATUS_NOT_SUPPORTED;
			goto err_out;
		}
	}

	ZERO_STRUCT(r_version_get);
	status = dcerpc_fss_GetSupportedVersion_r(b, tmp_ctx, &r_version_get);
	if (!NT_STATUS_IS_OK(status) || (r_version_get.out.result != 0)) {
		DEBUG(0, ("GetSupportedVersion failed: %s result: 0x%x\n",
			  nt_errstr(status), r_version_get.out.result));
		goto err_out;
	}

	ZERO_STRUCT(r_context_set);
	r_context_set.in.Context = fss_ctx_val;
	status = dcerpc_fss_SetContext_r(b, tmp_ctx, &r_context_set);
	if (!NT_STATUS_IS_OK(status) || (r_context_set.out.result != 0)) {
		DEBUG(0, ("SetContext failed: %s result: 0x%x\n",
			  nt_errstr(status), r_context_set.out.result));
		goto err_out;
	}

	ZERO_STRUCT(r_scset_start);
	r_scset_start.in.ClientShadowCopySetId = GUID_random();
	status = dcerpc_fss_StartShadowCopySet_r(b, tmp_ctx, &r_scset_start);
	if (!NT_STATUS_IS_OK(status) || (r_scset_start.out.result != 0)) {
		DEBUG(0, ("StartShadowCopySet failed: %s result: 0x%x\n",
			  nt_errstr(status), r_scset_start.out.result));
		goto err_out;
	}
	printf("%s: shadow-copy set created\n",
	       GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId));

	for (i = 0; i < num_maps; i++) {
		struct fss_AddToShadowCopySet r_scset_add;
		r_scset_add.in.ClientShadowCopyId = GUID_random();
		r_scset_add.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
		r_scset_add.in.ShareName = req_maps[i].ShareNameUNC;
		status = dcerpc_fss_AddToShadowCopySet_r(b, tmp_ctx, &r_scset_add);
		if (!NT_STATUS_IS_OK(status) || (r_scset_add.out.result != 0)) {
			DEBUG(0, ("AddToShadowCopySet failed: %s result: 0x%x\n",
				  nt_errstr(status), r_scset_add.out.result));
			goto err_sc_set_abort;
		}
		printf("%s(%s): %s shadow-copy added to set\n",
		       GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId),
		       GUID_string(tmp_ctx, r_scset_add.out.pShadowCopyId),
		       r_scset_add.in.ShareName);
		req_maps[i].ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
		req_maps[i].ShadowCopyId = *r_scset_add.out.pShadowCopyId;
	}

	start_time = time_mono(NULL);
	ZERO_STRUCT(r_scset_prep);
	r_scset_prep.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_scset_prep.in.TimeOutInMilliseconds = (240 * 1000);
	status = dcerpc_fss_PrepareShadowCopySet_r(b, tmp_ctx, &r_scset_prep);
	if (!NT_STATUS_IS_OK(status) || (r_scset_prep.out.result != 0)) {
		DEBUG(0, ("PrepareShadowCopySet failed: %s result: 0x%x\n",
			  nt_errstr(status), r_scset_prep.out.result));
		goto err_sc_set_abort;
	}
	printf("%s: prepare completed in %llu secs\n",
	       GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId),
	       (long long unsigned int)(time_mono(NULL) - start_time));

	start_time = time_mono(NULL);
	ZERO_STRUCT(r_scset_commit);
	r_scset_commit.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_scset_commit.in.TimeOutInMilliseconds = (180 * 1000);	/* win8 */
	status = dcerpc_fss_CommitShadowCopySet_r(b, tmp_ctx, &r_scset_commit);
	if (!NT_STATUS_IS_OK(status) || (r_scset_commit.out.result != 0)) {
		DEBUG(0, ("CommitShadowCopySet failed: %s result: 0x%x\n",
			  nt_errstr(status), r_scset_commit.out.result));
		goto err_sc_set_abort;
	}
	printf("%s: commit completed in %llu secs\n",
	       GUID_string(tmp_ctx, r_scset_start.out.pShadowCopySetId),
	       (long long unsigned int)(time_mono(NULL) - start_time));

	ZERO_STRUCT(r_scset_expose);
	r_scset_expose.in.ShadowCopySetId = *r_scset_start.out.pShadowCopySetId;
	r_scset_expose.in.TimeOutInMilliseconds = (120 * 1000);	/* win8 */
	status = dcerpc_fss_ExposeShadowCopySet_r(b, tmp_ctx, &r_scset_expose);
	if (!NT_STATUS_IS_OK(status) || (r_scset_expose.out.result != 0)) {
		DEBUG(0, ("ExposeShadowCopySet failed: %s result: 0x%x\n",
			  nt_errstr(status), r_scset_expose.out.result));
		goto err_out;
	}

	for (i = 0; i < num_maps; i++) {
		struct fss_GetShareMapping r_sharemap_get;
		struct fssagent_share_mapping_1 *map;
		r_sharemap_get.in.ShadowCopyId = req_maps[i].ShadowCopyId;
		r_sharemap_get.in.ShadowCopySetId = req_maps[i].ShadowCopySetId;
		r_sharemap_get.in.ShareName = req_maps[i].ShareNameUNC;
		r_sharemap_get.in.Level = 1;
		status = dcerpc_fss_GetShareMapping_r(b, tmp_ctx, &r_sharemap_get);
		if (!NT_STATUS_IS_OK(status) || (r_sharemap_get.out.result != 0)) {
			DEBUG(0, ("GetShareMapping failed: %s result: 0x%x\n",
				  nt_errstr(status), r_sharemap_get.out.result));
			goto err_out;
		}
		map = r_sharemap_get.out.ShareMapping->ShareMapping1;
		printf("%s(%s): share %s exposed as a snapshot of %s\n",
		       GUID_string(tmp_ctx, &map->ShadowCopySetId),
		       GUID_string(tmp_ctx, &map->ShadowCopyId),
		       map->ShadowCopyShareName, map->ShareNameUNC);
	}

	talloc_free(tmp_ctx);
	return NT_STATUS_OK;

err_sc_set_abort:
	cmd_fss_abort(tmp_ctx, b, r_scset_start.out.pShadowCopySetId);
err_out:
	talloc_free(tmp_ctx);
	return status;
}

static void cmd_fss_delete_usage(const char *script_name)
{
	printf("usage: %s [base_share] [shadow_copy_set_id] [shadow_copy_id]\n",
	       script_name);
}

static NTSTATUS cmd_fss_delete(struct rpc_pipe_client *cli,
			       TALLOC_CTX *mem_ctx, int argc,
			       const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	struct fss_DeleteShareMapping r_sharemap_del;
	const char *sc_set_id;
	const char *sc_id;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	if (argc < 4) {
		cmd_fss_delete_usage(argv[0]);
		return NT_STATUS_UNSUCCESSFUL;
	}
	sc_set_id = argv[2];
	sc_id = argv[3];

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(r_sharemap_del);
	r_sharemap_del.in.ShareName = talloc_asprintf(tmp_ctx, "\\\\%s\\%s\\",
						      cli->desthost, argv[1]);
	if (r_sharemap_del.in.ShareName == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_out;
	}
	status = GUID_from_string(sc_set_id, &r_sharemap_del.in.ShadowCopySetId);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Invalid shadow_copy_set_id parameter\n"));
		goto err_out;
	}
	status = GUID_from_string(sc_id, &r_sharemap_del.in.ShadowCopyId);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Invalid shadow_copy_id parameter\n"));
		goto err_out;
	}
	status = dcerpc_fss_DeleteShareMapping_r(b, tmp_ctx, &r_sharemap_del);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("DeleteShareMapping failed\n"));
		goto err_out;
	} else if (r_sharemap_del.out.result != 0) {
		DEBUG(0, ("failed DeleteShareMapping response: 0x%x\n",
			  r_sharemap_del.out.result));
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_out;
	}

	printf("%s(%s): %s shadow-copy deleted\n",
	       sc_set_id, sc_id, r_sharemap_del.in.ShareName);

err_out:
	talloc_free(tmp_ctx);
	return status;
}

static void cmd_fss_is_shadow_copied_usage(const char *script_name)
{
	printf("usage: %s [share_name]\n", script_name);
}

static NTSTATUS cmd_fss_is_shadow_copied(struct rpc_pipe_client *cli,
					 TALLOC_CTX *mem_ctx, int argc,
					 const char **argv)
{
	NTSTATUS status;
	struct fss_IsPathShadowCopied r;
	struct dcerpc_binding_handle *b = cli->binding_handle;

	if (argc != 2) {
		cmd_fss_is_shadow_copied_usage(argv[0]);
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCT(r);
	r.in.ShareName = talloc_asprintf(mem_ctx, "%s\\%s\\",
					 cli->srv_name_slash, argv[1]);
	if (r.in.ShareName == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_fss_IsPathShadowCopied_r(b, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("IsPathShadowCopied failed with UNC %s\n",
			  r.in.ShareName));
		return NT_STATUS_UNSUCCESSFUL;
	} else if (r.out.result) {
		DEBUG(0, ("failed IsPathShadowCopied response: 0x%x\n",
			  r.out.result));
		return NT_STATUS_UNSUCCESSFUL;
	}
	printf("UNC %s %s an associated shadow-copy with compatibility 0x%x\n",
	       r.in.ShareName,
	       *r.out.ShadowCopyPresent ? "has" : "does not have",
	       *r.out.ShadowCopyCompatibility);

	return NT_STATUS_OK;
}

static void cmd_fss_get_mapping_usage(const char *script_name)
{
	printf("usage: %s [base_share] [shadow_copy_set_id] [shadow_copy_id]\n",
	       script_name);
}

static NTSTATUS cmd_fss_get_mapping(struct rpc_pipe_client *cli,
				    TALLOC_CTX *mem_ctx, int argc,
				    const char **argv)
{
	struct dcerpc_binding_handle *b = cli->binding_handle;
	struct fss_GetShareMapping r_sharemap_get;
	const char *sc_set_id;
	const char *sc_id;
	struct fssagent_share_mapping_1 *map;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	if (argc < 4) {
		cmd_fss_get_mapping_usage(argv[0]);
		return NT_STATUS_UNSUCCESSFUL;
	}
	sc_set_id = argv[2];
	sc_id = argv[3];

	tmp_ctx = talloc_new(mem_ctx);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(r_sharemap_get);
	r_sharemap_get.in.ShareName = talloc_asprintf(tmp_ctx, "\\\\%s\\%s\\",
						      cli->desthost, argv[1]);
	if (r_sharemap_get.in.ShareName == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto err_out;
	}
	status = GUID_from_string(sc_set_id, &r_sharemap_get.in.ShadowCopySetId);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Invalid shadow_copy_set_id parameter\n"));
		goto err_out;
	}
	status = GUID_from_string(sc_id, &r_sharemap_get.in.ShadowCopyId);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Invalid shadow_copy_id parameter\n"));
		goto err_out;
	}
	r_sharemap_get.in.Level = 1;
	status = dcerpc_fss_GetShareMapping_r(b, tmp_ctx, &r_sharemap_get);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("GetShareMapping failed\n"));
		goto err_out;
	} else if (r_sharemap_get.out.result != 0) {
		DEBUG(0, ("failed GetShareMapping response: 0x%x\n",
			  r_sharemap_get.out.result));
		status = NT_STATUS_UNSUCCESSFUL;
		goto err_out;
	}

	map = r_sharemap_get.out.ShareMapping->ShareMapping1;
	printf("%s(%s): share %s is a shadow-copy of %s at %s\n",
	       GUID_string(tmp_ctx, &map->ShadowCopySetId),
	       GUID_string(tmp_ctx, &map->ShadowCopyId),
	       map->ShadowCopyShareName, map->ShareNameUNC,
	       nt_time_string(tmp_ctx, map->tstamp));

err_out:
	talloc_free(tmp_ctx);
	return status;
}

static void cmd_fss_recov_complete_usage(const char *script_name)
{
	printf("usage: %s [shadow_copy_set_id]\n", script_name);
}

static NTSTATUS cmd_fss_recov_complete(struct rpc_pipe_client *cli,
				       TALLOC_CTX *mem_ctx, int argc,
				       const char **argv)
{
	NTSTATUS status;
	struct fss_RecoveryCompleteShadowCopySet r;
	struct dcerpc_binding_handle *b = cli->binding_handle;
	const char *sc_set_id;

	if (argc != 2) {
		cmd_fss_recov_complete_usage(argv[0]);
		return NT_STATUS_UNSUCCESSFUL;
	}
	sc_set_id = argv[1];

	ZERO_STRUCT(r);
	status = GUID_from_string(sc_set_id, &r.in.ShadowCopySetId);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Invalid shadow_copy_set_id\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dcerpc_fss_RecoveryCompleteShadowCopySet_r(b, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status) || (r.out.result != 0)) {
		DEBUG(0, ("RecoveryCompleteShadowCopySet failed: %s "
			  "result: 0x%x\n", nt_errstr(status), r.out.result));
		return status;
	}
	printf("%s: shadow-copy set marked recovery complete\n", sc_set_id);

	return NT_STATUS_OK;
}

/* List of commands exported by this module */
struct cmd_set fss_commands[] = {

	{ "FSRVP" },

	{
		.name = "fss_is_path_sup",
		.returntype = RPC_RTYPE_NTSTATUS,
		.ntfn = cmd_fss_is_path_sup,
		.table = &ndr_table_FileServerVssAgent,
		.rpc_pipe = NULL,
		.description = "Check whether a share supports shadow-copy "
			       "requests",
		.usage = "",
	},
	{
		.name = "fss_get_sup_version",
		.returntype = RPC_RTYPE_NTSTATUS,
		.ntfn = cmd_fss_get_sup_version,
		.table = &ndr_table_FileServerVssAgent,
		.rpc_pipe = NULL,
		.description = "Get supported FSRVP version from server",
		.usage = "",
	},
	{
		.name = "fss_create_expose",
		.returntype = RPC_RTYPE_NTSTATUS,
		.ntfn = cmd_fss_create_expose,
		.table = &ndr_table_FileServerVssAgent,
		.rpc_pipe = NULL,
		.description = "Request shadow-copy creation and exposure",
		.usage = "",
	},
	{
		.name = "fss_delete",
		.returntype = RPC_RTYPE_NTSTATUS,
		.ntfn = cmd_fss_delete,
		.table = &ndr_table_FileServerVssAgent,
		.rpc_pipe = NULL,
		.description = "Request shadow-copy share deletion",
		.usage = "",
	},
	{
		.name = "fss_has_shadow_copy",
		.returntype = RPC_RTYPE_NTSTATUS,
		.ntfn = cmd_fss_is_shadow_copied,
		.table = &ndr_table_FileServerVssAgent,
		.rpc_pipe = NULL,
		.description = "Check for an associated share shadow-copy",
		.usage = "",
	},
	{
		.name = "fss_get_mapping",
		.returntype = RPC_RTYPE_NTSTATUS,
		.ntfn = cmd_fss_get_mapping,
		.table = &ndr_table_FileServerVssAgent,
		.rpc_pipe = NULL,
		.description = "Get shadow-copy share mapping information",
		.usage = "",
	},
	{
		.name = "fss_recovery_complete",
		.returntype = RPC_RTYPE_NTSTATUS,
		.ntfn = cmd_fss_recov_complete,
		.table = &ndr_table_FileServerVssAgent,
		.rpc_pipe = NULL,
		.description = "Flag read-write snapshot as recovery complete, "
			       "allowing further shadow-copy requests",
		.usage = "",
	},
	{ NULL }
};
