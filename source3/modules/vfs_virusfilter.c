/*
 * Copyright (C) 2010-2016 SATOH Fumiyasu @ OSS Technology Corp., Japan
 * Copyright (C) 2016-2017 Trever L. Adams
 * Copyright (C) 2017 Ralph Boehme <slow@samba.org>
 * Copyright (C) 2017 Jeremy Allison <jra@samba.org>
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

#include "vfs_virusfilter_common.h"
#include "vfs_virusfilter_utils.h"

/*
 * Default configuration values
 * ======================================================================
 */

#define VIRUSFILTER_DEFAULT_QUARANTINE_PREFIX		"virusfilter."
#define VIRUSFILTER_DEFAULT_QUARANTINE_SUFFIX		".infected"
#define VIRUSFILTER_DEFAULT_RENAME_PREFIX		"virusfilter."
#define VIRUSFILTER_DEFAULT_RENAME_SUFFIX		".infected"

/* ====================================================================== */

enum virusfilter_scanner_enum {
	VIRUSFILTER_SCANNER_CLAMAV,
	VIRUSFILTER_SCANNER_FSAV,
	VIRUSFILTER_SCANNER_SOPHOS
};

static const struct enum_list scanner_list[] = {
	{ VIRUSFILTER_SCANNER_CLAMAV,	"clamav" },
	{ VIRUSFILTER_SCANNER_FSAV,	"fsav" },
	{ VIRUSFILTER_SCANNER_SOPHOS,	"sophos" },
	{ -1,				NULL }
};

static const struct enum_list virusfilter_actions[] = {
	{ VIRUSFILTER_ACTION_QUARANTINE,	"quarantine" },
	{ VIRUSFILTER_ACTION_RENAME,		"rename" },
	{ VIRUSFILTER_ACTION_DELETE,		"delete" },

	/* alias for "delete" */
	{ VIRUSFILTER_ACTION_DELETE,		"remove" },

	/* alias for "delete" */
	{ VIRUSFILTER_ACTION_DELETE,		"unlink" },
	{ VIRUSFILTER_ACTION_DO_NOTHING,	"nothing" },
	{ -1,					NULL}
};

static int virusfilter_config_destructor(struct virusfilter_config *config)
{
	TALLOC_FREE(config->backend);
	return 0;
}

/*
 * This is adapted from vfs_recycle module.
 * Caller must have become_root();
 */
static bool quarantine_directory_exist(
	struct vfs_handle_struct *handle,
	const char *dname)
{
	int ret = -1;
	struct smb_filename smb_fname = {
		.base_name = discard_const_p(char, dname)
	};

	ret = SMB_VFS_STAT(handle->conn, &smb_fname);
	if (ret == 0) {
		return S_ISDIR(smb_fname.st.st_ex_mode);
	}

	return false;
}

/**
 * Create directory tree
 * @param conn connection
 * @param dname Directory tree to be created
 * @return Returns true for success
 * This is adapted from vfs_recycle module.
 * Caller must have become_root();
 */
static bool quarantine_create_dir(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	const char *dname)
{
	size_t len = 0;
	size_t cat_len = 0;
	char *new_dir = NULL;
	char *tmp_str = NULL;
	char *token = NULL;
	char *tok_str = NULL;
	bool status = false;
	bool ok = false;
	int ret = -1;
	char *saveptr = NULL;

	tmp_str = talloc_strdup(talloc_tos(), dname);
	if (tmp_str == NULL) {
		DBG_ERR("virusfilter-vfs: out of memory!\n");
		errno = ENOMEM;
		goto done;
	}
	tok_str = tmp_str;

	len = strlen(dname)+1;
	new_dir = (char *)talloc_size(talloc_tos(), len + 1);
	if (new_dir == NULL) {
		DBG_ERR("virusfilter-vfs: out of memory!\n");
		errno = ENOMEM;
		goto done;
	}
	*new_dir = '\0';
	if (dname[0] == '/') {
		/* Absolute path. */
		cat_len = strlcat(new_dir, "/", len + 1);
		if (cat_len >= len+1) {
			goto done;
		}
	}

	/* Create directory tree if necessary */
	for (token = strtok_r(tok_str, "/", &saveptr);
	     token != NULL;
	     token = strtok_r(NULL, "/", &saveptr))
	{
		cat_len = strlcat(new_dir, token, len + 1);
		if (cat_len >= len+1) {
			goto done;
		}
		ok = quarantine_directory_exist(handle, new_dir);
		if (ok == true) {
			DBG_DEBUG("quarantine: dir %s already exists\n",
				  new_dir);
		} else {
			struct smb_filename *smb_fname = NULL;

			DBG_INFO("quarantine: creating new dir %s\n", new_dir);

			smb_fname = synthetic_smb_fname(talloc_tos(),
							new_dir,
							NULL,
							NULL,
							0,
							0);
			if (smb_fname == NULL) {
				goto done;
			}

			ret = SMB_VFS_NEXT_MKDIRAT(handle,
					handle->conn->cwd_fsp,
					smb_fname,
					config->quarantine_dir_mode);
			if (ret != 0) {
				TALLOC_FREE(smb_fname);

				DBG_WARNING("quarantine: mkdirat failed for %s "
					    "with error: %s\n", new_dir,
					    strerror(errno));
				status = false;
				goto done;
			}
			TALLOC_FREE(smb_fname);
		}
		cat_len = strlcat(new_dir, "/", len + 1);
		if (cat_len >= len + 1) {
			goto done;
		}
	}

	status = true;
done:
	TALLOC_FREE(tmp_str);
	TALLOC_FREE(new_dir);
	return status;
}

static int virusfilter_vfs_connect(
	struct vfs_handle_struct *handle,
	const char *svc,
	const char *user)
{
	int snum = SNUM(handle->conn);
	struct virusfilter_config *config = NULL;
	const char *exclude_files = NULL;
	const char *temp_quarantine_dir_mode = NULL;
	const char *infected_file_command = NULL;
	const char *scan_error_command = NULL;
	const char *quarantine_dir = NULL;
	const char *quarantine_prefix = NULL;
	const char *quarantine_suffix = NULL;
	const char *rename_prefix = NULL;
	const char *rename_suffix = NULL;
	const char *socket_path = NULL;
	char *sret = NULL;
	char *tmp = NULL;
	enum virusfilter_scanner_enum backend;
	int connect_timeout = 0;
	int io_timeout = 0;
	int ret = -1;

	config = talloc_zero(handle, struct virusfilter_config);
	if (config == NULL) {
		DBG_ERR("talloc_zero failed\n");
		return -1;
	}
	talloc_set_destructor(config, virusfilter_config_destructor);

	SMB_VFS_HANDLE_SET_DATA(handle, config, NULL,
				struct virusfilter_config, return -1);

	config->scan_request_limit = lp_parm_int(
		snum, "virusfilter", "scan request limit", 0);

	config->scan_on_open = lp_parm_bool(
		snum, "virusfilter", "scan on open", true);

	config->scan_on_close = lp_parm_bool(
		snum, "virusfilter", "scan on close", false);

	config->max_nested_scan_archive = lp_parm_int(
		snum, "virusfilter", "max nested scan archive", 1);

	config->scan_archive = lp_parm_bool(
		snum, "virusfilter", "scan archive", false);

	config->scan_mime = lp_parm_bool(
		snum, "virusfilter", "scan mime", false);

	config->max_file_size = (ssize_t)lp_parm_ulong(
		snum, "virusfilter", "max file size", 100000000L);

	config->min_file_size = (ssize_t)lp_parm_ulong(
		snum, "virusfilter", "min file size", 10);

	exclude_files = lp_parm_const_string(
		snum, "virusfilter", "exclude files", NULL);
	if (exclude_files != NULL) {
		set_namearray(&config->exclude_files, exclude_files);
	}

	config->cache_entry_limit = lp_parm_int(
		snum, "virusfilter", "cache entry limit", 100);

	config->cache_time_limit = lp_parm_int(
		snum, "virusfilter", "cache time limit", 10);

	config->infected_file_action = lp_parm_enum(
		snum, "virusfilter", "infected file action",
		virusfilter_actions, VIRUSFILTER_ACTION_DO_NOTHING);

	infected_file_command = lp_parm_const_string(
		snum, "virusfilter", "infected file command", NULL);
	if (infected_file_command != NULL) {
		config->infected_file_command = talloc_strdup(config, infected_file_command);
		if (config->infected_file_command == NULL) {
			DBG_ERR("virusfilter-vfs: out of memory!\n");
			return -1;
		}
	}
	scan_error_command = lp_parm_const_string(
		snum, "virusfilter", "scan error command", NULL);
	if (scan_error_command != NULL) {
		config->scan_error_command = talloc_strdup(config, scan_error_command);
		if (config->scan_error_command == NULL) {
			DBG_ERR("virusfilter-vfs: out of memory!\n");
			return -1;
		}
	}

	config->block_access_on_error = lp_parm_bool(
		snum, "virusfilter", "block access on error", false);

	tmp = talloc_asprintf(config, "%s/.quarantine",
		handle->conn->connectpath);

	quarantine_dir = lp_parm_const_string(
		snum, "virusfilter", "quarantine directory",
		tmp ? tmp : "/tmp/.quarantine");
	if (quarantine_dir != NULL) {
		config->quarantine_dir = talloc_strdup(config, quarantine_dir);
		if (config->quarantine_dir == NULL) {
			DBG_ERR("virusfilter-vfs: out of memory!\n");
			return -1;
		}
	}

	if (tmp != config->quarantine_dir) {
		TALLOC_FREE(tmp);
	}

	temp_quarantine_dir_mode = lp_parm_const_string(
		snum, "virusfilter", "quarantine directory mode", "0755");
	if (temp_quarantine_dir_mode != NULL) {
		unsigned int mode = 0;
		sscanf(temp_quarantine_dir_mode, "%o", &mode);
		config->quarantine_dir_mode = mode;
	}

	quarantine_prefix = lp_parm_const_string(
		snum, "virusfilter", "quarantine prefix",
		VIRUSFILTER_DEFAULT_QUARANTINE_PREFIX);
	if (quarantine_prefix != NULL) {
		config->quarantine_prefix = talloc_strdup(config, quarantine_prefix);
		if (config->quarantine_prefix == NULL) {
			DBG_ERR("virusfilter-vfs: out of memory!\n");
			return -1;
		}
	}

	quarantine_suffix = lp_parm_const_string(
		snum, "virusfilter", "quarantine suffix",
		VIRUSFILTER_DEFAULT_QUARANTINE_SUFFIX);
	if (quarantine_suffix != NULL) {
		config->quarantine_suffix = talloc_strdup(config, quarantine_suffix);
		if (config->quarantine_suffix == NULL) {
			DBG_ERR("virusfilter-vfs: out of memory!\n");
			return -1;
		}
	}

	/*
	 * Make sure prefixes and suffixes do not contain directory
	 * delimiters
	 */
	if (config->quarantine_prefix != NULL) {
		sret = strstr(config->quarantine_prefix, "/");
		if (sret != NULL) {
			DBG_ERR("quarantine prefix must not contain directory "
				"delimiter(s) such as '/' (%s replaced with %s)\n",
				config->quarantine_prefix,
				VIRUSFILTER_DEFAULT_QUARANTINE_PREFIX);
			config->quarantine_prefix =
				VIRUSFILTER_DEFAULT_QUARANTINE_PREFIX;
		}
	}
	if (config->quarantine_suffix != NULL) {
		sret = strstr(config->quarantine_suffix, "/");
		if (sret != NULL) {
			DBG_ERR("quarantine suffix must not contain directory "
				"delimiter(s) such as '/' (%s replaced with %s)\n",
				config->quarantine_suffix,
				VIRUSFILTER_DEFAULT_QUARANTINE_SUFFIX);
			config->quarantine_suffix =
				VIRUSFILTER_DEFAULT_QUARANTINE_SUFFIX;
		}
	}

	config->quarantine_keep_tree = lp_parm_bool(
		snum, "virusfilter", "quarantine keep tree", true);

	config->quarantine_keep_name = lp_parm_bool(
		snum, "virusfilter", "quarantine keep name", true);

	rename_prefix = lp_parm_const_string(
		snum, "virusfilter", "rename prefix",
		VIRUSFILTER_DEFAULT_RENAME_PREFIX);
	if (rename_prefix != NULL) {
		config->rename_prefix = talloc_strdup(config, rename_prefix);
		if (config->rename_prefix == NULL) {
			DBG_ERR("virusfilter-vfs: out of memory!\n");
			return -1;
		}
	}

	rename_suffix = lp_parm_const_string(
		snum, "virusfilter", "rename suffix",
		VIRUSFILTER_DEFAULT_RENAME_SUFFIX);
	if (rename_suffix != NULL) {
		config->rename_suffix = talloc_strdup(config, rename_suffix);
		if (config->rename_suffix == NULL) {
			DBG_ERR("virusfilter-vfs: out of memory!\n");
			return -1;
		}
	}

	/*
	 * Make sure prefixes and suffixes do not contain directory
	 * delimiters
	 */
	if (config->rename_prefix != NULL) {
		sret = strstr(config->rename_prefix, "/");
		if (sret != NULL) {
			DBG_ERR("rename prefix must not contain directory "
				"delimiter(s) such as '/' (%s replaced with %s)\n",
				config->rename_prefix,
				VIRUSFILTER_DEFAULT_RENAME_PREFIX);
			config->rename_prefix =
				VIRUSFILTER_DEFAULT_RENAME_PREFIX;
		}
	}
	if (config->rename_suffix != NULL) {
		sret = strstr(config->rename_suffix, "/");
		if (sret != NULL) {
			DBG_ERR("rename suffix must not contain directory "
				"delimiter(s) such as '/' (%s replaced with %s)\n",
				config->rename_suffix,
				VIRUSFILTER_DEFAULT_RENAME_SUFFIX);
			config->rename_suffix =
				VIRUSFILTER_DEFAULT_RENAME_SUFFIX;
		}
	}

	config->infected_open_errno = lp_parm_int(
		snum, "virusfilter", "infected file errno on open", EACCES);

	config->infected_close_errno = lp_parm_int(
		snum, "virusfilter", "infected file errno on close", 0);

	config->scan_error_open_errno = lp_parm_int(
		snum, "virusfilter", "scan error errno on open", EACCES);

	config->scan_error_close_errno = lp_parm_int(
		snum, "virusfilter", "scan error errno on close", 0);

	socket_path = lp_parm_const_string(
		snum, "virusfilter", "socket path", NULL);
	if (socket_path != NULL) {
		config->socket_path = talloc_strdup(config, socket_path);
		if (config->socket_path == NULL) {
			DBG_ERR("virusfilter-vfs: out of memory!\n");
			return -1;
		}
	}

	/* canonicalize socket_path */
	if (config->socket_path != NULL && config->socket_path[0] != '/') {
		DBG_ERR("socket path must be an absolute path. "
			"Using backend default\n");
		config->socket_path = NULL;
	}
	if (config->socket_path != NULL) {
		config->socket_path = canonicalize_absolute_path(
			handle, config->socket_path);
		if (config->socket_path == NULL) {
			errno = ENOMEM;
			return -1;
		}
	}

	connect_timeout = lp_parm_int(snum, "virusfilter",
				      "connect timeout", 30000);

	io_timeout = lp_parm_int(snum, "virusfilter", "io timeout", 60000);

	config->io_h = virusfilter_io_new(config, connect_timeout, io_timeout);
	if (config->io_h == NULL) {
		DBG_ERR("virusfilter_io_new failed");
		return -1;
	}

	if (config->cache_entry_limit > 0) {
		config->cache = virusfilter_cache_new(handle,
					config->cache_entry_limit,
					config->cache_time_limit);
		if (config->cache == NULL) {
			DBG_ERR("Initializing cache failed: Cache disabled\n");
			return -1;
		}
	}

	/*
	 * Check quarantine directory now to save processing
	 * and becoming root over and over.
	 */
	if (config->infected_file_action == VIRUSFILTER_ACTION_QUARANTINE) {
		bool ok = true;
		bool dir_exists;

		/*
		 * Do SMB_VFS_NEXT_MKDIR(config->quarantine_dir)
		 * hierarchy
		 */
		become_root();
		dir_exists = quarantine_directory_exist(handle,
						config->quarantine_dir);
		if (!dir_exists) {
			DBG_DEBUG("Creating quarantine directory: %s\n",
				  config->quarantine_dir);
			ok = quarantine_create_dir(handle, config,
					      config->quarantine_dir);
		}
		unbecome_root();
		if (!ok) {
			DBG_ERR("Creating quarantine directory %s "
				"failed with %s\n",
				config->quarantine_dir,
				strerror(errno));
			return -1;
		}
	}

	/*
	 * Now that the frontend options are initialized, load the configured
	 * backend.
	 */

	backend = (enum virusfilter_scanner_enum)lp_parm_enum(snum,
				"virusfilter",
				"scanner",
				scanner_list,
			       -1);
	if (backend == (enum virusfilter_scanner_enum)-1) {
		DBG_ERR("No AV-Scanner configured, "
			"please set \"virusfilter:scanner\"\n");
		return -1;
	}

	switch (backend) {
	case VIRUSFILTER_SCANNER_SOPHOS:
		ret = virusfilter_sophos_init(config);
		break;
	case VIRUSFILTER_SCANNER_FSAV:
		ret = virusfilter_fsav_init(config);
		break;
	case VIRUSFILTER_SCANNER_CLAMAV:
		ret = virusfilter_clamav_init(config);
		break;
	default:
		DBG_ERR("Unhandled scanner %d\n", backend);
		return -1;
	}
	if (ret != 0) {
		DBG_ERR("Scanner backend init failed\n");
		return -1;
	}

	if (config->backend->fns->connect != NULL) {
		ret = config->backend->fns->connect(handle, config, svc, user);
		if (ret == -1) {
			return -1;
		}
	}

	return SMB_VFS_NEXT_CONNECT(handle, svc, user);
}

static void virusfilter_vfs_disconnect(struct vfs_handle_struct *handle)
{
	struct virusfilter_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct virusfilter_config, return);

	if (config->backend->fns->disconnect != NULL) {
		config->backend->fns->disconnect(handle);
	}

	free_namearray(config->exclude_files);
	virusfilter_io_disconnect(config->io_h);

	SMB_VFS_NEXT_DISCONNECT(handle);
}

static int virusfilter_set_module_env(TALLOC_CTX *mem_ctx,
				      struct virusfilter_config *config,
				      char **env_list)
{
	int ret;

	ret = virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_VERSION",
				  VIRUSFILTER_VERSION);
	if (ret == -1) {
		return -1;
	}
	ret = virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_MODULE_NAME",
				  config->backend->name);
	if (ret == -1) {
		return -1;
	}

	if (config->backend->version != 0) {
		char *version = NULL;

		version = talloc_asprintf(talloc_tos(), "%u",
					  config->backend->version);
		if (version == NULL) {
			return -1;
		}
		ret = virusfilter_env_set(mem_ctx, env_list,
					  "VIRUSFILTER_MODULE_VERSION",
					  version);
		TALLOC_FREE(version);
		if (ret == -1) {
			return -1;
		}
	}

	return 0;
}

static char *quarantine_check_tree(TALLOC_CTX *mem_ctx,
				   struct vfs_handle_struct *handle,
				   struct virusfilter_config *config,
				   const struct smb_filename *smb_fname,
				   char *q_dir_in,
				   char *cwd_fname)
{
	char *temp_path = NULL;
	char *q_dir_out = NULL;
	bool ok;

	temp_path = talloc_asprintf(talloc_tos(), "%s/%s", q_dir_in, cwd_fname);
	if (temp_path == NULL) {
		DBG_ERR("talloc_asprintf failed\n");
		goto out;
	}

	become_root();
	ok = quarantine_directory_exist(handle,	temp_path);
	unbecome_root();
	if (ok) {
		DBG_DEBUG("quarantine: directory [%s] exists\n", temp_path);
		q_dir_out = talloc_move(mem_ctx, &temp_path);
		goto out;
	}

	DBG_DEBUG("quarantine: Creating directory %s\n", temp_path);

	become_root();
	ok = quarantine_create_dir(handle, config, temp_path);
	unbecome_root();
	if (!ok) {
		DBG_NOTICE("Could not create quarantine directory [%s], "
			   "ignoring for [%s]\n",
			   temp_path, smb_fname_str_dbg(smb_fname));
		goto out;
	}

	q_dir_out = talloc_move(mem_ctx, &temp_path);

out:
	TALLOC_FREE(temp_path);
	return q_dir_out;
}

static virusfilter_action infected_file_action_quarantine(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	TALLOC_CTX *mem_ctx,
	const struct files_struct *fsp,
	const char **filepath_newp)
{
	TALLOC_CTX *frame = talloc_stackframe();
	connection_struct *conn = handle->conn;
	char *cwd_fname = fsp->conn->cwd_fsp->fsp_name->base_name;
	char *fname = fsp->fsp_name->base_name;
	const struct smb_filename *smb_fname = fsp->fsp_name;
	struct smb_filename *q_smb_fname = NULL;
	char *q_dir = NULL;
	char *q_prefix = NULL;
	char *q_suffix = NULL;
	char *q_filepath = NULL;
	char *dir_name = NULL;
	const char *base_name = NULL;
	char *rand_filename_component = NULL;
	virusfilter_action action = VIRUSFILTER_ACTION_QUARANTINE;
	bool ok = false;
	int ret = -1;
	int saved_errno = 0;

	q_dir = virusfilter_string_sub(frame, conn,
				       config->quarantine_dir);
	q_prefix = virusfilter_string_sub(frame, conn,
					  config->quarantine_prefix);
	q_suffix = virusfilter_string_sub(frame, conn,
					  config->quarantine_suffix);
	if (q_dir == NULL || q_prefix == NULL || q_suffix == NULL) {
		DBG_ERR("Quarantine failed: %s/%s: Cannot allocate "
			"memory\n", cwd_fname, fname);
		action = VIRUSFILTER_ACTION_DO_NOTHING;
		goto out;
	}

	if (config->quarantine_keep_name || config->quarantine_keep_tree) {
		ok = parent_dirname(frame, smb_fname->base_name,
				    &dir_name, &base_name);
		if (!ok) {
			DBG_ERR("parent_dirname failed\n");
			action = VIRUSFILTER_ACTION_DO_NOTHING;
			goto out;
		}

		if (config->quarantine_keep_tree) {
			char *tree = NULL;

			tree = quarantine_check_tree(frame, handle, config,
						     smb_fname, q_dir,
						     cwd_fname);
			if (tree == NULL) {
				/*
				 * If we can't create the tree, just move it
				 * into the toplevel quarantine dir.
				 */
				tree = q_dir;
			}
			q_dir = tree;
		}
	}

	/* Get a 16 byte + \0 random filename component. */
	rand_filename_component = generate_random_str(frame, 16);
	if (rand_filename_component == NULL) {
		DBG_ERR("generate_random_str failed\n");
		action = VIRUSFILTER_ACTION_DO_NOTHING;
		goto out;
	}

	if (config->quarantine_keep_name) {
		q_filepath = talloc_asprintf(frame, "%s/%s%s%s-%s",
					     q_dir, q_prefix,
					     base_name, q_suffix,
					     rand_filename_component);
	} else {
		q_filepath = talloc_asprintf(frame, "%s/%s%s",
					     q_dir, q_prefix,
					     rand_filename_component);
	}
	if (q_filepath == NULL) {
		DBG_ERR("talloc_asprintf failed\n");
		action = VIRUSFILTER_ACTION_DO_NOTHING;
		goto out;
	}

	q_smb_fname = synthetic_smb_fname(frame,
					  q_filepath,
					  smb_fname->stream_name,
					  NULL,
					  0,
					  smb_fname->flags);
	if (q_smb_fname == NULL) {
		action = VIRUSFILTER_ACTION_DO_NOTHING;
		goto out;
	}

	become_root();
	ret = virusfilter_vfs_next_move(handle, smb_fname, q_smb_fname);
	if (ret == -1) {
		saved_errno = errno;
	}
	unbecome_root();
	if (ret == -1) {
		DBG_ERR("Quarantine [%s/%s] rename to %s failed: %s\n",
			cwd_fname, fname, q_filepath, strerror(saved_errno));
		errno = saved_errno;
		action = VIRUSFILTER_ACTION_DO_NOTHING;
		goto out;
	}

	*filepath_newp = talloc_move(mem_ctx, &q_filepath);

out:
	TALLOC_FREE(frame);
	return action;
}

static virusfilter_action infected_file_action_rename(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	TALLOC_CTX *mem_ctx,
	const struct files_struct *fsp,
	const char **filepath_newp)
{
	TALLOC_CTX *frame = talloc_stackframe();
	connection_struct *conn = handle->conn;
	char *cwd_fname = fsp->conn->cwd_fsp->fsp_name->base_name;
	char *fname = fsp->fsp_name->base_name;
	const struct smb_filename *smb_fname = fsp->fsp_name;
	struct smb_filename *q_smb_fname = NULL;
	char *q_dir = NULL;
	char *q_prefix = NULL;
	char *q_suffix = NULL;
	char *q_filepath = NULL;
	const char *base_name = NULL;
	virusfilter_action action = VIRUSFILTER_ACTION_RENAME;
	bool ok = false;
	int ret = -1;
	int saved_errno = 0;

	q_prefix = virusfilter_string_sub(frame, conn,
					  config->rename_prefix);
	q_suffix = virusfilter_string_sub(frame, conn,
					  config->rename_suffix);
	if (q_prefix == NULL || q_suffix == NULL) {
		DBG_ERR("Rename failed: %s/%s: Cannot allocate "
			"memory\n", cwd_fname, fname);
		action = VIRUSFILTER_ACTION_DO_NOTHING;
		goto out;
	}

	ok = parent_dirname(frame, fname, &q_dir, &base_name);
	if (!ok) {
		DBG_ERR("Rename failed: %s/%s: Cannot allocate "
			"memory\n", cwd_fname, fname);
		action = VIRUSFILTER_ACTION_DO_NOTHING;
		goto out;
	}

	if (q_dir == NULL) {
		DBG_ERR("Rename failed: %s/%s: Cannot allocate "
			"memory\n", cwd_fname, fname);
		action = VIRUSFILTER_ACTION_DO_NOTHING;
		goto out;
	}

	q_filepath = talloc_asprintf(frame, "%s/%s%s%s", q_dir,
				     q_prefix, base_name, q_suffix);

	q_smb_fname = synthetic_smb_fname(frame, q_filepath,
					  smb_fname->stream_name, NULL,
					  0,
					  smb_fname->flags);
	if (q_smb_fname == NULL) {
		action = VIRUSFILTER_ACTION_DO_NOTHING;
		goto out;
	}

	become_root();
	ret = virusfilter_vfs_next_move(handle, smb_fname, q_smb_fname);
	if (ret == -1) {
		saved_errno = errno;
	}
	unbecome_root();

	if (ret == -1) {
		DBG_ERR("Rename failed: %s/%s: Rename failed: %s\n",
			cwd_fname, fname, strerror(saved_errno));
		errno = saved_errno;
		action = VIRUSFILTER_ACTION_DO_NOTHING;
		goto out;
	}

	*filepath_newp = talloc_move(mem_ctx, &q_filepath);

out:
	TALLOC_FREE(frame);
	return action;
}

static virusfilter_action infected_file_action_delete(
	struct vfs_handle_struct *handle,
	const struct files_struct *fsp)
{
	int ret;
	int saved_errno = 0;

	become_root();
	ret = SMB_VFS_NEXT_UNLINKAT(handle,
				handle->conn->cwd_fsp,
				fsp->fsp_name,
				0);
	if (ret == -1) {
		saved_errno = errno;
	}
	unbecome_root();
	if (ret == -1) {
		DBG_ERR("Delete [%s/%s] failed: %s\n",
			fsp->conn->cwd_fsp->fsp_name->base_name,
			fsp->fsp_name->base_name,
			strerror(saved_errno));
		errno = saved_errno;
		return VIRUSFILTER_ACTION_DO_NOTHING;
	}

	return VIRUSFILTER_ACTION_DELETE;
}

static virusfilter_action virusfilter_do_infected_file_action(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	TALLOC_CTX *mem_ctx,
	const struct files_struct *fsp,
	const char **filepath_newp)
{
	virusfilter_action action;

	*filepath_newp = NULL;

	switch (config->infected_file_action) {
	case VIRUSFILTER_ACTION_RENAME:
		action = infected_file_action_rename(handle, config, mem_ctx,
						     fsp, filepath_newp);
		break;

	case VIRUSFILTER_ACTION_QUARANTINE:
		action = infected_file_action_quarantine(handle, config, mem_ctx,
							 fsp, filepath_newp);
		break;

	case VIRUSFILTER_ACTION_DELETE:
		action = infected_file_action_delete(handle, fsp);
		break;

	case VIRUSFILTER_ACTION_DO_NOTHING:
	default:
		action = VIRUSFILTER_ACTION_DO_NOTHING;
		break;
	}

	return action;
}

static virusfilter_action virusfilter_treat_infected_file(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	const struct files_struct *fsp,
	const char *report,
	bool is_cache)
{
	connection_struct *conn = handle->conn;
	char *cwd_fname = fsp->conn->cwd_fsp->fsp_name->base_name;
	char *fname = fsp->fsp_name->base_name;
	TALLOC_CTX *mem_ctx = talloc_tos();
	int i;
	virusfilter_action action;
	const char *action_name = "UNKNOWN";
	const char *filepath_q = NULL;
	char *env_list = NULL;
	char *command = NULL;
	int command_result;
	int ret;

	action = virusfilter_do_infected_file_action(handle, config, mem_ctx,
						     fsp, &filepath_q);
	for (i=0; virusfilter_actions[i].name; i++) {
		if (virusfilter_actions[i].value == action) {
			action_name = virusfilter_actions[i].name;
			break;
		}
	}
	DBG_WARNING("Infected file action: %s/%s: %s\n", cwd_fname,
		    fname, action_name);

	if (!config->infected_file_command) {
		return action;
	}

	ret = virusfilter_set_module_env(mem_ctx, config, &env_list);
	if (ret == -1) {
		goto done;
	}
	ret = virusfilter_env_set(mem_ctx, &env_list,
				  "VIRUSFILTER_INFECTED_SERVICE_FILE_PATH",
				  fname);
	if (ret == -1) {
		goto done;
	}
	if (report != NULL) {
		ret = virusfilter_env_set(mem_ctx, &env_list,
					  "VIRUSFILTER_INFECTED_FILE_REPORT",
					  report);
		if (ret == -1) {
			goto done;
		}
	}
	ret = virusfilter_env_set(mem_ctx, &env_list,
				  "VIRUSFILTER_INFECTED_FILE_ACTION",
				  action_name);
	if (ret == -1) {
		goto done;
	}
	if (filepath_q != NULL) {
		ret = virusfilter_env_set(mem_ctx, &env_list,
					  "VIRUSFILTER_QUARANTINED_FILE_PATH",
					  filepath_q);
		if (ret == -1) {
			goto done;
		}
	}
	if (is_cache) {
		ret = virusfilter_env_set(mem_ctx, &env_list,
					  "VIRUSFILTER_RESULT_IS_CACHE", "yes");
		if (ret == -1) {
			goto done;
		}
	}

	command = virusfilter_string_sub(mem_ctx, conn,
					 config->infected_file_command);
	if (command == NULL) {
		DBG_ERR("virusfilter_string_sub failed\n");
		goto done;
	}

	DBG_NOTICE("Infected file command line: %s/%s: %s\n", cwd_fname,
		   fname, command);

	command_result = virusfilter_shell_run(mem_ctx, command, &env_list,
					       conn, true);
	if (command_result != 0) {
		DBG_ERR("Infected file command failed: %d\n", command_result);
	}

	DBG_DEBUG("Infected file command finished: %d\n", command_result);

done:
	TALLOC_FREE(env_list);
	TALLOC_FREE(command);

	return action;
}

static void virusfilter_treat_scan_error(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	const struct files_struct *fsp,
	const char *report,
	bool is_cache)
{
	connection_struct *conn = handle->conn;
	const char *cwd_fname = fsp->conn->cwd_fsp->fsp_name->base_name;
	const char *fname = fsp->fsp_name->base_name;
	TALLOC_CTX *mem_ctx = talloc_tos();
	char *env_list = NULL;
	char *command = NULL;
	int command_result;
	int ret;

	if (!config->scan_error_command) {
		return;
	}
	ret = virusfilter_set_module_env(mem_ctx, config, &env_list);
	if (ret == -1) {
		goto done;
	}
	ret = virusfilter_env_set(mem_ctx, &env_list,
				  "VIRUSFILTER_SCAN_ERROR_SERVICE_FILE_PATH",
				  fname);
	if (ret == -1) {
		goto done;
	}
	if (report != NULL) {
		ret = virusfilter_env_set(mem_ctx, &env_list,
					  "VIRUSFILTER_SCAN_ERROR_REPORT",
					  report);
		if (ret == -1) {
			goto done;
		}
	}
	if (is_cache) {
		ret = virusfilter_env_set(mem_ctx, &env_list,
					  "VIRUSFILTER_RESULT_IS_CACHE", "1");
		if (ret == -1) {
			goto done;
		}
	}

	command = virusfilter_string_sub(mem_ctx, conn,
					 config->scan_error_command);
	if (command == NULL) {
		DBG_ERR("virusfilter_string_sub failed\n");
		goto done;
	}

	DBG_NOTICE("Scan error command line: %s/%s: %s\n", cwd_fname,
		   fname, command);

	command_result = virusfilter_shell_run(mem_ctx, command, &env_list,
					       conn, true);
	if (command_result != 0) {
		DBG_ERR("Scan error command failed: %d\n", command_result);
	}

done:
	TALLOC_FREE(env_list);
	TALLOC_FREE(command);
}

static virusfilter_result virusfilter_scan(
	struct vfs_handle_struct *handle,
	struct virusfilter_config *config,
	const struct files_struct *fsp)
{
	virusfilter_result scan_result;
	char *scan_report = NULL;
	const char *fname = fsp->fsp_name->base_name;
	const char *cwd_fname = fsp->conn->cwd_fsp->fsp_name->base_name;
	struct virusfilter_cache_entry *scan_cache_e = NULL;
	bool is_cache = false;
	virusfilter_action file_action = VIRUSFILTER_ACTION_DO_NOTHING;
	bool add_scan_cache = true;
	bool ok = false;

	if (config->cache) {
		DBG_DEBUG("Searching cache entry: fname: %s\n", fname);
		scan_cache_e = virusfilter_cache_get(config->cache,
						     cwd_fname, fname);
		if (scan_cache_e != NULL) {
			DBG_DEBUG("Cache entry found: cached result: %d\n",
			      scan_cache_e->result);
			is_cache = true;
			scan_result = scan_cache_e->result;
			scan_report = scan_cache_e->report;
			goto virusfilter_scan_result_eval;
		}
		DBG_DEBUG("Cache entry not found\n");
	}

	if (config->backend->fns->scan_init != NULL) {
		scan_result = config->backend->fns->scan_init(config);
		if (scan_result != VIRUSFILTER_RESULT_OK) {
			scan_result = VIRUSFILTER_RESULT_ERROR;
			scan_report = talloc_asprintf(
				talloc_tos(),
				"Initializing scanner failed");
			goto virusfilter_scan_result_eval;
		}
	}

	scan_result = config->backend->fns->scan(handle, config, fsp,
						 &scan_report);

	if (config->backend->fns->scan_end != NULL) {
		bool scan_end = true;

		if (config->scan_request_limit > 0) {
			scan_end = false;
			config->scan_request_count++;
			if (config->scan_request_count >=
			    config->scan_request_limit)
			{
				scan_end = true;
				config->scan_request_count = 0;
			}
		}
		if (scan_end) {
			config->backend->fns->scan_end(config);
		}
	}

virusfilter_scan_result_eval:

	switch (scan_result) {
	case VIRUSFILTER_RESULT_CLEAN:
		DBG_INFO("Scan result: Clean: %s/%s\n", cwd_fname, fname);
		break;

	case VIRUSFILTER_RESULT_INFECTED:
		DBG_ERR("Scan result: Infected: %s/%s: %s\n",
			cwd_fname, fname, scan_report ? scan_report :
			"infected (memory error on report)");
		file_action = virusfilter_treat_infected_file(handle,
					config, fsp, scan_report, is_cache);
		if (file_action != VIRUSFILTER_ACTION_DO_NOTHING) {
			add_scan_cache = false;
		}
		break;

	case VIRUSFILTER_RESULT_SUSPECTED:
		if (!config->block_suspected_file) {
			break;
		}
		DBG_ERR("Scan result: Suspected: %s/%s: %s\n",
			cwd_fname, fname, scan_report ? scan_report :
			"suspected infection (memory error on report)");
		file_action = virusfilter_treat_infected_file(handle,
					config, fsp, scan_report, is_cache);
		if (file_action != VIRUSFILTER_ACTION_DO_NOTHING) {
			add_scan_cache = false;
		}
		break;

	case VIRUSFILTER_RESULT_ERROR:
		DBG_ERR("Scan result: Error: %s/%s: %s\n",
			cwd_fname, fname, scan_report ? scan_report :
			"error (memory error on report)");
		virusfilter_treat_scan_error(handle, config, fsp,
					     scan_report, is_cache);
		add_scan_cache = false;
		break;

	default:
		DBG_ERR("Scan result: Unknown result code %d: %s/%s: %s\n",
			scan_result, cwd_fname, fname, scan_report ?
			scan_report : "Unknown (memory error on report)");
		virusfilter_treat_scan_error(handle, config, fsp,
					     scan_report, is_cache);
		add_scan_cache = false;
		break;
	}

	if (config->cache) {
		if (!is_cache && add_scan_cache) {
			DBG_DEBUG("Adding new cache entry: %s, %d\n", fname,
				  scan_result);
			ok = virusfilter_cache_entry_add(
					config->cache, cwd_fname, fname,
					scan_result, scan_report);
			if (!ok) {
				DBG_ERR("Cannot create cache entry: "
					"virusfilter_cache_entry_new failed");
				goto virusfilter_scan_return;
			}
		} else if (is_cache) {
			virusfilter_cache_entry_free(scan_cache_e);
		}
	}

virusfilter_scan_return:
	return scan_result;
}

static int virusfilter_vfs_openat(struct vfs_handle_struct *handle,
				  const struct files_struct *dirfsp,
				  const struct smb_filename *smb_fname_in,
				  struct files_struct *fsp,
				  int flags,
				  mode_t mode)
{
	TALLOC_CTX *mem_ctx = talloc_tos();
	struct virusfilter_config *config = NULL;
	const char *cwd_fname = dirfsp->fsp_name->base_name;
	virusfilter_result scan_result;
	const char *fname = fsp->fsp_name->base_name;
	char *dir_name = NULL;
	const char *base_name = NULL;
	int scan_errno = 0;
	size_t test_prefix;
	size_t test_suffix;
	int rename_trap_count = 0;
	int ret;
	bool ok1;
	char *sret = NULL;
	struct smb_filename *smb_fname = NULL;

	/*
	 * For now assert this, so SMB_VFS_NEXT_STAT() below works.
	 */
	SMB_ASSERT(dirfsp->fh->fd == AT_FDCWD);

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct virusfilter_config, return -1);

	if (fsp->fsp_flags.is_directory) {
		DBG_INFO("Not scanned: Directory: %s/\n", cwd_fname);
		goto virusfilter_vfs_open_next;
	}

	test_prefix = strlen(config->rename_prefix);
	test_suffix = strlen(config->rename_suffix);
	if (test_prefix > 0) {
		rename_trap_count++;
	}
	if (test_suffix > 0) {
		rename_trap_count++;
	}

	smb_fname = cp_smb_filename(mem_ctx, smb_fname_in);
	if (smb_fname == NULL) {
		goto virusfilter_vfs_open_fail;
	}

	if (is_named_stream(smb_fname)) {
		DBG_INFO("Not scanned: only file backed streams can be scanned:"
			 " %s/%s\n", cwd_fname, fname);
		goto virusfilter_vfs_open_next;
	}

	if (!config->scan_on_open) {
		DBG_INFO("Not scanned: scan on open is disabled: %s/%s\n",
			 cwd_fname, fname);
		goto virusfilter_vfs_open_next;
	}

	if (flags & O_TRUNC) {
		DBG_INFO("Not scanned: Open flags have O_TRUNC: %s/%s\n",
			 cwd_fname, fname);
		goto virusfilter_vfs_open_next;
	}

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
	if (ret != 0) {

		/*
		 * Do not return immediately if !(flags & O_CREAT) &&
		 * errno != ENOENT.
		 * Do not do this here or anywhere else. The module is
		 * stackable and there may be modules below, such as audit
		 * modules, which should be handled.
		 */
		goto virusfilter_vfs_open_next;
	}
	ret = S_ISREG(smb_fname->st.st_ex_mode);
	if (ret == 0) {
		DBG_INFO("Not scanned: Directory or special file: %s/%s\n",
			 cwd_fname, fname);
		goto virusfilter_vfs_open_next;
	}
	if (config->max_file_size > 0 &&
	    smb_fname->st.st_ex_size > config->max_file_size)
	{
		DBG_INFO("Not scanned: file size > max file size: %s/%s\n",
			 cwd_fname, fname);
		goto virusfilter_vfs_open_next;
	}
	if (config->min_file_size > 0 &&
	    smb_fname->st.st_ex_size < config->min_file_size)
	{
		DBG_INFO("Not scanned: file size < min file size: %s/%s\n",
		      cwd_fname, fname);
		goto virusfilter_vfs_open_next;
	}

	ok1 = is_in_path(fname, config->exclude_files, false);
	if (config->exclude_files && ok1)
	{
		DBG_INFO("Not scanned: exclude files: %s/%s\n",
			 cwd_fname, fname);
		goto virusfilter_vfs_open_next;
	}

	if (config->infected_file_action == VIRUSFILTER_ACTION_QUARANTINE) {
		sret = strstr_m(fname, config->quarantine_dir);
		if (sret != NULL) {
			scan_errno = config->infected_open_errno;
			goto virusfilter_vfs_open_fail;
		}
	}

	if (test_prefix > 0 || test_suffix > 0) {
		ok1 = parent_dirname(mem_ctx, fname, &dir_name, &base_name);
		if (ok1)
		{
			if (test_prefix > 0) {
				ret = strncmp(base_name,
				    config->rename_prefix, test_prefix);
				if (ret != 0) {
					test_prefix = 0;
				}
			}
			if (test_suffix > 0) {
				ret = strcmp(base_name + (strlen(base_name)
						 - test_suffix),
						 config->rename_suffix);
				if (ret != 0) {
					test_suffix = 0;
				}
			}

			TALLOC_FREE(dir_name);

			if ((rename_trap_count == 2 && test_prefix &&
			    test_suffix) || (rename_trap_count == 1 &&
			    (test_prefix || test_suffix)))
			{
				scan_errno =
					config->infected_open_errno;
				goto virusfilter_vfs_open_fail;
			}
		}
	}

	scan_result = virusfilter_scan(handle, config, fsp);

	switch (scan_result) {
	case VIRUSFILTER_RESULT_CLEAN:
		break;
	case VIRUSFILTER_RESULT_INFECTED:
		scan_errno = config->infected_open_errno;
		goto virusfilter_vfs_open_fail;
	case VIRUSFILTER_RESULT_ERROR:
		if (config->block_access_on_error) {
			DBG_INFO("Block access\n");
			scan_errno = config->scan_error_open_errno;
			goto virusfilter_vfs_open_fail;
		}
		break;
	default:
		scan_errno = config->scan_error_open_errno;
		goto virusfilter_vfs_open_fail;
	}

	TALLOC_FREE(smb_fname);

virusfilter_vfs_open_next:
	return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname_in, fsp, flags, mode);

virusfilter_vfs_open_fail:
	TALLOC_FREE(smb_fname);
	errno = (scan_errno != 0) ? scan_errno : EACCES;
	return -1;
}

static int virusfilter_vfs_close(
	struct vfs_handle_struct *handle,
	files_struct *fsp)
{
	/*
         * The name of this variable is for consistency. If API changes to
         * match _open change to cwd_fname as in virusfilter_vfs_open.
         */
	const char *cwd_fname = handle->conn->connectpath;

	struct virusfilter_config *config = NULL;
	char *fname = fsp->fsp_name->base_name;
	int close_result = -1;
	int close_errno = 0;
	virusfilter_result scan_result;
	int scan_errno = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct virusfilter_config, return -1);

	/*
	 * Must close after scan? It appears not as the scanners are not
	 * internal and other modules such as greyhole seem to do
	 * SMB_VFS_NEXT_* functions before processing.
	 */
	close_result = SMB_VFS_NEXT_CLOSE(handle, fsp);
	if (close_result == -1) {
		close_errno = errno;
	}

	/*
	 * Return immediately if close_result == -1, and close_errno == EBADF.
	 * If close failed, file likely doesn't exist, do not try to scan.
	 */
	if (close_result == -1 && close_errno == EBADF) {
		if (fsp->fsp_flags.modified) {
			DBG_DEBUG("Removing cache entry (if existent): "
				  "fname: %s\n", fname);
			virusfilter_cache_remove(config->cache,
						 cwd_fname, fname);
		}
		goto virusfilter_vfs_close_fail;
	}

	if (fsp->fsp_flags.is_directory) {
		DBG_INFO("Not scanned: Directory: %s/\n", cwd_fname);
		return close_result;
	}

	if (is_named_stream(fsp->fsp_name)) {
		if (config->scan_on_open && fsp->fsp_flags.modified) {
			if (config->cache) {
				DBG_DEBUG("Removing cache entry (if existent)"
					  ": fname: %s\n", fname);
				virusfilter_cache_remove(
						config->cache,
						cwd_fname, fname);
			}
		}
		DBG_INFO("Not scanned: only file backed streams can be scanned:"
			 " %s/%s\n", cwd_fname, fname);
		return close_result;
	}

	if (!config->scan_on_close) {
		if (config->scan_on_open && fsp->fsp_flags.modified) {
			if (config->cache) {
				DBG_DEBUG("Removing cache entry (if existent)"
					  ": fname: %s\n", fname);
				virusfilter_cache_remove(
						config->cache,
						cwd_fname, fname);
			}
		}
		DBG_INFO("Not scanned: scan on close is disabled: %s/%s\n",
			 cwd_fname, fname);
		return close_result;
	}

	if (!fsp->fsp_flags.modified) {
		DBG_NOTICE("Not scanned: File not modified: %s/%s\n",
			   cwd_fname, fname);

		return close_result;
	}

	if (config->exclude_files && is_in_path(fname,
	    config->exclude_files, false))
	{
		DBG_INFO("Not scanned: exclude files: %s/%s\n",
			 cwd_fname, fname);
		return close_result;
	}

	scan_result = virusfilter_scan(handle, config, fsp);

	switch (scan_result) {
	case VIRUSFILTER_RESULT_CLEAN:
		break;
	case VIRUSFILTER_RESULT_INFECTED:
		scan_errno = config->infected_close_errno;
		goto virusfilter_vfs_close_fail;
	case VIRUSFILTER_RESULT_ERROR:
		if (config->block_access_on_error) {
			DBG_INFO("Block access\n");
			scan_errno = config->scan_error_close_errno;
			goto virusfilter_vfs_close_fail;
		}
		break;
	default:
		scan_errno = config->scan_error_close_errno;
		goto virusfilter_vfs_close_fail;
	}

	if (close_errno != 0) {
		errno = close_errno;
	}

	return close_result;

virusfilter_vfs_close_fail:

	errno = (scan_errno != 0) ? scan_errno : close_errno;

	return close_result;
}

static int virusfilter_vfs_unlinkat(struct vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		int flags)
{
	int ret = SMB_VFS_NEXT_UNLINKAT(handle,
			dirfsp,
			smb_fname,
			flags);
	struct virusfilter_config *config = NULL;
	char *fname = NULL;
	char *cwd_fname = handle->conn->cwd_fsp->fsp_name->base_name;

	if (ret != 0 && errno != ENOENT) {
		return ret;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct virusfilter_config, return -1);

	if (config->cache == NULL) {
		return 0;
	}

	fname = smb_fname->base_name;

	DBG_DEBUG("Removing cache entry (if existent): fname: %s\n", fname);
	virusfilter_cache_remove(config->cache, cwd_fname, fname);

	return 0;
}

static int virusfilter_vfs_renameat(
	struct vfs_handle_struct *handle,
	files_struct *srcfsp,
	const struct smb_filename *smb_fname_src,
	files_struct *dstfsp,
	const struct smb_filename *smb_fname_dst)
{
	int ret = SMB_VFS_NEXT_RENAMEAT(handle,
			srcfsp,
			smb_fname_src,
			dstfsp,
			smb_fname_dst);
	struct virusfilter_config *config = NULL;
	char *fname = NULL;
	char *dst_fname = NULL;
	char *cwd_fname = handle->conn->cwd_fsp->fsp_name->base_name;

	if (ret != 0) {
		return ret;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct virusfilter_config, return -1);

	if (config->cache == NULL) {
		return 0;
	}

	fname = smb_fname_src->base_name;
	dst_fname = smb_fname_dst->base_name;

	DBG_DEBUG("Renaming cache entry: fname: %s to: %s\n",
		  fname, dst_fname);
	virusfilter_cache_entry_rename(config->cache,
				       cwd_fname, fname,
				       dst_fname);

	return 0;
}


/* VFS operations */
static struct vfs_fn_pointers vfs_virusfilter_fns = {
	.connect_fn	= virusfilter_vfs_connect,
	.disconnect_fn	= virusfilter_vfs_disconnect,
	.openat_fn	= virusfilter_vfs_openat,
	.close_fn	= virusfilter_vfs_close,
	.unlinkat_fn	= virusfilter_vfs_unlinkat,
	.renameat_fn	= virusfilter_vfs_renameat,
};

NTSTATUS vfs_virusfilter_init(TALLOC_CTX *);
NTSTATUS vfs_virusfilter_init(TALLOC_CTX *ctx)
{
	NTSTATUS status;

	status = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				  "virusfilter",
				  &vfs_virusfilter_fns);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	virusfilter_debug_class = debug_add_class("virusfilter");
	if (virusfilter_debug_class == -1) {
		virusfilter_debug_class = DBGC_VFS;
		DBG_ERR("Couldn't register custom debugging class!\n");
	} else {
		DBG_DEBUG("Debug class number: %d\n", virusfilter_debug_class);
	}

	DBG_INFO("registered\n");

	return status;
}
