/*
 * Samba-VirusFilter VFS template
 * #included into modules/vfs_virusfilter_clamav.c,
 * modules/vfs_virusfilter_fsav.c and modules/vfs_virusfilter_sophos.c.
 *
 * The defines virusfilter_module_connect, virusfilter_module_scan_init,
 * virusfilter_module_scan_end, virusfilter_module_scan must be defined, before
 * including this file, as functions which implements those operations. The
 * function names are normally the same as the define with the "module" part
 * replaced with the module name. virusfilter_module_destruct_config may
 * optionally be defined.
 *
 * The following must be defined before the include in every module:
 * VIRUSFILTER_DEFAULT_CONNECT_TIMEOUT, VIRUSFILTER_DEFAULT_SOCKET_PATH,
 * VIRUSFILTER_DEFAULT_TIMEOUT, VIRUSFILTER_ENGINE (non-string module name),
 * VIRUSFILTER_MODULE_ENGINE (string module name). See existing modules for
 * examples.
 *
 * The following must be defined before the include if used in the module:
 * VIRUSFILTER_DEFAULT_SCAN_ARCHIVE, VIRUSFILTER_DEFAULT_SCAN_MIME,
 * VIRUSFILTER_DEFAULT_MAX_NESTED_SCAN_ARCHIVE,
 * VIRUSFILTER_DEFAULT_SCAN_REQUEST_LIMIT,
 * VIRUSFILTER_DEFAULT_BLOCK_SUSPECTED_FILE.
 *
 * Optionally, VIRUSFILTER_MODULE_CONFIG_MEMBERS may be defined
 * (see modules/vfs_virusfilter_fsav.c for example). The configuration should
 * be done in virusfilter_MODULENAME_connect inside of the virus scanning
 * engine specific module.
 *
 * Copyright (C) 2010-2016 SATOH Fumiyasu @ OSS Technology Corp., Japan
 * Copyright (C) 2016 Trever L. Adams
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

#include "modules/vfs_virusfilter_common.h"
#include "modules/vfs_virusfilter_utils.h"

#define VIRUSFILTER_MODULE_NAME "virusfilter_" VIRUSFILTER_MODULE_ENGINE

/*
 * Default configuration values
 * ======================================================================
 */

#define VIRUSFILTER_DEFAULT_SCAN_ON_OPEN		true
#define VIRUSFILTER_DEFAULT_SCAN_ON_CLOSE		false
#define VIRUSFILTER_DEFAULT_MAX_FILE_SIZE		100000000L /* 100MB */
#define VIRUSFILTER_DEFAULT_MIN_FILE_SIZE		0
#define VIRUSFILTER_DEFAULT_EXCLUDE_FILES		NULL

#define VIRUSFILTER_DEFAULT_CACHE_ENTRY_LIMIT		100
#define VIRUSFILTER_DEFAULT_CACHE_TIME_LIMIT		10

#define VIRUSFILTER_DEFAULT_INFECTED_FILE_ACTION	\
	VIRUSFILTER_ACTION_DO_NOTHING
#define VIRUSFILTER_DEFAULT_INFECTED_FILE_COMMAND	NULL
#define VIRUSFILTER_DEFAULT_INFECTED_FILE_ERRNO_ON_OPEN	EACCES
#define VIRUSFILTER_DEFAULT_INFECTED_FILE_ERRNO_ON_CLOSE 0

#define VIRUSFILTER_DEFAULT_SCAN_ERROR_COMMAND		NULL
#define VIRUSFILTER_DEFAULT_SCAN_ERROR_ERRNO_ON_OPEN	EACCES
#define VIRUSFILTER_DEFAULT_SCAN_ERROR_ERRNO_ON_CLOSE	0
#define VIRUSFILTER_DEFAULT_BLOCK_ACCESS_ON_ERROR	false

#define VIRUSFILTER_DEFAULT_QUARANTINE_PREFIX		"virusfilter."
#define VIRUSFILTER_DEFAULT_QUARANTINE_SUFFIX		".infected"
#define VIRUSFILTER_DEFAULT_QUARANTINE_KEEP_NAME	false
#define VIRUSFILTER_DEFAULT_QUARANTINE_KEEP_TREE	false

/* 700 = S_IRUSR | S_IWUSR | S_IXUSR */
#define VIRUSFILTER_DEFAULT_QUARANTINE_DIR_MODE		"700"

#define VIRUSFILTER_DEFAULT_RENAME_PREFIX		"virusfilter."
#define VIRUSFILTER_DEFAULT_RENAME_SUFFIX		".infected"

/* ====================================================================== */

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

typedef struct {
#ifdef VIRUSFILTER_DEFAULT_SCAN_REQUEST_LIMIT
	int				scan_request_count;
	int				scan_request_limit;
#endif

	/* Scan on file operations */
	bool				scan_on_open;
	bool				scan_on_close;

	/* Special scan options */
#ifdef VIRUSFILTER_DEFAULT_SCAN_ARCHIVE
        bool				scan_archive;
#endif
#ifdef VIRUSFILTER_DEFAULT_MAX_NESTED_SCAN_ARCHIVE
        int				max_nested_scan_archive;
#endif
#ifdef VIRUSFILTER_DEFAULT_SCAN_MIME
        bool				scan_mime;
#endif
#ifdef VIRUSFILTER_DEFAULT_BLOCK_SUSPECTED_FILE
	bool				block_suspected_file;
#endif

	/* Size limit */
	ssize_t				max_file_size;
	ssize_t				min_file_size;

	/* Exclude files */
	name_compare_entry		*exclude_files;

	/* Scan result cache */
	virusfilter_cache_handle	*cache_h;
	int				cache_entry_limit;
	int				cache_time_limit;

	/* Infected file options */
	virusfilter_action		infected_file_action;
	const char *			infected_file_command;
	int				infected_open_errno;
	int				infected_close_errno;

	/* Scan error options */
	const char *			scan_error_command;
	int				scan_error_open_errno;
	int				scan_error_close_errno;
	bool				block_access_on_error;

	/* Quarantine infected files */
	const char *			quarantine_dir;
	const char *			default_quarantine_directory;
	const char *			quarantine_prefix;
	const char *			quarantine_suffix;
	bool				quarantine_keep_name;
	bool				quarantine_keep_tree;
	mode_t				quarantine_dir_mode;

	/* Rename infected files */
	const char *			rename_prefix;
	const char *			rename_suffix;

	/* Network options */
#ifdef VIRUSFILTER_DEFAULT_SOCKET_PATH
        const char *			socket_path;
	virusfilter_io_handle		*io_h;
#endif

	/* Module specific configuration options */
#ifdef VIRUSFILTER_MODULE_CONFIG_MEMBERS
	VIRUSFILTER_MODULE_CONFIG_MEMBERS
#endif
} virusfilter_handle;

/* ====================================================================== */

#ifdef virusfilter_module_connect
static int virusfilter_module_connect(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const char *svc,
	const char *user);
#endif

#ifdef virusfilter_module_disconnect
static int virusfilter_module_disconnect(vfs_handle_struct *vfs_h);
#endif

#ifdef virusfilter_module_destruct_config
static int virusfilter_module_destruct_config(
	virusfilter_handle *virusfilter_h);
#endif

#ifdef virusfilter_module_scan_init
static virusfilter_result virusfilter_module_scan_init(
	virusfilter_handle *virusfilter_h);
#endif

#ifdef virusfilter_module_scan_end
static void virusfilter_module_scan_end(virusfilter_handle *virusfilter_h);
#endif

static virusfilter_result virusfilter_module_scan(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const struct smb_filename *smb_fname,
	const char **reportp);

/* ====================================================================== */

static int virusfilter_destruct_config(virusfilter_handle *virusfilter_h)
{
#ifdef virusfilter_module_destruct_config
	return virusfilter_module_destruct_config(virusfilter_h);
#else
	return 0;
#endif
}

/*
 * This is adapted from vfs_recycle module.
 * Caller must have become_root();
 */
static bool quarantine_directory_exist(
	vfs_handle_struct *handle,
	const char *dname)
{
	struct smb_filename smb_fname = {
		.base_name = discard_const_p(char, dname)
	};

	if (SMB_VFS_STAT(handle->conn, &smb_fname) == 0) {
		if (S_ISDIR(smb_fname.st.st_ex_mode)) {
			return true;
		}
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
	vfs_handle_struct *handle,
	virusfilter_handle *virusfilter_h,
	const char *dname)
{
	size_t len;
	mode_t mode;
	char *new_dir = NULL;
	char *tmp_str = NULL;
	char *token;
	char *tok_str;
	bool ret = false;
	char *saveptr;

	mode = virusfilter_h->quarantine_dir_mode;

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
		if (strlcat(new_dir,"/",len+1) >= len+1) {
			goto done;
		}
	}

	/* Create directory tree if neccessary */
	for (token = strtok_r(tok_str, "/", &saveptr); token;
	     token = strtok_r(NULL, "/", &saveptr))
	{
		if (strlcat(new_dir, token, len+1) >= len+1) {
			goto done;
		}
		if (quarantine_directory_exist(handle, new_dir)) {
			DBG_DEBUG("quarantine: dir %s already exists\n",
				  new_dir);
		} else {
			struct smb_filename *smb_fname = NULL;

			DBG_INFO("quarantine: creating new dir %s\n", new_dir);

			smb_fname = synthetic_smb_fname(talloc_tos(), new_dir,
							NULL, NULL, 0);
			if (smb_fname == NULL) {
				goto done;
			}

			if (SMB_VFS_NEXT_MKDIR(handle, smb_fname, mode) != 0) {
				TALLOC_FREE(smb_fname);

				DBG_WARNING("quarantine: mkdir failed for %s "
					    "with error: %s\n", new_dir,
					    strerror(errno));
				ret = false;
				goto done;
			}
			TALLOC_FREE(smb_fname);
		}
		if (strlcat(new_dir, "/", len+1) >= len+1) {
			goto done;
		}
		mode = virusfilter_h->quarantine_dir_mode;
	}

	ret = true;
	done:
		TALLOC_FREE(tmp_str);
		TALLOC_FREE(new_dir);
		return ret;
}

static int virusfilter_vfs_connect(
	vfs_handle_struct *vfs_h,
	const char *svc,
	const char *user)
{
	int snum = SNUM(vfs_h->conn);
	virusfilter_handle *virusfilter_h;
	const char *exclude_files;
	const char *temp_quarantine_dir_mode = NULL;
#ifdef VIRUSFILTER_DEFAULT_SOCKET_PATH
	int connect_timeout, io_timeout;
#endif


	virusfilter_h = talloc_zero(vfs_h, virusfilter_handle);
	if (!virusfilter_h) {
		DBG_ERR("talloc_zero failed\n");
		return -1;
	}

	talloc_set_destructor(virusfilter_h, virusfilter_destruct_config);

	SMB_VFS_HANDLE_SET_DATA(vfs_h, virusfilter_h, NULL, virusfilter_handle,
				return -1);

#ifdef VIRUSFILTER_DEFAULT_SCAN_REQUEST_LIMIT
        virusfilter_h->scan_request_limit = lp_parm_int(snum,
		VIRUSFILTER_MODULE_NAME, "scan request limit",
		VIRUSFILTER_DEFAULT_SCAN_REQUEST_LIMIT);
#endif

        virusfilter_h->scan_on_open = lp_parm_bool(snum,
		VIRUSFILTER_MODULE_NAME, "scan on open",
		VIRUSFILTER_DEFAULT_SCAN_ON_OPEN);
        virusfilter_h->scan_on_close = lp_parm_bool(snum,
		VIRUSFILTER_MODULE_NAME, "scan on close",
		VIRUSFILTER_DEFAULT_SCAN_ON_CLOSE);
#ifdef VIRUSFILTER_DEFAULT_MAX_NESTED_SCAN_ARCHIVE
        virusfilter_h->max_nested_scan_archive = lp_parm_int(snum,
		VIRUSFILTER_MODULE_NAME, "max nested scan archive",
		VIRUSFILTER_DEFAULT_MAX_NESTED_SCAN_ARCHIVE);
#endif
#ifdef VIRUSFILTER_DEFAULT_SCAN_ARCHIVE
        virusfilter_h->scan_archive = lp_parm_bool(snum,
		VIRUSFILTER_MODULE_NAME, "scan archive",
		VIRUSFILTER_DEFAULT_SCAN_ARCHIVE);
#endif
#ifdef VIRUSFILTER_DEFAULT_MIME_SCAN
        virusfilter_h->scan_mime = lp_parm_bool(snum,
		VIRUSFILTER_MODULE_NAME, "scan mime",
		VIRUSFILTER_DEFAULT_SCAN_MIME);
#endif

        virusfilter_h->max_file_size = (ssize_t)lp_parm_ulong(snum,
		VIRUSFILTER_MODULE_NAME, "max file size",
		VIRUSFILTER_DEFAULT_MAX_FILE_SIZE);
        virusfilter_h->min_file_size = (ssize_t)lp_parm_ulong(snum,
		VIRUSFILTER_MODULE_NAME, "min file size",
		VIRUSFILTER_DEFAULT_MIN_FILE_SIZE);

        exclude_files = lp_parm_const_string(snum,
		VIRUSFILTER_MODULE_NAME, "exclude files",
		VIRUSFILTER_DEFAULT_EXCLUDE_FILES);
	if (exclude_files) {
		set_namearray(&virusfilter_h->exclude_files, exclude_files);
	}

        virusfilter_h->cache_entry_limit = lp_parm_int(snum,
		VIRUSFILTER_MODULE_NAME, "cache entry limit",
		VIRUSFILTER_DEFAULT_CACHE_ENTRY_LIMIT);
        virusfilter_h->cache_time_limit = lp_parm_int(snum,
		VIRUSFILTER_MODULE_NAME, "cache time limit",
		VIRUSFILTER_DEFAULT_CACHE_TIME_LIMIT);

        virusfilter_h->infected_file_action = lp_parm_enum(snum,
		VIRUSFILTER_MODULE_NAME, "infected file action",
		virusfilter_actions, VIRUSFILTER_DEFAULT_INFECTED_FILE_ACTION);
        virusfilter_h->infected_file_command = lp_parm_const_string(snum,
		VIRUSFILTER_MODULE_NAME, "infected file command",
		VIRUSFILTER_DEFAULT_INFECTED_FILE_COMMAND);
        virusfilter_h->scan_error_command = lp_parm_const_string(snum,
		VIRUSFILTER_MODULE_NAME, "scan error command",
		VIRUSFILTER_DEFAULT_SCAN_ERROR_COMMAND);
        virusfilter_h->block_access_on_error = lp_parm_bool(snum,
		VIRUSFILTER_MODULE_NAME, "block access on error",
		VIRUSFILTER_DEFAULT_BLOCK_ACCESS_ON_ERROR);

	virusfilter_h->default_quarantine_directory =
		talloc_strdup(virusfilter_h,
			      state_path("virusfilter/quarantine"));
	virusfilter_h->quarantine_dir = lp_parm_const_string(snum,
		VIRUSFILTER_MODULE_NAME, "quarantine directory",
		virusfilter_h->default_quarantine_directory);
        temp_quarantine_dir_mode = lp_parm_const_string(snum,
		VIRUSFILTER_MODULE_NAME, "quarantine directory mode",
		VIRUSFILTER_DEFAULT_QUARANTINE_DIR_MODE);
        if (temp_quarantine_dir_mode != NULL) {
                sscanf(temp_quarantine_dir_mode, "%o",
                       &virusfilter_h->quarantine_dir_mode);
        }
        virusfilter_h->quarantine_prefix = lp_parm_const_string(snum,
		VIRUSFILTER_MODULE_NAME, "quarantine prefix",
		VIRUSFILTER_DEFAULT_QUARANTINE_PREFIX);
        virusfilter_h->quarantine_suffix = lp_parm_const_string(snum,
		VIRUSFILTER_MODULE_NAME, "quarantine suffix",
		VIRUSFILTER_DEFAULT_QUARANTINE_SUFFIX);
        virusfilter_h->quarantine_keep_tree = lp_parm_bool(snum,
		VIRUSFILTER_MODULE_NAME, "quarantine keep tree",
		VIRUSFILTER_DEFAULT_QUARANTINE_KEEP_TREE);
        virusfilter_h->quarantine_keep_name = lp_parm_bool(snum,
		VIRUSFILTER_MODULE_NAME, "quarantine keep name",
		VIRUSFILTER_DEFAULT_QUARANTINE_KEEP_NAME);

        virusfilter_h->rename_prefix = lp_parm_const_string(snum,
		VIRUSFILTER_MODULE_NAME, "rename prefix",
		VIRUSFILTER_DEFAULT_RENAME_PREFIX);
        virusfilter_h->rename_suffix = lp_parm_const_string(snum,
		VIRUSFILTER_MODULE_NAME, "rename suffix",
		VIRUSFILTER_DEFAULT_RENAME_SUFFIX);

        virusfilter_h->infected_open_errno = lp_parm_int(snum,
		VIRUSFILTER_MODULE_NAME, "infected file errno on open",
		VIRUSFILTER_DEFAULT_INFECTED_FILE_ERRNO_ON_OPEN);
        virusfilter_h->infected_close_errno = lp_parm_int(snum,
		VIRUSFILTER_MODULE_NAME, "infected file errno on close",
		VIRUSFILTER_DEFAULT_INFECTED_FILE_ERRNO_ON_CLOSE);
        virusfilter_h->scan_error_open_errno = lp_parm_int(snum,
		VIRUSFILTER_MODULE_NAME, "scan error errno on open",
		VIRUSFILTER_DEFAULT_SCAN_ERROR_ERRNO_ON_OPEN);
        virusfilter_h->scan_error_close_errno = lp_parm_int(snum,
		VIRUSFILTER_MODULE_NAME, "scan error errno on close",
		VIRUSFILTER_DEFAULT_SCAN_ERROR_ERRNO_ON_CLOSE);

#ifdef VIRUSFILTER_DEFAULT_SOCKET_PATH
        virusfilter_h->socket_path = lp_parm_const_string(snum,
		VIRUSFILTER_MODULE_NAME, "socket path",
		VIRUSFILTER_DEFAULT_SOCKET_PATH);
        connect_timeout = lp_parm_int(snum, VIRUSFILTER_MODULE_NAME,
		"connect timeout", VIRUSFILTER_DEFAULT_CONNECT_TIMEOUT);
        io_timeout = lp_parm_int(snum, VIRUSFILTER_MODULE_NAME, "io timeout",
		VIRUSFILTER_DEFAULT_TIMEOUT);

	virusfilter_h->io_h =
		virusfilter_io_new(virusfilter_h, connect_timeout, io_timeout);

	if (!virusfilter_h->io_h) {
		DBG_ERR("virusfilter_io_new failed");
		return -1;
	}
#endif

	if (virusfilter_h->cache_entry_limit > 0) {
		virusfilter_h->cache_h = virusfilter_cache_new(vfs_h,
					virusfilter_h->cache_entry_limit,
					virusfilter_h->cache_time_limit);
		if (!virusfilter_h->cache_h) {
			DBG_ERR("Initializing cache failed: Cache disabled\n");
		}
	}

#ifdef virusfilter_module_connect
	if (virusfilter_module_connect(vfs_h, virusfilter_h, svc, user) == -1) {
		return -1;
	}
#endif

	/*
	 * Check quarantine directory now to save processing
	 * and becoming root over and over.
	 */
	if (virusfilter_h->infected_file_action ==
	    VIRUSFILTER_ACTION_QUARANTINE)
	{

		/*
		 * Do SMB_VFS_NEXT_MKDIR(virusfilter_h->quarantine_dir)
		 * hierarchy
		 */
		become_root();
		if (!quarantine_directory_exist(vfs_h,
		    virusfilter_h->quarantine_dir))
		{
			DBG_DEBUG("Creating quarantine directory: %s\n",
				  virusfilter_h->quarantine_dir);
			quarantine_create_dir(vfs_h, virusfilter_h,
					      virusfilter_h->quarantine_dir);
		}
		unbecome_root();
	}

	return SMB_VFS_NEXT_CONNECT(vfs_h, svc, user);
}

static void virusfilter_vfs_disconnect(vfs_handle_struct *vfs_h)
{
	virusfilter_handle *virusfilter_h;

#ifdef virusfilter_module_disconnect
	virusfilter_module_disconnect(vfs_h);
#endif

	SMB_VFS_HANDLE_GET_DATA(vfs_h, virusfilter_h, virusfilter_handle,
				return);

	free_namearray(virusfilter_h->exclude_files);
#ifdef VIRUSFILTER_DEFAULT_SOCKET_PATH
	virusfilter_io_disconnect(virusfilter_h->io_h);
#endif

	SMB_VFS_NEXT_DISCONNECT(vfs_h);
}

static int virusfilter_set_module_env(TALLOC_CTX *mem_ctx, char **env_list)
{
	if (virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_VERSION",
	    VIRUSFILTER_VERSION) == -1)
	{
		return -1;
	}
	if (virusfilter_env_set(mem_ctx, env_list, "VIRUSFILTER_MODULE_NAME",
	    VIRUSFILTER_MODULE_NAME) == -1)
	{
		return -1;
	}
#ifdef VIRUSFILTER_MODULE_VERSION
	if (virusfilter_env_set(mem_ctx, env_list,
	    "VIRUSFILTER_MODULE_VERSION", VIRUSFILTER_MODULE_VERSION) == -1)
	{
		return -1;
	}
#endif

	return 0;
}

static virusfilter_action virusfilter_do_infected_file_action(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const struct smb_filename *smb_fname,
	const char **filepath_newp)
{
	TALLOC_CTX *mem_ctx = talloc_tos();
	connection_struct *conn = vfs_h->conn;
	struct smb_filename *q_smb_fname = NULL;
	char *q_dir;
	char *q_prefix;
	char *q_suffix;
	char *q_filepath;
	char *dir_name = NULL;
	char *temp_path;
	const char *base_name = NULL;
	int q_fd;

	*filepath_newp = NULL;

	switch (virusfilter_h->infected_file_action) {
	case VIRUSFILTER_ACTION_RENAME:
		q_prefix = virusfilter_string_sub(mem_ctx, conn,
						virusfilter_h->rename_prefix);
		q_suffix = virusfilter_string_sub(mem_ctx, conn,
						virusfilter_h->rename_suffix);
		if (q_prefix == NULL || q_suffix == NULL) {
			DBG_ERR("Rename failed: %s/%s: Cannot allocate "
				"memory\n", conn->connectpath,
				smb_fname->base_name);
			TALLOC_FREE(q_prefix);
			TALLOC_FREE(q_suffix);
			return VIRUSFILTER_ACTION_DO_NOTHING;
		}

		if (!parent_dirname(mem_ctx, smb_fname->base_name, &q_dir,
		    &base_name))
		{
			DBG_ERR("Rename failed: %s/%s: Cannot allocate "
				"memory\n", conn->connectpath,
				smb_fname->base_name);
			TALLOC_FREE(q_prefix);
			TALLOC_FREE(q_suffix);
			return VIRUSFILTER_ACTION_DO_NOTHING;
		}

		if (q_dir == NULL) {
			DBG_ERR("Rename failed: %s/%s: Cannot allocate "
				"memory\n", conn->connectpath,
				smb_fname->base_name);
			TALLOC_FREE(q_prefix);
			TALLOC_FREE(q_suffix);
			return VIRUSFILTER_ACTION_DO_NOTHING;
		}

		q_filepath = talloc_asprintf(talloc_tos(), "%s/%s%s%s", q_dir,
					     q_prefix, base_name, q_suffix);

		TALLOC_FREE(q_dir);
		TALLOC_FREE(q_prefix);
		TALLOC_FREE(q_suffix);

		become_root();

		q_smb_fname = synthetic_smb_fname(mem_ctx, q_filepath,
						  smb_fname->stream_name, NULL,
						  smb_fname->flags);
		if (q_smb_fname == NULL) {
			unlink(q_filepath);
			unbecome_root();
			return VIRUSFILTER_ACTION_DO_NOTHING;
		}

		if (virusfilter_vfs_next_move(vfs_h, smb_fname, q_smb_fname)
		    == -1)
		{
			unbecome_root();
			DBG_ERR("Rename failed: %s/%s: Rename failed: %s\n",
				conn->connectpath, smb_fname->base_name,
				strerror(errno));
			return VIRUSFILTER_ACTION_DO_NOTHING;
		}
		unbecome_root();

		*filepath_newp = q_filepath;

		return VIRUSFILTER_ACTION_RENAME;

	case VIRUSFILTER_ACTION_QUARANTINE:
		q_dir = virusfilter_string_sub(mem_ctx, conn,
					virusfilter_h->quarantine_dir);
		q_prefix = virusfilter_string_sub(mem_ctx, conn,
					virusfilter_h->quarantine_prefix);
		q_suffix = virusfilter_string_sub(mem_ctx, conn,
					virusfilter_h->quarantine_suffix);
		if (q_dir == NULL || q_prefix == NULL || q_suffix == NULL) {
			DBG_ERR("Quarantine failed: %s/%s: Cannot allocate "
				"memory\n", conn->connectpath,
				smb_fname->base_name);
			TALLOC_FREE(q_dir);
			TALLOC_FREE(q_prefix);
			TALLOC_FREE(q_suffix);
			return VIRUSFILTER_ACTION_DO_NOTHING;
		}

		if (virusfilter_h->quarantine_keep_name ||
		    virusfilter_h->quarantine_keep_tree)
                {
			if (!parent_dirname(mem_ctx, smb_fname->base_name,
			    &dir_name, &base_name))
			{
				DBG_ERR("Quarantine failed: %s/%s: Cannot "
					"allocate memory\n", conn->connectpath,
					smb_fname->base_name);
				TALLOC_FREE(q_dir);
				TALLOC_FREE(q_prefix);
				TALLOC_FREE(q_suffix);
				return VIRUSFILTER_ACTION_DO_NOTHING;
			}

			if (virusfilter_h->quarantine_keep_tree) {
				temp_path = talloc_asprintf(mem_ctx, "%s/%s",
							    q_dir, dir_name);
				if (temp_path == NULL) {
					DBG_ERR("Quarantine failed: %s/%s: "
						"Cannot allocate memory\n",
						conn->connectpath,
						smb_fname->base_name);
					TALLOC_FREE(q_dir);
					TALLOC_FREE(q_prefix);
					TALLOC_FREE(q_suffix);
					return VIRUSFILTER_ACTION_DO_NOTHING;
				}

				become_root();
				if (quarantine_directory_exist(vfs_h,
				    temp_path))
				{
					DBG_DEBUG("quarantine: Directory "
						  "already exists\n");
					TALLOC_FREE(q_dir);
					q_dir = temp_path;
				} else {
					DBG_DEBUG("quarantine: Creating "
					      "directory %s\n", temp_path);
					if (quarantine_create_dir(vfs_h,
					    virusfilter_h, temp_path) == false)
					{
						DBG_NOTICE("quarantine: Could "
							"not create directory "
							"ignoring for %s...\n",
							smb_fname_str_dbg(
								smb_fname));
						TALLOC_FREE(temp_path);
					} else {
						TALLOC_FREE(q_dir);
						q_dir = temp_path;
					}
				}
				unbecome_root();
			}
		}
		if (virusfilter_h->quarantine_keep_name) {
			q_filepath = talloc_asprintf(talloc_tos(),
					"%s/%s%s%s-XXXXXX", q_dir, q_prefix,
					base_name, q_suffix);
		} else {
			q_filepath = talloc_asprintf(talloc_tos(),
					"%s/%sXXXXXX", q_dir, q_prefix);
		}

		TALLOC_FREE(dir_name);
		TALLOC_FREE(q_dir);
		TALLOC_FREE(q_prefix);
		TALLOC_FREE(q_suffix);

		if (q_filepath == NULL) {
			DBG_ERR("Quarantine failed: %s/%s: Cannot allocate "
				"memory\n", conn->connectpath,
				smb_fname->base_name);
			return VIRUSFILTER_ACTION_DO_NOTHING;
		}

		become_root();

		q_fd = mkstemp(q_filepath);
		if (q_fd == -1) {
			unbecome_root();
			DBG_ERR("Quarantine failed: %s/%s: Cannot open "
				"destination: %s: %s\n", conn->connectpath,
				smb_fname->base_name, q_filepath,
				strerror(errno));
			return VIRUSFILTER_ACTION_DO_NOTHING;
		}
		close(q_fd);

		q_smb_fname = synthetic_smb_fname(mem_ctx, q_filepath,
			smb_fname->stream_name, NULL, smb_fname->flags);
		if (q_smb_fname == NULL) {
			unlink(q_filepath);
			unbecome_root();
			return VIRUSFILTER_ACTION_DO_NOTHING;
		}

		if (virusfilter_vfs_next_move(vfs_h, smb_fname, q_smb_fname)
		    == -1)
		{
			unbecome_root();
			DBG_ERR("Quarantine failed: %s/%s: Rename failed: "
				"%s\n", conn->connectpath, smb_fname->base_name,
				strerror(errno));
			return VIRUSFILTER_ACTION_DO_NOTHING;
		}
		unbecome_root();

		*filepath_newp = q_filepath;

		return VIRUSFILTER_ACTION_QUARANTINE;

	case VIRUSFILTER_ACTION_DELETE:
		become_root();
		if (SMB_VFS_NEXT_UNLINK(vfs_h, smb_fname) == -1) {
			unbecome_root();
			DBG_ERR("Delete failed: %s/%s: Unlink failed: %s\n",
				conn->connectpath, smb_fname->base_name,
				strerror(errno));
			return VIRUSFILTER_ACTION_DO_NOTHING;
		}
		unbecome_root();
		return VIRUSFILTER_ACTION_DELETE;

	case VIRUSFILTER_ACTION_DO_NOTHING:
	default:
		return VIRUSFILTER_ACTION_DO_NOTHING;
	}
}

static virusfilter_action virusfilter_treat_infected_file(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const struct smb_filename *smb_fname,
	const char *report,
	bool is_cache)
{
	connection_struct *conn = vfs_h->conn;
	TALLOC_CTX *mem_ctx = talloc_tos();
	int i;
	virusfilter_action action;
	const char *action_name = "UNKNOWN";
	const char *filepath_q = NULL;
	char *env_list = NULL;
	char *command = NULL;
	int command_result;

	action = virusfilter_do_infected_file_action(vfs_h, virusfilter_h,
						     smb_fname, &filepath_q);
	for (i=0; virusfilter_actions[i].name; i++) {
		if (virusfilter_actions[i].value == action) {
			action_name = virusfilter_actions[i].name;
			break;
		}
	}
	DBG_WARNING("Infected file action: %s/%s: %s\n",
		    vfs_h->conn->connectpath, smb_fname->base_name, action_name);

	if (!virusfilter_h->infected_file_command) {
		return action;
	}

	if (virusfilter_set_module_env(mem_ctx, &env_list) == -1) {
		goto done;
	}
	if (virusfilter_env_set(mem_ctx, &env_list,
	    "VIRUSFILTER_INFECTED_SERVICE_FILE_PATH",
	    smb_fname->base_name) == -1)
	{
		goto done;
	}
	if (report && virusfilter_env_set(mem_ctx, &env_list,
	    "VIRUSFILTER_INFECTED_FILE_REPORT", report) == -1)
	{
		goto done;
	}
	if (virusfilter_env_set(mem_ctx, &env_list,
	    "VIRUSFILTER_INFECTED_FILE_ACTION", action_name) == -1)
	{
		goto done;
	}
	if (filepath_q && virusfilter_env_set(mem_ctx, &env_list,
	    "VIRUSFILTER_QUARANTINED_FILE_PATH", filepath_q) == -1)
	{
		goto done;
	}
	if (is_cache && virusfilter_env_set(mem_ctx, &env_list,
	    "VIRUSFILTER_RESULT_IS_CACHE", "yes") == -1)
	{
		goto done;
	}

	command = virusfilter_string_sub(mem_ctx, conn,
					 virusfilter_h->infected_file_command);
	if (command == NULL) {
		DBG_ERR("virusfilter_string_sub failed\n");
		goto done;
	}

	DBG_NOTICE("Infected file command line: %s/%s: %s\n",
		   vfs_h->conn->connectpath, smb_fname->base_name, command);

	command_result = virusfilter_shell_run(mem_ctx, command, &env_list,
					       vfs_h->conn, true);
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
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const struct smb_filename *smb_fname,
	const char *report,
	bool is_cache)
{
	connection_struct *conn = vfs_h->conn;
	TALLOC_CTX *mem_ctx = talloc_tos();
	char *env_list = NULL;
	char *command = NULL;
	int command_result;

	if (!virusfilter_h->scan_error_command) {
		return;
	}
	if (virusfilter_set_module_env(mem_ctx, &env_list) == -1) {
		goto done;
	}
	if (virusfilter_env_set(mem_ctx, &env_list,
	    "VIRUSFILTER_SCAN_ERROR_SERVICE_FILE_PATH",
	    smb_fname->base_name) == -1)
	{
		goto done;
	}
	if (report && virusfilter_env_set(mem_ctx, &env_list,
	    "VIRUSFILTER_SCAN_ERROR_REPORT", report) == -1)
	{
		goto done;
	}
	if (is_cache && virusfilter_env_set(mem_ctx, &env_list,
	    "VIRUSFILTER_RESULT_IS_CACHE", "1") == -1)
	{
		goto done;
	}

	command = virusfilter_string_sub(mem_ctx, conn,
					 virusfilter_h->scan_error_command);
	if (!command) {
		DBG_ERR("virusfilter_string_sub failed\n");
		goto done;
	}

	DBG_NOTICE("Scan error command line: %s/%s: %s\n",
	      vfs_h->conn->connectpath, smb_fname->base_name, command);

	command_result = virusfilter_shell_run(mem_ctx, command, &env_list,
					       vfs_h->conn, true);
	if (command_result != 0) {
		DBG_ERR("Scan error command failed: %d\n", command_result);
	}

done:
	TALLOC_FREE(env_list);
	TALLOC_FREE(command);
}

static virusfilter_result virusfilter_scan(
	vfs_handle_struct *vfs_h,
	virusfilter_handle *virusfilter_h,
	const struct smb_filename *smb_fname)
{
	virusfilter_result scan_result;
	const char *scan_report = NULL;
	char *fname = smb_fname->base_name;
	virusfilter_cache_entry *scan_cache_e = NULL;
	bool is_cache = false;
	virusfilter_action file_action = VIRUSFILTER_ACTION_DO_NOTHING;
	bool add_scan_cache = true;

	if (virusfilter_h->cache_h) {
		DBG_DEBUG("Searching cache entry: fname: %s\n", fname);
		scan_cache_e = virusfilter_cache_get(virusfilter_h->cache_h,
						     fname);
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

#ifdef virusfilter_module_scan_init
	if (virusfilter_module_scan_init(virusfilter_h) !=
	    VIRUSFILTER_RESULT_OK)
	{
		scan_result = VIRUSFILTER_RESULT_ERROR;
		scan_report = "Initializing scanner failed";
		goto virusfilter_scan_result_eval;
	}
#endif

	scan_result = virusfilter_module_scan(vfs_h, virusfilter_h, smb_fname,
					      &scan_report);

#ifdef virusfilter_module_scan_end
#ifdef VIRUSFILTER_DEFAULT_SCAN_REQUEST_LIMIT
	if (virusfilter_h->scan_request_limit > 0) {
		virusfilter_h->scan_request_count++;
		if (virusfilter_h->scan_request_count >=
		    virusfilter_h->scan_request_limit)
		{
			virusfilter_module_scan_end(virusfilter_h);
			virusfilter_h->scan_request_count = 0;
		}
	}
#else
	virusfilter_module_scan_end(virusfilter_h);
#endif
#endif

virusfilter_scan_result_eval:

	switch (scan_result) {
	case VIRUSFILTER_RESULT_CLEAN:
		DBG_INFO("Scan result: Clean: %s/%s\n",
		      vfs_h->conn->connectpath, fname);
		break;
	case VIRUSFILTER_RESULT_INFECTED:
		DBG_ERR("Scan result: Infected: %s/%s: %s\n",
		      vfs_h->conn->connectpath, fname, scan_report);
		file_action = virusfilter_treat_infected_file(vfs_h,
					virusfilter_h, smb_fname,
					scan_report, is_cache);
		if (file_action != VIRUSFILTER_ACTION_DO_NOTHING) {
			add_scan_cache = false;
		}
		break;
#ifdef VIRUSFILTER_DEFAULT_BLOCK_SUSPECTED_FILE
	case VIRUSFILTER_RESULT_SUSPECTED:
		DBG_ERR("Scan result: Suspected: %s/%s: %s\n",
		      vfs_h->conn->connectpath, fname, scan_report);
		file_action = virusfilter_treat_infected_file(vfs_h,
					virusfilter_h, smb_fname,
					scan_report, is_cache);
		if (file_action != VIRUSFILTER_ACTION_DO_NOTHING) {
			add_scan_cache = false;
		}
		break;
#endif
	case VIRUSFILTER_RESULT_ERROR:
		DBG_ERR("Scan result: Error: %s/%s: %s\n",
		      vfs_h->conn->connectpath, fname, scan_report);
		virusfilter_treat_scan_error(vfs_h, virusfilter_h, smb_fname,
					     scan_report, is_cache);
		add_scan_cache = false;
		break;
	default:
		DBG_ERR("Scan result: Unknown result code %d: %s/%s: %s\n",
			scan_result, vfs_h->conn->connectpath, fname,
			scan_report);
		virusfilter_treat_scan_error(vfs_h, virusfilter_h, smb_fname,
					     scan_report, is_cache);
		add_scan_cache = false;
		break;
	}

	if (virusfilter_h->cache_h) {
		if (!is_cache && add_scan_cache) {
			DBG_DEBUG("Adding new cache entry: %s, %d\n", fname,
				  scan_result);
			if (!virusfilter_cache_entry_add(
			    virusfilter_h->cache_h, fname, scan_result,
			    scan_report))
			{
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

static int virusfilter_vfs_open(
	vfs_handle_struct *vfs_h,
	struct smb_filename *smb_fname,
	files_struct *fsp,
	int flags,
	mode_t mode)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	virusfilter_handle *virusfilter_h;
	virusfilter_result scan_result;
	char *fname = smb_fname->base_name;
	char *dir_name = NULL;
	const char *base_name = NULL;
	int scan_errno = 0;
	int test_prefix;
	int test_suffix;
	int rename_trap_count = 0;

	SMB_VFS_HANDLE_GET_DATA(vfs_h, virusfilter_h, virusfilter_handle,
				return -1);

	test_prefix = strlen(virusfilter_h->rename_prefix);
	test_suffix = strlen(virusfilter_h->rename_suffix);
	if (test_prefix) {
		rename_trap_count++;
	}
	if (test_suffix) {
		rename_trap_count++;
	}

        if (!virusfilter_h->scan_on_open) {
                DBG_INFO("Not scanned: scan on open is disabled: %s/%s\n",
			 vfs_h->conn->connectpath, fname);
		goto virusfilter_vfs_open_next;
        }

	if (flags & O_TRUNC) {
                DBG_INFO("Not scanned: Open flags have O_TRUNC: %s/%s\n",
			 vfs_h->conn->connectpath, fname);
		goto virusfilter_vfs_open_next;
	}

	if (SMB_VFS_NEXT_STAT(vfs_h, smb_fname) != 0) {

		/*
		 * Do not return immediately if !(flags & O_CREAT) &&
		 * errno != ENOENT.
		 * Do not do this here or anywhere else. The module is
		 * stackable and there may be modules below, such as audit
		 * modules, which should be handled.
		 */
		goto virusfilter_vfs_open_next;
	}
	if (!S_ISREG(smb_fname->st.st_ex_mode)) {
                DBG_INFO("Not scanned: Directory or special file: %s/%s\n",
			 vfs_h->conn->connectpath, fname);
		goto virusfilter_vfs_open_next;
	}
	if (virusfilter_h->max_file_size > 0 && smb_fname->st.st_ex_size >
	    virusfilter_h->max_file_size)
	{
                DBG_INFO("Not scanned: file size > max file size: %s/%s\n",
			 vfs_h->conn->connectpath, fname);
		goto virusfilter_vfs_open_next;
	}
	if (virusfilter_h->min_file_size > 0 && smb_fname->st.st_ex_size <
	    virusfilter_h->min_file_size)
	{
                DBG_INFO("Not scanned: file size < min file size: %s/%s\n",
		      vfs_h->conn->connectpath, fname);
		goto virusfilter_vfs_open_next;
	}

	if (virusfilter_h->exclude_files && is_in_path(fname,
	    virusfilter_h->exclude_files, false))
	{
                DBG_INFO("Not scanned: exclude files: %s/%s\n",
			 vfs_h->conn->connectpath, fname);
		goto virusfilter_vfs_open_next;
	}

	if (test_prefix || test_suffix) {
		if (parent_dirname(mem_ctx, smb_fname->base_name, &dir_name,
		    &base_name))
		{
			if (test_prefix) {
				if (strncmp(base_name,
				    virusfilter_h->rename_prefix,
				    test_prefix) != 0)
				{
					test_prefix = 0;
				}
			}
			if (test_suffix) {
				if (strcmp(base_name + (strlen(base_name) -
				    test_suffix),
				    virusfilter_h->rename_suffix) != 0)
				{
					test_suffix = 0;
				}
			}

			TALLOC_FREE(dir_name);

			if ((rename_trap_count == 2 && test_prefix &&
			    test_suffix) || (rename_trap_count == 1 &&
			    (test_prefix || test_suffix)))
			{
				scan_errno =
					virusfilter_h->infected_open_errno;
				goto virusfilter_vfs_open_fail;
			}
		}
	}

	scan_result = virusfilter_scan(vfs_h, virusfilter_h, smb_fname);

	switch (scan_result) {
	case VIRUSFILTER_RESULT_CLEAN:
		break;
	case VIRUSFILTER_RESULT_INFECTED:
		scan_errno = virusfilter_h->infected_open_errno;
		goto virusfilter_vfs_open_fail;
	case VIRUSFILTER_RESULT_ERROR:
		if (virusfilter_h->block_access_on_error) {
			DBG_INFO("Block access\n");
			scan_errno = virusfilter_h->scan_error_open_errno;
			goto virusfilter_vfs_open_fail;
		}
		break;
	default:
		scan_errno = virusfilter_h->scan_error_open_errno;
		goto virusfilter_vfs_open_fail;
	}

virusfilter_vfs_open_next:
	TALLOC_FREE(mem_ctx);
	return SMB_VFS_NEXT_OPEN(vfs_h, smb_fname, fsp, flags, mode);

virusfilter_vfs_open_fail:
	TALLOC_FREE(mem_ctx);
	errno = (scan_errno != 0) ? scan_errno : EACCES;
	return -1;
}

static int virusfilter_vfs_close(vfs_handle_struct *vfs_h, files_struct *fsp)
{
	TALLOC_CTX *mem_ctx = talloc_stackframe();
	connection_struct *conn = vfs_h->conn;
	virusfilter_handle *virusfilter_h;
	char *fname = fsp->fsp_name->base_name;
	int close_result, close_errno;
	virusfilter_result scan_result;
	int scan_errno = 0;

	SMB_VFS_HANDLE_GET_DATA(vfs_h, virusfilter_h, virusfilter_handle,
				return -1);

	/*
	 * Must close after scan? It appears not as the scanners are not
	 * internal and other modules such as greyhole seem to do
	 * SMB_VFS_NEXT_* functions before processing.
	 */
	close_result = SMB_VFS_NEXT_CLOSE(vfs_h, fsp);
	close_errno = errno;

	/*
	 * Return immediately if close_result == -1, and close_errno == EBADF.
	 * If close failed, file likely doesn't exist, do not try to scan.
	 */
	if (close_result == -1 && close_errno == EBADF) {
		if (fsp->modified) {
			DBG_DEBUG("Removing cache entry (if existent): "
				  "fname: %s\n", fname);
			virusfilter_cache_remove(virusfilter_h->cache_h,
						 fname);
		}
		goto virusfilter_vfs_close_fail;
	}

	if (fsp->is_directory) {
                DBG_INFO("Not scanned: Directory: %s/%s\n", conn->connectpath,
			 fname);
		TALLOC_FREE(mem_ctx);
		return close_result;
	}

	if (!virusfilter_h->scan_on_close) {
                if (virusfilter_h->scan_on_open && fsp->modified) {
			if (virusfilter_h->cache_h) {
				DBG_DEBUG("Removing cache entry (if existent)"
					  ": fname: %s\n", fname);
				virusfilter_cache_remove(
						virusfilter_h->cache_h, fname);
			}
                }
                DBG_INFO("Not scanned: scan on close is disabled: %s/%s\n",
			 conn->connectpath, fname);
		TALLOC_FREE(mem_ctx);
		return close_result;
	}

	if (!fsp->modified) {
		DBG_NOTICE("Not scanned: File not modified: %s/%s\n",
			   conn->connectpath, fname);

		TALLOC_FREE(mem_ctx);
		return close_result;
	}

	if (virusfilter_h->exclude_files && is_in_path(fname,
	    virusfilter_h->exclude_files, false))
	{
                DBG_INFO("Not scanned: exclude files: %s/%s\n",
			 conn->connectpath, fname);
		TALLOC_FREE(mem_ctx);
		return close_result;
	}

	scan_result = virusfilter_scan(vfs_h, virusfilter_h, fsp->fsp_name);

	switch (scan_result) {
	case VIRUSFILTER_RESULT_CLEAN:
		break;
	case VIRUSFILTER_RESULT_INFECTED:
		scan_errno = virusfilter_h->infected_close_errno;
		goto virusfilter_vfs_close_fail;
	case VIRUSFILTER_RESULT_ERROR:
		if (virusfilter_h->block_access_on_error) {
			DBG_INFO("Block access\n");
			scan_errno = virusfilter_h->scan_error_close_errno;
			goto virusfilter_vfs_close_fail;
		}
		break;
	default:
		scan_errno = virusfilter_h->scan_error_close_errno;
		goto virusfilter_vfs_close_fail;
	}

	TALLOC_FREE(mem_ctx);
	errno = close_errno;

	return close_result;

virusfilter_vfs_close_fail:

	TALLOC_FREE(mem_ctx);
	errno = (scan_errno != 0) ? scan_errno : close_errno;

	return close_result;
}

static int virusfilter_vfs_unlink(
	vfs_handle_struct *vfs_h,
	const struct smb_filename *smb_fname)
{
	int ret = SMB_VFS_NEXT_UNLINK(vfs_h, smb_fname);
	virusfilter_handle *virusfilter_h;
	char *fname;

	if (ret != 0 && errno != ENOENT) {
		return ret;
	}

	SMB_VFS_HANDLE_GET_DATA(vfs_h, virusfilter_h, virusfilter_handle,
				return -1);

	if (virusfilter_h->cache_h) {
		fname = smb_fname->base_name;
		DBG_DEBUG("Removing cache entry (if existent): fname: %s\n",
			  fname);
		virusfilter_cache_remove(virusfilter_h->cache_h, fname);
	}

	return ret;
}

static int virusfilter_vfs_rename(
	vfs_handle_struct *vfs_h,
	const struct smb_filename *smb_fname_src,
	const struct smb_filename *smb_fname_dst)
{
	int ret = SMB_VFS_NEXT_RENAME(vfs_h, smb_fname_src, smb_fname_dst);
	virusfilter_handle *virusfilter_h;
	char *fname;

	if (ret != 0) {
		return ret;
	}

	SMB_VFS_HANDLE_GET_DATA(vfs_h, virusfilter_h, virusfilter_handle,
				return -1);

	if (virusfilter_h->cache_h) {
		fname = smb_fname_dst->base_name;
		DBG_DEBUG("Removing cache entry (if existent): fname: %s\n",
			  fname);
		virusfilter_cache_remove(virusfilter_h->cache_h, fname);

		fname = smb_fname_src->base_name;
		DBG_DEBUG("Renaming cache entry: fname: %s to: %s\n", fname,
			  smb_fname_dst->base_name);
		virusfilter_cache_entry_rename(virusfilter_h->cache_h, fname,
					       smb_fname_dst->base_name);
	}

	return ret;
}

/* VFS operations */
static struct vfs_fn_pointers vfs_virusfilter_fns = {
	.connect_fn =	virusfilter_vfs_connect,
	.disconnect_fn =virusfilter_vfs_disconnect,
	.open_fn =	virusfilter_vfs_open,
	.close_fn =	virusfilter_vfs_close,
	.unlink_fn =	virusfilter_vfs_unlink,
	.rename_fn =	virusfilter_vfs_rename,
};

#define MAKE_FN_NAME(x) NTSTATUS vfs_virusfilter_ ## x ## _init(void)
#define VFS_VIRUSFILTER_INIT(ENGINE) MAKE_FN_NAME(ENGINE)

VFS_VIRUSFILTER_INIT(VIRUSFILTER_ENGINE);
VFS_VIRUSFILTER_INIT(VIRUSFILTER_ENGINE)
{
	NTSTATUS ret;

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
			       VIRUSFILTER_MODULE_NAME, &vfs_virusfilter_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	virusfilter_debug_level = debug_add_class(VIRUSFILTER_MODULE_NAME);
	if (virusfilter_debug_level == -1) {
		virusfilter_debug_level = DBGC_VFS;
		DBG_ERR("Couldn't register custom debugging class!\n");
	} else {
		DBG_DEBUG("Debug class number of '%s': %d\n",
			  VIRUSFILTER_MODULE_NAME, virusfilter_debug_level);
	}

	DBG_INFO("%s registered\n", VIRUSFILTER_MODULE_NAME);

	return ret;
}
