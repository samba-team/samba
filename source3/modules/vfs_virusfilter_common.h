/*
   Samba-VirusFilter VFS modules
   Copyright (C) 2010-2016 SATOH Fumiyasu @ OSS Technology Corp., Japan

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

#ifndef _VIRUSFILTER_COMMON_H
#define _VIRUSFILTER_COMMON_H

#include <stdint.h>
#include <time.h>

/* Samba common include file */
#include "includes.h"

#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "system/filesys.h"
#include "transfer_file.h"
#include "auth.h"
#include "passdb.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "../lib/tsocket/tsocket.h"

/* Samba debug class for VIRUSFILTER */
#undef DBGC_CLASS
#define DBGC_CLASS virusfilter_debug_class
extern int virusfilter_debug_class;

/* Samba's global variable */
extern userdom_struct current_user_info;

#define VIRUSFILTER_VERSION "0.1.5"

/* ====================================================================== */

typedef enum {
	VIRUSFILTER_ACTION_DO_NOTHING,
	VIRUSFILTER_ACTION_QUARANTINE,
	VIRUSFILTER_ACTION_RENAME,
	VIRUSFILTER_ACTION_DELETE,
} virusfilter_action;

typedef enum {
	VIRUSFILTER_RESULT_OK,
	VIRUSFILTER_RESULT_CLEAN,
	VIRUSFILTER_RESULT_ERROR,
	VIRUSFILTER_RESULT_INFECTED,
	VIRUSFILTER_RESULT_SUSPECTED,
	/* FIXME: VIRUSFILTER_RESULT_RISKWARE, */
} virusfilter_result;

struct virusfilter_config {
	int				scan_request_count;
	int				scan_request_limit;

	/* Scan on file operations */
	bool				scan_on_open;
	bool				scan_on_close;

	/* Special scan options */
	bool				scan_archive;
	int				max_nested_scan_archive;
	bool				scan_mime;
	bool				block_suspected_file;

	/* Size limit */
	size_t				max_file_size;
	size_t				min_file_size;

	/* Exclude files */
	name_compare_entry		*exclude_files;

	/* Scan result cache */
	struct virusfilter_cache	*cache;
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
	const char *			quarantine_prefix;
	const char *			quarantine_suffix;
	bool				quarantine_keep_tree;
	bool				quarantine_keep_name;
	mode_t				quarantine_dir_mode;

	/* Rename infected files */
	const char *			rename_prefix;
	const char *			rename_suffix;

	/* Network options */
	const char *			socket_path;
	struct virusfilter_io_handle	*io_h;

	/* The backend AV engine */
	struct virusfilter_backend	*backend;
};

struct virusfilter_backend_fns {
	int (*connect)(
		struct vfs_handle_struct *handle,
		struct virusfilter_config *config,
		const char *svc,
		const char *user);
	void (*disconnect)(
		struct vfs_handle_struct *handle);
	virusfilter_result (*scan_init)(
		struct virusfilter_config *config);
	virusfilter_result (*scan)(
		struct vfs_handle_struct *handle,
		struct virusfilter_config *config,
		const struct files_struct *fsp,
		char **reportp);
	void (*scan_end)(
		struct virusfilter_config *config);
};

struct virusfilter_backend {
	unsigned version;
	const char *name;
	const struct virusfilter_backend_fns *fns;
	void *backend_private;
};

int virusfilter_sophos_init(struct virusfilter_config *config);
int virusfilter_fsav_init(struct virusfilter_config *config);
int virusfilter_clamav_init(struct virusfilter_config *config);

#endif /* _VIRUSFILTER_COMMON_H */
