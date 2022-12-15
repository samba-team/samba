/*
 * Unix SMB/CIFS implementation.
 * Samba utility functions
 * Copyright (C) Andrew Tridgell 1992-1998
 * Copyright (C) Jeremy Allison 2001-2007
 * Copyright (C) Simo Sorce 2001
 * Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2003
 * Copyright (C) James Peach 2006
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

#ifndef __LIB_UTIL_PATH_H__
#define __LIB_UTIL_PATH_H__

#include "replace.h"
#include <talloc.h>
#include "lib/util/time.h"

/*
 * Timestamp format used in "previous versions":
 * This is the windows-level format of the @GMT- token.
 * It is a fixed format not to be confused with the
 * format for the POSIX-Level token of the shadow_copy2
 * VFS module that can be configured via the "shadow:format"
 * configuration option but defaults to the same format.
 * See the shadow_copy2 module.
 */
#define GMT_NAME_LEN 24 /* length of a @GMT- name */
#define GMT_FORMAT "@GMT-%Y.%m.%d-%H.%M.%S"

char *lock_path(TALLOC_CTX *mem_ctx, const char *name);
char *state_path(TALLOC_CTX *mem_ctx, const char *name);
char *cache_path(TALLOC_CTX *mem_ctx, const char *name);
char *canonicalize_absolute_path(TALLOC_CTX *ctx, const char *abs_path);
bool extract_snapshot_token(char *fname, NTTIME *twrp);
bool clistr_smb2_extract_snapshot_token(char *fname, NTTIME *twrp);
bool clistr_is_previous_version_path(const char *path);
bool subdir_of(const char *parent,
	       size_t parent_len,
	       const char *subdir,
	       const char **_relative);

#endif
