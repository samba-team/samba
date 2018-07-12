/*
   Low level event script handling

   Copyright (C) Amitay Isaacs  2017
   Copyright (C) Martin Schwenke  2018

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __CTDB_SCRIPT_H__
#define __CTDB_SCRIPT_H__

#include "replace.h"
#include "system/filesys.h"

#include <talloc.h>

/**
 * @file script.h
 *
 * @brief Script listing and manipulation
 */


struct event_script {
	char *name;
	char *path;
	bool enabled;
};

struct event_script_list {
	unsigned int num_scripts;
	struct event_script **script;
};


/**
 * @brief Retrieve a list of scripts
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] script_dir Directory containing scripts
 * @param[out] out List of scripts
 * @return 0 on success, errno on failure
 */
int event_script_get_list(TALLOC_CTX *mem_ctx,
			  const char *script_dir,
			  struct event_script_list **out);

/**
 * @brief Make a script executable or not executable
 *
 * @param[in] script_dir Directory containing script
 * @param[in] script_name Name of the script to enable
 * @param[in] executable True if script should be made executable
 * @return 0 on success, errno on failure
 */
int event_script_chmod(const char *script_dir,
		       const char *script_name,
		       bool executable);

#endif /* __CTDB_SCRIPT_H__ */
