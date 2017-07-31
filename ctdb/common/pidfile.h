/*
   Create and remove pidfile

   Copyright (C) Amitay Isaacs  2016

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

#ifndef __CTDB_PIDFILE_H__
#define __CTDB_PIDFILE_H__

#include <talloc.h>

/**
 * @file pidfile.h
 *
 * @brief Routines to manage PID file
 */

/**
 * @brief Abstract struct to store pidfile details
 */
struct pidfile_context;

/**
 * @brief Create a PID file
 *
 * This creates a PID file, locks it, and writes PID.
 *
 * @param[in] mem_ctx Talloc memory context
 * @param[in] pidfile Path of PID file
 * @param[out] result Pidfile context
 * @return 0 on success, errno on failure
 *
 * Freeing the pidfile_context, will delete the pidfile.
 */
int pidfile_context_create(TALLOC_CTX *mem_ctx, const char *pidfile,
			   struct pidfile_context **result);

#endif /* __CTDB_PIDFILE_H__ */
