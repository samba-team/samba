/*
 * Unix SMB/CIFS implementation.
 * SMB parameters and setup
 * Copyright (C) Andrew Tridgell 1992-1998 Modified by Jeremy Allison 1995.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __LIB_UTIL_FILE_H__
#define __LIB_UTIL_FILE_H__

#include "replace.h"
#include <tevent.h>

struct tevent_req *file_ploadv_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   char * const argl[], size_t maxsize);
int file_ploadv_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		    uint8_t **buf);
char **file_lines_ploadv(TALLOC_CTX *mem_ctx,
			char * const argl[],
			int *numlines);

#endif
