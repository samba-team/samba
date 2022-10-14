/*
 * Unix SMB/CIFS implementation.
 *
 * Implementation of
 * http://msdn.microsoft.com/en-us/library/cc232006%28v=PROT.13%29.aspx
 *
 * Copyright (C) Volker Lendecke 2011
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

#ifndef __REPARSE_SYMLINK_H__
#define __REPARSE_SYMLINK_H__

#include "replace.h"
#include <talloc.h>

struct symlink_reparse_struct {
	uint16_t unparsed_path_length; /* reserved for the reparse point */
	char *substitute_name;
	char *print_name;
	uint32_t flags;
};

bool symlink_reparse_buffer_marshall(
	const char *substitute,
	const char *printname,
	uint16_t unparsed_path_length,
	uint32_t flags,
	TALLOC_CTX *mem_ctx,
	uint8_t **pdst,
	size_t *pdstlen);
struct symlink_reparse_struct *symlink_reparse_buffer_parse(
	TALLOC_CTX *mem_ctx, const uint8_t *src, size_t srclen);

#endif
