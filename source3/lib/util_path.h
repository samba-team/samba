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

char *lock_path(TALLOC_CTX *mem_ctx, const char *name);
char *state_path(TALLOC_CTX *mem_ctx, const char *name);
char *cache_path(TALLOC_CTX *mem_ctx, const char *name);
char *canonicalize_absolute_path(TALLOC_CTX *ctx, const char *abs_path);

#endif
