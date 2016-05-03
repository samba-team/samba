/*
 * Unix SMB/CIFS implementation.
 * Samba utility functions
 *
 * Copyright (C) Andrew Tridgell 1992-2001
 * Copyright (C) Simo Sorce      2001-2002
 * Copyright (C) Martin Pool     2003
 * Copyright (C) James Peach	 2006
 * Copyright (C) Jeremy Allison  1992-2007
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

#ifndef __LIB_UTIL_BASE64_H__
#define __LIB_UTIL_BASE64_H__

#include "replace.h"
#include "lib/util/data_blob.h"

/**
 Base64 decode a string, place into a data blob.  Caller to
 data_blob_free() the result.
**/
DATA_BLOB base64_decode_data_blob_talloc(TALLOC_CTX *mem_ctx, const char *s);

/**
 Base64 decode a string, place into a data blob on NULL context.
 Caller to data_blob_free() the result.
**/
DATA_BLOB base64_decode_data_blob(const char *s);

/**
 Base64 decode a string, inplace
**/
void base64_decode_inplace(char *s);
/**
 Base64 encode a binary data blob into a string
**/
char *base64_encode_data_blob(TALLOC_CTX *mem_ctx, DATA_BLOB data);

#endif
