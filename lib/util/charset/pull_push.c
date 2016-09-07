/*
   Unix SMB/CIFS implementation.
   Character set conversion Extensions
   Copyright (C) Igor Vergeichik <iverg@mail.ru> 2001
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Simo Sorce 2001
   Copyright (C) Martin Pool 2003

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

#include "includes.h"
#include "system/locale.h"

/**
 * Copy a string from a unix char* src to a UCS2 destination,
 * allocating a buffer using talloc().
 *
 * @param dest always set at least to NULL
 * @parm converted_size set to the number of bytes occupied by the string in
 * the destination on success.
 *
 * @return true if new buffer was correctly allocated, and string was
 * converted.
 **/
bool push_ucs2_talloc(TALLOC_CTX *ctx, smb_ucs2_t **dest, const char *src,
		      size_t *converted_size)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(ctx, CH_UNIX, CH_UTF16LE, src, src_len,
				     (void **)dest, converted_size);
}

/**
 * @brief Create a UTF-8 string from a unix charset string.
 *
 * The resulting UTF-8 string is talloc'ed.
 *
 * @param[in]  ctx      The talloc memory context.
 *
 * @param[in]  dest     A pointer to store the pointer to the talloc'ed UTF-8
 *                      string.
 *
 * @param[in]  src      The unix charset string to convert.
 *
 * @param[in]  converted_size A pointer to store the length of the talloc'ed
 *                            UTF-8 string including the nul-termination bytes.
 *
 * The destination string should be free'd using talloc_free() if no longer
 * needed.
 *
 * @return True on succcess, false otherwise.
 */
bool push_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		      size_t *converted_size)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(ctx, CH_UNIX, CH_UTF8, src, src_len,
				     (void**)dest, converted_size);
}

/**
 * Copy a string from a unix char* src to an ASCII destination,
 * allocating a buffer using talloc().
 *
 * @param dest always set at least to NULL
 *
 * @param converted_size The number of bytes occupied by the string in the destination
 * @returns boolean indicating if the conversion was successful
 **/
bool push_ascii_talloc(TALLOC_CTX *mem_ctx, char **dest, const char *src, size_t *converted_size)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(mem_ctx, CH_UNIX, CH_DOS, src, src_len,
				     (void **)dest, converted_size);
}

/**
 * Copy a string from a UCS2 src to a unix char * destination, allocating a buffer using talloc
 *
 * @param dest always set at least to NULL
 * @parm converted_size set to the number of bytes occupied by the string in
 * the destination on success.
 *
 * @return true if new buffer was correctly allocated, and string was
 * converted.
 **/

bool pull_ucs2_talloc(TALLOC_CTX *ctx, char **dest, const smb_ucs2_t *src,
		      size_t *converted_size)
{
	size_t src_len = (strlen_w(src)+1) * sizeof(smb_ucs2_t);

	*dest = NULL;
	return convert_string_talloc(ctx, CH_UTF16LE, CH_UNIX, src, src_len,
				     (void **)dest, converted_size);
}


/**
 * Copy a string from a UTF-8 src to a unix char * destination, allocating a buffer using talloc
 *
 * @param dest always set at least to NULL
 * @parm converted_size set to the number of bytes occupied by the string in
 * the destination on success.
 *
 * @return true if new buffer was correctly allocated, and string was
 * converted.
 **/

bool pull_utf8_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		      size_t *converted_size)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(ctx, CH_UTF8, CH_UNIX, src, src_len,
				     (void **)dest, converted_size);
}


/**
 * Copy a string from a DOS src to a unix char * destination, allocating a buffer using talloc
 *
 * @param dest always set at least to NULL
 * @parm converted_size set to the number of bytes occupied by the string in
 * the destination on success.
 *
 * @return true if new buffer was correctly allocated, and string was
 * converted.
 **/

bool pull_ascii_talloc(TALLOC_CTX *ctx, char **dest, const char *src,
		       size_t *converted_size)
{
	size_t src_len = strlen(src)+1;

	*dest = NULL;
	return convert_string_talloc(ctx, CH_DOS, CH_UNIX, src, src_len,
				     (void **)dest, converted_size);
}
