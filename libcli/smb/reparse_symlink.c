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

#include "replace.h"
#include "reparse_symlink.h"
#include "lib/util/charset/charset.h"
#include "lib/util/byteorder.h"
#include "libcli/smb/smb_constants.h"
#include "libcli/smb/smb_util.h"
#include "lib/util/debug.h"

bool symlink_reparse_buffer_marshall(
	const char *substitute,
	const char *printname,
	uint16_t unparsed_path_length,
	uint32_t flags,
	TALLOC_CTX *mem_ctx,
	uint8_t **pdst,
	size_t *pdstlen)
{
	uint8_t *dst = NULL;
	size_t dst_len;
	uint8_t *subst_utf16 = NULL;
	uint8_t *print_utf16 = NULL;
	size_t subst_len = 0;
	size_t print_len = 0;
	bool ret = false;
	bool ok;

	if (substitute == NULL) {
		return false;
	}
	if (printname == NULL) {
		printname = substitute;
	}

	ok = convert_string_talloc(
		mem_ctx,
		CH_UNIX,
		CH_UTF16,
		substitute,
		strlen(substitute),
		&subst_utf16,
		&subst_len);
	if (!ok) {
		goto fail;
	}

	ok = convert_string_talloc(
		mem_ctx,
		CH_UNIX,
		CH_UTF16,
		printname,
		strlen(printname),
		&print_utf16,
		&print_len);
	if (!ok) {
		goto fail;
	}

	dst_len = subst_len + 20;
	if (dst_len < 20) {
		goto fail;
	}
	dst_len += print_len;
	if (dst_len < print_len) {
		goto fail;
	}
	dst = talloc_array(mem_ctx, uint8_t, dst_len);
	if (dst == NULL) {
		goto fail;
	}

	SIVAL(dst, 0, IO_REPARSE_TAG_SYMLINK);	   /* ReparseTag */
	SSVAL(dst, 4, 12 + subst_len + print_len); /* ReparseDataLength */
	SSVAL(dst, 6, unparsed_path_length);	   /* Reserved */
	SSVAL(dst, 8, 0);			   /* SubstituteNameOffset */
	SSVAL(dst, 10, subst_len);		   /* SubstituteNameLength */
	SSVAL(dst, 12, subst_len);		   /* PrintNameOffset */
	SSVAL(dst, 14, print_len);		   /* PrintNameLength */
	SIVAL(dst, 16, flags);			   /* Flags */

	if ((subst_utf16 != NULL) && (subst_len != 0)) {
		memcpy(dst + 20, subst_utf16, subst_len);
	}

	if ((print_utf16 != NULL) && (print_len != 0)) {
		memcpy(dst + 20 + subst_len, print_utf16, print_len);
	}

	*pdst = dst;
	*pdstlen = dst_len;
	ret = true;

fail:
	TALLOC_FREE(subst_utf16);
	TALLOC_FREE(print_utf16);
	return ret;
}

struct symlink_reparse_struct *symlink_reparse_buffer_parse(
	TALLOC_CTX *mem_ctx, const uint8_t *src, size_t srclen)
{
	struct symlink_reparse_struct *result = NULL;
	uint16_t reparse_data_length;
	uint16_t substitute_name_offset, substitute_name_length;
	uint16_t print_name_offset, print_name_length;
	bool ok;

	if (srclen < 20) {
		DBG_DEBUG("srclen = %zu, expected >= 20\n", srclen);
		goto fail;
	}
	if (IVAL(src, 0) != IO_REPARSE_TAG_SYMLINK) {
		DBG_DEBUG("Got ReparseTag %8.8x, expected %8.8x\n",
			  IVAL(src, 0),
			  IO_REPARSE_TAG_SYMLINK);
		goto fail;
	}

	reparse_data_length	= SVAL(src, 4);
	substitute_name_offset	= SVAL(src, 8);
	substitute_name_length	= SVAL(src, 10);
	print_name_offset	= SVAL(src, 12);
	print_name_length	= SVAL(src, 14);

	if (reparse_data_length < 12) {
		DBG_DEBUG("reparse_data_length = %"PRIu16", expected >= 12\n",
			  reparse_data_length);
		goto fail;
	}
	if (smb_buffer_oob(srclen - 8, reparse_data_length, 0)) {
		DBG_DEBUG("reparse_data_length (%"PRIu16") too large for "
			   "src_len (%zu)\n",
			  reparse_data_length,
			  srclen);
		goto fail;
	}
	if (smb_buffer_oob(reparse_data_length - 12, substitute_name_offset,
			   substitute_name_length)) {
		DBG_DEBUG("substitute_name (%"PRIu16"/%"PRIu16") does not fit "
			  "in reparse_data_length (%"PRIu16")\n",
			  substitute_name_offset,
			  substitute_name_length,
			  reparse_data_length - 12);
		goto fail;
	}
	if (smb_buffer_oob(reparse_data_length - 12, print_name_offset,
			   print_name_length)) {
		DBG_DEBUG("print_name (%"PRIu16"/%"PRIu16") does not fit in "
			  "reparse_data_length (%"PRIu16")\n",
			  print_name_offset,
			  print_name_length,
			  reparse_data_length - 12);
		goto fail;
	}

	result = talloc_zero(mem_ctx, struct symlink_reparse_struct);
	if (result == NULL) {
		DBG_DEBUG("talloc failed\n");
		goto fail;
	}

	ok = convert_string_talloc(
		result,
		CH_UTF16,
		CH_UNIX,
		src + 20 + substitute_name_offset,
		substitute_name_length,
		&result->substitute_name,
		NULL);
	if (!ok) {
		DBG_DEBUG("convert_string_talloc for substitute_name "
			  "failed\n");
		goto fail;
	}

	ok = convert_string_talloc(
		result,
		CH_UTF16,
		CH_UNIX,
		src + 20 + print_name_offset,
		print_name_length,
		&result->print_name,
		NULL);
	if (!ok) {
		DBG_DEBUG("convert_string_talloc for print_name failed\n");
		goto fail;
	}

	result->unparsed_path_length = SVAL(src, 6);
	result->flags = IVAL(src, 16);

	return result;
fail:
	TALLOC_FREE(result);
	return NULL;
}
