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

#include "includes.h"
#include "include/client.h"
#include "libsmb/proto.h"
#include "include/ntioctl.h"

bool symlink_reparse_buffer_marshall(
	const char *substitute, const char *printname, uint32_t flags,
	TALLOC_CTX *mem_ctx, uint8_t **pdst, size_t *pdstlen)
{
	uint8_t *dst = NULL;
	size_t dst_len;
	uint8_t *subst_utf16 = NULL;
	uint8_t *print_utf16 = NULL;
	size_t subst_len = 0;
	size_t print_len = 0;

	if (substitute == NULL) {
		return false;
	}
	if (printname == NULL) {
		printname = substitute;
	}

	if (!convert_string_talloc(talloc_tos(), CH_UNIX, CH_UTF16,
				   substitute, strlen(substitute),
				   &subst_utf16, &subst_len)) {
		goto fail;
	}
	if (!convert_string_talloc(talloc_tos(), CH_UNIX, CH_UTF16,
				   printname, strlen(printname),
				   &print_utf16, &print_len)) {
		goto fail;
	}
	dst_len = 20 + subst_len + print_len;
	dst = talloc_array(mem_ctx, uint8_t, dst_len);
	if (dst == NULL) {
		goto fail;
	}

	SIVAL(dst, 0, IO_REPARSE_TAG_SYMLINK);	   /* ReparseTag */
	SSVAL(dst, 4, 12 + subst_len + print_len); /* ReparseDataLength */
	SSVAL(dst, 6, 0);			   /* Reserved */
	SSVAL(dst, 8, 0);			   /* SubstituteNameOffset */
	SSVAL(dst, 10, subst_len);		   /* SubstituteNameLength */
	SSVAL(dst, 12, subst_len);		   /* PrintNameOffset */
	SSVAL(dst, 14, print_len);		   /* PrintNameLength */
	SIVAL(dst, 16, flags);			   /* Flags */

	if ((subst_utf16 != NULL) && (subst_len != 0)) {
		memcpy(dst + 20, subst_utf16, subst_len);
		TALLOC_FREE(subst_utf16);
	}

	if ((print_utf16 != NULL) && (print_len != 0)) {
		memcpy(dst + 20 + subst_len, print_utf16, print_len);
		TALLOC_FREE(print_utf16);
	}

	*pdst = dst;
	*pdstlen = dst_len;
	return true;
fail:
	TALLOC_FREE(subst_utf16);
	TALLOC_FREE(print_utf16);
	return false;
}

bool symlink_reparse_buffer_parse(
	const uint8_t *src, size_t srclen, TALLOC_CTX *mem_ctx,
	char **psubstitute_name, char **pprint_name, uint32_t *pflags)
{
	uint16_t reparse_data_length;
	uint16_t substitute_name_offset, substitute_name_length;
	uint16_t print_name_offset, print_name_length;
	uint32_t flags;
	char *substitute_name = NULL;
	char *print_name = NULL;

	if (srclen < 20) {
		DEBUG(10, ("srclen = %d, expected >= 20\n", (int)srclen));
		return false;
	}
	if (IVAL(src, 0) != IO_REPARSE_TAG_SYMLINK) {
		DEBUG(10, ("Got ReparseTag %8.8x, expected %8.8x\n",
			   IVAL(src, 0), IO_REPARSE_TAG_SYMLINK));
		return false;
	}

	reparse_data_length	= SVAL(src, 4);
	substitute_name_offset	= SVAL(src, 8);
	substitute_name_length	= SVAL(src, 10);
	print_name_offset	= SVAL(src, 12);
	print_name_length	= SVAL(src, 14);
	flags			= IVAL(src, 16);

	if (reparse_data_length < 12) {
		DEBUG(10, ("reparse_data_length = %d, expected >= 12\n",
			   (int)reparse_data_length));
		return false;
	}
	if (trans_oob(srclen - 8, reparse_data_length, 0)) {
		DEBUG(10, ("reparse_data_length (%d) too large for "
			   "src_len (%d)\n", (int)reparse_data_length,
			   (int)srclen));
		return false;
	}
	if (trans_oob(reparse_data_length - 12, substitute_name_offset,
		      substitute_name_length)) {
		DEBUG(10, ("substitute_name (%d/%d) does not fit in "
			   "reparse_data_length (%d)\n",
			   (int)substitute_name_offset,
			   (int)substitute_name_length,
			   (int)reparse_data_length - 12));
		return false;
	}
	if (trans_oob(reparse_data_length - 12, print_name_offset,
		      print_name_length)) {
		DEBUG(10, ("print_name (%d/%d) does not fit in "
			   "reparse_data_length (%d)\n",
			   (int)print_name_offset,
			   (int)print_name_length,
			   (int)reparse_data_length - 12));
		return false;
	}

	if ((psubstitute_name != NULL) &&
	    !convert_string_talloc(mem_ctx, CH_UTF16, CH_UNIX,
				   src + 20 + substitute_name_offset,
				   substitute_name_length,
				   &substitute_name, NULL)) {
		DEBUG(10, ("convert_string_talloc for substitute_name "
			   "failed\n"));
		return false;
	}
	if ((pprint_name != NULL) &&
	    !convert_string_talloc(mem_ctx, CH_UTF16, CH_UNIX,
				   src + 20 + print_name_offset,
				   print_name_length,
				   &print_name, NULL)) {
		DEBUG(10, ("convert_string_talloc for print_name "
			   "failed\n"));
		TALLOC_FREE(substitute_name);
		return false;
	}
	if (psubstitute_name != NULL) {
		*psubstitute_name = substitute_name;
	}
	if (pprint_name != NULL) {
		*pprint_name = print_name;
	}
	if (pflags != NULL) {
		*pflags = flags;
	}
	return true;
}
