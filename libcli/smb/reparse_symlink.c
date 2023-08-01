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
#include "lib/util/bytearray.h"
#include "libcli/smb/smb_constants.h"
#include "libcli/smb/smb_util.h"
#include "lib/util/debug.h"

ssize_t reparse_buffer_marshall(
	uint32_t reparse_tag,
	uint16_t reserved,
	const struct iovec *iov,
	int iovlen,
	uint8_t *buf,
	size_t buflen)
{
	ssize_t reparse_data_length = iov_buflen(iov, iovlen);
	size_t needed;

	if (reparse_data_length == -1) {
		return -1;
	}
	if (reparse_data_length > UINT16_MAX) {
		return -1;
	}

	needed = reparse_data_length + 8;
	if (needed < reparse_data_length) {
		return -1;
	}

	if (buflen >= needed) {
		PUSH_LE_U32(buf, 0, reparse_tag);
		PUSH_LE_U16(buf, 4, reparse_data_length);
		PUSH_LE_U16(buf, 6, reserved);
		iov_buf(iov, iovlen, buf+8, buflen-8);
	}

	return needed;
}

bool symlink_reparse_buffer_marshall(
	const char *substitute,
	const char *printname,
	uint16_t unparsed_path_length,
	uint32_t flags,
	TALLOC_CTX *mem_ctx,
	uint8_t **pdst,
	size_t *pdstlen)
{
	uint8_t sbuf[12];
	struct iovec iov[3];
	uint8_t *dst = NULL;
	ssize_t dst_len;
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

	iov[0] = (struct iovec) { .iov_base = sbuf, .iov_len = sizeof(sbuf), };

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
	if (subst_len > UINT16_MAX) {
		goto fail;
	}
	iov[1] = (struct iovec) {
		.iov_base = subst_utf16, .iov_len = subst_len,
	};

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
	if (print_len > UINT16_MAX) {
		goto fail;
	}
	iov[2] = (struct iovec) {
		.iov_base = print_utf16, .iov_len = print_len,
	};

	PUSH_LE_U16(sbuf, 0, 0);	 /* SubstituteNameOffset */
	PUSH_LE_U16(sbuf, 2, subst_len); /* SubstituteNameLength */
	PUSH_LE_U16(sbuf, 4, subst_len); /* PrintNameOffset */
	PUSH_LE_U16(sbuf, 6, print_len); /* PrintNameLength */
	PUSH_LE_U32(sbuf, 8, flags);	 /* Flags */

	dst_len = reparse_buffer_marshall(
		IO_REPARSE_TAG_SYMLINK,
		unparsed_path_length,
		iov,
		ARRAY_SIZE(iov),
		NULL,
		0);
	if (dst_len == -1) {
		goto fail;
	}

	dst = talloc_array(mem_ctx, uint8_t, dst_len);
	if (dst == NULL) {
		goto fail;
	}

	reparse_buffer_marshall(
		IO_REPARSE_TAG_SYMLINK,
		unparsed_path_length,
		iov,
		ARRAY_SIZE(iov),
		dst,
		dst_len);

	*pdst = dst;
	*pdstlen = dst_len;
	ret = true;

fail:
	TALLOC_FREE(subst_utf16);
	TALLOC_FREE(print_utf16);
	return ret;
}
