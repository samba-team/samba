/*
   Unix SMB/CIFS implementation.

   routines for marshalling/unmarshalling string types

   Copyright (C) Andrew Tridgell 2003

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
#include "librpc/ndr/libndr.h"

/**
  pull a general string from the wire
*/
_PUBLIC_ enum ndr_err_code ndr_pull_string(struct ndr_pull *ndr, ndr_flags_type ndr_flags, const char **s)
{
	char *as=NULL;
	uint32_t len1, ofs, len2;
	uint16_t len3;
	size_t conv_src_len = 0, converted_size;
	int do_convert = 1, chset = CH_UTF16;
	unsigned byte_mul = 2;
	libndr_flags flags = ndr->flags;
	unsigned c_len_term = 0;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	if (NDR_BE(ndr)) {
		chset = CH_UTF16BE;
	}

	/*
	 * We will check this flag, but from the unmodified
	 * ndr->flags, so just remove it from flags
	 */
	flags &= ~LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	switch (flags & LIBNDR_ENCODING_FLAGS) {
	case 0:
		break;

	case LIBNDR_FLAG_STR_ASCII:
		chset = CH_DOS;
		byte_mul = 1;
		break;

	case LIBNDR_FLAG_STR_UTF8:
		chset = CH_UTF8;
		byte_mul = 1;
		break;

	case LIBNDR_FLAG_STR_RAW8:
		do_convert = 0;
		byte_mul = 1;
		break;

	default:
		return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%"PRI_LIBNDR_FLAGS"\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);
	}
	flags &= ~LIBNDR_ENCODING_FLAGS;

	flags &= ~LIBNDR_FLAG_STR_CONFORMANT;
	if (flags & LIBNDR_FLAG_STR_CHARLEN) {
		c_len_term = 1;
		flags &= ~LIBNDR_FLAG_STR_CHARLEN;
	}

	switch (flags & LIBNDR_STRING_FLAGS) {
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len1));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &ofs));
		if (ofs != 0) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, "non-zero array offset with string flags 0x%"PRI_LIBNDR_FLAGS"\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len2));
		if (len2 > len1) {
			return ndr_pull_error(ndr, NDR_ERR_STRING,
					      "Bad string lengths len1=%"PRIu32" ofs=%"PRIu32" len2=%"PRIu32"\n",
					      len1, ofs, len2);
		} else if (len1 != len2) {
			DEBUG(6,("len1[%"PRIu32"] != len2[%"PRIu32"]\n", len1, len2));
		}
		conv_src_len = len2 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len1));
		conv_src_len = len1 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM|LIBNDR_FLAG_STR_BYTESIZE:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len1));
		conv_src_len = len1;
		byte_mul = 1; /* the length is now absolute */
		break;

	case LIBNDR_FLAG_STR_LEN4:
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &ofs));
		if (ofs != 0) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, "non-zero array offset with string flags 0x%"PRI_LIBNDR_FLAGS"\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len1));
		conv_src_len = len1 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_SIZE2:
	case LIBNDR_FLAG_STR_SIZE2|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &len3));
		conv_src_len = len3 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_SIZE2|LIBNDR_FLAG_STR_NOTERM|LIBNDR_FLAG_STR_BYTESIZE:
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &len3));
		conv_src_len = len3;
		byte_mul = 1; /* the length is now absolute */
		break;

	case LIBNDR_FLAG_STR_NULLTERM:
		/*
		 * We ensure that conv_src_len cannot equal 0 by
		 * requiring that there be enough bytes for at least
		 * the NULL terminator
		 */
		if (byte_mul == 1) {
			NDR_PULL_NEED_BYTES(ndr, 1);
			conv_src_len = ascii_len_n((const char *)(ndr->data+ndr->offset), ndr->data_size - ndr->offset);
		} else {
			NDR_PULL_NEED_BYTES(ndr, 2);
			conv_src_len = utf16_null_terminated_len_n(ndr->data+ndr->offset, ndr->data_size - ndr->offset);
		}
		byte_mul = 1; /* the length is now absolute */
		break;

	case LIBNDR_FLAG_STR_NOTERM:
		if (!(ndr->flags & LIBNDR_FLAG_REMAINING)) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%"PRI_LIBNDR_FLAGS" (missing NDR_REMAINING)\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		conv_src_len = ndr->data_size - ndr->offset;
		byte_mul = 1; /* the length is now absolute */
		break;

	default:
		return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%"PRI_LIBNDR_FLAGS"\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);
	}

	NDR_PULL_NEED_BYTES(ndr, conv_src_len * byte_mul);
	if (conv_src_len == 0) {
		as = talloc_strdup(ndr->current_mem_ctx, "");
		converted_size = 0;
		if (!as) {
			return ndr_pull_error(ndr, NDR_ERR_ALLOC,
					      "Failed to talloc_strndup() in zero-length ndr_pull_string()");
		}
	} else {
		if (!do_convert) {
			as = talloc_strndup(ndr->current_mem_ctx,
			                    (char *)ndr->data + ndr->offset,
					    conv_src_len);
			if (!as) {
				return ndr_pull_error(ndr, NDR_ERR_ALLOC,
						      "Failed to talloc_strndup() in RAW8 ndr_pull_string()");
			}
			converted_size = MIN(strlen(as)+1, conv_src_len);
		} else if (!convert_string_talloc(ndr->current_mem_ctx, chset,
						  CH_UNIX, ndr->data + ndr->offset,
						  conv_src_len * byte_mul,
						  &as,
						  &converted_size)) {
			return ndr_pull_error(ndr, NDR_ERR_CHARCNV,
					      "Bad character conversion with flags 0x%"PRI_LIBNDR_FLAGS, flags);
		}
	}

	/* this is a way of detecting if a string is sent with the wrong
	   termination */
	if (ndr->flags & LIBNDR_FLAG_STR_NOTERM) {
		if (converted_size > 0 && as[converted_size-1] == '\0') {
			DEBUG(6,("short string '%s', sent with NULL termination despite NOTERM flag in IDL\n", as));
		}
		/*
		 * We check the original ndr->flags as it has already
		 * been removed from the local variable flags
		 */
		if (ndr->flags & LIBNDR_FLAG_STR_NO_EMBEDDED_NUL) {
			size_t strlen_of_unix_string = strlen(as);
			if (strlen_of_unix_string != converted_size) {
				return ndr_pull_error(ndr, NDR_ERR_CHARCNV,
						      "Embedded NUL at position %zu in "
						      "converted string "
						      "(and therefore source string) "
						      "despite "
						      "LIBNDR_FLAG_STR_NO_EMBEDDED_NUL\n",
						      strlen_of_unix_string);
			}
		}
	} else {
		/*
		 * We check the original ndr->flags as it has already
		 * been removed from the local variable flags
		 */
		if (ndr->flags & LIBNDR_FLAG_STR_NO_EMBEDDED_NUL) {
			size_t strlen_of_unix_string = strlen(as);
			if (converted_size > 0 && strlen_of_unix_string != converted_size - 1) {
				return ndr_pull_error(ndr, NDR_ERR_CHARCNV,
						      "Embedded NUL at position %zu in "
						      "converted string "
						      "(and therefore source string) "
						      "despite "
						      "LIBNDR_FLAG_STR_NO_EMBEDDED_NUL\n",
						      strlen_of_unix_string);
			}
		}
		if (converted_size > 0 && as[converted_size-1] != '\0') {
			DEBUG(6,("long string '%s', sent without NULL termination (which was expected)\n", as));
		}
	}

	NDR_CHECK(ndr_pull_advance(ndr, conv_src_len * byte_mul));
	*s = as;

	return NDR_ERR_SUCCESS;
}


/**
  push a general string onto the wire
*/
_PUBLIC_ enum ndr_err_code ndr_push_string(struct ndr_push *ndr, ndr_flags_type ndr_flags, const char *s)
{
	ssize_t s_len, c_len;
	size_t d_len;
	int do_convert = 1, chset = CH_UTF16;
	libndr_flags flags = ndr->flags;
	unsigned byte_mul = 2;
	const uint8_t *dest = NULL;
	uint8_t *dest_to_free = NULL;
	static const uint8_t null_byte[] = {0};
	enum ndr_err_code ndr_err = NDR_ERR_SUCCESS;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	if (NDR_BE(ndr)) {
		chset = CH_UTF16BE;
	}

	s_len = s?strlen(s):0;

	/*
	 * We will check this flag, but from the unmodified
	 * ndr->flags, so just remove it from flags
	 */
	flags &= ~LIBNDR_FLAG_STR_NO_EMBEDDED_NUL;

	switch (flags & LIBNDR_ENCODING_FLAGS) {
	case 0:
		break;

	case LIBNDR_FLAG_STR_ASCII:
		chset = CH_DOS;
		byte_mul = 1;
		break;

	case LIBNDR_FLAG_STR_UTF8:
		chset = CH_UTF8;
		byte_mul = 1;
		break;

	case LIBNDR_FLAG_STR_RAW8:
		do_convert = 0;
		byte_mul = 1;
		break;

	default:
		return ndr_push_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%"PRI_LIBNDR_FLAGS"\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);
	}
	flags &= ~LIBNDR_ENCODING_FLAGS;

	flags &= ~LIBNDR_FLAG_STR_CONFORMANT;

	if (!(flags & LIBNDR_FLAG_STR_NOTERM)) {
		s_len++;
	}

	if (s_len == 0) {
		d_len = 0;
		dest = null_byte;
	} else if (!do_convert) {
		d_len = s_len;
		dest = (const uint8_t *)s;
	} else {
		bool ok;

		ok = convert_string_talloc(ndr, CH_UNIX, chset, s, s_len,
					   &dest_to_free, &d_len);
		if (!ok) {
			return ndr_push_error(ndr, NDR_ERR_CHARCNV,
					      "Bad character push conversion with flags 0x%"PRI_LIBNDR_FLAGS, flags);
		}

		dest = dest_to_free;
	}

	if (flags & LIBNDR_FLAG_STR_BYTESIZE) {
		c_len = d_len;
		flags &= ~LIBNDR_FLAG_STR_BYTESIZE;
	} else if (flags & LIBNDR_FLAG_STR_CHARLEN) {
		c_len = (d_len / byte_mul)-1;
		flags &= ~LIBNDR_FLAG_STR_CHARLEN;
	} else {
		c_len = d_len / byte_mul;
	}

	switch (flags & LIBNDR_STRING_FLAGS) {
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:
		ndr_err = ndr_push_uint32(ndr, NDR_SCALARS, c_len);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		ndr_err = ndr_push_uint32(ndr, NDR_SCALARS, 0);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		ndr_err = ndr_push_uint32(ndr, NDR_SCALARS, c_len);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		ndr_err = ndr_push_bytes(ndr, dest, d_len);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		break;

	case LIBNDR_FLAG_STR_LEN4:
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_NOTERM:
		ndr_err = ndr_push_uint32(ndr, NDR_SCALARS, 0);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		ndr_err = ndr_push_uint32(ndr, NDR_SCALARS, c_len);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		ndr_err = ndr_push_bytes(ndr, dest, d_len);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		break;

	case LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:
		ndr_err = ndr_push_uint32(ndr, NDR_SCALARS, c_len);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		ndr_err = ndr_push_bytes(ndr, dest, d_len);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		break;

	case LIBNDR_FLAG_STR_SIZE2:
	case LIBNDR_FLAG_STR_SIZE2|LIBNDR_FLAG_STR_NOTERM:
		ndr_err = ndr_push_uint16(ndr, NDR_SCALARS, c_len);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		ndr_err = ndr_push_bytes(ndr, dest, d_len);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		break;

	case LIBNDR_FLAG_STR_NULLTERM:
		ndr_err = ndr_push_bytes(ndr, dest, d_len);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			goto out;
		}
		break;

	default:
		if (ndr->flags & LIBNDR_FLAG_REMAINING) {
			ndr_err = ndr_push_bytes(ndr, dest, d_len);
			if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
				goto out;
			}
			break;
		}

		ndr_err = ndr_push_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%"PRI_LIBNDR_FLAGS"\n",
					 ndr->flags & LIBNDR_STRING_FLAGS);
		goto out;
	}

out:
	TALLOC_FREE(dest_to_free);
	return ndr_err;
}

/**
  push a general string onto the wire
*/
_PUBLIC_ size_t ndr_string_array_size(struct ndr_push *ndr, const char *s)
{
	size_t c_len;
	libndr_flags flags = ndr->flags;
	unsigned byte_mul = 2;
	unsigned c_len_term = 1;

	if (flags & LIBNDR_FLAG_STR_RAW8) {
		c_len = s?strlen(s):0;
	} else {
		c_len = s?strlen_m(s):0;
	}

	if (flags & (LIBNDR_FLAG_STR_ASCII|LIBNDR_FLAG_STR_RAW8|LIBNDR_FLAG_STR_UTF8)) {
		byte_mul = 1;
	}

	if (flags & LIBNDR_FLAG_STR_NOTERM) {
		c_len_term = 0;
	}

	c_len = c_len + c_len_term;

	if (flags & LIBNDR_FLAG_STR_BYTESIZE) {
		c_len = c_len * byte_mul;
	}

	return c_len;
}

_PUBLIC_ void ndr_print_string(struct ndr_print *ndr, const char *name, const char *s)
{
	if (NDR_HIDE_SECRET(ndr)) {
		ndr->print(ndr, "%-25s: <REDACTED SECRET VALUE>", name);
		return;
	}
	if (s) {
		ndr->print(ndr, "%-25s: '%s'", name, s);
	} else {
		ndr->print(ndr, "%-25s: NULL", name);
	}
}

_PUBLIC_ uint32_t ndr_size_string(int ret, const char * const* string, ndr_flags_type flags)
{
	/* FIXME: Is this correct for all strings ? */
	if(!(*string)) return ret;
	return ret+strlen(*string)+1;
}

/**
  pull a UTF‐16 string from the wire
*/
_PUBLIC_ enum ndr_err_code ndr_pull_u16string(struct ndr_pull *ndr,
					      ndr_flags_type ndr_flags,
					      const unsigned char **s)
{
	unsigned char *as = NULL;
	const char *const src_str = (char *)ndr->data + ndr->offset;
	size_t src_len = 0;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	if (NDR_BE(ndr)) {
		/*
		 * It isn’t clear how this type should be encoded in a
		 * big‐endian context.
		 */
		return ndr_pull_error(
			ndr,
			NDR_ERR_STRING,
			"u16string does not support big‐endian encoding\n");
	}

	if (ndr->flags & LIBNDR_ENCODING_FLAGS) {
		return ndr_pull_error(
			ndr,
			NDR_ERR_STRING,
			"Unsupported string flags 0x%" PRI_LIBNDR_FLAGS
			" passed to ndr_pull_u16string()\n",
			ndr->flags & LIBNDR_STRING_FLAGS);
	}

	switch (ndr->flags & LIBNDR_STRING_FLAGS) {
	case LIBNDR_FLAG_STR_NULLTERM:
		/*
		 * We ensure that src_len cannot equal 0 by
		 * requiring that there be enough bytes for at least
		 * the NULL terminator
		 */
		NDR_PULL_NEED_BYTES(ndr, 2);
		src_len = utf16_null_terminated_len_n(src_str,
						      ndr->data_size -
							      ndr->offset);
		break;

	default:
		return ndr_pull_error(
			ndr,
			NDR_ERR_STRING,
			"Unsupported string flags 0x%" PRI_LIBNDR_FLAGS
			" passed to ndr_pull_u16string()\n",
			ndr->flags & LIBNDR_STRING_FLAGS);
	}

	NDR_PULL_NEED_BYTES(ndr, src_len);
	as = talloc_utf16_strlendup(ndr->current_mem_ctx,
				    src_str,
				    src_len);
	if (as == NULL) {
		return ndr_pull_error(ndr,
				      NDR_ERR_ALLOC,
				      "Failed to talloc_utf16_strlendup() in "
				      "ndr_pull_u16string()");
	}

	NDR_CHECK(ndr_pull_advance(ndr, src_len));
	*s = as;

	return NDR_ERR_SUCCESS;
}

/**
  push a UTF‐16 string onto the wire
*/
_PUBLIC_ enum ndr_err_code ndr_push_u16string(struct ndr_push *ndr,
					      ndr_flags_type ndr_flags,
					      const unsigned char *s)
{
	size_t s_len;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	if (NDR_BE(ndr)) {
		/*
		 * It isn’t clear how this type should be encoded in a
		 * big‐endian context.
		 */
		return ndr_push_error(
			ndr,
			NDR_ERR_STRING,
			"u16string does not support big‐endian encoding\n");
	}

	if (s == NULL) {
		return ndr_push_error(
			ndr,
			NDR_ERR_INVALID_POINTER,
			"NULL pointer passed to ndr_push_u16string()");
	}

	s_len = utf16_null_terminated_len(s);
	if (s_len > UINT32_MAX) {
		return ndr_push_error(
			ndr,
			NDR_ERR_LENGTH,
			"length overflow in ndr_push_u16string()");
	}

	if (ndr->flags & LIBNDR_ENCODING_FLAGS) {
		return ndr_push_error(
			ndr,
			NDR_ERR_STRING,
			"Unsupported string flags 0x%" PRI_LIBNDR_FLAGS
			" passed to ndr_push_u16string()\n",
			ndr->flags & LIBNDR_STRING_FLAGS);
	}

	switch (ndr->flags & LIBNDR_STRING_FLAGS) {
	case LIBNDR_FLAG_STR_NULLTERM:
		NDR_CHECK(ndr_push_bytes(ndr, s, s_len));
		break;

	default:
		if (ndr->flags & LIBNDR_FLAG_REMAINING) {
			NDR_CHECK(ndr_push_bytes(ndr, s, s_len));
			break;
		}

		return ndr_push_error(
			ndr,
			NDR_ERR_STRING,
			"Unsupported string flags 0x%" PRI_LIBNDR_FLAGS
			" passed to ndr_push_u16string()\n",
			ndr->flags & LIBNDR_STRING_FLAGS);
	}

	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_u16string(struct ndr_print *ndr,
				  const char *name,
				  const unsigned char *s)
{
	return ndr_print_array_uint8(ndr,
				     name,
				     s,
				     utf16_len(s));
}

static uint32_t guess_string_array_size(struct ndr_pull *ndr, ndr_flags_type ndr_flags)
{
	/*
	 * Here we could do something clever like count the number of zeros in
	 * the ndr data, but it is probably sufficient to pick a lowish number
	 * (compared to the overhead of the talloc header) and let the
	 * exponential resizing deal with longer arrays.
	 */
	return 5;
}

static enum ndr_err_code extend_string_array(struct ndr_pull *ndr,
					     const char ***_a,
					     uint32_t *count)
{
	const char **a = *_a;
	uint32_t inc = *count / 4 + 3;
	uint32_t alloc_size = *count + inc;

	if (alloc_size < *count) {
		/* overflow ! */
		return NDR_ERR_ALLOC;
	}
	/*
	 * We allocate and zero two more bytes than we report back, so that
	 * the string array will always be NULL terminated.
	 */
	a = talloc_realloc(ndr->current_mem_ctx, a,
			   const char *,
			   alloc_size);
	NDR_ERR_HAVE_NO_MEMORY(a);

	memset(a + *count, 0, inc * sizeof(a[0]));
	*_a = a;
	*count = alloc_size - 2;
	return NDR_ERR_SUCCESS;
}

/**
  pull a general string array from the wire
*/
_PUBLIC_ enum ndr_err_code ndr_pull_string_array(struct ndr_pull *ndr, ndr_flags_type ndr_flags, const char ***_a)
{
	const char **a = NULL;
	uint32_t count;
	libndr_flags flags = ndr->flags;
	libndr_flags saved_flags = ndr->flags;
	uint32_t alloc_size;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	alloc_size = guess_string_array_size(ndr, ndr_flags);
	a = talloc_zero_array(ndr->current_mem_ctx, const char *, alloc_size + 2);
	NDR_ERR_HAVE_NO_MEMORY(a);

	switch (flags & (LIBNDR_FLAG_STR_NULLTERM|LIBNDR_FLAG_STR_NOTERM)) {
	case LIBNDR_FLAG_STR_NULLTERM:
		/*
		 * here the strings are null terminated
		 * but also the array is null terminated if LIBNDR_FLAG_REMAINING
		 * is specified
		 */
		for (count = 0;; count++) {
			TALLOC_CTX *tmp_ctx;
			const char *s = NULL;
			if (count == alloc_size) {
				NDR_CHECK(extend_string_array(ndr,
							      &a,
							      &alloc_size));
			}

			tmp_ctx = ndr->current_mem_ctx;
			ndr->current_mem_ctx = a;
			NDR_CHECK(ndr_pull_string(ndr, ndr_flags, &s));
			ndr->current_mem_ctx = tmp_ctx;
			if ((ndr->data_size - ndr->offset) == 0 && ndr->flags & LIBNDR_FLAG_REMAINING)
			{
				a[count] = s;
				break;
			}
			if (strcmp("", s)==0) {
				a[count] = NULL;
				break;
			} else {
				a[count] = s;
			}
		}

		*_a =a;
		break;

	case LIBNDR_FLAG_STR_NOTERM:
		if (!(ndr->flags & LIBNDR_FLAG_REMAINING)) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%"PRI_LIBNDR_FLAGS" (missing NDR_REMAINING)\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		/*
		 * here the strings are not null terminated
		 * but separated by a null terminator
		 *
		 * which means the same as:
		 * Every string is null terminated except the last
		 * string is terminated by the end of the buffer
		 *
		 * as LIBNDR_FLAG_STR_NULLTERM also end at the end
		 * of the buffer, we can pull each string with this flag
		 *
		 * The big difference with the case LIBNDR_FLAG_STR_NOTERM +
		 * LIBNDR_FLAG_REMAINING is that the last string will not be null terminated
		 */
		ndr->flags &= ~(LIBNDR_FLAG_STR_NOTERM|LIBNDR_FLAG_REMAINING);
		ndr->flags |= LIBNDR_FLAG_STR_NULLTERM;

		for (count = 0; ((ndr->data_size - ndr->offset) > 0); count++) {
			TALLOC_CTX *tmp_ctx;
			const char *s = NULL;
			if (count == alloc_size) {
				NDR_CHECK(extend_string_array(ndr,
							      &a,
							      &alloc_size));
			}

			tmp_ctx = ndr->current_mem_ctx;
			ndr->current_mem_ctx = a;
			NDR_CHECK(ndr_pull_string(ndr, ndr_flags, &s));
			ndr->current_mem_ctx = tmp_ctx;
			a[count] = s;
		}

		a = talloc_realloc(ndr->current_mem_ctx, a, const char *, count + 1);
		NDR_ERR_HAVE_NO_MEMORY(a);
		*_a = a;
		break;

	default:
		return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%"PRI_LIBNDR_FLAGS"\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);
	}

	ndr->flags = saved_flags;
	return NDR_ERR_SUCCESS;
}

/**
  push a general string array onto the wire
*/
_PUBLIC_ enum ndr_err_code ndr_push_string_array(struct ndr_push *ndr, ndr_flags_type ndr_flags, const char **a)
{
	uint32_t count;
	libndr_flags flags = ndr->flags;
	libndr_flags saved_flags = ndr->flags;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	switch (flags & LIBNDR_STRING_FLAGS) {
	case LIBNDR_FLAG_STR_NULLTERM:
		for (count = 0; a && a[count]; count++) {
			NDR_CHECK(ndr_push_string(ndr, ndr_flags, a[count]));
		}
		/* If LIBNDR_FLAG_REMAINING then we do not add a null terminator to the array */
		if (!(flags & LIBNDR_FLAG_REMAINING))
		{
			NDR_CHECK(ndr_push_string(ndr, ndr_flags, ""));
		}
		break;

	case LIBNDR_FLAG_STR_NOTERM:
		if (!(ndr->flags & LIBNDR_FLAG_REMAINING)) {
			return ndr_push_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%"PRI_LIBNDR_FLAGS" (missing NDR_REMAINING)\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}

		for (count = 0; a && a[count]; count++) {
			if (count > 0) {
				ndr->flags &= ~(LIBNDR_FLAG_STR_NOTERM|LIBNDR_FLAG_REMAINING);
				ndr->flags |= LIBNDR_FLAG_STR_NULLTERM;
				NDR_CHECK(ndr_push_string(ndr, ndr_flags, ""));
				ndr->flags = saved_flags;
			}
			NDR_CHECK(ndr_push_string(ndr, ndr_flags, a[count]));
		}

		break;

	default:
		return ndr_push_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%"PRI_LIBNDR_FLAGS"\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);
	}

	ndr->flags = saved_flags;
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_string_array(struct ndr_print *ndr, const char *name, const char **a)
{
	uint32_t count;
	uint32_t i;

	for (count = 0; a && a[count]; count++) {}

	ndr->print(ndr, "%s: ARRAY(%"PRIu32")", name, count);
	ndr->depth++;
	for (i=0;i<count;i++) {
		char *idx=NULL;
		if (asprintf(&idx, "[%"PRIu32"]", i) != -1) {
			ndr_print_string(ndr, idx, a[i]);
			free(idx);
		}
	}
	ndr->depth--;
}

_PUBLIC_ size_t ndr_size_string_array(const char **a, uint32_t count, libndr_flags flags)
{
	uint32_t i;
	size_t size = 0;
	int rawbytes = 0;

	if (flags & LIBNDR_FLAG_STR_RAW8) {
		rawbytes = 1;
		flags &= ~LIBNDR_FLAG_STR_RAW8;
	}

	switch (flags & LIBNDR_STRING_FLAGS) {
	case LIBNDR_FLAG_STR_NULLTERM:
		for (i = 0; i < count; i++) {
			size += rawbytes?strlen(a[i]) + 1:strlen_m_term(a[i]);
		}
		break;
	case LIBNDR_FLAG_STR_NOTERM:
		for (i = 0; i < count; i++) {
			size += rawbytes?strlen(a[i]):strlen_m(a[i]);
		}
		break;
	default:
		return 0;
	}

	return size;
}

/**
 * Return number of elements in a string including the last (zeroed) element
 */
_PUBLIC_ uint32_t ndr_string_length(const void *_var, uint32_t element_size)
{
	uint32_t i;
	uint8_t zero[4] = {0,0,0,0};
	const char *var = (const char *)_var;

	for (i = 0; memcmp(var+i*element_size,zero,element_size) != 0; i++);

	return i+1;
}

/**
 * @brief Get the string length including the null terminator if available.
 *
 * This checks the string length based on the elements. The returned number
 * includes the terminating null byte(s) if found.
 *
 * @param[in]  _var    The string to calculate the length for.
 *
 * @param[in]  length  The length of the buffer passed by _var.
 *
 * @param[in]  element_size The element_size of a string char in bytes.
 *
 * @return The length of the strings or 0.
 */
static uint32_t ndr_string_n_length(const void *_var,
				    size_t length,
				    uint32_t element_size)
{
	size_t i = 0;
	uint8_t zero[4] = {0,0,0,0};
	const char *var = (const char *)_var;
	int cmp;

	if (element_size > 4) {
		return 0;
	}

	for (i = 0; i < length; i++, var += element_size) {
		cmp = memcmp(var, zero, element_size);
		if (cmp == 0) {
			break;
		}
	}

	if (i == length) {
		return length;
	}

	return i + 1;
}

_PUBLIC_ enum ndr_err_code ndr_check_string_terminator(struct ndr_pull *ndr, uint32_t count, uint32_t element_size)
{
	uint32_t i;
	uint32_t save_offset;

	if (count == 0) {
		return NDR_ERR_RANGE;
	}

	if (element_size && count - 1 > UINT32_MAX / element_size) {
		return NDR_ERR_RANGE;
	}

	save_offset = ndr->offset;
	NDR_CHECK(ndr_pull_advance(ndr, (count - 1) * element_size));
	NDR_PULL_NEED_BYTES(ndr, element_size);

	for (i = 0; i < element_size; i++) {
		if (ndr->data[ndr->offset+i] != 0) {
			ndr->offset = save_offset;

			return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, "String terminator not present or outside string boundaries");
		}
	}

	ndr->offset = save_offset;

	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_charset(struct ndr_pull *ndr, ndr_flags_type ndr_flags, const char **var, uint32_t length, uint8_t byte_mul, charset_t chset)
{
	size_t converted_size;

	if (length == 0) {
		*var = talloc_strdup(ndr->current_mem_ctx, "");
		if (*var == NULL) {
			return ndr_pull_error(ndr, NDR_ERR_ALLOC,
					      "Failed to talloc_strdup() in ndr_pull_charset()");
		}
		return NDR_ERR_SUCCESS;
	}

	if (NDR_BE(ndr) && chset == CH_UTF16) {
		chset = CH_UTF16BE;
	}

	if ((byte_mul != 0) && (length > UINT32_MAX/byte_mul)) {
		return ndr_pull_error(ndr, NDR_ERR_BUFSIZE, "length overflow");
	}
	NDR_PULL_NEED_BYTES(ndr, length*byte_mul);

	if (!convert_string_talloc(ndr->current_mem_ctx, chset, CH_UNIX,
				   ndr->data+ndr->offset, length*byte_mul,
				   var,
				   &converted_size))
	{
		return ndr_pull_error(ndr, NDR_ERR_CHARCNV,
				      "Bad character conversion");
	}
	NDR_CHECK(ndr_pull_advance(ndr, length*byte_mul));

	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_charset_to_null(struct ndr_pull *ndr, ndr_flags_type ndr_flags, const char **var, uint32_t length, uint8_t byte_mul, charset_t chset)
{
	size_t converted_size;
	uint32_t str_len;

	if (length == 0) {
		*var = talloc_strdup(ndr->current_mem_ctx, "");
		if (*var == NULL) {
			return ndr_pull_error(ndr, NDR_ERR_ALLOC,
					      "Failed to talloc_strdup() in ndr_pull_charset_to_null()");
		}
		return NDR_ERR_SUCCESS;
	}

	if (NDR_BE(ndr) && chset == CH_UTF16) {
		chset = CH_UTF16BE;
	}

	if ((byte_mul != 0) && (length > UINT32_MAX/byte_mul)) {
		return ndr_pull_error(ndr, NDR_ERR_BUFSIZE, "length overflow");
	}
	NDR_PULL_NEED_BYTES(ndr, length*byte_mul);

	str_len = ndr_string_n_length(ndr->data+ndr->offset, length, byte_mul);
	if (str_len == 0) {
		return ndr_pull_error(ndr, NDR_ERR_LENGTH,
				      "Invalid length");
	}

	if (!convert_string_talloc(ndr->current_mem_ctx, chset, CH_UNIX,
				   ndr->data+ndr->offset, str_len*byte_mul,
				   var,
				   &converted_size))
	{
		return ndr_pull_error(ndr, NDR_ERR_CHARCNV,
				      "Bad character conversion");
	}
	NDR_CHECK(ndr_pull_advance(ndr, length*byte_mul));

	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_push_charset(struct ndr_push *ndr, ndr_flags_type ndr_flags, const char *var, uint32_t length, uint8_t byte_mul, charset_t chset)
{
	size_t required;

	if (NDR_BE(ndr) && chset == CH_UTF16) {
		chset = CH_UTF16BE;
	}

	if ((byte_mul != 0) && (length > SIZE_MAX/byte_mul)) {
		return ndr_push_error(ndr, NDR_ERR_LENGTH, "length overflow");
	}
	required = byte_mul * length;

	NDR_PUSH_NEED_BYTES(ndr, required);

	if (required) {
		size_t size = 0;

		if (var == NULL) {
			return ndr_push_error(ndr, NDR_ERR_INVALID_POINTER, "NULL [ref] pointer");
		}

		if (!convert_string(CH_UNIX, chset,
				    var, strlen(var),
				    ndr->data+ndr->offset, required, &size)) {
			return ndr_push_error(ndr, NDR_ERR_CHARCNV,
					      "Bad character conversion");
		}

		/* Make sure the remaining part of the string is filled with zeroes */
		if (size < required) {
			memset(ndr->data+ndr->offset+size, 0, required-size);
		}
	}

	ndr->offset += required;

	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_push_charset_to_null(struct ndr_push *ndr, ndr_flags_type ndr_flags, const char *var, uint32_t length, uint8_t byte_mul, charset_t chset)
{
	const char *str = var;

	if (str == NULL) {
		str = "\0"; /* i.e. two zero bytes, for UTF16 null word. */
		length = 1;
	}

	return ndr_push_charset(ndr, ndr_flags, str, length, byte_mul, chset);
}

/* Return number of elements in a string in the specified charset */
_PUBLIC_ uint32_t ndr_charset_length(const void *var, charset_t chset)
{
	switch (chset) {
	/* case CH_UTF16: this has the same value as CH_UTF16LE */
	case CH_UTF16LE:
	case CH_UTF16BE:
	case CH_UTF16MUNGED:
	case CH_UTF8:
		return strlen_m_ext_term((const char *)var, CH_UNIX, chset);
	case CH_DOS:
	case CH_UNIX:
		return strlen((const char *)var)+1;
	default:
		/* Fallback, this should never happen */
		return strlen((const char *)var)+1;
	}
}
