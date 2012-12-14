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
_PUBLIC_ enum ndr_err_code ndr_pull_string(struct ndr_pull *ndr, int ndr_flags, const char **s)
{
	char *as=NULL;
	uint32_t len1, ofs, len2;
	uint16_t len3;
	size_t conv_src_len = 0, converted_size;
	int do_convert = 1, chset = CH_UTF16;
	unsigned byte_mul = 2;
	unsigned flags = ndr->flags;
	unsigned c_len_term = 0;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	if (NDR_BE(ndr)) {
		chset = CH_UTF16BE;
	}

	if (flags & LIBNDR_FLAG_STR_ASCII) {
		chset = CH_DOS;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_ASCII;
	}

	if (flags & LIBNDR_FLAG_STR_UTF8) {
		chset = CH_UTF8;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_UTF8;
	}

	if (flags & LIBNDR_FLAG_STR_RAW8) {
		do_convert = 0;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_RAW8;
	}

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
			return ndr_pull_error(ndr, NDR_ERR_STRING, "non-zero array offset with string flags 0x%x\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len2));
		if (len2 > len1) {
			return ndr_pull_error(ndr, NDR_ERR_STRING,
					      "Bad string lengths len1=%u ofs=%u len2=%u\n",
					      len1, ofs, len2);
		} else if (len1 != len2) {
			DEBUG(6,("len1[%u] != len2[%u] '%s'\n", len1, len2, as));
		}
		conv_src_len = len2 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_SIZE4:
	case LIBNDR_FLAG_STR_SIZE4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &len1));
		conv_src_len = len1 + c_len_term;
		break;

	case LIBNDR_FLAG_STR_LEN4:
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_NOTERM:
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &ofs));
		if (ofs != 0) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, "non-zero array offset with string flags 0x%x\n",
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
		if (byte_mul == 1) {
			conv_src_len = ascii_len_n((const char *)(ndr->data+ndr->offset), ndr->data_size - ndr->offset);
		} else {
			conv_src_len = utf16_len_n(ndr->data+ndr->offset, ndr->data_size - ndr->offset);
		}
		byte_mul = 1; /* the length is now absolute */
		break;

	case LIBNDR_FLAG_STR_NOTERM:
		if (!(ndr->flags & LIBNDR_FLAG_REMAINING)) {
			return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x (missing NDR_REMAINING)\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		conv_src_len = ndr->data_size - ndr->offset;
		byte_mul = 1; /* the length is now absolute */
		break;

	default:
		return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);
	}

	NDR_PULL_NEED_BYTES(ndr, conv_src_len * byte_mul);
	if (conv_src_len == 0) {
		as = talloc_strdup(ndr->current_mem_ctx, "");
		converted_size = 0;
	} else {
		if (!do_convert) {
			as = talloc_strndup(ndr->current_mem_ctx,
			                    (char *)ndr->data + ndr->offset,
					    conv_src_len);
			if (!as) {
				return ndr_pull_error(ndr, NDR_ERR_ALLOC,
						      "Failed to talloc_strndup() in RAW8 ndr_string_pull()");
			}
			converted_size = MIN(strlen(as)+1, conv_src_len);
		} else if (!convert_string_talloc(ndr->current_mem_ctx, chset,
					   CH_UNIX, ndr->data + ndr->offset,
					   conv_src_len * byte_mul,
					   (void **)(void *)&as,
					   &converted_size)) {
			return ndr_pull_error(ndr, NDR_ERR_CHARCNV,
					      "Bad character conversion with flags 0x%x", flags);
		}
	}

	/* this is a way of detecting if a string is sent with the wrong
	   termination */
	if (ndr->flags & LIBNDR_FLAG_STR_NOTERM) {
		if (as && converted_size > 0 && as[converted_size-1] == '\0') {
			DEBUG(6,("short string '%s', sent with NULL termination despite NOTERM flag in IDL\n", as));
		}
	} else {
		if (as && converted_size > 0 && as[converted_size-1] != '\0') {
			DEBUG(6,("long string '%s', send without NULL termination (which was expected)\n", as));
		}
	}

	NDR_CHECK(ndr_pull_advance(ndr, conv_src_len * byte_mul));
	*s = as;

	return NDR_ERR_SUCCESS;
}


/**
  push a general string onto the wire
*/
_PUBLIC_ enum ndr_err_code ndr_push_string(struct ndr_push *ndr, int ndr_flags, const char *s)
{
	ssize_t s_len, c_len;
	size_t d_len;
	int do_convert = 1, chset = CH_UTF16;
	unsigned flags = ndr->flags;
	unsigned byte_mul = 2;
	uint8_t *dest = NULL;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

	if (NDR_BE(ndr)) {
		chset = CH_UTF16BE;
	}
	
	s_len = s?strlen(s):0;

	if (flags & LIBNDR_FLAG_STR_ASCII) {
		chset = CH_DOS;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_ASCII;
	}

	if (flags & LIBNDR_FLAG_STR_UTF8) {
		chset = CH_UTF8;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_UTF8;
	}

	if (flags & LIBNDR_FLAG_STR_RAW8) {
		do_convert = 0;
		byte_mul = 1;
		flags &= ~LIBNDR_FLAG_STR_RAW8;
	}

	flags &= ~LIBNDR_FLAG_STR_CONFORMANT;

	if (!(flags & LIBNDR_FLAG_STR_NOTERM)) {
		s_len++;
	}

	if (!do_convert) {
		d_len = s_len;
		dest = (uint8_t *)talloc_strndup(ndr, s, s_len);
	} else if (!convert_string_talloc(ndr, CH_UNIX, chset, s, s_len,
				   (void **)(void *)&dest, &d_len))
	{
		return ndr_push_error(ndr, NDR_ERR_CHARCNV, 
				      "Bad character push conversion with flags 0x%x", flags);
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

	switch ((flags & LIBNDR_STRING_FLAGS) & ~LIBNDR_FLAG_STR_NOTERM) {
	case LIBNDR_FLAG_STR_LEN4|LIBNDR_FLAG_STR_SIZE4:
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, c_len));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, c_len));
		NDR_CHECK(ndr_push_bytes(ndr, dest, d_len));
		break;

	case LIBNDR_FLAG_STR_LEN4:
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, 0));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, c_len));
		NDR_CHECK(ndr_push_bytes(ndr, dest, d_len));
		break;

	case LIBNDR_FLAG_STR_SIZE4:
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, c_len));
		NDR_CHECK(ndr_push_bytes(ndr, dest, d_len));
		break;

	case LIBNDR_FLAG_STR_SIZE2:
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, c_len));
		NDR_CHECK(ndr_push_bytes(ndr, dest, d_len));
		break;

	case LIBNDR_FLAG_STR_NULLTERM:
		NDR_CHECK(ndr_push_bytes(ndr, dest, d_len));
		break;

	default:
		if (ndr->flags & LIBNDR_FLAG_REMAINING) {
			NDR_CHECK(ndr_push_bytes(ndr, dest, d_len));
			break;		
		}

		return ndr_push_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);
	}

	talloc_free(dest);

	return NDR_ERR_SUCCESS;
}

/**
  push a general string onto the wire
*/
_PUBLIC_ size_t ndr_string_array_size(struct ndr_push *ndr, const char *s)
{
	size_t c_len;
	unsigned flags = ndr->flags;
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
	if (s) {
		ndr->print(ndr, "%-25s: '%s'", name, s);
	} else {
		ndr->print(ndr, "%-25s: NULL", name);
	}
}

_PUBLIC_ uint32_t ndr_size_string(int ret, const char * const* string, int flags) 
{
	/* FIXME: Is this correct for all strings ? */
	if(!(*string)) return ret;
	return ret+strlen(*string)+1;
}

/**
  pull a general string array from the wire
*/
_PUBLIC_ enum ndr_err_code ndr_pull_string_array(struct ndr_pull *ndr, int ndr_flags, const char ***_a)
{
	const char **a = NULL;
	uint32_t count;
	unsigned flags = ndr->flags;
	unsigned saved_flags = ndr->flags;

	if (!(ndr_flags & NDR_SCALARS)) {
		return NDR_ERR_SUCCESS;
	}

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
			a = talloc_realloc(ndr->current_mem_ctx, a, const char *, count + 2);
			NDR_ERR_HAVE_NO_MEMORY(a);
			a[count]   = NULL;
			a[count+1]   = NULL;

			tmp_ctx = ndr->current_mem_ctx;
			ndr->current_mem_ctx = a;
			NDR_CHECK(ndr_pull_string(ndr, ndr_flags, &s));
			if ((ndr->data_size - ndr->offset) == 0 && ndr->flags & LIBNDR_FLAG_REMAINING)
			{
				a[count] = s;
				break;
			}
			ndr->current_mem_ctx = tmp_ctx;
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
			return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x (missing NDR_REMAINING)\n",
					      ndr->flags & LIBNDR_STRING_FLAGS);
		}
		/*
		 * here the strings are not null terminated
		 * but serarated by a null terminator
		 *
		 * which means the same as:
		 * Every string is null terminated exept the last
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
			a = talloc_realloc(ndr->current_mem_ctx, a, const char *, count + 2);
			NDR_ERR_HAVE_NO_MEMORY(a);
			a[count]   = NULL;
			a[count+1]   = NULL;

			tmp_ctx = ndr->current_mem_ctx;
			ndr->current_mem_ctx = a;
			NDR_CHECK(ndr_pull_string(ndr, ndr_flags, &s));
			ndr->current_mem_ctx = tmp_ctx;
			a[count] = s;
		}

		*_a =a;
		break;

	default:
		return ndr_pull_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x\n",
				      ndr->flags & LIBNDR_STRING_FLAGS);
	}

	ndr->flags = saved_flags;
	return NDR_ERR_SUCCESS;
}

/**
  push a general string array onto the wire
*/
_PUBLIC_ enum ndr_err_code ndr_push_string_array(struct ndr_push *ndr, int ndr_flags, const char **a)
{
	uint32_t count;
	unsigned flags = ndr->flags;
	unsigned saved_flags = ndr->flags;

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
			return ndr_push_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x (missing NDR_REMAINING)\n",
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
		return ndr_push_error(ndr, NDR_ERR_STRING, "Bad string flags 0x%x\n",
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

	ndr->print(ndr, "%s: ARRAY(%d)", name, count);
	ndr->depth++;
	for (i=0;i<count;i++) {
		char *idx=NULL;
		if (asprintf(&idx, "[%d]", i) != -1) {
			ndr_print_string(ndr, idx, a[i]);
			free(idx);
		}
	}
	ndr->depth--;
}

_PUBLIC_ size_t ndr_size_string_array(const char **a, uint32_t count, int flags)
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

_PUBLIC_ enum ndr_err_code ndr_check_string_terminator(struct ndr_pull *ndr, uint32_t count, uint32_t element_size)
{
	uint32_t i;
	uint32_t save_offset;

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

_PUBLIC_ enum ndr_err_code ndr_pull_charset(struct ndr_pull *ndr, int ndr_flags, const char **var, uint32_t length, uint8_t byte_mul, charset_t chset)
{
	size_t converted_size;

	if (length == 0) {
		*var = talloc_strdup(ndr->current_mem_ctx, "");
		return NDR_ERR_SUCCESS;
	}

	if (NDR_BE(ndr) && chset == CH_UTF16) {
		chset = CH_UTF16BE;
	}

	NDR_PULL_NEED_BYTES(ndr, length*byte_mul);

	if (!convert_string_talloc(ndr->current_mem_ctx, chset, CH_UNIX,
				   ndr->data+ndr->offset, length*byte_mul,
				   discard_const_p(void *, var),
				   &converted_size))
	{
		return ndr_pull_error(ndr, NDR_ERR_CHARCNV, 
				      "Bad character conversion");
	}
	NDR_CHECK(ndr_pull_advance(ndr, length*byte_mul));

	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_charset_to_null(struct ndr_pull *ndr, int ndr_flags, const char **var, uint32_t length, uint8_t byte_mul, charset_t chset)
{
	size_t converted_size;
	uint32_t str_len;

	if (length == 0) {
		*var = talloc_strdup(ndr->current_mem_ctx, "");
		return NDR_ERR_SUCCESS;
	}

	if (NDR_BE(ndr) && chset == CH_UTF16) {
		chset = CH_UTF16BE;
	}

	NDR_PULL_NEED_BYTES(ndr, length*byte_mul);

	str_len = ndr_string_length(ndr->data+ndr->offset, byte_mul);
	str_len = MIN(str_len, length);	/* overrun protection */
	if (!convert_string_talloc(ndr->current_mem_ctx, chset, CH_UNIX,
				   ndr->data+ndr->offset, str_len*byte_mul,
				   discard_const_p(void *, var),
				   &converted_size))
	{
		return ndr_pull_error(ndr, NDR_ERR_CHARCNV,
				      "Bad character conversion");
	}
	NDR_CHECK(ndr_pull_advance(ndr, length*byte_mul));

	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_push_charset(struct ndr_push *ndr, int ndr_flags, const char *var, uint32_t length, uint8_t byte_mul, charset_t chset)
{
	ssize_t required;

	if (NDR_BE(ndr) && chset == CH_UTF16) {
		chset = CH_UTF16BE;
	}

	required = byte_mul * length;
	
	NDR_PUSH_NEED_BYTES(ndr, required);

	if (required) {
		size_t size = 0;
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
	}

	/* Fallback, this should never happen */
	return strlen((const char *)var)+1;
}
