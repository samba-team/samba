/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) Andrew Tridgell 1992-2001
   Copyright (C) Simo Sorce      2001-2002
   Copyright (C) Martin Pool     2003
   Copyright (C) James Peach	 2006
   Copyright (C) Jeremy Allison  1992-2007

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

static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Decode a base64 string into a DATA_BLOB - simple and slow algorithm
 **/
_PUBLIC_ DATA_BLOB base64_decode_data_blob_talloc(TALLOC_CTX *mem_ctx, const char *s)
{
	int bit_offset, byte_offset, idx, i, n;
	DATA_BLOB decoded = data_blob_talloc(mem_ctx, s, strlen(s)+1);
	unsigned char *d = decoded.data;
	char *p;

	n=i=0;

	while (*s && (p=strchr_m(b64,*s))) {
		idx = (int)(p - b64);
		byte_offset = (i*6)/8;
		bit_offset = (i*6)%8;
		d[byte_offset] &= ~((1<<(8-bit_offset))-1);
		if (bit_offset < 3) {
			d[byte_offset] |= (idx << (2-bit_offset));
			n = byte_offset+1;
		} else {
			d[byte_offset] |= (idx >> (bit_offset-2));
			d[byte_offset+1] = 0;
			d[byte_offset+1] |= (idx << (8-(bit_offset-2))) & 0xFF;
			n = byte_offset+2;
		}
		s++; i++;
	}

	if ((n > 0) && (*s == '=')) {
		n -= 1;
	}

	/* fix up length */
	decoded.length = n;
	decoded.data = talloc_realloc(mem_ctx, decoded.data, uint8_t, n);
	return decoded;
}

/**
 * Decode a base64 string into a DATA_BLOB - simple and slow algorithm
 **/
_PUBLIC_ DATA_BLOB base64_decode_data_blob(const char *s)
{
	return base64_decode_data_blob_talloc(NULL, s);
}

/**
 * Decode a base64 string in-place - wrapper for the above
 **/
_PUBLIC_ void base64_decode_inplace(char *s)
{
	DATA_BLOB decoded = base64_decode_data_blob(s);

	if ( decoded.length != 0 ) {
		memcpy(s, decoded.data, decoded.length);

		/* null terminate */
		s[decoded.length] = '\0';
	} else {
		*s = '\0';
	}

	data_blob_free(&decoded);
}

/**
 * Encode a base64 string into a talloc()ed string caller to free.
 *
 * From SQUID: adopted from http://ftp.sunet.se/pub2/gnu/vm/base64-encode.c
 * with adjustments
 **/

_PUBLIC_ char *base64_encode_data_blob(TALLOC_CTX *mem_ctx, DATA_BLOB data)
{
	int bits = 0;
	int char_count = 0;
	size_t out_cnt, len, output_len;
	char *result;

        if (!data.length || !data.data)
		return NULL;

	out_cnt = 0;
	len = data.length;
	output_len = data.length * 2 + 4; /* Account for closing bytes. 4 is
					   * random but should be enough for
					   * the = and \0 */
	result = talloc_array(mem_ctx, char, output_len); /* get us plenty of space */
	SMB_ASSERT(result != NULL);

	while (len--) {
		int c = (unsigned char) *(data.data++);
		bits += c;
		char_count++;
		if (char_count == 3) {
			result[out_cnt++] = b64[bits >> 18];
			result[out_cnt++] = b64[(bits >> 12) & 0x3f];
			result[out_cnt++] = b64[(bits >> 6) & 0x3f];
			result[out_cnt++] = b64[bits & 0x3f];
			bits = 0;
			char_count = 0;
		} else {
			bits <<= 8;
		}
	}
	if (char_count != 0) {
		bits <<= 16 - (8 * char_count);
		result[out_cnt++] = b64[bits >> 18];
		result[out_cnt++] = b64[(bits >> 12) & 0x3f];
		if (char_count == 1) {
			result[out_cnt++] = '=';
			result[out_cnt++] = '=';
		} else {
			result[out_cnt++] = b64[(bits >> 6) & 0x3f];
			result[out_cnt++] = '=';
		}
	}
	result[out_cnt] = '\0';	/* terminate */
	return result;
}

