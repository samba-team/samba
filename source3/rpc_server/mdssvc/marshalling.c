/*
   Unix SMB/CIFS implementation.
   Main metadata server / Spotlight routines

   Copyright (C) Ralph Boehme			2012-2014

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
#include "dalloc.h"
#include "marshalling.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_RPC_SRV

/*
 * This is used to talloc an array that will hold the table of
 * contents of a marshalled Spotlight RPC (S-RPC) reply. Each ToC
 * entry is 8 bytes, so we allocate space for 1024 entries which
 * should be sufficient for even the largest S-RPC replies.
 *
 * The total buffersize for S-RPC packets is typically limited to 64k,
 * so we can only store so many elements there anyway.
 */
#define MAX_SLQ_TOC 1024*8
#define MAX_SLQ_TOCIDX 1024
#define MAX_SLQ_COUNT 4096
#define MAX_SL_STRLEN 1024

/******************************************************************************
 * RPC data marshalling and unmarshalling
 ******************************************************************************/

/* Spotlight epoch is UNIX epoch minus SPOTLIGHT_TIME_DELTA */
#define SPOTLIGHT_TIME_DELTA 280878921600ULL

#define SQ_TYPE_NULL    0x0000
#define SQ_TYPE_COMPLEX 0x0200
#define SQ_TYPE_INT64   0x8400
#define SQ_TYPE_BOOL    0x0100
#define SQ_TYPE_FLOAT   0x8500
#define SQ_TYPE_DATA    0x0700
#define SQ_TYPE_CNIDS   0x8700
#define SQ_TYPE_UUID    0x0e00
#define SQ_TYPE_DATE    0x8600
#define SQ_TYPE_TOC     0x8800

#define SQ_CPX_TYPE_ARRAY           0x0a00
#define SQ_CPX_TYPE_STRING          0x0c00
#define SQ_CPX_TYPE_UTF16_STRING    0x1c00
#define SQ_CPX_TYPE_DICT            0x0d00
#define SQ_CPX_TYPE_CNIDS           0x1a00
#define SQ_CPX_TYPE_FILEMETA        0x1b00

struct sl_tag  {
	int type;
	int count;
	size_t length;
	size_t size;
};

static ssize_t sl_pack_loop(DALLOC_CTX *query, char *buf,
			    ssize_t offset, size_t bufsize,
			    char *toc_buf, int *toc_idx, int *count);
static ssize_t sl_unpack_loop(DALLOC_CTX *query, const char *buf,
			      ssize_t offset, size_t bufsize,
			      int count, ssize_t toc_offset,
			      int encoding);

/******************************************************************************
 * Wrapper functions for the *VAL macros with bound checking
 ******************************************************************************/

static ssize_t sl_push_uint64_val(char *buf,
				  ssize_t offset,
				  size_t max_offset,
				  uint64_t val)
{
	if (offset + 8 > max_offset) {
		DEBUG(1, ("%s: offset: %zd, max_offset: %zu",
			  __func__, offset, max_offset));
		return -1;
	}

	SBVAL(buf, offset, val);
	return offset + 8;
}

static ssize_t sl_pull_uint64_val(const char *buf,
				  ssize_t offset,
				  size_t bufsize,
				  uint encoding,
				  uint64_t *presult)
{
	uint64_t val;

	if (offset + 8 > bufsize) {
		DEBUG(1,("%s: buffer overflow\n", __func__));
		return -1;
	}

	if (encoding == SL_ENC_LITTLE_ENDIAN) {
		val = BVAL(buf, offset);
	} else {
		val = RBVAL(buf, offset);
	}

	*presult = val;

	return offset + 8;
}

/*
 * Returns the UTF-16 string encoding, by checking the 2-byte byte order mark.
 * If there is no byte order mark, -1 is returned.
 */
static int spotlight_get_utf16_string_encoding(const char *buf, ssize_t offset,
					       size_t query_length, int encoding)
{
	int utf16_encoding;

	/* Assumed encoding in absence of a bom is little endian */
	utf16_encoding = SL_ENC_LITTLE_ENDIAN;

	if (query_length >= 2) {
		uint8_t le_bom[] = {0xff, 0xfe};
		uint8_t be_bom[] = {0xfe, 0xff};
		if (memcmp(le_bom, buf + offset, sizeof(uint16_t)) == 0) {
			utf16_encoding = SL_ENC_LITTLE_ENDIAN | SL_ENC_UTF_16;
		} else if (memcmp(be_bom, buf + offset, sizeof(uint16_t)) == 0) {
			utf16_encoding = SL_ENC_BIG_ENDIAN | SL_ENC_UTF_16;
		}
	}

	return utf16_encoding;
}

/******************************************************************************
 * marshalling functions
 ******************************************************************************/

static inline uint64_t sl_pack_tag(uint16_t type, uint16_t size_or_count, uint32_t val)
{
	uint64_t tag = ((uint64_t)val << 32) | ((uint64_t)type << 16) | size_or_count;
	return tag;
}

static ssize_t sl_pack_float(double d, char *buf, ssize_t offset, size_t bufsize)
{
	union {
		double d;
		uint64_t w;
	} ieee_fp_union;

	ieee_fp_union.d = d;

	offset = sl_push_uint64_val(buf, offset, bufsize, sl_pack_tag(SQ_TYPE_FLOAT, 2, 1));
	if (offset == -1) {
		return -1;
	}
	offset = sl_push_uint64_val(buf, offset, bufsize, ieee_fp_union.w);
	if (offset == -1) {
		return -1;
	}

	return offset;
}

static ssize_t sl_pack_uint64(uint64_t u, char *buf, ssize_t offset, size_t bufsize)
{
	uint64_t tag;

	tag = sl_pack_tag(SQ_TYPE_INT64, 2, 1);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}
	offset = sl_push_uint64_val(buf, offset, bufsize, u);
	if (offset == -1) {
		return -1;
	}

	return offset;
}

static ssize_t sl_pack_uint64_array(uint64_t *u, char *buf, ssize_t offset, size_t bufsize, int *toc_count)
{
	int count, i;
	uint64_t tag;

	count = talloc_array_length(u);

	tag = sl_pack_tag(SQ_TYPE_INT64, count + 1, count);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	for (i = 0; i < count; i++) {
		offset = sl_push_uint64_val(buf, offset, bufsize, u[i]);
		if (offset == -1) {
			return -1;
		}
	}

	if (count > 1) {
		*toc_count += (count - 1);
	}

	return offset;
}

static ssize_t sl_pack_bool(sl_bool_t val, char *buf, ssize_t offset, size_t bufsize)
{
	uint64_t tag;

	tag = sl_pack_tag(SQ_TYPE_BOOL, 1, val ? 1 : 0);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	return offset;
}

static ssize_t sl_pack_nil(char *buf, ssize_t offset, size_t bufsize)
{
	uint64_t tag;

	tag = sl_pack_tag(SQ_TYPE_NULL, 1, 1);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	return offset;
}

static ssize_t sl_pack_date(sl_time_t t, char *buf, ssize_t offset, size_t bufsize)
{
	uint64_t data;
	uint64_t tag;

	tag = sl_pack_tag(SQ_TYPE_DATE, 2, 1);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	data = (t.tv_sec + SPOTLIGHT_TIME_DELTA) << 24;
	offset = sl_push_uint64_val(buf, offset, bufsize, data);
	if (offset == -1) {
		return -1;
	}

	return offset;
}

static ssize_t sl_pack_uuid(sl_uuid_t *uuid, char *buf, ssize_t offset, size_t bufsize)
{
	uint64_t tag;

	tag = sl_pack_tag(SQ_TYPE_UUID, 3, 1);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	if (offset + 16 > bufsize) {
		return -1;
	}
	memcpy(buf + offset, uuid, 16);

	return offset + 16;
}

static ssize_t sl_pack_CNID(sl_cnids_t *cnids, char *buf, ssize_t offset,
			    size_t bufsize, char *toc_buf, int *toc_idx)
{
	ssize_t result;
	int len, i;
	int cnid_count = dalloc_size(cnids->ca_cnids);
	uint64_t tag;
	uint64_t id;
	void *p;

	tag = sl_pack_tag(SQ_CPX_TYPE_CNIDS, offset / 8, 0);
	result = sl_push_uint64_val(toc_buf, *toc_idx * 8, MAX_SLQ_TOC, tag);
	if (result == -1) {
		return -1;
	}

	tag = sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	*toc_idx += 1;

	len = cnid_count + 1;
	if (cnid_count > 0) {
		len ++;
	}

	/* unknown meaning, but always 8 */
	tag = sl_pack_tag(SQ_TYPE_CNIDS, len, 8 );
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	if (cnid_count > 0) {
		tag = sl_pack_tag(cnids->ca_unkn1, cnid_count, cnids->ca_context);
		offset = sl_push_uint64_val(buf, offset, bufsize, tag);
		if (offset == -1) {
			return -1;
		}

		for (i = 0; i < cnid_count; i++) {
			p = dalloc_get_object(cnids->ca_cnids, i);
			if (p == NULL) {
				return -1;
			}
			memcpy(&id, p, sizeof(uint64_t));
			offset = sl_push_uint64_val(buf, offset, bufsize, id);
			if (offset == -1) {
				return -1;
			}
		}
	}

	return offset;
}

static ssize_t sl_pack_array(sl_array_t *array, char *buf, ssize_t offset,
			     size_t bufsize, char *toc_buf, int *toc_idx)
{
	ssize_t result;
	int count = dalloc_size(array);
	int octets = offset / 8;
	uint64_t tag;
	int toc_idx_save = *toc_idx;

	tag = sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	*toc_idx += 1;

	offset = sl_pack_loop(array, buf, offset, bufsize - offset, toc_buf, toc_idx, &count);

	tag = sl_pack_tag(SQ_CPX_TYPE_ARRAY, octets, count);
	result = sl_push_uint64_val(toc_buf, toc_idx_save * 8, MAX_SLQ_TOC, tag);
	if (result == -1) {
		return -1;
	}

	return offset;
}

static ssize_t sl_pack_dict(sl_array_t *dict, char *buf, ssize_t offset,
			    size_t bufsize, char *toc_buf, int *toc_idx, int *count)
{
	ssize_t result;
	uint64_t tag;

	tag = sl_pack_tag(SQ_CPX_TYPE_DICT, offset / 8,
			  dalloc_size(dict));
	result = sl_push_uint64_val(toc_buf, *toc_idx * 8, MAX_SLQ_TOC, tag);
	if (result == -1) {
		return -1;
	}

	tag = sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	*toc_idx += 1;

	offset = sl_pack_loop(dict, buf, offset, bufsize - offset, toc_buf, toc_idx, count);

	return offset;
}

static ssize_t sl_pack_filemeta(sl_filemeta_t *fm, char *buf, ssize_t offset,
				size_t bufsize, char *toc_buf, int *toc_idx)
{
	ssize_t result;
	ssize_t fmlen;
	ssize_t saveoff = offset;
	uint64_t tag;

	tag = sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	offset += 8;

	fmlen = sl_pack(fm, buf + offset, bufsize - offset);
	if (fmlen == -1) {
		return -1;
	}

	/*
	 * Check for empty filemeta array, if it's only 40 bytes, it's
	 * only the header but no content
	 */
	if (fmlen > 40) {
		offset += fmlen;
	} else {
		fmlen = 0;
	}

	/* unknown meaning, but always 8 */
	tag = sl_pack_tag(SQ_TYPE_DATA, (fmlen / 8) + 1, 8);
	result = sl_push_uint64_val(buf, saveoff + 8, bufsize, tag);
	if (result == -1) {
		return -1;
	}

	tag = sl_pack_tag(SQ_CPX_TYPE_FILEMETA, saveoff / 8, fmlen / 8);
	result = sl_push_uint64_val(toc_buf, *toc_idx * 8, MAX_SLQ_TOC, tag);
	if (result == -1) {
		return -1;
	}

	*toc_idx += 1;

	return offset;
}

static ssize_t sl_pack_string(char *s, char *buf, ssize_t offset, size_t bufsize,
			      char *toc_buf, int *toc_idx)
{
	ssize_t result;
	size_t len, octets, used_in_last_octet;
	uint64_t tag;

	len = strlen(s);
	if (len > MAX_SL_STRLEN) {
		return -1;
	}
	octets = (len + 7) / 8;
	used_in_last_octet = len % 8;
	if (used_in_last_octet == 0) {
		used_in_last_octet = 8;
	}

	tag = sl_pack_tag(SQ_CPX_TYPE_STRING, offset / 8, used_in_last_octet);
	result = sl_push_uint64_val(toc_buf, *toc_idx * 8, MAX_SLQ_TOC, tag);
	if (result == -1) {
		return -1;
	}

	tag = sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	*toc_idx += 1;

	tag = sl_pack_tag(SQ_TYPE_DATA, octets + 1, used_in_last_octet);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		return -1;
	}

	if (offset + (octets * 8) > bufsize) {
		return -1;
	}

	memset(buf + offset, 0, octets * 8);
	memcpy(buf + offset, s, len);
	offset += octets * 8;

	return offset;
}

static ssize_t sl_pack_string_as_utf16(char *s, char *buf, ssize_t offset,
				       size_t bufsize, char *toc_buf, int *toc_idx)
{
	ssize_t result;
	int utf16_plus_bom_len, octets, used_in_last_octet;
	char *utf16string = NULL;
	char bom[] = { 0xff, 0xfe };
	size_t slen, utf16len;
	uint64_t tag;
	bool ok;

	slen = strlen(s);
	if (slen > MAX_SL_STRLEN) {
		return -1;
	}

	ok = convert_string_talloc(talloc_tos(),
				   CH_UTF8,
				   CH_UTF16LE,
				   s,
				   slen,
				   &utf16string,
				   &utf16len);
	if (!ok) {
		return -1;
	}

	utf16_plus_bom_len = utf16len + 2;
	octets = (utf16_plus_bom_len + 7) / 8;
	used_in_last_octet = utf16_plus_bom_len % 8;
	if (used_in_last_octet == 0) {
		used_in_last_octet = 8;
	}

	tag = sl_pack_tag(SQ_CPX_TYPE_UTF16_STRING, offset / 8, used_in_last_octet);
	result = sl_push_uint64_val(toc_buf, *toc_idx * 8, MAX_SLQ_TOC, tag);
	if (result == -1) {
		offset = -1;
		goto done;
	}

	tag = sl_pack_tag(SQ_TYPE_COMPLEX, 1, *toc_idx + 1);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		goto done;
	}

	*toc_idx += 1;

	tag = sl_pack_tag(SQ_TYPE_DATA, octets + 1, used_in_last_octet);
	offset = sl_push_uint64_val(buf, offset, bufsize, tag);
	if (offset == -1) {
		goto done;
	}

	if (offset + (octets * 8) > bufsize) {
		offset = -1;
		goto done;
	}

	memset(buf + offset, 0, octets * 8);
	memcpy(buf + offset, &bom, sizeof(bom));
	memcpy(buf + offset + 2, utf16string, utf16len);
	offset += octets * 8;

done:
	TALLOC_FREE(utf16string);
	return offset;
}

static ssize_t sl_pack_loop(DALLOC_CTX *query, char *buf, ssize_t offset,
			    size_t bufsize, char *toc_buf, int *toc_idx, int *count)
{
	const char *type;
	int n;
	uint64_t i;
	sl_bool_t bl;
	double d;
	sl_time_t t;
	void *p;

	for (n = 0; n < dalloc_size(query); n++) {

		type = dalloc_get_name(query, n);
		if (type == NULL) {
			return -1;
		}
		p = dalloc_get_object(query, n);
		if (p == NULL) {
			return -1;
		}

		if (strcmp(type, "sl_array_t") == 0) {
			offset = sl_pack_array(p, buf, offset, bufsize,
					       toc_buf, toc_idx);
		} else if (strcmp(type, "sl_dict_t") == 0) {
			offset = sl_pack_dict(p, buf, offset, bufsize,
					      toc_buf, toc_idx, count);
		} else if (strcmp(type, "sl_filemeta_t") == 0) {
			offset = sl_pack_filemeta(p, buf, offset, bufsize,
						  toc_buf, toc_idx);
		} else if (strcmp(type, "uint64_t") == 0) {
			memcpy(&i, p, sizeof(uint64_t));
			offset = sl_pack_uint64(i, buf, offset, bufsize);
		} else if (strcmp(type, "uint64_t *") == 0) {
			offset = sl_pack_uint64_array(p, buf, offset,
						      bufsize, count);
		} else if (strcmp(type, "char *") == 0) {
			offset = sl_pack_string(p, buf, offset, bufsize,
						toc_buf, toc_idx);						
		} else if (strcmp(type, "smb_ucs2_t *") == 0) {
			offset = sl_pack_string_as_utf16(p, buf, offset, bufsize,
							 toc_buf, toc_idx);
		} else if (strcmp(type, "sl_bool_t") == 0) {
			memcpy(&bl, p, sizeof(sl_bool_t));
			offset = sl_pack_bool(bl, buf, offset, bufsize);
		} else if (strcmp(type, "double") == 0) {
			memcpy(&d, p, sizeof(double));
			offset = sl_pack_float(d, buf, offset, bufsize);
		} else if (strcmp(type, "sl_nil_t") == 0) {
			offset = sl_pack_nil(buf, offset, bufsize);
		} else if (strcmp(type, "sl_time_t") == 0) {
			memcpy(&t, p, sizeof(sl_time_t));
			offset = sl_pack_date(t, buf, offset, bufsize);
		} else if (strcmp(type, "sl_uuid_t") == 0) {
			offset = sl_pack_uuid(p, buf, offset, bufsize);
		} else if (strcmp(type, "sl_cnids_t") == 0) {
			offset = sl_pack_CNID(p, buf, offset,
					      bufsize, toc_buf, toc_idx);
		} else {
			DEBUG(1, ("unknown type: %s", type));
			return -1;
		}
		if (offset == -1) {
			DEBUG(1, ("error packing type: %s\n", type));
			return -1;
		}
	}

	return offset;
}

/******************************************************************************
 * unmarshalling functions
 ******************************************************************************/

static ssize_t sl_unpack_tag(const char *buf,
			     ssize_t offset,
			     size_t bufsize,
			     uint encoding,
			     struct sl_tag *tag)
{
	uint64_t val;

	if (offset + 8 > bufsize) {
		DEBUG(1,("%s: buffer overflow\n", __func__));
		return -1;
	}

	if (encoding == SL_ENC_LITTLE_ENDIAN) {
		val = BVAL(buf, offset);
	} else {
		val = RBVAL(buf, offset);
	}

	tag->size = (val & 0xffff) * 8;
	tag->type = (val & 0xffff0000) >> 16;
	tag->count = val >> 32;
	tag->length = tag->count * 8;

	if (tag->size > MAX_SL_FRAGMENT_SIZE) {
		DEBUG(1,("%s: size limit %zu\n", __func__, tag->size));
		return -1;
	}

	if (tag->length > MAX_SL_FRAGMENT_SIZE) {
		DEBUG(1,("%s: length limit %zu\n", __func__, tag->length));
		return -1;
	}

	if (tag->count > MAX_SLQ_COUNT) {
		DEBUG(1,("%s: count limit %d\n", __func__, tag->count));
		return -1;
	}

	return offset + 8;
}

static int sl_unpack_ints(DALLOC_CTX *query,
			  const char *buf,
			  ssize_t offset,
			  size_t bufsize,
			  int encoding)
{
	int i, result;
	struct sl_tag tag;
	uint64_t query_data64;

	offset = sl_unpack_tag(buf, offset, bufsize, encoding, &tag);
	if (offset == -1) {
		return -1;
	}

	for (i = 0; i < tag.count; i++) {
		offset = sl_pull_uint64_val(buf, offset, bufsize, encoding, &query_data64);
		if (offset == -1) {
			return -1;
		}
		result = dalloc_add_copy(query, &query_data64, uint64_t);
		if (result != 0) {
			return -1;
		}
	}

	return tag.count;
}

static int sl_unpack_date(DALLOC_CTX *query,
			  const char *buf,
			  ssize_t offset,
			  size_t bufsize,
			  int encoding)
{
	int i, result;
	struct sl_tag tag;
	uint64_t query_data64;
	sl_time_t t;

	offset = sl_unpack_tag(buf, offset, bufsize, encoding, &tag);
	if (offset == -1) {
		return -1;
	}

	for (i = 0; i < tag.count; i++) {
		offset = sl_pull_uint64_val(buf, offset, bufsize, encoding, &query_data64);
		if (offset == -1) {
			return -1;
		}
		query_data64 = query_data64 >> 24;
		t.tv_sec = query_data64 - SPOTLIGHT_TIME_DELTA;
		t.tv_usec = 0;
		result = dalloc_add_copy(query, &t, sl_time_t);
		if (result != 0) {
			return -1;
		}
	}

	return tag.count;
}

static int sl_unpack_uuid(DALLOC_CTX *query,
			  const char *buf,
			  ssize_t offset,
			  size_t bufsize,
			  int encoding)
{
	int i, result;
	sl_uuid_t uuid;
	struct sl_tag tag;

	offset = sl_unpack_tag(buf, offset, bufsize, encoding, &tag);
	if (offset == -1) {
		return -1;
	}

	for (i = 0; i < tag.count; i++) {
		if (offset + 16 > bufsize) {
			DEBUG(1,("%s: buffer overflow\n", __func__));
			return -1;
		}
		memcpy(uuid.sl_uuid, buf + offset, 16);
		result = dalloc_add_copy(query, &uuid, sl_uuid_t);
		if (result != 0) {
			return -1;
		}
		offset += 16;
	}

	return tag.count;
}

static int sl_unpack_floats(DALLOC_CTX *query,
			    const char *buf,
			    ssize_t offset,
			    size_t bufsize,
			    int encoding)
{
	int i, result;
	union {
		double d;
		uint32_t w[2];
	} ieee_fp_union;
	struct sl_tag tag;

	offset = sl_unpack_tag(buf, offset, bufsize, encoding, &tag);
	if (offset == -1) {
		return -1;
	}

	for (i = 0; i < tag.count; i++) {
		if (offset + 8 > bufsize) {
			DEBUG(1,("%s: buffer overflow\n", __func__));
			return -1;
		}
		if (encoding == SL_ENC_LITTLE_ENDIAN) {
#ifdef WORDS_BIGENDIAN
			ieee_fp_union.w[0] = IVAL(buf, offset + 4);
			ieee_fp_union.w[1] = IVAL(buf, offset);
#else
			ieee_fp_union.w[0] = IVAL(buf, offset);
			ieee_fp_union.w[1] = IVAL(buf, offset + 4);
#endif
		} else {
#ifdef WORDS_BIGENDIAN
			ieee_fp_union.w[0] = RIVAL(buf, offset);
			ieee_fp_union.w[1] = RIVAL(buf, offset + 4);
#else
			ieee_fp_union.w[0] = RIVAL(buf, offset + 4);
			ieee_fp_union.w[1] = RIVAL(buf, offset);
#endif
		}
		result = dalloc_add_copy(query, &ieee_fp_union.d, double);
		if (result != 0) {
			return -1;
		}
		offset += 8;
	}

	return tag.count;
}

static int sl_unpack_CNID(DALLOC_CTX *query,
			  const char *buf,
			  ssize_t offset,
			  size_t bufsize,
			  int length,
			  int encoding)
{
	int i, count, result;
	uint64_t query_data64;
	sl_cnids_t *cnids;

	cnids = talloc_zero(query, sl_cnids_t);
	if (cnids == NULL) {
		return -1;
	}
	cnids->ca_cnids = dalloc_new(cnids);
	if (cnids->ca_cnids == NULL) {
		return -1;
	}

	if (length < 8) {
		return -1;
	}
	if (length == 8) {
		/*
		 * That's permitted, length=8 is an empty CNID array.
		 */
		result = dalloc_add(query, cnids, sl_cnids_t);
		if (result != 0) {
			return -1;
		}
		return 0;
	}

	offset = sl_pull_uint64_val(buf, offset, bufsize, encoding, &query_data64);
	if (offset == -1) {
		return -1;
	}

	/*
	 * Note: ca_unkn1 and ca_context could be taken from the tag
	 * type and count members, but the fields are packed
	 * differently in this context, so we can't use
	 * sl_unpack_tag().
	 */
	count = query_data64 & 0xffff;;
	cnids->ca_unkn1 = (query_data64 & 0xffff0000) >> 16;
	cnids->ca_context = query_data64 >> 32;

	for (i = 0; i < count; i++) {
		offset = sl_pull_uint64_val(buf, offset, bufsize, encoding, &query_data64);
		if (offset == -1) {
			return -1;
		}

		result = dalloc_add_copy(cnids->ca_cnids, &query_data64, uint64_t);
		if (result != 0) {
			return -1;
		}
	}

	result = dalloc_add(query, cnids, sl_cnids_t);
	if (result != 0) {
		return -1;
	}

	return 0;
}

static ssize_t sl_unpack_cpx(DALLOC_CTX *query,
			     const char *buf,
			     ssize_t offset,
			     size_t bufsize,
			     int cpx_query_type,
			     int cpx_query_count,
			     ssize_t toc_offset,
			     int encoding)
{
	int result;
	ssize_t roffset = offset;
	int unicode_encoding;
	bool mark_exists;
	char *p;
	size_t slen, tmp_len;
	sl_array_t *sl_array;
	sl_dict_t *sl_dict;
	sl_filemeta_t *sl_fm;
	bool ok;
	struct sl_tag tag;

	switch (cpx_query_type) {
	case SQ_CPX_TYPE_ARRAY:
		sl_array = dalloc_zero(query, sl_array_t);
		if (sl_array == NULL) {
			return -1;
		}
		roffset = sl_unpack_loop(sl_array, buf, offset, bufsize,
					 cpx_query_count, toc_offset, encoding);
		if (roffset == -1) {
			return -1;
		}
		result = dalloc_add(query, sl_array, sl_array_t);
		if (result != 0) {
			return -1;
		}
		break;

	case SQ_CPX_TYPE_DICT:
		sl_dict = dalloc_zero(query, sl_dict_t);
		if (sl_dict == NULL) {
			return -1;
		}
		roffset = sl_unpack_loop(sl_dict, buf, offset, bufsize,
					 cpx_query_count, toc_offset, encoding);
		if (roffset == -1) {
			return -1;
		}
		result = dalloc_add(query, sl_dict, sl_dict_t);
		if (result != 0) {
			return -1;
		}
		break;

	case SQ_CPX_TYPE_STRING:
	case SQ_CPX_TYPE_UTF16_STRING:
		offset = sl_unpack_tag(buf, offset, bufsize, encoding, &tag);
		if (offset == -1) {
			return -1;
		}

		if (tag.size < 16) {
			DEBUG(1,("%s: string buffer too small\n", __func__));
			return -1;
		}
		slen = tag.size - 16 + tag.count;
		if (slen > MAX_SL_FRAGMENT_SIZE) {
			return -1;
		}

		if (offset + slen > bufsize) {
			DEBUG(1,("%s: buffer overflow\n", __func__));
			return -1;
		}

		if (cpx_query_type == SQ_CPX_TYPE_STRING) {
			p = talloc_strndup(query, buf + offset, slen);
			if (p == NULL) {
				return -1;
			}
		} else {
			unicode_encoding = spotlight_get_utf16_string_encoding(
				buf, offset, slen, encoding);
			mark_exists = (unicode_encoding & SL_ENC_UTF_16) ? true : false;
			if (unicode_encoding & SL_ENC_BIG_ENDIAN) {
				DEBUG(1, ("Unsupported big endian UTF16 string"));
				return -1;
			}
			slen -= mark_exists ? 2 : 0;
			ok = convert_string_talloc(
				query,
				CH_UTF16LE,
				CH_UTF8,
				buf + offset + (mark_exists ? 2 : 0),
				slen,
				&p,
				&tmp_len);
			if (!ok) {
				return -1;
			}
		}

		result = dalloc_stradd(query, p);
		if (result != 0) {
			return -1;
		}
		roffset += tag.size;
		break;

	case SQ_CPX_TYPE_FILEMETA:
		offset = sl_unpack_tag(buf, offset, bufsize, encoding, &tag);
		if (offset == -1) {
			return -1;
		}
		if (tag.size < 8) {
			DBG_WARNING("size too mall: %zu\n", tag.size);
			return -1;
		}

		sl_fm = dalloc_zero(query, sl_filemeta_t);
		if (sl_fm == NULL) {
			return -1;
		}

		if (tag.size >= 16) {
			result = sl_unpack(sl_fm,
					   buf + offset,
					   bufsize - offset );
			if (result == -1) {
				return -1;
			}
		}
		result = dalloc_add(query, sl_fm, sl_filemeta_t);
		if (result != 0) {
			return -1;
		}
		roffset += tag.size;
		break;

	case SQ_CPX_TYPE_CNIDS:
		offset = sl_unpack_tag(buf, offset, bufsize, encoding, &tag);
		if (offset == -1) {
			return -1;
		}

		result = sl_unpack_CNID(query, buf, offset, bufsize,
					tag.size, encoding);
		if (result == -1) {
			return -1;
		}
		roffset += tag.size;
		break;

	default:
		DEBUG(1, ("unkown complex query type: %u", cpx_query_type));
		return -1;
	}

	return roffset;
}

static ssize_t sl_unpack_loop(DALLOC_CTX *query,
			      const char *buf,
			      ssize_t offset,
			      size_t bufsize,
			      int count,
			      ssize_t toc_offset,
			      int encoding)
{
	int i, toc_index, subcount;
	uint64_t result;

	while (count > 0) {
		struct sl_tag tag;

		if (offset >= toc_offset) {
			return -1;
		}

		result = sl_unpack_tag(buf, offset, bufsize, encoding, &tag);
		if (result == -1) {
			return -1;
		}

		switch (tag.type) {
		case SQ_TYPE_COMPLEX: {
			struct sl_tag cpx_tag;

			if (tag.count < 1) {
				DEBUG(1,("%s: invalid tag.count: %d\n",
					 __func__, tag.count));
				return -1;
			}
			toc_index = tag.count - 1;
			if (toc_index > MAX_SLQ_TOCIDX) {
				DEBUG(1,("%s: toc_index too large: %d\n",
					 __func__, toc_index));
				return -1;
			}
			result = sl_unpack_tag(buf, toc_offset + (toc_index * 8),
					       bufsize, encoding, &cpx_tag);
			if (result == -1) {
				return -1;
			}

			offset = sl_unpack_cpx(query, buf, offset + 8, bufsize, cpx_tag.type,
					       cpx_tag.count, toc_offset, encoding);
			if (offset == -1) {
				return -1;
			}
			/*
			 * tag.size is not the size here, so we need
			 * to use the offset returned from sl_unpack_cpx()
			 * instead of offset += tag.size;
			 */
			count--;
			break;
		}

		case SQ_TYPE_NULL: {
			sl_nil_t nil = 0;

			subcount = tag.count;
			if (subcount > count) {
				return -1;
			}
			for (i = 0; i < subcount; i++) {
				result = dalloc_add_copy(query, &nil, sl_nil_t);
				if (result != 0) {
					return -1;
				}
			}
			offset += tag.size;
			count -= subcount;
			break;
		}

		case SQ_TYPE_BOOL: {
			sl_bool_t b = (tag.count != 0);

			result = dalloc_add_copy(query, &b, sl_bool_t);
			if (result != 0) {
				return -1;
			}
			offset += tag.size;
			count--;
			break;
		}

		case SQ_TYPE_INT64:
			subcount = sl_unpack_ints(query, buf, offset, bufsize, encoding);
			if (subcount == -1 || subcount > count) {
				return -1;
			}
			offset += tag.size;
			count -= subcount;
			break;

		case SQ_TYPE_UUID:
			subcount = sl_unpack_uuid(query, buf, offset, bufsize, encoding);
			if (subcount == -1 || subcount > count) {
				return -1;
			}
			offset += tag.size;
			count -= subcount;
			break;

		case SQ_TYPE_FLOAT:
			subcount = sl_unpack_floats(query, buf, offset, bufsize, encoding);
			if (subcount == -1 || subcount > count) {
				return -1;
			}
			offset += tag.size;
			count -= subcount;
			break;

		case SQ_TYPE_DATE:
			subcount = sl_unpack_date(query, buf, offset, bufsize, encoding);
			if (subcount == -1 || subcount > count) {
				return -1;
			}
			offset += tag.size;
			count -= subcount;
			break;

		default:
			DEBUG(1, ("unknown query type: %d\n", tag.type));
			return -1;
		}
	}

	return offset;
}

/******************************************************************************
 * Global functions for packing und unpacking
 ******************************************************************************/

ssize_t sl_pack(DALLOC_CTX *query, char *buf, size_t bufsize)
{
	ssize_t result;
	char *toc_buf;
	int toc_index = 0;
	int toc_count = 0;
	ssize_t offset, len;
	uint64_t hdr;
	uint32_t total_octets;
	uint32_t data_octets;
	uint64_t tag;

	memset(buf, 0, bufsize);

	toc_buf = talloc_zero_size(query, MAX_SLQ_TOC + 8);
	if (toc_buf == NULL) {
		return -1;
	}

	offset = sl_pack_loop(query, buf, 16, bufsize, toc_buf + 8, &toc_index, &toc_count);
	if (offset == -1 || offset < 16) {
		DEBUG(10,("%s: sl_pack_loop error\n", __func__));
		return -1;
	}
	len = offset - 16;

	/*
	 * Marshalling overview:
	 *
	 * 16 bytes at the start of buf:
	 *
	 * 8 bytes byte order mark
	 * 4 bytes total octets
	 * 4 bytes table of content octets
	 *
	 * x bytes total octets * 8 from sl_pack_loop
	 * x bytes ToC octets * 8 from toc_buf
	 */

	/* Byte-order mark - we are using little endian only for now */
	memcpy(buf, "432130dm", strlen("432130dm"));

	/*
	 * The data buffer and ToC buffer sizes are enocoded in number
	 * of octets (size / 8), plus one, because the octet encoding
	 * the sizes is included.
	 */
	data_octets = (len / 8) + 1;
	total_octets = data_octets + toc_index + 1;

	hdr = total_octets;
	hdr |= ((uint64_t)data_octets << 32);

	/* HDR */
	result = sl_push_uint64_val(buf, 8, bufsize, hdr);
	if (result == -1) {
		return -1;
	}

	/*
	 * ToC tag with number of ToC entries plus one, the ToC tag
	 * header.
	 */
	tag = sl_pack_tag(SQ_TYPE_TOC, toc_index + 1, 0);
	result = sl_push_uint64_val(toc_buf, 0, MAX_SLQ_TOC, tag);
	if (result == -1) {
		return -1;
	}

	if ((16 + len + ((toc_index + 1 ) * 8)) > bufsize) {
		DEBUG(1, ("%s: exceeding size limit %zu", __func__, bufsize));
		return -1;
	}

	memcpy(buf + 16 + len, toc_buf, (toc_index + 1 ) * 8);
	len += 16 + (toc_index + 1 ) * 8;

	return len;
}

bool sl_unpack(DALLOC_CTX *query, const char *buf, size_t bufsize)
{
	ssize_t result;
	ssize_t offset = 0;
	int encoding;
	uint64_t hdr;
	uint32_t total_octets;
	uint64_t total_bytes;
	uint32_t data_octets;
	uint64_t data_bytes;
	uint64_t toc_offset;
	struct sl_tag toc_tag;

	if (bufsize > MAX_SL_FRAGMENT_SIZE) {
		return false;
	}

	if (bufsize < 8) {
		return false;
	}
	if (strncmp(buf + offset, "md031234", 8) == 0) {
		encoding = SL_ENC_BIG_ENDIAN;
	} else {
		encoding = SL_ENC_LITTLE_ENDIAN;
	}
	offset += 8;

	offset = sl_pull_uint64_val(buf, offset, bufsize, encoding, &hdr);
	if (offset == -1) {
		return false;
	}

	total_octets = hdr & UINT32_MAX;
	data_octets = hdr >> 32;

	/*
	 * Both fields contain the number of octets of the
	 * corresponding buffer plus the tag octet. We adjust the
	 * values to match just the number of octets in the buffers.
	 */
	if (total_octets < 1) {
		return false;
	}
	if (data_octets < 1) {
		return false;
	}
	total_octets--;
	data_octets--;
	data_bytes = ((uint64_t)data_octets) * 8;
	total_bytes = ((uint64_t)total_octets) * 8;

	if (data_bytes >= total_bytes) {
		DEBUG(1,("%s: data_bytes: %" PRIu64 ", total_bytes: %" PRIu64 "\n",
			 __func__, data_bytes, total_bytes));
		return false;
	}

	if (total_bytes > (bufsize - offset)) {
		return false;
	}

	toc_offset = data_bytes;

	toc_offset = sl_unpack_tag(buf + offset, toc_offset,
				   bufsize - offset, encoding, &toc_tag);
	if (toc_offset == -1) {
		return false;
	}

	if (toc_tag.type != SQ_TYPE_TOC) {
		DEBUG(1,("%s: unknown tag type %d\n", __func__, toc_tag.type));
		return false;
	}

	/*
	 * Check toc_tag.size even though we don't use it when unmarshalling
	 */
	if (toc_tag.size > MAX_SLQ_TOC) {
		DEBUG(1,("%s: bad size %zu\n", __func__, toc_tag.size));
		return false;
	}
	if (toc_tag.size > (total_bytes - data_bytes)) {
		DEBUG(1,("%s: bad size %zu\n", __func__, toc_tag.size));
		return false;
	}

	if (toc_tag.count != 0) {
		DEBUG(1,("%s: bad count %u\n", __func__, toc_tag.count));
		return false;
	}

	/*
	 * We already consumed 16 bytes from the buffer (BOM and size
	 * tag), so we start at buf + offset.
	 */
	result = sl_unpack_loop(query, buf + offset, 0, bufsize - offset,
				1, toc_offset, encoding);
	if (result == -1) {
		DEBUG(1,("%s: sl_unpack_loop failed\n", __func__));
		return false;
	}

	return true;
}
