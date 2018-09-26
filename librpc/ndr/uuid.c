/* 
   Unix SMB/CIFS implementation.

   UUID/GUID functions

   Copyright (C) Theodore Ts'o               1996, 1997,
   Copyright (C) Jim McDonough                     2002.
   Copyright (C) Andrew Tridgell                   2003.
   
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
#include "librpc/gen_ndr/ndr_misc.h"
#include "lib/util/util_str_hex.h"
/**
  build a NDR blob from a GUID
*/
_PUBLIC_ NTSTATUS GUID_to_ndr_blob(const struct GUID *guid, TALLOC_CTX *mem_ctx, DATA_BLOB *b)
{
	enum ndr_err_code ndr_err;
	*b = data_blob_talloc(mem_ctx, NULL, 16);
	if (b->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ndr_err = ndr_push_struct_into_fixed_blob(
		b, guid, (ndr_push_flags_fn_t)ndr_push_GUID);
	return ndr_map_error2ntstatus(ndr_err);
}


/**
  build a GUID from a NDR data blob
*/
_PUBLIC_ NTSTATUS GUID_from_ndr_blob(const DATA_BLOB *b, struct GUID *guid)
{
	enum ndr_err_code ndr_err =
		ndr_pull_struct_blob_all_noalloc(b, guid,
						 (ndr_pull_flags_fn_t)ndr_pull_GUID);
	return ndr_map_error2ntstatus(ndr_err);
}


/**
  build a GUID from a string
*/
_PUBLIC_ NTSTATUS GUID_from_data_blob(const DATA_BLOB *s, struct GUID *guid)
{
	NTSTATUS status = NT_STATUS_INVALID_PARAMETER;
	uint32_t time_low = 0;
	uint32_t time_mid = 0;
	uint32_t time_hi_and_version = 0;
	uint32_t clock_seq[2] = {0};
	uint32_t node[6] = {0};
	uint8_t buf16[16] = {0};

	DATA_BLOB blob16 = data_blob_const(buf16, sizeof(buf16));
	int i;

	if (s->data == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch(s->length) {
	case 36:
	{
		status = parse_guid_string((char *)s->data,
					   &time_low,
					   &time_mid,
					   &time_hi_and_version,
					   clock_seq,
					   node);
		break;
	}
	case 38:
	{
		if (s->data[0] != '{' || s->data[37] != '}') {
			break;
		}

		status = parse_guid_string((char *)s->data + 1,
					   &time_low,
					   &time_mid,
					   &time_hi_and_version,
					   clock_seq,
					   node);
		break;
	}
	case 32:
	{
		size_t rlen = strhex_to_str((char *)blob16.data, blob16.length,
					    (const char *)s->data, s->length);
		if (rlen != blob16.length) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		s = &blob16;
		return GUID_from_ndr_blob(s, guid);
	}
	case 16:
		return GUID_from_ndr_blob(s, guid);
	default:
		status = NT_STATUS_INVALID_PARAMETER;
		break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	guid->time_low = time_low;
	guid->time_mid = time_mid;
	guid->time_hi_and_version = time_hi_and_version;
	guid->clock_seq[0] = clock_seq[0];
	guid->clock_seq[1] = clock_seq[1];
	for (i=0;i<6;i++) {
		guid->node[i] = node[i];
	}

	return NT_STATUS_OK;
}

/**
  build a GUID from a string
*/
_PUBLIC_ NTSTATUS GUID_from_string(const char *s, struct GUID *guid)
{
	DATA_BLOB blob = data_blob_string_const(s);
	return GUID_from_data_blob(&blob, guid);
}

/**
 * generate a random GUID
 */
_PUBLIC_ struct GUID GUID_random(void)
{
	struct GUID guid;

	generate_random_buffer((uint8_t *)&guid, sizeof(guid));
	guid.clock_seq[0] = (guid.clock_seq[0] & 0x3F) | 0x80;
	guid.time_hi_and_version = (guid.time_hi_and_version & 0x0FFF) | 0x4000;

	return guid;
}

/**
 * generate an empty GUID 
 */
_PUBLIC_ struct GUID GUID_zero(void)
{
	struct GUID guid;

	ZERO_STRUCT(guid);

	return guid;
}

_PUBLIC_ bool GUID_all_zero(const struct GUID *u)
{
	if (u->time_low != 0 ||
	    u->time_mid != 0 ||
	    u->time_hi_and_version != 0 ||
	    u->clock_seq[0] != 0 ||
	    u->clock_seq[1] != 0 ||
	    !all_zero(u->node, 6)) {
		return false;
	}
	return true;
}

_PUBLIC_ bool GUID_equal(const struct GUID *u1, const struct GUID *u2)
{
	return (GUID_compare(u1, u2) == 0);
}

_PUBLIC_ int GUID_compare(const struct GUID *u1, const struct GUID *u2)
{
	if (u1->time_low != u2->time_low) {
		return u1->time_low > u2->time_low ? 1 : -1;
	}

	if (u1->time_mid != u2->time_mid) {
		return u1->time_mid > u2->time_mid ? 1 : -1;
	}

	if (u1->time_hi_and_version != u2->time_hi_and_version) {
		return u1->time_hi_and_version > u2->time_hi_and_version ? 1 : -1;
	}

	if (u1->clock_seq[0] != u2->clock_seq[0]) {
		return u1->clock_seq[0] > u2->clock_seq[0] ? 1 : -1;
	}

	if (u1->clock_seq[1] != u2->clock_seq[1]) {
		return u1->clock_seq[1] > u2->clock_seq[1] ? 1 : -1;
	}

	return memcmp(u1->node, u2->node, 6);
}

/**
  its useful to be able to display these in debugging messages
*/
_PUBLIC_ char *GUID_string(TALLOC_CTX *mem_ctx, const struct GUID *guid)
{
	struct GUID_txt_buf buf;
	return talloc_strdup(mem_ctx, GUID_buf_string(guid, &buf));
}

/**
 * Does the same without allocating memory, using the structure buffer.
 * Useful for debug messages, so that you do not have to talloc_free the result
 */
_PUBLIC_ char* GUID_buf_string(const struct GUID *guid,
			       struct GUID_txt_buf *dst)
{
	if (!guid) {
		return NULL;
	}
	snprintf(dst->buf, sizeof(dst->buf),
		 "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 guid->time_low, guid->time_mid,
		 guid->time_hi_and_version,
		 guid->clock_seq[0],
		 guid->clock_seq[1],
		 guid->node[0], guid->node[1],
		 guid->node[2], guid->node[3],
		 guid->node[4], guid->node[5]);
	return dst->buf;
}

_PUBLIC_ char *GUID_string2(TALLOC_CTX *mem_ctx, const struct GUID *guid)
{
	char *ret, *s = GUID_string(mem_ctx, guid);
	ret = talloc_asprintf(mem_ctx, "{%s}", s);
	talloc_free(s);
	return ret;
}

_PUBLIC_ char *GUID_hexstring(TALLOC_CTX *mem_ctx, const struct GUID *guid)
{
	char *ret;
	DATA_BLOB guid_blob;
	TALLOC_CTX *tmp_mem;
	NTSTATUS status;

	tmp_mem = talloc_new(mem_ctx);
	if (!tmp_mem) {
		return NULL;
	}
	status = GUID_to_ndr_blob(guid, tmp_mem, &guid_blob);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_mem);
		return NULL;
	}

	ret = data_blob_hex_string_upper(mem_ctx, &guid_blob);
	talloc_free(tmp_mem);
	return ret;
}

_PUBLIC_ bool ndr_policy_handle_empty(const struct policy_handle *h)
{
	return (h->handle_type == 0 && GUID_all_zero(&h->uuid));
}

_PUBLIC_ bool ndr_policy_handle_equal(const struct policy_handle *hnd1,
				  const struct policy_handle *hnd2)
{
	if (!hnd1 || !hnd2) {
		return false;
	}

	return (memcmp(hnd1, hnd2, sizeof(*hnd1)) == 0);
}
