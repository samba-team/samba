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

#include "replace.h"
#include "lib/util/samba_util.h"
#include "lib/util/genrand.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "lib/util/util_str_hex.h"

_PUBLIC_ NTSTATUS GUID_to_ndr_buf(
	const struct GUID *guid, struct GUID_ndr_buf *buf)
{
	DATA_BLOB b = { .data = buf->buf, .length = sizeof(buf->buf), };
	enum ndr_err_code ndr_err;

	ndr_err = ndr_push_struct_into_fixed_blob(
		&b, guid, (ndr_push_flags_fn_t)ndr_push_GUID);
	return ndr_map_error2ntstatus(ndr_err);
}

/**
  build a NDR blob from a GUID
*/
_PUBLIC_ NTSTATUS GUID_to_ndr_blob(const struct GUID *guid, TALLOC_CTX *mem_ctx, DATA_BLOB *b)
{
	struct GUID_ndr_buf buf = { .buf = {0}, };
	NTSTATUS status;

	status = GUID_to_ndr_buf(guid, &buf);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*b = data_blob_talloc(mem_ctx, buf.buf, sizeof(buf.buf));
	if (b->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	return NT_STATUS_OK;
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
	bool ok;

	if (s->data == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (s->length == 36) {
		ok = parse_guid_string((char *)s->data, guid);
		return ok ? NT_STATUS_OK : NT_STATUS_INVALID_PARAMETER;
	}

	if (s->length == 38) {
		if (s->data[0] != '{' || s->data[37] != '}') {
			return NT_STATUS_INVALID_PARAMETER;
		}
		ok = parse_guid_string((char *)s->data + 1, guid);
		return ok ? NT_STATUS_OK : NT_STATUS_INVALID_PARAMETER;
	}

	if (s->length == 32) {
		uint8_t buf16[16] = {0};
		DATA_BLOB blob16 = { .data = buf16, .length = sizeof(buf16) };
		size_t rlen = strhex_to_str((char *)blob16.data, blob16.length,
					    (const char *)s->data, s->length);
		if (rlen != blob16.length) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		return GUID_from_ndr_blob(&blob16, guid);
	}

	if (s->length == 16) {
		return GUID_from_ndr_blob(s, guid);
	}

	return NT_STATUS_INVALID_PARAMETER;
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
	return (struct GUID) { .time_low = 0 };
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
	struct GUID_txt_buf buf;
	char *ret = talloc_asprintf(
		mem_ctx, "{%s}", GUID_buf_string(guid, &buf));
	return ret;
}

_PUBLIC_ char *GUID_hexstring(TALLOC_CTX *mem_ctx, const struct GUID *guid)
{
	char *ret = NULL;
	DATA_BLOB guid_blob = { .data = NULL };
	NTSTATUS status;

	status = GUID_to_ndr_blob(guid, mem_ctx, &guid_blob);
	if (NT_STATUS_IS_OK(status)) {
		ret = data_blob_hex_string_upper(mem_ctx, &guid_blob);
	}
	TALLOC_FREE(guid_blob.data);
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
