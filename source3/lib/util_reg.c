/*
 * Unix SMB/CIFS implementation.
 * Registry helper routines
 * Copyright (C) Volker Lendecke 2006
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

const char *reg_type_lookup(enum winreg_Type type)
{
	const char *result;

	switch(type) {
	case REG_NONE:
		result = "REG_NONE";
		break;
	case REG_SZ:
		result = "REG_SZ";
		break;
	case REG_EXPAND_SZ:
		result = "REG_EXPAND_SZ";
		break;
	case REG_BINARY:
		result = "REG_BINARY";
		break;
	case REG_DWORD:
		result = "REG_DWORD";
		break;
	case REG_DWORD_BIG_ENDIAN:
		result = "REG_DWORD_BIG_ENDIAN";
		break;
	case REG_LINK:
		result = "REG_LINK";
		break;
	case REG_MULTI_SZ:
		result = "REG_MULTI_SZ";
		break;
	case REG_RESOURCE_LIST:
		result = "REG_RESOURCE_LIST";
		break;
	case REG_FULL_RESOURCE_DESCRIPTOR:
		result = "REG_FULL_RESOURCE_DESCRIPTOR";
		break;
	case REG_RESOURCE_REQUIREMENTS_LIST:
		result = "REG_RESOURCE_REQUIREMENTS_LIST";
		break;
	case REG_QWORD:
		result = "REG_QWORD";
		break;
	default:
		result = "REG TYPE IS UNKNOWN";
		break;
	}
	return result;
}

NTSTATUS reg_pull_multi_sz(TALLOC_CTX *mem_ctx, const void *buf, size_t len,
			   uint32 *num_values, char ***values)
{
	const smb_ucs2_t *p = (const smb_ucs2_t *)buf;
	*num_values = 0;

	/*
	 * Make sure that a talloc context for the strings retrieved exists
	 */

	if (!(*values = TALLOC_ARRAY(mem_ctx, char *, 1))) {
		return NT_STATUS_NO_MEMORY;
	}

	len /= 2; 		/* buf is a set of UCS2 strings */

	while (len > 0) {
		char *val;
		size_t dstlen, thislen;

		thislen = strnlen_w(p, len) + 1;
		dstlen = convert_string_allocate(*values, CH_UTF16LE, CH_UNIX,
						 p, thislen*2, (void *)&val,
						 True);
		if (dstlen == (size_t)-1) {
			TALLOC_FREE(*values);
			return NT_STATUS_NO_MEMORY;
		}

		ADD_TO_ARRAY(*values, char *, val, values, num_values);
		if (*values == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		p += thislen;
		len -= thislen;
	}

	return NT_STATUS_OK;
}

NTSTATUS registry_pull_value(TALLOC_CTX *mem_ctx,
			     struct registry_value **pvalue,
			     enum winreg_Type type, uint8 *data,
			     uint32 size, uint32 length)
{
	struct registry_value *value;
	NTSTATUS status;

	if (!(value = TALLOC_ZERO_P(mem_ctx, struct registry_value))) {
		return NT_STATUS_NO_MEMORY;
	}

	value->type = type;

	switch (type) {
	case REG_DWORD:
		if ((size != 4) || (length != 4)) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto error;
		}
		value->v.dword = IVAL(data, 0);
		break;
	case REG_SZ:
	case REG_EXPAND_SZ:
	{
		/*
		 * Make sure we get a NULL terminated string for
		 * convert_string_talloc().
		 */

		smb_ucs2_t *tmp;
		uint32 num_ucs2 = length / 2;

		if ((length % 2) != 0) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto error;
		}

		if (!(tmp = SMB_MALLOC_ARRAY(smb_ucs2_t, num_ucs2+1))) {
			status = NT_STATUS_NO_MEMORY;
			goto error;
		}

		memcpy((void *)tmp, (const void *)data, length);
		tmp[num_ucs2] = 0;

		value->v.sz.len = convert_string_talloc(
			value, CH_UTF16LE, CH_UNIX, tmp, length+2,
			&value->v.sz.str, False);

		SAFE_FREE(tmp);

		if (value->v.sz.len == (size_t)-1) {
			status = NT_STATUS_INVALID_PARAMETER;
			goto error;
		}
		break;
	}
	case REG_MULTI_SZ:
		status = reg_pull_multi_sz(value, (void *)data, length,
					   &value->v.multi_sz.num_strings,
					   &value->v.multi_sz.strings);
		if (!(NT_STATUS_IS_OK(status))) {
			goto error;
		}
		break;
	case REG_BINARY:
		value->v.binary.data = talloc_move(value, &data);
		value->v.binary.length = length;
		break;
	default:
		status = NT_STATUS_INVALID_PARAMETER;
		goto error;
	}

	*pvalue = value;
	return NT_STATUS_OK;

 error:
	TALLOC_FREE(value);
	return status;
}

NTSTATUS registry_push_value(TALLOC_CTX *mem_ctx,
			     const struct registry_value *value,
			     DATA_BLOB *presult)
{
	switch (value->type) {
	case REG_DWORD: {
		char buf[4];
		SIVAL(buf, 0, value->v.dword);
		*presult = data_blob_talloc(mem_ctx, (void *)buf, 4);
		if (presult->data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		break;
	}
	case REG_SZ:
	case REG_EXPAND_SZ: {
		presult->length = convert_string_talloc(
			mem_ctx, CH_UNIX, CH_UTF16LE, value->v.sz.str,
			MIN(value->v.sz.len, strlen(value->v.sz.str)+1),
			(void *)&(presult->data), False);
		if (presult->length == (size_t)-1) {
			return NT_STATUS_NO_MEMORY;
		}
		break;
	}
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}
