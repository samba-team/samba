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

WERROR registry_pull_value(TALLOC_CTX *mem_ctx,
			   struct registry_value **pvalue,
			   enum winreg_Type type, uint8 *data,
			   uint32 size, uint32 length)
{
	struct registry_value *value;
	WERROR err;

	if (!(value = TALLOC_ZERO_P(mem_ctx, struct registry_value))) {
		return WERR_NOMEM;
	}

	value->type = type;

	switch (type) {
	case REG_DWORD:
		if ((size != 4) || (length != 4)) {
			err = WERR_INVALID_PARAM;
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
			err = WERR_INVALID_PARAM;
			goto error;
		}

		if (!(tmp = SMB_MALLOC_ARRAY(smb_ucs2_t, num_ucs2+1))) {
			err = WERR_NOMEM;
			goto error;
		}

		memcpy((void *)tmp, (const void *)data, length);
		tmp[num_ucs2] = 0;

		value->v.sz.len = convert_string_talloc(
			value, CH_UTF16LE, CH_UNIX, tmp, length+2,
			&value->v.sz.str, False);

		SAFE_FREE(tmp);

		if (value->v.sz.len == (size_t)-1) {
			err = WERR_INVALID_PARAM;
			goto error;
		}
		break;
	}
	case REG_MULTI_SZ:
		err = reg_pull_multi_sz(value, (void *)data, length,
					&value->v.multi_sz.num_strings,
					&value->v.multi_sz.strings);
		if (!(W_ERROR_IS_OK(err))) {
			goto error;
		}
		break;
	case REG_BINARY:
		value->v.binary.data = talloc_move(value, &data);
		value->v.binary.length = length;
		break;
	default:
		err = WERR_INVALID_PARAM;
		goto error;
	}

	*pvalue = value;
	return WERR_OK;

 error:
	TALLOC_FREE(value);
	return err;
}

WERROR registry_push_value(TALLOC_CTX *mem_ctx,
			   const struct registry_value *value,
			   DATA_BLOB *presult)
{
	switch (value->type) {
	case REG_DWORD: {
		char buf[4];
		SIVAL(buf, 0, value->v.dword);
		*presult = data_blob_talloc(mem_ctx, (void *)buf, 4);
		if (presult->data == NULL) {
			return WERR_NOMEM;
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
			return WERR_NOMEM;
		}
		break;
	}
	default:
		return WERR_INVALID_PARAM;
	}

	return WERR_OK;
}
