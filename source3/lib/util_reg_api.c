/*
 * Unix SMB/CIFS implementation.
 * Registry helper routines
 * Copyright (C) Volker Lendecke 2006
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_REGISTRY

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

		if (length == 1) {
			/* win2k regedit gives us a string of 1 byte when
			 * creating a new value of type REG_SZ. this workaround
			 * replaces the input by using the same string as
			 * winxp delivers. */
			length = 2;
			if (!(tmp = SMB_MALLOC_ARRAY(smb_ucs2_t, 2))) {
				err = WERR_NOMEM;
				goto error;
			}
			tmp[0] = 0;
			tmp[1] = 0;
			DEBUG(10, ("got REG_SZ value of length 1 - workaround "
				   "activated.\n"));
		}
		else if ((length % 2) != 0) {
			err = WERR_INVALID_PARAM;
			goto error;
		}
		else {
			uint32 num_ucs2 = length / 2;
			if (!(tmp = SMB_MALLOC_ARRAY(smb_ucs2_t, num_ucs2+1))) {
				err = WERR_NOMEM;
				goto error;
			}

			memcpy((void *)tmp, (const void *)data, length);
			tmp[num_ucs2] = 0;
		}

		if (length + 2 < length) {
			/* Integer wrap. */
			SAFE_FREE(tmp);
			err = WERR_INVALID_PARAM;
			goto error;
		}

		if (!convert_string_talloc(value, CH_UTF16LE, CH_UNIX, tmp,
					   length+2, &value->v.sz.str,
					   &value->v.sz.len, False)) {
			SAFE_FREE(tmp);
			err = WERR_INVALID_PARAM;
			goto error;
		}

		SAFE_FREE(tmp);
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
		value->v.binary = data_blob_talloc(mem_ctx, data, length);
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
		if (!convert_string_talloc(mem_ctx, CH_UNIX, CH_UTF16LE,
					   value->v.sz.str,
					   MIN(value->v.sz.len,
					       strlen(value->v.sz.str)+1),
					   (void *)&(presult->data),
					   &presult->length, False))
		{
			return WERR_NOMEM;
		}
		break;
	}
	case REG_MULTI_SZ: {
		uint32_t count;
		size_t len = 0;
		char **strings;
		size_t *string_lengths;
		uint32_t ofs;
		TALLOC_CTX *tmp_ctx = talloc_stackframe();

		strings = TALLOC_ARRAY(tmp_ctx, char *,
				       value->v.multi_sz.num_strings);
		if (strings == NULL) {
			return WERR_NOMEM;
		}

		string_lengths = TALLOC_ARRAY(tmp_ctx, size_t,
					      value->v.multi_sz.num_strings);
		if (string_lengths == NULL) {
			TALLOC_FREE(tmp_ctx);
			return WERR_NOMEM;
		}

		/* convert the single strings */
		for (count = 0; count < value->v.multi_sz.num_strings; count++)
		{
			if (!convert_string_talloc(strings, CH_UNIX,
				CH_UTF16LE, value->v.multi_sz.strings[count],
				strlen(value->v.multi_sz.strings[count])+1,
				(void *)&strings[count],
				&string_lengths[count], false))
			{

				TALLOC_FREE(tmp_ctx);
				return WERR_NOMEM;
			}
			len += string_lengths[count];
		}

		/* now concatenate all into the data blob */
		presult->data = TALLOC_ARRAY(mem_ctx, uint8_t, len);
		if (presult->data == NULL) {
			TALLOC_FREE(tmp_ctx);
			return WERR_NOMEM;
		}
		for (count = 0, ofs = 0;
		     count < value->v.multi_sz.num_strings;
		     count++)
		{
			memcpy(presult->data + ofs, strings[count],
			       string_lengths[count]);
			ofs += string_lengths[count];
		}
		presult->length = len;

		TALLOC_FREE(tmp_ctx);

		break;
	}
	case REG_BINARY:
		*presult = data_blob_talloc(mem_ctx,
					    value->v.binary.data,
					    value->v.binary.length);
		break;
	default:
		return WERR_INVALID_PARAM;
	}

	return WERR_OK;
}
