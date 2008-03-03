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

extern REGISTRY_OPS smbconf_reg_ops;

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

WERROR reg_pull_multi_sz(TALLOC_CTX *mem_ctx, const void *buf, size_t len,
			 uint32 *num_values, char ***values)
{
	const smb_ucs2_t *p = (const smb_ucs2_t *)buf;
	*num_values = 0;

	/*
	 * Make sure that a talloc context for the strings retrieved exists
	 */

	if (!(*values = TALLOC_ARRAY(mem_ctx, char *, 1))) {
		return WERR_NOMEM;
	}

	len /= 2; 		/* buf is a set of UCS2 strings */

	while (len > 0) {
		char *val;
		size_t dstlen, thislen;

		thislen = strnlen_w(p, len) + 1;
		if (!convert_string_allocate(*values, CH_UTF16LE, CH_UNIX,
			p, thislen*2, (void *)&val, &dstlen, true)) {
			TALLOC_FREE(*values);
			return WERR_NOMEM;
		}

		ADD_TO_ARRAY(*values, char *, val, values, num_values);
		if (*values == NULL) {
			return WERR_NOMEM;
		}

		p += thislen;
		len -= thislen;
	}

	return WERR_OK;
}
