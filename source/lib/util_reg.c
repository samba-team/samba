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

const char *reg_type_lookup(uint32 type)
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
	case REG_DWORD_BE:
		result = "REG_DWORD_BE";
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
			   int *num_values, char ***values)
{
	int nvals;
	char **vals;
	const smb_ucs2_t *p = buf;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS result = NT_STATUS_NO_MEMORY;

	if (!(tmp_ctx = talloc_new(mem_ctx))) {
		return NT_STATUS_NO_MEMORY;
	}

	nvals = 0;
	vals = NULL;

	len /= 2; 		/* buf is a set of UCS2 strings */

	while (len > 0) {
		char *val;
		size_t dstlen, thislen;

		thislen = strnlen_w(p, len) + 1;
		dstlen = convert_string_allocate(tmp_ctx, CH_UCS2, CH_UNIX,
						 p, thislen*2, (void *)&val,
						 True);
		if (dstlen == (size_t)-1) {
			goto done;
		}

		ADD_TO_ARRAY(tmp_ctx, char *, val, &vals, &nvals);
		if (vals == NULL) {
			goto done;
		}

		talloc_steal(vals, val);

		p += thislen;
		len -= thislen;
	}

	*num_values = nvals;
	*values = talloc_steal(mem_ctx, vals);
	result = NT_STATUS_OK;

 done:
	TALLOC_FREE(tmp_ctx);
	return result;
}
