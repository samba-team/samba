/* 
   Unix SMB/CIFS mplementation.

   wrap/unwrap NDR encoded elements for ldap calls
   
   Copyright (C) Andrew Tridgell  2005
    
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
   
*/

#include "includes.h"
#include "libcli/ldap/ldap.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_misc.h"

/*
  encode a NDR uint32 as a ldap filter element
*/
char *ldap_encode_ndr_uint32(TALLOC_CTX *mem_ctx, uint32_t value)
{
	uint8_t buf[4];
	struct ldb_val val;
	SIVAL(buf, 0, value);
	val.data = buf;
	val.length = 4;
	return ldb_binary_encode(mem_ctx, val);
}

/*
  encode a NDR dom_sid as a ldap filter element
*/
char *ldap_encode_ndr_dom_sid(TALLOC_CTX *mem_ctx, const struct dom_sid *sid)
{
	DATA_BLOB blob;
	NTSTATUS status;
	char *ret;
	status = ndr_push_struct_blob(&blob, mem_ctx, sid, 
				      (ndr_push_flags_fn_t)ndr_push_dom_sid);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}
	ret = ldb_binary_encode(mem_ctx, blob);
	data_blob_free(&blob);
	return ret;
}


/*
  encode a NDR GUID as a ldap filter element
*/
char *ldap_encode_ndr_GUID(TALLOC_CTX *mem_ctx, struct GUID *guid)
{
	DATA_BLOB blob;
	NTSTATUS status;
	char *ret;
	status = ndr_push_struct_blob(&blob, mem_ctx, guid, 
				      (ndr_push_flags_fn_t)ndr_push_GUID);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}
	ret = ldb_binary_encode(mem_ctx, blob);
	data_blob_free(&blob);
	return ret;
}

/*
  decode a NDR GUID from a ldap filter element
*/
NTSTATUS ldap_decode_ndr_GUID(TALLOC_CTX *mem_ctx, struct ldb_val val, struct GUID *guid)
{
	DATA_BLOB blob;
	NTSTATUS status;

	blob.data = val.data;
	blob.length = val.length;
	status = ndr_pull_struct_blob(&blob, mem_ctx, guid, 
				      (ndr_pull_flags_fn_t)ndr_pull_GUID);
	talloc_free(val.data);
	return status;
}
