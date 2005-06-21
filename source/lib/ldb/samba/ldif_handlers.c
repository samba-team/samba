/* 
   ldb database library - ldif handlers for Samba

   Copyright (C) Andrew Tridgell  2005

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"
#include "librpc/gen_ndr/ndr_security.h"

/*
  convert a ldif formatted objectSid to a NDR formatted blob
*/
static int ldif_read_objectSid(struct ldb_context *ldb, const struct ldb_val *in,
			       struct ldb_val *out)
{
	struct dom_sid *sid;
	NTSTATUS status;
	sid = dom_sid_parse_talloc(ldb, in->data);
	if (sid == NULL) {
		return -1;
	}
	status = ndr_push_struct_blob(out, ldb, sid, 
				      (ndr_push_flags_fn_t)ndr_push_dom_sid);
	talloc_free(sid);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	return 0;
}

/*
  convert a NDR formatted blob to a ldif formatted objectSid
*/
static int ldif_write_objectSid(struct ldb_context *ldb, const struct ldb_val *in,
			       struct ldb_val *out)
{
	struct dom_sid *sid;
	NTSTATUS status;
	sid = talloc(ldb, struct dom_sid);
	if (sid == NULL) {
		return -1;
	}
	status = ndr_pull_struct_blob(in, sid, sid, 
				      (ndr_pull_flags_fn_t)ndr_pull_dom_sid);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(sid);
		return -1;
	}
	out->data = dom_sid_string(ldb, sid);
	talloc_free(sid);
	if (out->data == NULL) {
		return -1;
	}
	out->length = strlen(out->data);
	return 0;
}


static const struct ldb_ldif_handler samba_handlers[] = {
	{ "objectSid", ldif_read_objectSid, ldif_write_objectSid }
};

/*
  register the samba ldif handlers
*/
int ldb_register_samba_handlers(struct ldb_context *ldb)
{
#if 0
	/* we can't enable this until we fix the sam code to handle
	   non-string elements */
	return ldb_ldif_add_handlers(ldb, samba_handlers, ARRAY_SIZE(samba_handlers));
#else
	return 0;
#endif
}
