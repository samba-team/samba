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

/*
  compare two objectSids
*/
static int ldb_comparison_objectSid(struct ldb_context *ldb, 
				    const struct ldb_val *v1, const struct ldb_val *v2)
{
	if (strncmp(v1->data, "S-", 2) == 0 &&
	    strncmp(v2->data, "S-", 2) == 0) {
		return strcmp(v1->data, v2->data);
	}
	if (strncmp(v1->data, "S-", 2) == 0) {
		struct ldb_val v;
		int ret;
		if (ldif_read_objectSid(ldb, v1, &v) != 0) {
			return -1;
		}
		ret = ldb_comparison_binary(ldb, &v, v2);
		talloc_free(v.data);
		return ret;
	}
	return ldb_comparison_binary(ldb, v1, v2);
}

/*
  canonicalise a objectSid
*/
static int ldb_canonicalise_objectSid(struct ldb_context *ldb, const struct ldb_val *in,
				      struct ldb_val *out)
{
	if (strncmp(in->data, "S-", 2) == 0) {
		return ldif_read_objectSid(ldb, in, out);
	}
	return ldb_handler_copy(ldb, in, out);
}


static const struct ldb_attrib_handler samba_handlers[] = {
	{ 
		.attr            = "objectSid",
		.flags           = 0,
		.ldif_read_fn    = ldif_read_objectSid,
		.ldif_write_fn   = ldif_write_objectSid,
		.canonicalise_fn = ldb_canonicalise_objectSid,
		.comparison_fn   = ldb_comparison_objectSid
	}
};

/*
  register the samba ldif handlers
*/
int ldb_register_samba_handlers(struct ldb_context *ldb)
{
	return ldb_set_attrib_handlers(ldb, samba_handlers, ARRAY_SIZE(samba_handlers));
}
