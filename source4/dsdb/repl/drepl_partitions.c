/* 
   Unix SMB/CIFS mplementation.
   DSDB replication service
   
   Copyright (C) Stefan Metzmacher 2007
    
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
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"
#include "smbd/service.h"
#include "lib/events/events.h"
#include "lib/messaging/irpc.h"
#include "dsdb/repl/drepl_service.h"
#include "lib/ldb/include/ldb_errors.h"
#include "../lib/util/dlinklist.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "param/param.h"

WERROR dreplsrv_load_partitions(struct dreplsrv_service *s)
{
	WERROR status;
	struct ldb_dn *basedn;
	struct ldb_result *r;
	struct ldb_message_element *el;
	static const char *attrs[] = { "hasMasterNCs", NULL };
	unsigned int i;
	int ret;

	basedn = samdb_ntds_settings_dn(s->samdb);
	W_ERROR_HAVE_NO_MEMORY(basedn);

	ret = ldb_search(s->samdb, s, &r, basedn, LDB_SCOPE_BASE, attrs,
			 "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		return WERR_FOOBAR;
	} else if (r->count != 1) {
		talloc_free(r);
		return WERR_FOOBAR;
	}

	el = ldb_msg_find_element(r->msgs[0], "hasMasterNCs");
	if (!el) {
		return WERR_FOOBAR;
	}

	for (i=0; el && i < el->num_values; i++) {
		const char *v = (const char *)el->values[i].data;
		struct ldb_dn *pdn;
		struct dreplsrv_partition *p;

		pdn = ldb_dn_new(s, s->samdb, v);
		if (!ldb_dn_validate(pdn)) {
			return WERR_FOOBAR;
		}

		p = talloc_zero(s, struct dreplsrv_partition);
		W_ERROR_HAVE_NO_MEMORY(p);

		p->dn = talloc_steal(p, pdn);

		DLIST_ADD(s->partitions, p);

		DEBUG(2, ("dreplsrv_partition[%s] loaded\n", v));
	}

	talloc_free(r);

	status = dreplsrv_refresh_partitions(s);
	W_ERROR_NOT_OK_RETURN(status);

	return WERR_OK;
}

WERROR dreplsrv_out_connection_attach(struct dreplsrv_service *s,
				      const struct repsFromTo1 *rft,
				      struct dreplsrv_out_connection **_conn)
{
	struct dreplsrv_out_connection *cur, *conn = NULL;
	const char *hostname;

	if (!rft->other_info) {
		return WERR_FOOBAR;
	}

	if (!rft->other_info->dns_name) {
		return WERR_FOOBAR;
	}

	hostname = rft->other_info->dns_name;

	for (cur = s->connections; cur; cur = cur->next) {		
		if (strcmp(cur->binding->host, hostname) == 0) {
			conn = cur;
			break;
		}
	}

	if (!conn) {
		NTSTATUS nt_status;
		char *binding_str;

		conn = talloc_zero(s, struct dreplsrv_out_connection);
		W_ERROR_HAVE_NO_MEMORY(conn);

		conn->service	= s;

		binding_str = talloc_asprintf(conn, "ncacn_ip_tcp:%s[krb5,seal]",
					      hostname);
		W_ERROR_HAVE_NO_MEMORY(binding_str);
		nt_status = dcerpc_parse_binding(conn, binding_str, &conn->binding);
		talloc_free(binding_str);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return ntstatus_to_werror(nt_status);
		}

		DLIST_ADD_END(s->connections, conn, struct dreplsrv_out_connection *);

		DEBUG(2,("dreplsrv_out_connection_attach(%s): create\n", conn->binding->host));
	} else {
		DEBUG(2,("dreplsrv_out_connection_attach(%s): attach\n", conn->binding->host));
	}

	*_conn = conn;
	return WERR_OK;
}

static WERROR dreplsrv_partition_add_source_dsa(struct dreplsrv_service *s,
						struct dreplsrv_partition *p,
						const struct ldb_val *val)
{
	WERROR status;
	enum ndr_err_code ndr_err;
	struct dreplsrv_partition_source_dsa *source, *s2;

	source = talloc_zero(p, struct dreplsrv_partition_source_dsa);
	W_ERROR_HAVE_NO_MEMORY(source);

	ndr_err = ndr_pull_struct_blob(val, source, 
				       &source->_repsFromBlob,
				       (ndr_pull_flags_fn_t)ndr_pull_repsFromToBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
		talloc_free(source);
		return ntstatus_to_werror(nt_status);
	}
	/* NDR_PRINT_DEBUG(repsFromToBlob, &source->_repsFromBlob); */
	if (source->_repsFromBlob.version != 1) {
		talloc_free(source);
		return WERR_DS_DRA_INTERNAL_ERROR;
	}

	source->partition	= p;
	source->repsFrom1	= &source->_repsFromBlob.ctr.ctr1;

	status = dreplsrv_out_connection_attach(s, source->repsFrom1, &source->conn);
	W_ERROR_NOT_OK_RETURN(status);

	/* remove any existing source with the same GUID */
	for (s2=p->sources; s2; s2=s2->next) {
		if (GUID_compare(&s2->repsFrom1->source_dsa_obj_guid, 
				 &source->repsFrom1->source_dsa_obj_guid) == 0) {
			talloc_free(s2->repsFrom1->other_info);
			*s2->repsFrom1 = *source->repsFrom1;
			talloc_steal(s2, s2->repsFrom1->other_info);
			talloc_free(source);
			return WERR_OK;
		}
	}

	DLIST_ADD_END(p->sources, source, struct dreplsrv_partition_source_dsa *);
	return WERR_OK;
}

/*
  convert from one udv format to the other
 */
static WERROR udv_convert(TALLOC_CTX *mem_ctx,
			  const struct replUpToDateVectorCtr2 *udv,
			  struct drsuapi_DsReplicaCursorCtrEx *udv_ex)
{
	uint32_t i;

	udv_ex->version = 2;
	udv_ex->reserved1 = 0;
	udv_ex->reserved2 = 0;
	udv_ex->count = udv->count;
	udv_ex->cursors = talloc_array(mem_ctx, struct drsuapi_DsReplicaCursor, udv->count);
	W_ERROR_HAVE_NO_MEMORY(udv_ex->cursors);

	for (i=0; i<udv->count; i++) {
		udv_ex->cursors[i].source_dsa_invocation_id = udv->cursors[i].source_dsa_invocation_id;
		udv_ex->cursors[i].highest_usn = udv->cursors[i].highest_usn;
	}

	return WERR_OK;
}


static WERROR dreplsrv_refresh_partition(struct dreplsrv_service *s,
					 struct dreplsrv_partition *p)
{
	WERROR status;
	struct dom_sid *nc_sid;
	struct ldb_message_element *orf_el = NULL;
	struct ldb_result *r;
	unsigned int i;
	int ret;
	TALLOC_CTX *mem_ctx = talloc_new(p);
	static const char *attrs[] = {
		"objectSid",
		"objectGUID",
		"repsFrom",
		NULL
	};

	DEBUG(2, ("dreplsrv_refresh_partition(%s)\n",
		ldb_dn_get_linearized(p->dn)));

	ret = ldb_search(s->samdb, mem_ctx, &r, p->dn, LDB_SCOPE_BASE, attrs,
			 "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		talloc_free(mem_ctx);
		return WERR_FOOBAR;
	}
	
	talloc_free(discard_const(p->nc.dn));
	ZERO_STRUCT(p->nc);
	p->nc.dn	= ldb_dn_alloc_linearized(p, p->dn);
	W_ERROR_HAVE_NO_MEMORY(p->nc.dn);
	p->nc.guid	= samdb_result_guid(r->msgs[0], "objectGUID");
	nc_sid		= samdb_result_dom_sid(p, r->msgs[0], "objectSid");
	if (nc_sid) {
		p->nc.sid	= *nc_sid;
		talloc_free(nc_sid);
	}

	talloc_free(p->uptodatevector.cursors);
	talloc_free(p->uptodatevector_ex.cursors);
	ZERO_STRUCT(p->uptodatevector);
	ZERO_STRUCT(p->uptodatevector_ex);

	ret = dsdb_load_udv_v2(s->samdb, p->dn, p, &p->uptodatevector.cursors, &p->uptodatevector.count);
	if (ret == LDB_SUCCESS) {
		status = udv_convert(p, &p->uptodatevector, &p->uptodatevector_ex);
		W_ERROR_NOT_OK_RETURN(status);
	}

	orf_el = ldb_msg_find_element(r->msgs[0], "repsFrom");
	if (orf_el) {
		for (i=0; i < orf_el->num_values; i++) {
			status = dreplsrv_partition_add_source_dsa(s, p, &orf_el->values[i]);
			W_ERROR_NOT_OK_RETURN(status);	
		}
	}

	talloc_free(mem_ctx);

	return WERR_OK;
}

WERROR dreplsrv_refresh_partitions(struct dreplsrv_service *s)
{
	WERROR status;
	struct dreplsrv_partition *p;

	for (p = s->partitions; p; p = p->next) {
		status = dreplsrv_refresh_partition(s, p);
		W_ERROR_NOT_OK_RETURN(status);
	}

	return WERR_OK;
}
