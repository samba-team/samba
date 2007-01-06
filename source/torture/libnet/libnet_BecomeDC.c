/* 
   Unix SMB/CIFS implementation.

   libnet_BecomeDC() tests

   Copyright (C) Stefan (metze) Metzmacher 2006
   
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
#include "lib/cmdline/popt_common.h"
#include "torture/torture.h"
#include "torture/rpc/rpc.h"
#include "libnet/libnet.h"
#include "lib/events/events.h"
#include "dsdb/samdb/samdb.h"
#include "lib/util/dlinklist.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "system/time.h"
#include "auth/auth.h"
#include "lib/db_wrap.h"
#include "lib/appweb/ejs/ejs.h"
#include "lib/appweb/ejs/ejsInternal.h"
#include "scripting/ejs/smbcalls.h"

static EjsId eid;
static int ejs_error;

static void test_ejs_exception(const char *reason)
{
	Ejs *ep = ejsPtr(eid);
	ejsSetErrorMsg(eid, "%s", reason);
	fprintf(stderr, "%s", ep->error);
	ejs_error = 127;
}

static int test_run_ejs(char *script)
{
	EjsHandle handle = 0;
	MprVar result;
	char *emsg;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	struct MprVar *return_var;

	mprSetCtx(mem_ctx);

	if (ejsOpen(NULL, NULL, NULL) != 0) {
		d_printf("ejsOpen(): unable to initialise EJS subsystem\n");
		ejs_error = 127;
		goto failed;
	}

	smb_setup_ejs_functions(test_ejs_exception);

	if ((eid = ejsOpenEngine(handle, 0)) == (EjsId)-1) {
		d_printf("smbscript: ejsOpenEngine(): unable to initialise an EJS engine\n");
		ejs_error = 127;
		goto failed;
	}

	mprSetVar(ejsGetGlobalObject(eid), "ARGV", mprList("ARGV", NULL));

	/* run the script */
	if (ejsEvalScript(eid, script, &result, &emsg) == -1) {
		d_printf("smbscript: ejsEvalScript(): %s\n", emsg);
		if (ejs_error == 0) ejs_error = 127;
		goto failed;
	}

	return_var = ejsGetReturnValue(eid);
	ejs_error = mprVarToNumber(return_var);

failed:
	ejsClose();
	talloc_free(mem_ctx);
	return ejs_error;
}

#define TORTURE_NETBIOS_NAME "smbtorturedc"
#define TORTURE_SAMDB_LDB "test_samdb.ldb"

struct test_become_dc_state {
	struct libnet_context *ctx;
	struct test_join *tj;
	struct cli_credentials *machine_account;
	struct dsdb_schema *schema;

	struct ldb_context *ldb;

	struct {
		struct drsuapi_DsReplicaObjectListItemEx *first_object;
		struct drsuapi_DsReplicaObjectListItemEx *last_object;
	} schema_part;
};

static NTSTATUS test_become_dc_check_options(void *private_data,
					     const struct libnet_BecomeDC_CheckOptions *o)
{
	DEBUG(0,("Become DC of Domain[%s]/[%s]\n",
		o->domain->netbios_name, o->domain->dns_name));

	DEBUG(0,("Promotion Partner is Server[%s] from Site[%s]\n",
		o->source_dsa->dns_name, o->source_dsa->site_name));

	DEBUG(0,("Options:crossRef behavior_version[%u]\n"
		       "\tschema object_version[%u]\n"
		       "\tdomain behavior_version[%u]\n"
		       "\tdomain w2k3_update_revision[%u]\n", 
		o->forest->crossref_behavior_version,
		o->forest->schema_object_version,
		o->domain->behavior_version,
		o->domain->w2k3_update_revision));

	return NT_STATUS_OK;
}

static NTSTATUS test_become_dc_prepare_db(void *private_data,
					  const struct libnet_BecomeDC_PrepareDB *p)
{
	struct test_become_dc_state *s = talloc_get_type(private_data, struct test_become_dc_state);
	char *ejs;
	int ret;

	DEBUG(0,("New Server[%s] in Site[%s]\n",
		p->dest_dsa->dns_name, p->dest_dsa->site_name));

	DEBUG(0,("DSA Instance [%s]\n"
		"\tobjectGUID[%s]\n"
		"\tinvocationId[%s]\n",
		p->dest_dsa->ntds_dn_str,
		GUID_string(s, &p->dest_dsa->ntds_guid),
		GUID_string(s, &p->dest_dsa->invocation_id)));

	DEBUG(0,("Schema Partition[%s]\n",
		p->forest->schema_dn_str));

	DEBUG(0,("Config Partition[%s]\n",
		p->forest->config_dn_str));

	DEBUG(0,("Domain Partition[%s]\n",
		p->domain->dn_str));

	ejs = talloc_asprintf(s,
		"libinclude(\"base.js\");\n"
		"libinclude(\"provision.js\");\n"
		"\n"
		"function message() { print(vsprintf(arguments)); }\n"
		"\n"
		"var subobj = provision_guess();\n"
		"subobj.ROOTDN       = \"%s\";\n"
		"subobj.DOMAINDN     = \"%s\";\n"
		"subobj.DOMAINDN_LDB = \"test_domain.ldb\";\n"
		"subobj.CONFIGDN     = \"%s\";\n"
		"subobj.CONFIGDN_LDB = \"test_config.ldb\";\n"
		"subobj.SCHEMADN     = \"%s\";\n"
		"subobj.SCHEMADN_LDB = \"test_schema.ldb\";\n"
		"subobj.HOSTNAME     = \"%s\";\n"
		"subobj.DNSNAME      = \"%s\";\n"
		"subobj.DEFAULTSITE  = \"%s\";\n"
		"\n"
		"modules_list        = new Array(\"rootdse\",\n"
		"                                \"kludge_acl\",\n"
		"                                \"paged_results\",\n"
		"                                \"server_sort\",\n"
		"                                \"extended_dn\",\n"
		"                                \"asq\",\n"
		"                                \"samldb\",\n"
		"                                \"password_hash\",\n"
		"                                \"operational\",\n"
		"                                \"objectclass\",\n"
		"                                \"rdn_name\",\n"
		"                                \"partition\");\n"
		"subobj.MODULES_LIST = join(\",\", modules_list);\n"
		"subobj.DOMAINDN_MOD = \"repl_meta_data\";\n"
		"subobj.CONFIGDN_MOD = \"repl_meta_data\";\n"
		"subobj.SCHEMADN_MOD = \"repl_meta_data\";\n"
		"\n"
		"var paths = provision_default_paths(subobj);\n"
		"paths.samdb = \"%s\";\n"
		"\n"
		"var system_session = system_session();\n"
		"\n"
		"var ok = provision_become_dc(subobj, message, paths, system_session);\n"
		"assert(ok);\n"
		"\n"
		"return 0;\n",
		p->forest->root_dn_str,
		p->domain->dn_str,
		p->forest->config_dn_str,
		p->forest->schema_dn_str,
		p->dest_dsa->netbios_name,
		p->dest_dsa->dns_name,
		p->dest_dsa->site_name,
		TORTURE_SAMDB_LDB);
	NT_STATUS_HAVE_NO_MEMORY(ejs);

	ret = test_run_ejs(ejs);
	if (ret != 0) {
		DEBUG(0,("Failed to run ejs script: %d:\n%s",
			ret, ejs));
		talloc_free(ejs);
		return NT_STATUS_FOOBAR;
	}
	talloc_free(ejs);

	talloc_free(s->ldb);

	s->ldb = ldb_wrap_connect(s, TORTURE_SAMDB_LDB,
				  system_session(s),
				  NULL, 0, NULL);
	if (!s->ldb) {
		DEBUG(0,("Failed to open '%s'\n",
			TORTURE_SAMDB_LDB));
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	ret = ldb_transaction_start(s->ldb);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS_OK;
}

static WERROR test_object_to_ldb(struct test_become_dc_state *s,
				 const struct libnet_BecomeDC_StoreChunk *c,
				 struct drsuapi_DsReplicaObjectListItemEx *obj,
				 TALLOC_CTX *mem_ctx,
				 struct ldb_message **_msg)
{
	NTSTATUS nt_status;
	WERROR status;
	uint32_t i;
	struct ldb_message *msg;
	struct replPropertyMetaDataBlob md;
	struct ldb_val md_value;
	struct drsuapi_DsReplicaObjMetaDataCtr mdc;
	struct ldb_val guid_value;
	NTTIME whenChanged = 0;
	time_t whenChanged_t;
	const char *whenChanged_s;
	const char *rdn_name;
	const struct ldb_val *rdn_value;
	const struct dsdb_attribute *rdn_attr;
	uint32_t rdn_attid;
	struct drsuapi_DsReplicaAttribute *name_a;
	struct drsuapi_DsReplicaMetaData *name_d;
	struct replPropertyMetaData1 *rdn_m;
	struct drsuapi_DsReplicaObjMetaData *rdn_mc;
	struct ldb_request *req;
	struct ldb_control **ctrls;
	struct dsdb_control_replicated_object *ctrl;
	int ret;

	if (!obj->object.identifier) {
		return WERR_FOOBAR;
	}

	if (!obj->object.identifier->dn || !obj->object.identifier->dn[0]) {
		return WERR_FOOBAR;
	}

	msg = ldb_msg_new(mem_ctx);
	W_ERROR_HAVE_NO_MEMORY(msg);

	msg->dn			= ldb_dn_new(msg, s->ldb, obj->object.identifier->dn);
	W_ERROR_HAVE_NO_MEMORY(msg->dn);

	rdn_name	= ldb_dn_get_rdn_name(msg->dn);
	rdn_attr	= dsdb_attribute_by_lDAPDisplayName(s->schema, rdn_name);
	if (!rdn_attr) {
		return WERR_FOOBAR;
	}
	rdn_attid	= rdn_attr->attributeID_id;
	rdn_value	= ldb_dn_get_rdn_val(msg->dn);

	msg->num_elements	= obj->object.attribute_ctr.num_attributes;
	msg->elements		= talloc_array(msg, struct ldb_message_element,
					       msg->num_elements);
	W_ERROR_HAVE_NO_MEMORY(msg->elements);

	for (i=0; i < msg->num_elements; i++) {
		status = dsdb_attribute_drsuapi_to_ldb(s->schema,
						       &obj->object.attribute_ctr.attributes[i],
						       msg->elements, &msg->elements[i]);
		W_ERROR_NOT_OK_RETURN(status);
	}

	if (obj->object.attribute_ctr.num_attributes != 0 && !obj->meta_data_ctr) {
		return WERR_FOOBAR;
	}

	if (obj->object.attribute_ctr.num_attributes != obj->meta_data_ctr->count) {
		return WERR_FOOBAR;
	}

	md.version		= 1;
	md.reserved		= 0;
	md.ctr.ctr1.count	= obj->meta_data_ctr->count;
	md.ctr.ctr1.reserved	= 0;
	md.ctr.ctr1.array	= talloc_array(mem_ctx,
					       struct replPropertyMetaData1,
					       md.ctr.ctr1.count + 1);
	W_ERROR_HAVE_NO_MEMORY(md.ctr.ctr1.array);

	mdc.count	= obj->meta_data_ctr->count;
	mdc.reserved	= 0;
	mdc.array	= talloc_array(mem_ctx,
				       struct drsuapi_DsReplicaObjMetaData,
				       mdc.count + 1);
	W_ERROR_HAVE_NO_MEMORY(mdc.array);

	for (i=0; i < obj->meta_data_ctr->count; i++) {
		struct drsuapi_DsReplicaAttribute *a;
		struct drsuapi_DsReplicaMetaData *d;
		struct replPropertyMetaData1 *m;
		struct drsuapi_DsReplicaObjMetaData *mc;

		a = &obj->object.attribute_ctr.attributes[i];
		d = &obj->meta_data_ctr->meta_data[i];
		m = &md.ctr.ctr1.array[i];
		mc = &mdc.array[i];

		m->attid			= a->attid;
		m->version			= d->version;
		m->orginating_time		= d->orginating_time;
		m->orginating_invocation_id	= d->orginating_invocation_id;
		m->orginating_usn		= d->orginating_usn;
		m->local_usn			= 0;

		mc->attribute_name		= dsdb_lDAPDisplayName_by_id(s->schema, a->attid);
		mc->version			= d->version;
		mc->originating_last_changed	= d->orginating_time;
		mc->originating_dsa_invocation_id= d->orginating_invocation_id;
		mc->originating_usn		= d->orginating_usn;
		mc->local_usn			= 0;

		if (d->orginating_time > whenChanged) {
			whenChanged = d->orginating_time;
		}

		if (a->attid == DRSUAPI_ATTRIBUTE_name) {
			name_a = a;
			name_d = d;
			rdn_m = &md.ctr.ctr1.array[md.ctr.ctr1.count];
			rdn_mc = &mdc.array[mdc.count];
		}
	}

	if (!name_d) {
		return WERR_FOOBAR;
	}

	ret = ldb_msg_add_value(msg, rdn_attr->lDAPDisplayName, rdn_value, NULL);
	if (ret != LDB_SUCCESS) {
		return WERR_FOOBAR;
	}

	nt_status = ndr_push_struct_blob(&guid_value, msg, &obj->object.identifier->guid,
					 (ndr_push_flags_fn_t)ndr_push_GUID);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return ntstatus_to_werror(nt_status);
	}
	ret = ldb_msg_add_value(msg, "objectGUID", &guid_value, NULL);
	if (ret != LDB_SUCCESS) {
		return WERR_FOOBAR;
	}

	whenChanged_t = nt_time_to_unix(whenChanged);
	whenChanged_s = ldb_timestring(msg, whenChanged_t);
	W_ERROR_HAVE_NO_MEMORY(whenChanged_s);
	ret = ldb_msg_add_string(msg, "whenChanged", whenChanged_s);
	if (ret != LDB_SUCCESS) {
		return WERR_FOOBAR;
	}

	rdn_m->attid				= rdn_attid;
	rdn_m->version				= name_d->version;
	rdn_m->orginating_time			= name_d->orginating_time;
	rdn_m->orginating_invocation_id		= name_d->orginating_invocation_id;
	rdn_m->orginating_usn			= name_d->orginating_usn;
	rdn_m->local_usn			= 0;
	md.ctr.ctr1.count++;

	rdn_mc->attribute_name			= rdn_attr->lDAPDisplayName;
	rdn_mc->version				= name_d->version;
	rdn_mc->originating_last_changed	= name_d->orginating_time;
	rdn_mc->originating_dsa_invocation_id	= name_d->orginating_invocation_id;
	rdn_mc->originating_usn			= name_d->orginating_usn;
	rdn_mc->local_usn			= 0;
	mdc.count++;

	nt_status = ndr_push_struct_blob(&md_value, msg, &md,
					 (ndr_push_flags_fn_t)ndr_push_replPropertyMetaDataBlob);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return ntstatus_to_werror(nt_status);
	}
	ret = ldb_msg_add_value(msg, "replPropertyMetaData", &md_value, NULL);
	if (ret != LDB_SUCCESS) {
		return WERR_FOOBAR;
	}

	if (lp_parm_bool(-1, "become dc", "dump objects", False)) {
		struct ldb_ldif ldif;
		fprintf(stdout, "#\n");
		ldif.changetype = LDB_CHANGETYPE_NONE;
		ldif.msg = msg;
		ldb_ldif_write_file(s->ldb, stdout, &ldif);
		NDR_PRINT_DEBUG(drsuapi_DsReplicaObjMetaDataCtr, &mdc);
	}

	/*
	 * apply the record to the ldb
	 * using an ldb_control so indicate
	 * that it's a replicated change
	 */
	ret = ldb_msg_sanity_check(s->ldb, msg);
	if (ret != LDB_SUCCESS) {
		return WERR_FOOBAR;
	}
	ctrls = talloc_array(msg, struct ldb_control *, 2);
	W_ERROR_HAVE_NO_MEMORY(ctrls);
	ctrls[0] = talloc(ctrls, struct ldb_control);
	W_ERROR_HAVE_NO_MEMORY(ctrls[0]);
	ctrls[1] = NULL;

	ctrl = talloc(ctrls, struct dsdb_control_replicated_object);
	W_ERROR_HAVE_NO_MEMORY(ctrl);
	ctrls[0]->oid		= DSDB_CONTROL_REPLICATED_OBJECT_OID;
	ctrls[0]->critical	= True;
	ctrls[0]->data		= ctrl;

	ret = ldb_build_add_req(&req, s->ldb, msg, msg, ctrls, NULL, NULL);
	if (ret != LDB_SUCCESS) {
		return WERR_FOOBAR;
	}
	ldb_set_timeout(s->ldb, req, 0); /* use default timeout */
	ret = ldb_request(s->ldb, req);
	if (ret == LDB_SUCCESS) {
		ret = ldb_wait(req->handle, LDB_WAIT_ALL);
	}
	talloc_free(req);
	if (ret != LDB_SUCCESS) {
		if (ret == LDB_ERR_ENTRY_ALREADY_EXISTS) {
			DEBUG(0,("record exists (ignored): %s: %d\n",
				obj->object.identifier->dn, ret));
		} else {
			DEBUG(0,("Failed to add record: %s: %d\n",
				obj->object.identifier->dn, ret));
			return WERR_FOOBAR;
		}
	}

	*_msg = msg;
	return WERR_OK;
}

static NTSTATUS test_apply_schema(struct test_become_dc_state *s,
				  const struct libnet_BecomeDC_StoreChunk *c)
{
	WERROR status;
	struct drsuapi_DsReplicaObjectListItemEx *cur;
	int ret;

	for (cur = s->schema_part.first_object; cur; cur = cur->next_object) {
		uint32_t i;
		bool is_attr = false;
		bool is_class = false;

		for (i=0; i < cur->object.attribute_ctr.num_attributes; i++) {
			struct drsuapi_DsReplicaAttribute *a;
			uint32_t j;
			const char *oid = NULL;

			a = &cur->object.attribute_ctr.attributes[i];
			status = dsdb_map_int2oid(s->schema, a->attid, s, &oid);
			if (!W_ERROR_IS_OK(status)) {
				return werror_to_ntstatus(status);
			}

			switch (a->attid) {
			case DRSUAPI_ATTRIBUTE_objectClass:
				for (j=0; j < a->value_ctr.num_values; j++) {
					uint32_t val = 0xFFFFFFFF;

					if (a->value_ctr.values[i].blob
					    && a->value_ctr.values[i].blob->length == 4) {
						val = IVAL(a->value_ctr.values[i].blob->data,0);
					}

					if (val == DRSUAPI_OBJECTCLASS_attributeSchema) {
						is_attr = true;
					}
					if (val == DRSUAPI_OBJECTCLASS_classSchema) {
						is_class = true;
					}
				}

				break;
			default:
				break;
			}
		}

		if (is_attr) {
			struct dsdb_attribute *sa;

			sa = talloc_zero(s->schema, struct dsdb_attribute);
			NT_STATUS_HAVE_NO_MEMORY(sa);

			status = dsdb_attribute_from_drsuapi(s->schema, &cur->object, s, sa);
			if (!W_ERROR_IS_OK(status)) {
				return werror_to_ntstatus(status);
			}

			DLIST_ADD_END(s->schema->attributes, sa, struct dsdb_attribute *);
		}

		if (is_class) {
			struct dsdb_class *sc;

			sc = talloc_zero(s->schema, struct dsdb_class);
			NT_STATUS_HAVE_NO_MEMORY(sc);

			status = dsdb_class_from_drsuapi(s->schema, &cur->object, s, sc);
			if (!W_ERROR_IS_OK(status)) {
				return werror_to_ntstatus(status);
			}

			DLIST_ADD_END(s->schema->classes, sc, struct dsdb_class *);
		}
	}

	for (cur = s->schema_part.first_object; cur; cur = cur->next_object) {
		struct ldb_message *msg;
		status = test_object_to_ldb(s, c, cur, s, &msg);
		if (!W_ERROR_IS_OK(status)) {
			return werror_to_ntstatus(status);
		}
	}

	ret = ldb_transaction_commit(s->ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to commit the schema changes: %d\n", ret));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ret = ldb_transaction_start(s->ldb);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS_OK;
}

static NTSTATUS test_become_dc_schema_chunk(void *private_data,
					    const struct libnet_BecomeDC_StoreChunk *c)
{
	struct test_become_dc_state *s = talloc_get_type(private_data, struct test_become_dc_state);
	WERROR status;
	const struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr;
	uint32_t total_object_count;
	uint32_t object_count;
	struct drsuapi_DsReplicaObjectListItemEx *first_object;
	struct drsuapi_DsReplicaObjectListItemEx *cur;

	switch (c->ctr_level) {
	case 1:
		mapping_ctr		= &c->ctr1->mapping_ctr;
		total_object_count	= c->ctr1->total_object_count;
		object_count		= c->ctr1->object_count;
		first_object		= c->ctr1->first_object;
		break;
	case 6:
		mapping_ctr		= &c->ctr6->mapping_ctr;
		total_object_count	= c->ctr6->total_object_count;
		object_count		= c->ctr6->object_count;
		first_object		= c->ctr6->first_object;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (total_object_count) {
		DEBUG(0,("Schema-DN[%s] objects[%u/%u]\n",
			c->partition->nc.dn, object_count, total_object_count));
	} else {
		DEBUG(0,("Schema-DN[%s] objects[%u]\n",
		c->partition->nc.dn, object_count));
	}

	if (!s->schema) {
		s->schema = talloc_zero(s, struct dsdb_schema);
		NT_STATUS_HAVE_NO_MEMORY(s->schema);

		status = dsdb_load_oid_mappings(s->schema, mapping_ctr);
		if (!W_ERROR_IS_OK(status)) {
			return werror_to_ntstatus(status);
		}
	} else {
		status = dsdb_verify_oid_mappings(s->schema, mapping_ctr);
		if (!W_ERROR_IS_OK(status)) {
			return werror_to_ntstatus(status);
		}
	}

	if (!s->schema_part.first_object) {
		s->schema_part.first_object = talloc_steal(s, first_object);
	} else {
		s->schema_part.last_object->next_object = talloc_steal(s->schema_part.last_object,
								       first_object);
	}
	for (cur = first_object; cur->next_object; cur = cur->next_object) {}
	s->schema_part.last_object = cur;

	if (c->partition->highwatermark.tmp_highest_usn == c->partition->highwatermark.highest_usn) {
		return test_apply_schema(s, c);
	}

	return NT_STATUS_OK;
}

static NTSTATUS test_become_dc_store_chunk(void *private_data,
					   const struct libnet_BecomeDC_StoreChunk *c)
{
	struct test_become_dc_state *s = talloc_get_type(private_data, struct test_become_dc_state);
	WERROR status;
	const struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr;
	uint32_t total_object_count;
	uint32_t object_count;
	struct drsuapi_DsReplicaObjectListItemEx *first_object;
	struct drsuapi_DsReplicaObjectListItemEx *cur;
	uint32_t linked_attributes_count;
	struct drsuapi_DsReplicaLinkedAttribute *linked_attributes;
	uint32_t i;
	int ret;

	switch (c->ctr_level) {
	case 1:
		mapping_ctr		= &c->ctr1->mapping_ctr;
		total_object_count	= c->ctr1->total_object_count;
		object_count		= c->ctr1->object_count;
		first_object		= c->ctr1->first_object;
		linked_attributes_count	= 0;
		linked_attributes	= NULL;
		break;
	case 6:
		mapping_ctr		= &c->ctr6->mapping_ctr;
		total_object_count	= c->ctr6->total_object_count;
		object_count		= c->ctr6->object_count;
		first_object		= c->ctr6->first_object;
		linked_attributes_count	= c->ctr6->linked_attributes_count;
		linked_attributes	= c->ctr6->linked_attributes;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (total_object_count) {
		DEBUG(0,("Partition[%s] objects[%u/%u]\n",
			c->partition->nc.dn, object_count, total_object_count));
	} else {
		DEBUG(0,("Partition[%s] objects[%u]\n",
		c->partition->nc.dn, object_count));
	}

	status = dsdb_verify_oid_mappings(s->schema, mapping_ctr);
	if (!W_ERROR_IS_OK(status)) {
		return werror_to_ntstatus(status);
	}

	for (cur = first_object; cur; cur = cur->next_object) {
		struct ldb_message *msg;
		status = test_object_to_ldb(s, c, cur, s, &msg);
		if (!W_ERROR_IS_OK(status)) {
			return werror_to_ntstatus(status);
		}
	}

	for (i=0; i < linked_attributes_count; i++) {
		const struct dsdb_attribute *sa;

		if (!linked_attributes[i].identifier) {
			return NT_STATUS_FOOBAR;		
		}

		if (!linked_attributes[i].value.blob) {
			return NT_STATUS_FOOBAR;		
		}

		sa = dsdb_attribute_by_attributeID_id(s->schema,
						      linked_attributes[i].attid);
		if (!sa) {
			return NT_STATUS_FOOBAR;
		}

		if (lp_parm_bool(-1, "become dc", "dump objects", False)) {
			DEBUG(0,("# %s\n", sa->lDAPDisplayName));
			NDR_PRINT_DEBUG(drsuapi_DsReplicaLinkedAttribute, &linked_attributes[i]);
			dump_data(0,
				linked_attributes[i].value.blob->data,
				linked_attributes[i].value.blob->length);
		}
	}

	ret = ldb_transaction_commit(s->ldb);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to commit the changes: %d\n", ret));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	ret = ldb_transaction_start(s->ldb);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS_OK;
}

BOOL torture_net_become_dc(struct torture_context *torture)
{
	BOOL ret = True;
	NTSTATUS status;
	struct libnet_BecomeDC b;
	struct libnet_UnbecomeDC u;
	struct test_become_dc_state *s;

	s = talloc_zero(torture, struct test_become_dc_state);
	if (!s) return False;

	/* Join domain as a member server. */
	s->tj = torture_join_domain(TORTURE_NETBIOS_NAME,
				 ACB_WSTRUST,
				 &s->machine_account);
	if (!s->tj) {
		DEBUG(0, ("%s failed to join domain as workstation\n",
			  TORTURE_NETBIOS_NAME));
		return False;
	}

	s->ctx = libnet_context_init(event_context_init(s));
	s->ctx->cred = cmdline_credentials;

	s->ldb = ldb_init(s);

	ZERO_STRUCT(b);
	b.in.domain_dns_name		= torture_join_dom_dns_name(s->tj);
	b.in.domain_netbios_name	= torture_join_dom_netbios_name(s->tj);
	b.in.domain_sid			= torture_join_sid(s->tj);
	b.in.source_dsa_address		= lp_parm_string(-1, "torture", "host");
	b.in.dest_dsa_netbios_name	= TORTURE_NETBIOS_NAME;

	b.in.callbacks.private_data	= s;
	b.in.callbacks.check_options	= test_become_dc_check_options;
	b.in.callbacks.prepare_db	= test_become_dc_prepare_db;
	b.in.callbacks.schema_chunk	= test_become_dc_schema_chunk;
	b.in.callbacks.config_chunk	= test_become_dc_store_chunk;
	b.in.callbacks.domain_chunk	= test_become_dc_store_chunk;

	status = libnet_BecomeDC(s->ctx, s, &b);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_BecomeDC() failed - %s\n", nt_errstr(status));
		ret = False;
	}

	ZERO_STRUCT(u);
	u.in.domain_dns_name		= torture_join_dom_dns_name(s->tj);
	u.in.domain_netbios_name	= torture_join_dom_netbios_name(s->tj);
	u.in.source_dsa_address		= lp_parm_string(-1, "torture", "host");
	u.in.dest_dsa_netbios_name	= TORTURE_NETBIOS_NAME;

	status = libnet_UnbecomeDC(s->ctx, s, &u);
	if (!NT_STATUS_IS_OK(status)) {
		printf("libnet_UnbecomeDC() failed - %s\n", nt_errstr(status));
		ret = False;
	}

	/* Leave domain. */                          
	torture_leave_domain(s->tj);

	talloc_free(s);
	return ret;
}
