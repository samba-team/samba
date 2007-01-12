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
		uint32_t object_count;
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
	bool ok;

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

	ok = samdb_set_ntds_invocation_id(s->ldb, &p->dest_dsa->invocation_id);
	if (!ok) {
		DEBUG(0,("Failed to set cached ntds invocationId\n"));
		return NT_STATUS_FOOBAR;
	}
	ok = samdb_set_ntds_objectGUID(s->ldb, &p->dest_dsa->ntds_guid);
	if (!ok) {
		DEBUG(0,("Failed to set cached ntds objectGUID\n"));
		return NT_STATUS_FOOBAR;
	}

	return NT_STATUS_OK;
}

static NTSTATUS test_apply_schema(struct test_become_dc_state *s,
				  const struct libnet_BecomeDC_StoreChunk *c)
{
	WERROR status;
	const struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr;
	uint32_t total_object_count;
	uint32_t object_count;
	struct drsuapi_DsReplicaObjectListItemEx *first_object;
	struct drsuapi_DsReplicaObjectListItemEx *cur;
	uint32_t linked_attributes_count;
	struct drsuapi_DsReplicaLinkedAttribute *linked_attributes;
	const struct drsuapi_DsReplicaCursor2CtrEx *uptodateness_vector;
	struct dsdb_extended_replicated_objects *objs;
	struct repsFromTo1 *s_dsa;
	char *tmp_dns_name;
	uint32_t i;
	int ret;

	s_dsa			= talloc_zero(s, struct repsFromTo1);
	NT_STATUS_HAVE_NO_MEMORY(s_dsa);
	s_dsa->other_info	= talloc(s_dsa, struct repsFromTo1OtherInfo);
	NT_STATUS_HAVE_NO_MEMORY(s_dsa->other_info);

	switch (c->ctr_level) {
	case 1:
		mapping_ctr			= &c->ctr1->mapping_ctr;
		total_object_count		= c->ctr1->total_object_count;
		object_count			= s->schema_part.object_count;
		first_object			= s->schema_part.first_object;
		linked_attributes_count		= 0;
		linked_attributes		= NULL;
		s_dsa->highwatermark		= c->ctr1->new_highwatermark;
		s_dsa->source_dsa_obj_guid	= c->ctr1->source_dsa_guid;
		s_dsa->source_dsa_invocation_id = c->ctr1->source_dsa_invocation_id;
		uptodateness_vector		= NULL; /* TODO: map it */
		break;
	case 6:
		mapping_ctr			= &c->ctr6->mapping_ctr;
		total_object_count		= c->ctr6->total_object_count;
		object_count			= s->schema_part.object_count;
		first_object			= s->schema_part.first_object;
		linked_attributes_count		= 0; /* TODO: ! */
		linked_attributes		= NULL; /* TODO: ! */;
		s_dsa->highwatermark		= c->ctr6->new_highwatermark;
		s_dsa->source_dsa_obj_guid	= c->ctr6->source_dsa_guid;
		s_dsa->source_dsa_invocation_id = c->ctr6->source_dsa_invocation_id;
		uptodateness_vector		= c->ctr6->uptodateness_vector;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	s_dsa->replica_flags		= DRSUAPI_DS_REPLICA_NEIGHBOUR_WRITEABLE
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_SYNC_ON_STARTUP
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_DO_SCHEDULED_SYNCS;
	memset(s_dsa->schedule, 0x11, sizeof(s_dsa->schedule));

	tmp_dns_name	= GUID_string(s_dsa->other_info, &s_dsa->source_dsa_obj_guid);
	NT_STATUS_HAVE_NO_MEMORY(tmp_dns_name);
	tmp_dns_name	= talloc_asprintf_append(tmp_dns_name, "._msdcs.%s", c->forest->dns_name);
	NT_STATUS_HAVE_NO_MEMORY(tmp_dns_name);
	s_dsa->other_info->dns_name = tmp_dns_name;

	for (cur = first_object; cur; cur = cur->next_object) {
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

	ret = dsdb_set_schema(s->ldb, s->schema);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_FOOBAR;
	}

	status = dsdb_extended_replicated_objects_commit(s->ldb,
							 c->partition->nc.dn,
							 s->schema,
							 mapping_ctr,
							 object_count,
							 first_object,
							 linked_attributes_count,
							 linked_attributes,
							 s_dsa,
							 uptodateness_vector,
							 s, &objs);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("Failed to commit objects: %s\n", win_errstr(status)));
		return werror_to_ntstatus(status);
	}

	if (lp_parm_bool(-1, "become dc", "dump objects", False)) {
		for (i=0; i < objs->num_objects; i++) {
			struct ldb_ldif ldif;
			fprintf(stdout, "#\n");
			ldif.changetype = LDB_CHANGETYPE_NONE;
			ldif.msg = objs->objects[i].msg;
			ldb_ldif_write_file(s->ldb, stdout, &ldif);
			NDR_PRINT_DEBUG(replPropertyMetaDataBlob, objs->objects[i].meta_data);
		}
	}

	talloc_free(s_dsa);
	talloc_free(objs);
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
		s->schema_part.object_count = object_count;
		s->schema_part.first_object = talloc_steal(s, first_object);
	} else {
		s->schema_part.object_count		+= object_count;
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
	uint32_t linked_attributes_count;
	struct drsuapi_DsReplicaLinkedAttribute *linked_attributes;
	const struct drsuapi_DsReplicaCursor2CtrEx *uptodateness_vector;
	struct dsdb_extended_replicated_objects *objs;
	struct repsFromTo1 *s_dsa;
	char *tmp_dns_name;
	uint32_t i;

	s_dsa			= talloc_zero(s, struct repsFromTo1);
	NT_STATUS_HAVE_NO_MEMORY(s_dsa);
	s_dsa->other_info	= talloc(s_dsa, struct repsFromTo1OtherInfo);
	NT_STATUS_HAVE_NO_MEMORY(s_dsa->other_info);

	switch (c->ctr_level) {
	case 1:
		mapping_ctr			= &c->ctr1->mapping_ctr;
		total_object_count		= c->ctr1->total_object_count;
		object_count			= c->ctr1->object_count;
		first_object			= c->ctr1->first_object;
		linked_attributes_count		= 0;
		linked_attributes		= NULL;
		s_dsa->highwatermark		= c->ctr1->new_highwatermark;
		s_dsa->source_dsa_obj_guid	= c->ctr1->source_dsa_guid;
		s_dsa->source_dsa_invocation_id = c->ctr1->source_dsa_invocation_id;
		uptodateness_vector		= NULL; /* TODO: map it */
		break;
	case 6:
		mapping_ctr			= &c->ctr6->mapping_ctr;
		total_object_count		= c->ctr6->total_object_count;
		object_count			= c->ctr6->object_count;
		first_object			= c->ctr6->first_object;
		linked_attributes_count		= c->ctr6->linked_attributes_count;
		linked_attributes		= c->ctr6->linked_attributes;
		s_dsa->highwatermark		= c->ctr6->new_highwatermark;
		s_dsa->source_dsa_obj_guid	= c->ctr6->source_dsa_guid;
		s_dsa->source_dsa_invocation_id = c->ctr6->source_dsa_invocation_id;
		uptodateness_vector		= c->ctr6->uptodateness_vector;
		break;
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	s_dsa->replica_flags		= DRSUAPI_DS_REPLICA_NEIGHBOUR_WRITEABLE
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_SYNC_ON_STARTUP
					| DRSUAPI_DS_REPLICA_NEIGHBOUR_DO_SCHEDULED_SYNCS;
	memset(s_dsa->schedule, 0x11, sizeof(s_dsa->schedule));

	tmp_dns_name	= GUID_string(s_dsa->other_info, &s_dsa->source_dsa_obj_guid);
	NT_STATUS_HAVE_NO_MEMORY(tmp_dns_name);
	tmp_dns_name	= talloc_asprintf_append(tmp_dns_name, "._msdcs.%s", c->forest->dns_name);
	NT_STATUS_HAVE_NO_MEMORY(tmp_dns_name);
	s_dsa->other_info->dns_name = tmp_dns_name;

	if (total_object_count) {
		DEBUG(0,("Partition[%s] objects[%u/%u]\n",
			c->partition->nc.dn, object_count, total_object_count));
	} else {
		DEBUG(0,("Partition[%s] objects[%u]\n",
		c->partition->nc.dn, object_count));
	}

	status = dsdb_extended_replicated_objects_commit(s->ldb,
							 c->partition->nc.dn,
							 s->schema,
							 mapping_ctr,
							 object_count,
							 first_object,
							 linked_attributes_count,
							 linked_attributes,
							 s_dsa,
							 uptodateness_vector,
							 s, &objs);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("Failed to commit objects: %s\n", win_errstr(status)));
		return werror_to_ntstatus(status);
	}

	if (lp_parm_bool(-1, "become dc", "dump objects", False)) {
		for (i=0; i < objs->num_objects; i++) {
			struct ldb_ldif ldif;
			fprintf(stdout, "#\n");
			ldif.changetype = LDB_CHANGETYPE_NONE;
			ldif.msg = objs->objects[i].msg;
			ldb_ldif_write_file(s->ldb, stdout, &ldif);
			NDR_PRINT_DEBUG(replPropertyMetaDataBlob, objs->objects[i].meta_data);
		}
	}
	talloc_free(s_dsa);
	talloc_free(objs);

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
