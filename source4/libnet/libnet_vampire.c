/* 
   Unix SMB/CIFS implementation.
   
   Extract the user/system database from a remote server

   Copyright (C) Stefan Metzmacher	2004-2006
   Copyright (C) Brad Henry 2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2008
   
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
#include "libnet/libnet.h"
#include "lib/events/events.h"
#include "dsdb/samdb/samdb.h"
#include "../lib/util/dlinklist.h"
#include <ldb.h>
#include <ldb_errors.h>
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "librpc/gen_ndr/ndr_drsblobs.h"
#include "librpc/gen_ndr/ndr_misc.h"
#include "system/time.h"
#include "ldb_wrap.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "param/param.h"
#include "param/provision.h"
#include "libcli/security/security.h"
#include "dsdb/common/util.h"

#undef DBGC_CLASS
#define DBGC_CLASS            DBGC_DRS_REPL

/* 
List of tasks vampire.py must perform:
- Domain Join
 - but don't write the secrets.ldb
 - results for this should be enough to handle the provision
- if vampire method is samsync 
 - Provision using these results 
  - do we still want to support this NT4 technology?
- Start samsync with libnet code
 - provision in the callback 
- Write out the secrets database, using the code from libnet_Join

*/
struct libnet_vampire_cb_state {
	const char *netbios_name;
	const char *domain_name;
	const char *realm;
	struct cli_credentials *machine_account;

	/* Schema loaded from local LDIF files */
	struct dsdb_schema *provision_schema;

        /* 1st pass, with some OIDs/attribute names/class names not
	 * converted, because we may not know them yet */
	struct dsdb_schema *self_made_schema;

	/* prefixMap in LDB format, from the remote DRS server */
	DATA_BLOB prefixmap_blob;
	const struct dsdb_schema *schema;

	struct ldb_context *ldb;

	struct {
		uint32_t object_count;
		struct drsuapi_DsReplicaObjectListItemEx *first_object;
		struct drsuapi_DsReplicaObjectListItemEx *last_object;
	} schema_part;

	const char *targetdir;

	struct loadparm_context *lp_ctx;
	struct tevent_context *event_ctx;
	unsigned total_objects;
	unsigned total_links;
	char *last_partition;
	const char *server_dn_str;
};

/* initialise a state structure ready for replication of chunks */
void *libnet_vampire_replicate_init(TALLOC_CTX *mem_ctx,
				    struct ldb_context *samdb,
				    struct loadparm_context *lp_ctx)
{
	struct libnet_vampire_cb_state *s = talloc_zero(mem_ctx, struct libnet_vampire_cb_state);
	if (!s) {
		return NULL;
	}

	s->ldb              = samdb;
	s->lp_ctx           = lp_ctx;
	s->provision_schema = dsdb_get_schema(s->ldb, s);
	s->schema           = s->provision_schema;
	s->netbios_name     = lpcfg_netbios_name(lp_ctx);
	s->domain_name      = lpcfg_workgroup(lp_ctx);
	s->realm            = lpcfg_realm(lp_ctx);

	return s;
}

/* Caller is expected to keep supplied pointers around for the lifetime of the structure */
void *libnet_vampire_cb_state_init(TALLOC_CTX *mem_ctx,
				   struct loadparm_context *lp_ctx, struct tevent_context *event_ctx,
				   const char *netbios_name, const char *domain_name, const char *realm,
				   const char *targetdir)
{
	struct libnet_vampire_cb_state *s = talloc_zero(mem_ctx, struct libnet_vampire_cb_state);
	if (!s) {
		return NULL;
	}

	s->lp_ctx = lp_ctx;
	s->event_ctx = event_ctx;
	s->netbios_name = netbios_name;
	s->domain_name = domain_name;
	s->realm = realm;
	s->targetdir = targetdir;
	return s;
}

struct ldb_context *libnet_vampire_cb_ldb(struct libnet_vampire_cb_state *state)
{
	state = talloc_get_type_abort(state, struct libnet_vampire_cb_state);
	return state->ldb;
}

struct loadparm_context *libnet_vampire_cb_lp_ctx(struct libnet_vampire_cb_state *state)
{
	state = talloc_get_type_abort(state, struct libnet_vampire_cb_state);
	return state->lp_ctx;
}

NTSTATUS libnet_vampire_cb_prepare_db(void *private_data,
				      const struct libnet_BecomeDC_PrepareDB *p)
{
	struct libnet_vampire_cb_state *s = talloc_get_type(private_data, struct libnet_vampire_cb_state);
	struct provision_settings settings;
	struct provision_result result;
	NTSTATUS status;

	ZERO_STRUCT(settings);
	settings.site_name = p->dest_dsa->site_name;
	settings.root_dn_str = p->forest->root_dn_str;
	settings.domain_dn_str = p->domain->dn_str;
	settings.config_dn_str = p->forest->config_dn_str;
	settings.schema_dn_str = p->forest->schema_dn_str;
	settings.netbios_name = p->dest_dsa->netbios_name;
	settings.realm = s->realm;
	settings.domain = s->domain_name;
	settings.server_dn_str = p->dest_dsa->server_dn_str;
	settings.machine_password = generate_random_machine_password(s, 128, 255);
	settings.targetdir = s->targetdir;
	settings.use_ntvfs = true;
	status = provision_bare(s, s->lp_ctx, &settings, &result);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	s->ldb = talloc_steal(s, result.samdb);
	s->lp_ctx = talloc_reparent(talloc_parent(result.lp_ctx), s, result.lp_ctx);
	s->provision_schema = dsdb_get_schema(s->ldb, s);
	s->server_dn_str = talloc_steal(s, p->dest_dsa->server_dn_str);

	/* wrap the entire vapire operation in a transaction.  This
	   isn't just cosmetic - we use this to ensure that linked
	   attribute back links are added at the end by relying on a
	   transaction commit hook in the linked attributes module. We
	   need to do this as the order of objects coming from the
	   server is not sufficiently deterministic to know that the
	   record that a backlink needs to be created in has itself
	   been created before the object containing the forward link
	   has come over the wire */
	if (ldb_transaction_start(s->ldb) != LDB_SUCCESS) {
		return NT_STATUS_FOOBAR;
	}

        return NT_STATUS_OK;


}

NTSTATUS libnet_vampire_cb_check_options(void *private_data,
					 const struct libnet_BecomeDC_CheckOptions *o)
{
	struct libnet_vampire_cb_state *s = talloc_get_type(private_data, struct libnet_vampire_cb_state);

	DEBUG(0,("Become DC [%s] of Domain[%s]/[%s]\n",
		s->netbios_name,
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

static WERROR libnet_vampire_cb_apply_schema(struct libnet_vampire_cb_state *s,
					     const struct libnet_BecomeDC_StoreChunk *c)
{
	WERROR status;
	struct dsdb_schema_prefixmap *pfm_remote;
	const struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr;
	struct dsdb_schema *provision_schema;
	uint32_t object_count = 0;
	struct drsuapi_DsReplicaObjectListItemEx *first_object;
	uint32_t linked_attributes_count;
	struct drsuapi_DsReplicaLinkedAttribute *linked_attributes;
	const struct drsuapi_DsReplicaCursor2CtrEx *uptodateness_vector;
	struct dsdb_extended_replicated_objects *schema_objs;
	struct repsFromTo1 *s_dsa;
	char *tmp_dns_name;
	struct ldb_context *schema_ldb;
	struct ldb_dn *partition_dn;
	struct ldb_message *msg;
	struct ldb_message_element *prefixMap_el;
	uint32_t i;
	int ret;
	bool ok;
	uint64_t seq_num = 0;
	uint32_t cycle_before_switching;

	DEBUG(0,("Analyze and apply schema objects\n"));

	s_dsa			= talloc_zero(s, struct repsFromTo1);
	if (s_dsa == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	s_dsa->other_info	= talloc(s_dsa, struct repsFromTo1OtherInfo);
	if (s_dsa->other_info == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	switch (c->ctr_level) {
	case 1:
		mapping_ctr			= &c->ctr1->mapping_ctr;
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
		object_count			= s->schema_part.object_count;
		first_object			= s->schema_part.first_object;
		linked_attributes_count		= c->ctr6->linked_attributes_count;
		linked_attributes		= c->ctr6->linked_attributes;
		s_dsa->highwatermark		= c->ctr6->new_highwatermark;
		s_dsa->source_dsa_obj_guid	= c->ctr6->source_dsa_guid;
		s_dsa->source_dsa_invocation_id = c->ctr6->source_dsa_invocation_id;
		uptodateness_vector		= c->ctr6->uptodateness_vector;
		break;
	default:
		return WERR_INVALID_PARAMETER;
	}
	/* We must set these up to ensure the replMetaData is written
	 * correctly, before our NTDS Settings entry is replicated */
	ok = samdb_set_ntds_invocation_id(s->ldb, &c->dest_dsa->invocation_id);
	if (!ok) {
		DEBUG(0,("Failed to set cached ntds invocationId\n"));
		return WERR_INTERNAL_ERROR;
	}
	ok = samdb_set_ntds_objectGUID(s->ldb, &c->dest_dsa->ntds_guid);
	if (!ok) {
		DEBUG(0,("Failed to set cached ntds objectGUID\n"));
		return WERR_INTERNAL_ERROR;
	}

	status = dsdb_schema_pfm_from_drsuapi_pfm(mapping_ctr, true,
						  s, &pfm_remote, NULL);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,(__location__ ": Failed to decode remote prefixMap: %s",
			 win_errstr(status)));
		return status;
	}

	s_dsa->replica_flags		= DRSUAPI_DRS_WRIT_REP
					| DRSUAPI_DRS_INIT_SYNC
					| DRSUAPI_DRS_PER_SYNC;
	memset(s_dsa->schedule, 0x11, sizeof(s_dsa->schedule));

	tmp_dns_name	= GUID_string(s_dsa->other_info, &s_dsa->source_dsa_obj_guid);
	if (tmp_dns_name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	tmp_dns_name	= talloc_asprintf_append_buffer(tmp_dns_name, "._msdcs.%s", c->forest->dns_name);
	if (tmp_dns_name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	s_dsa->other_info->dns_name = tmp_dns_name;

	if (s->self_made_schema == NULL) {
		DEBUG(0,("libnet_vampire_cb_apply_schema: called with out self_made_schema\n"));
		return WERR_INTERNAL_ERROR;
	}

	schema_ldb = provision_get_schema(s, s->lp_ctx,
					  c->forest->schema_dn_str,
					  &s->prefixmap_blob);
	if (!schema_ldb) {
		DEBUG(0,("Failed to re-load from local provision using remote prefixMap. "
			 "Will continue with local prefixMap\n"));
		provision_schema = dsdb_get_schema(s->ldb, s);
	} else {
		provision_schema = dsdb_get_schema(schema_ldb, s);
		ret = dsdb_reference_schema(s->ldb, provision_schema, SCHEMA_MEMORY_ONLY);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,("Failed to attach schema from local provision using remote prefixMap."));
			return WERR_INTERNAL_ERROR;
		}
		talloc_unlink(s, schema_ldb);
	}

	cycle_before_switching = lpcfg_parm_long(s->lp_ctx, NULL,
						 "become dc",
						 "schema convert retrial", 1);

	provision_schema->resolving_in_progress = true;
	s->self_made_schema->resolving_in_progress = true;

	status = dsdb_repl_resolve_working_schema(s->ldb,
						  pfm_remote,
						  cycle_before_switching,
						  provision_schema,
						  s->self_made_schema,
						  object_count,
						  first_object);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0, ("%s: dsdb_repl_resolve_working_schema() failed: %s",
			  __location__, win_errstr(status)));
		return status;
	}

	/* free temp objects for 1st conversion phase */
	talloc_unlink(s, provision_schema);

	s->self_made_schema->resolving_in_progress = false;

	/*
	 * attach the schema we just brought over DRS to the ldb,
	 * so we can use it in dsdb_convert_object_ex below
	 */
	ret = dsdb_set_schema(s->ldb, s->self_made_schema, SCHEMA_WRITE);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to attach working schema from DRS.\n"));
		return WERR_INTERNAL_ERROR;
	}

	/* we don't want to access the self made schema anymore */
	s->schema = s->self_made_schema;
	s->self_made_schema = NULL;

	partition_dn = ldb_dn_new(s, s->ldb, c->partition->nc.dn);
	if (partition_dn == NULL) {
		DEBUG(0,("Failed to parse partition DN from DRS.\n"));
		return WERR_INVALID_PARAMETER;
	}

	/* Now convert the schema elements again, using the schema we finalised, ready to actually import */
	status = dsdb_replicated_objects_convert(s->ldb,
						 s->schema,
						 partition_dn,
						 mapping_ctr,
						 object_count,
						 first_object,
						 linked_attributes_count,
						 linked_attributes,
						 s_dsa,
						 uptodateness_vector,
						 c->gensec_skey,
						 0,
						 s, &schema_objs);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("Failed to convert objects when trying to import over DRS (2nd pass, to store remote schema): %s\n", win_errstr(status)));
		return status;
	}

	if (lpcfg_parm_bool(s->lp_ctx, NULL, "become dc", "dump objects", false)) {
		for (i=0; i < schema_objs->num_objects; i++) {
			struct ldb_ldif ldif;
			fprintf(stdout, "#\n");
			ldif.changetype = LDB_CHANGETYPE_NONE;
			ldif.msg = schema_objs->objects[i].msg;
			ldb_ldif_write_file(s->ldb, stdout, &ldif);
			NDR_PRINT_DEBUG(replPropertyMetaDataBlob, schema_objs->objects[i].meta_data);
		}
	}

	status = dsdb_replicated_objects_commit(s->ldb, NULL, schema_objs, &seq_num);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("Failed to commit objects: %s\n", win_errstr(status)));
		return status;
	}

	msg = ldb_msg_new(schema_objs);
	if (msg == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	msg->dn = schema_objs->partition_dn;

	/* We must ensure a prefixMap has been written.  Unlike other
	 * attributes (including schemaInfo), it is not replicated in
	 * the normal replication stream.  We can use the one from
	 * s->prefixmap_blob because we operate with one, unchanging
	 * prefixMap for this entire operation.  */
	ret = ldb_msg_add_value(msg, "prefixMap", &s->prefixmap_blob, &prefixMap_el);
	if (ret != LDB_SUCCESS) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	/* We want to know if a prefixMap was written already, as it
	 * would mean that the above comment was not true, and we have
	 * somehow updated the prefixMap during this transaction */
	prefixMap_el->flags = LDB_FLAG_MOD_ADD;

	ret = dsdb_modify(s->ldb, msg, DSDB_FLAG_AS_SYSTEM);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to add prefixMap: %s\n", ldb_errstring(s->ldb)));
		return WERR_INTERNAL_ERROR;
	}

	talloc_free(s_dsa);
	talloc_free(schema_objs);

	s->schema = dsdb_get_schema(s->ldb, s);
	if (!s->schema) {
		DEBUG(0,("Failed to get loaded dsdb_schema\n"));
		return WERR_INTERNAL_ERROR;
	}

	return WERR_OK;
}

WERROR libnet_vampire_cb_schema_chunk(void *private_data,
				      const struct libnet_BecomeDC_StoreChunk *c)
{
	struct libnet_vampire_cb_state *s = talloc_get_type(private_data, struct libnet_vampire_cb_state);
	WERROR werr;
	const struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr;
	uint32_t nc_object_count;
	uint32_t nc_total_received = 0;
	uint32_t object_count;
	struct drsuapi_DsReplicaObjectListItemEx *first_object;
	struct drsuapi_DsReplicaObjectListItemEx *cur;
	uint32_t nc_linked_attributes_count;
	uint32_t linked_attributes_count;

	switch (c->ctr_level) {
	case 1:
		mapping_ctr			= &c->ctr1->mapping_ctr;
		nc_object_count			= c->ctr1->extended_ret; /* maybe w2k send this unexpected? */
		object_count			= c->ctr1->object_count;
		first_object			= c->ctr1->first_object;
		nc_linked_attributes_count	= 0;
		linked_attributes_count		= 0;
		break;
	case 6:
		mapping_ctr			= &c->ctr6->mapping_ctr;
		nc_object_count			= c->ctr6->nc_object_count;
		object_count			= c->ctr6->object_count;
		first_object			= c->ctr6->first_object;
		nc_linked_attributes_count	= c->ctr6->nc_linked_attributes_count;
		linked_attributes_count		= c->ctr6->linked_attributes_count;
		break;
	default:
		return WERR_INVALID_PARAMETER;
	}

	if (!s->schema_part.first_object) {
		nc_total_received = object_count;
	} else {
		nc_total_received = s->schema_part.object_count + object_count;
	}
	if (nc_object_count) {
		DEBUG(0,("Schema-DN[%s] objects[%u/%u] linked_values[%u/%u]\n",
			c->partition->nc.dn, nc_total_received, nc_object_count,
			linked_attributes_count, nc_linked_attributes_count));
	} else {
		DEBUG(0,("Schema-DN[%s] objects[%u] linked_values[%u]\n",
		c->partition->nc.dn, nc_total_received, linked_attributes_count));
	}

	if (!s->self_made_schema) {
		struct drsuapi_DsReplicaOIDMapping_Ctr mapping_ctr_without_schema_info;
		/* Put the DRS prefixmap aside for the schema we are
		 * about to load in the provision, and into the one we
		 * are making with the help of DRS */

		mapping_ctr_without_schema_info = *mapping_ctr;

		/* This strips off the 0xFF schema info from the end,
		 * because we don't want it in the blob */
		if (mapping_ctr_without_schema_info.num_mappings > 0) {
			mapping_ctr_without_schema_info.num_mappings--;
		}
		werr = dsdb_get_drsuapi_prefixmap_as_blob(&mapping_ctr_without_schema_info, s, &s->prefixmap_blob);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}

		/* Set up two manually-constructed schema - the local
		 * schema from the provision will be used to build
		 * one, which will then in turn be used to build the
		 * other. */
		s->self_made_schema = dsdb_new_schema(s);
		if (s->self_made_schema == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}

		werr = dsdb_load_prefixmap_from_drsuapi(s->self_made_schema, mapping_ctr);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
		}
	} else {
		werr = dsdb_schema_pfm_contains_drsuapi_pfm(s->self_made_schema->prefixmap, mapping_ctr);
		if (!W_ERROR_IS_OK(werr)) {
			return werr;
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
	if (first_object != NULL) {
		for (cur = first_object; cur->next_object; cur = cur->next_object) {}
	} else {
		cur = first_object;
	}

	s->schema_part.last_object = cur;

	if (!c->partition->more_data) {
		return libnet_vampire_cb_apply_schema(s, c);
	}

	return WERR_OK;
}

WERROR libnet_vampire_cb_store_chunk(void *private_data,
				     const struct libnet_BecomeDC_StoreChunk *c)
{
	struct libnet_vampire_cb_state *s = talloc_get_type(private_data, struct libnet_vampire_cb_state);
	WERROR status;
	struct dsdb_schema *schema;
	const struct drsuapi_DsReplicaOIDMapping_Ctr *mapping_ctr;
	uint32_t nc_object_count;
	uint32_t object_count;
	struct drsuapi_DsReplicaObjectListItemEx *first_object;
	uint32_t nc_linked_attributes_count;
	uint32_t linked_attributes_count;
	struct drsuapi_DsReplicaLinkedAttribute *linked_attributes;
	const struct drsuapi_DsReplicaCursor2CtrEx *uptodateness_vector;
	struct dsdb_extended_replicated_objects *objs;
	uint32_t req_replica_flags;
	uint32_t dsdb_repl_flags = 0;
	struct repsFromTo1 *s_dsa;
	char *tmp_dns_name;
	uint32_t i;
	uint64_t seq_num;
	bool is_exop = false;
	struct ldb_dn *partition_dn = NULL;
	struct ldb_dn *nc_root = NULL;

	s_dsa			= talloc_zero(s, struct repsFromTo1);
	if (s_dsa == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	s_dsa->other_info	= talloc(s_dsa, struct repsFromTo1OtherInfo);
	if (s_dsa->other_info == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	switch (c->ctr_level) {
	case 1:
		mapping_ctr			= &c->ctr1->mapping_ctr;
		nc_object_count			= c->ctr1->extended_ret; /* maybe w2k send this unexpected? */
		object_count			= c->ctr1->object_count;
		first_object			= c->ctr1->first_object;
		nc_linked_attributes_count	= 0;
		linked_attributes_count		= 0;
		linked_attributes		= NULL;
		s_dsa->highwatermark		= c->ctr1->new_highwatermark;
		s_dsa->source_dsa_obj_guid	= c->ctr1->source_dsa_guid;
		s_dsa->source_dsa_invocation_id = c->ctr1->source_dsa_invocation_id;
		uptodateness_vector		= NULL; /* TODO: map it */
		break;
	case 6:
		mapping_ctr			= &c->ctr6->mapping_ctr;
		nc_object_count			= c->ctr6->nc_object_count;
		object_count			= c->ctr6->object_count;
		first_object			= c->ctr6->first_object;
		nc_linked_attributes_count	= c->ctr6->nc_linked_attributes_count;
		linked_attributes_count		= c->ctr6->linked_attributes_count;
		linked_attributes		= c->ctr6->linked_attributes;
		s_dsa->highwatermark		= c->ctr6->new_highwatermark;
		s_dsa->source_dsa_obj_guid	= c->ctr6->source_dsa_guid;
		s_dsa->source_dsa_invocation_id = c->ctr6->source_dsa_invocation_id;
		uptodateness_vector		= c->ctr6->uptodateness_vector;
		break;
	default:
		return WERR_INVALID_PARAMETER;
	}

	switch (c->req_level) {
	case 0:
		/* none */
		req_replica_flags = 0;
		break;
	case 5:
		if (c->req5->extended_op != DRSUAPI_EXOP_NONE) {
			is_exop = true;
		}
		req_replica_flags = c->req5->replica_flags;
		break;
	case 8:
		if (c->req8->extended_op != DRSUAPI_EXOP_NONE) {
			is_exop = true;
		}
		req_replica_flags = c->req8->replica_flags;
		break;
	case 10:
		if (c->req10->extended_op != DRSUAPI_EXOP_NONE) {
			is_exop = true;
		}
		req_replica_flags = c->req10->replica_flags;

		if (c->req10->more_flags & DRSUAPI_DRS_GET_TGT) {
			dsdb_repl_flags |= DSDB_REPL_FLAG_TARGETS_UPTODATE;
		}
		break;
	default:
		return WERR_INVALID_PARAMETER;
	}

	/*
	 * If the peer DC doesn't support GET_TGT (req v10), then the link
	 * targets are as up-to-date as they're ever gonna be. (Without this,
	 * cases where we'd normally retry with GET_TGT cause the join to fail)
	 */
	if (c->req_level < 10) {
		dsdb_repl_flags |= DSDB_REPL_FLAG_TARGETS_UPTODATE;
	}

	if (req_replica_flags & DRSUAPI_DRS_CRITICAL_ONLY || is_exop) {
		/*
		 * If we only replicate the critical objects, or this
		 * is an exop we should not remember what we already
		 * got, as it is incomplete.
		 */
		ZERO_STRUCT(s_dsa->highwatermark);
		uptodateness_vector = NULL;
		dsdb_repl_flags |= DSDB_REPL_FLAG_OBJECT_SUBSET;
	}

	/* TODO: avoid hardcoded flags */
	s_dsa->replica_flags		= DRSUAPI_DRS_WRIT_REP
					| DRSUAPI_DRS_INIT_SYNC
					| DRSUAPI_DRS_PER_SYNC;
	memset(s_dsa->schedule, 0x11, sizeof(s_dsa->schedule));

	tmp_dns_name	= GUID_string(s_dsa->other_info, &s_dsa->source_dsa_obj_guid);
	if (tmp_dns_name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	tmp_dns_name	= talloc_asprintf_append_buffer(tmp_dns_name, "._msdcs.%s", c->forest->dns_name);
	if (tmp_dns_name == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}
	s_dsa->other_info->dns_name = tmp_dns_name;

	/* we want to show a count per partition */
	if (!s->last_partition || strcmp(s->last_partition, c->partition->nc.dn) != 0) {
		s->total_objects = 0;
		s->total_links = 0;
		talloc_free(s->last_partition);
		s->last_partition = talloc_strdup(s, c->partition->nc.dn);
	}
	s->total_objects += object_count;
	s->total_links += linked_attributes_count;

	partition_dn = ldb_dn_new(s_dsa, s->ldb, c->partition->nc.dn);
	if (partition_dn == NULL) {
		DEBUG(0,("Failed to parse partition DN from DRS.\n"));
		return WERR_INVALID_PARAMETER;
	}

	if (is_exop) {
		int ret;
		if (nc_object_count) {
			DEBUG(0,("Exop on[%s] objects[%u/%u] linked_values[%u/%u]\n",
				c->partition->nc.dn, s->total_objects, nc_object_count,
				s->total_links, nc_linked_attributes_count));
		} else {
			DEBUG(0,("Exop on[%s] objects[%u] linked_values[%u]\n",
			c->partition->nc.dn, s->total_objects, linked_attributes_count));
		}
		ret = dsdb_find_nc_root(s->ldb, s_dsa,
					partition_dn, &nc_root);
		if (ret != LDB_SUCCESS) {
			DEBUG(0,(__location__ ": Failed to find nc_root for %s\n",
				 ldb_dn_get_linearized(partition_dn)));
			return WERR_INTERNAL_ERROR;
		}
	} else {
		if (nc_object_count) {
			DEBUG(0,("Partition[%s] objects[%u/%u] linked_values[%u/%u]\n",
				c->partition->nc.dn, s->total_objects, nc_object_count,
				s->total_links, nc_linked_attributes_count));
		} else {
			DEBUG(0,("Partition[%s] objects[%u] linked_values[%u]\n",
			c->partition->nc.dn, s->total_objects, s->total_links));
		}
		nc_root = partition_dn;
	}


	schema = dsdb_get_schema(s->ldb, NULL);
	if (!schema) {
		DEBUG(0,(__location__ ": Schema is not loaded yet!\n"));
		return WERR_INTERNAL_ERROR;
	}

	if (req_replica_flags & DRSUAPI_DRS_FULL_SYNC_IN_PROGRESS) {
		dsdb_repl_flags |= DSDB_REPL_FLAG_PRIORITISE_INCOMING;
	}

	if (req_replica_flags & DRSUAPI_DRS_SPECIAL_SECRET_PROCESSING) {
		dsdb_repl_flags |= DSDB_REPL_FLAG_EXPECT_NO_SECRETS;
	}

	status = dsdb_replicated_objects_convert(s->ldb,
						 schema,
						 nc_root,
						 mapping_ctr,
						 object_count,
						 first_object,
						 linked_attributes_count,
						 linked_attributes,
						 s_dsa,
						 uptodateness_vector,
						 c->gensec_skey,
						 dsdb_repl_flags,
						 s, &objs);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("Failed to convert objects: %s\n", win_errstr(status)));
		return status;
	}

	if (lpcfg_parm_bool(s->lp_ctx, NULL, "become dc", "dump objects", false)) {
		for (i=0; i < objs->num_objects; i++) {
			struct ldb_ldif ldif;
			fprintf(stdout, "#\n");
			ldif.changetype = LDB_CHANGETYPE_NONE;
			ldif.msg = objs->objects[i].msg;
			ldb_ldif_write_file(s->ldb, stdout, &ldif);
			NDR_PRINT_DEBUG(replPropertyMetaDataBlob, objs->objects[i].meta_data);
		}
	}
	status = dsdb_replicated_objects_commit(s->ldb, NULL, objs, &seq_num);
	if (!W_ERROR_IS_OK(status)) {
		DEBUG(0,("Failed to commit objects: %s\n", win_errstr(status)));
		return status;
	}

	/* reset debug counters once we've finished replicating the partition */
	if (!c->partition->more_data) {
		s->total_objects = 0;
		s->total_links = 0;
	}

	talloc_free(s_dsa);
	talloc_free(objs);

	for (i=0; i < linked_attributes_count; i++) {
		const struct dsdb_attribute *sa;

		if (!linked_attributes[i].identifier) {
			DEBUG(0, ("No linked attribute identifier\n"));
			return WERR_INTERNAL_ERROR;
		}

		if (!linked_attributes[i].value.blob) {
			DEBUG(0, ("No linked attribute value\n"));
			return WERR_INTERNAL_ERROR;
		}

		sa = dsdb_attribute_by_attributeID_id(s->schema,
						      linked_attributes[i].attid);
		if (!sa) {
			DEBUG(0, ("Unable to find attribute via attribute id %d\n", linked_attributes[i].attid));
			return WERR_INTERNAL_ERROR;
		}

		if (lpcfg_parm_bool(s->lp_ctx, NULL, "become dc", "dump objects", false)) {
			DEBUG(0,("# %s\n", sa->lDAPDisplayName));
			NDR_PRINT_DEBUG(drsuapi_DsReplicaLinkedAttribute, &linked_attributes[i]);
			dump_data(0,
				linked_attributes[i].value.blob->data,
				linked_attributes[i].value.blob->length);
		}
	}

	return WERR_OK;
}

