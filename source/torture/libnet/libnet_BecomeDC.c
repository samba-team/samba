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

#define TORTURE_NETBIOS_NAME "smbtorturedc"

struct test_become_dc_state {
	struct libnet_context *ctx;
	struct test_join *tj;
	struct cli_credentials *machine_account;
	struct dsdb_schema *schema;
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
	}

	for (cur = first_object; cur; cur = cur->next_object) {
		uint32_t i;
		bool dn_printed = false;
		bool is_attr = false;
		bool is_class = false;

		for (i=0; i < cur->object.attribute_ctr.num_attributes; i++) {
			struct drsuapi_DsReplicaAttribute *a;
			uint32_t j;
			const char *oid = NULL;

			a = &cur->object.attribute_ctr.attributes[i];
			status = dsdb_map_int2oid(s->schema, a->attid, s, &oid);
			if (!W_ERROR_IS_OK(status)) {
				if (!dn_printed) {
					DEBUG(0,("%s:\n", cur->object.identifier->dn));
					dn_printed = true;
				}
				DEBUG(0,("\tattr 0x%08X => %s\n", a->attid, win_errstr(status)));
			}

			switch (a->attid) {
			case DRSUAPI_ATTRIBUTE_objectClass:
			case DRSUAPI_ATTRIBUTE_attributeID:
			case DRSUAPI_ATTRIBUTE_attributeSyntax:
				for (j=0; j < a->value_ctr.uint32.num_values; j++) {
					uint32_t val = *a->value_ctr.uint32.values[j].value;

					if (val == DRSUAPI_OBJECTCLASS_attributeSchema) {
						is_attr = true;
					}
					if (val == DRSUAPI_OBJECTCLASS_classSchema) {
						is_class = true;
					}

					status = dsdb_map_int2oid(s->schema, val, s, &oid);
					if (!W_ERROR_IS_OK(status)) {
						if (!dn_printed) {
							DEBUG(0,("%s:\n", cur->object.identifier->dn));
							dn_printed = true;
						}
						DEBUG(0,("\tattr 0x%08X => %s value[%u] 0x%08X => %s\n",
							 a->attid, oid, j, val, win_errstr(status)));
					}
				}
				break;
			default:
				break;
			}
		}

		if (is_attr) {
			struct dsdb_attribute sa;
			status = dsdb_attribute_from_drsuapi(s->schema, &cur->object, s, &sa);
			if (!W_ERROR_IS_OK(status)) {
				return werror_to_ntstatus(status);
			}
		}

		if (is_class) {
			struct dsdb_class sc;
			status = dsdb_class_from_drsuapi(s->schema, &cur->object, s, &sc);
			if (!W_ERROR_IS_OK(status)) {
				return werror_to_ntstatus(status);
			}
		}
	}

	return NT_STATUS_OK;
}

static NTSTATUS test_become_dc_store_chunk(void *private_data,
					   const struct libnet_BecomeDC_StoreChunk *c)
{
	uint32_t total_object_count;
	uint32_t object_count;

	switch (c->ctr_level) {
	case 1:
		total_object_count	= c->ctr1->total_object_count;
		object_count		= c->ctr1->object_count;
		break;
	case 6:
		total_object_count	= c->ctr6->total_object_count;
		object_count		= c->ctr6->object_count;
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
