/* 
   Unix SMB/CIFS implementation.

   DRSUapi tests

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Stefan (metze) Metzmacher 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005-2006

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
#include "torture/torture.h"
#include "librpc/gen_ndr/ndr_drsuapi_c.h"
#include "torture/rpc/rpc.h"
#include "dlinklist.h"
#include "param/param.h"

#define TEST_MACHINE_NAME "torturetest"

bool test_DsBind(struct dcerpc_pipe *p, struct torture_context *tctx,
		 struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsBind r;
	struct torture_rpc_tcase_data *rpc_tcase;

	GUID_from_string(DRSUAPI_DS_BIND_GUID, &priv->bind_guid);

	r.in.bind_guid = &priv->bind_guid;
	r.in.bind_info = NULL;
	r.out.bind_handle = &priv->bind_handle;

	status = dcerpc_drsuapi_DsBind(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "DsBind");
	torture_assert_werr_ok(tctx, r.out.result, "DsBind");

	rpc_tcase = (struct torture_rpc_tcase_data *)tctx->active_tcase->data;

	priv->join = rpc_tcase->join_ctx;

	return true;
}

bool test_DsUnbind(struct dcerpc_pipe *p, struct torture_context *tctx,
		   struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsUnbind r;

	r.in.bind_handle = &priv->bind_handle;
	r.out.bind_handle = &priv->bind_handle;

	status = dcerpc_drsuapi_DsUnbind(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status,
			"dcerpc_drsuapi_DsUnbind failed");
	torture_assert_werr_ok(tctx, r.out.result, "DsBind failed");

	return true;
}

static bool wrap_test_drsuapi(struct torture_context *tctx, 
			      struct torture_tcase *tcase,
			      struct torture_test *test)
{
	bool (*fn) (struct torture_context *, struct dcerpc_pipe *, struct DsPrivate *);
	struct torture_rpc_tcase_data *tcase_data = 
		(struct torture_rpc_tcase_data *)tcase->data;
	bool ret;
	struct DsPrivate priv;

	ZERO_STRUCT(priv);

	fn = test->fn;

	if (!test_DsBind(tcase_data->pipe, tctx, &priv))
		return false;

	ret = fn(tctx, tcase_data->pipe, &priv);
	
	if (!test_DsUnbind(tcase_data->pipe, tctx, &priv))
		return false;

	return ret;
}

static struct torture_test *torture_rpc_tcase_add_drsuapi_test(
					struct torture_rpc_tcase *tcase, 
					const char *name, 
					bool (*fn) (struct torture_context *, struct dcerpc_pipe *, struct DsPrivate *priv))
{
	struct torture_test *test;

	test = talloc(tcase, struct torture_test);

	test->name = talloc_strdup(test, name);
	test->description = NULL;
	test->run = wrap_test_drsuapi;
	test->dangerous = false;
	test->data = NULL;
	test->fn = fn;

	DLIST_ADD(tcase->tcase.tests, test);

	return test;
}

static bool test_DsGetDomainControllerInfo(struct torture_context *torture, 
					   struct dcerpc_pipe *p, 
					   struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsGetDomainControllerInfo r;
	bool found = false;
	int i, j, k;
	
	struct {
		const char *name;
		WERROR expected;
	} names[] = { 
		{	
			.name = torture_join_dom_netbios_name(priv->join),
			.expected = WERR_OK
		},
		{
			.name = torture_join_dom_dns_name(priv->join),
			.expected = WERR_OK
		},
		{
			.name = "__UNKNOWN_DOMAIN__",
			.expected = WERR_DS_OBJ_NOT_FOUND
		},
		{
			.name = "unknown.domain.samba.example.com",
			.expected = WERR_DS_OBJ_NOT_FOUND
		},
	};
	int levels[] = {1, 2};
	int level;

	for (i=0; i < ARRAY_SIZE(levels); i++) {
		for (j=0; j < ARRAY_SIZE(names); j++) {
			level = levels[i];
			r.in.bind_handle = &priv->bind_handle;
			r.in.level = 1;
			
			r.in.req.req1.domain_name = names[j].name;
			r.in.req.req1.level = level;
			
			torture_comment(torture,
				   "testing DsGetDomainControllerInfo level %d on domainname '%s'\n",
			       r.in.req.req1.level, r.in.req.req1.domain_name);
		
			status = dcerpc_drsuapi_DsGetDomainControllerInfo(p, torture, &r);
			torture_assert_ntstatus_ok(torture, status,
				   "dcerpc_drsuapi_DsGetDomainControllerInfo with dns domain failed");
			torture_assert_werr_equal(torture, 
									  r.out.result, names[j].expected, 
					   "DsGetDomainControllerInfo level with dns domain failed");
		
			if (!W_ERROR_IS_OK(r.out.result)) {
				/* If this was an error, we can't read the result structure */
				continue;
			}

			torture_assert_int_equal(torture, 
						 r.in.req.req1.level, r.out.level_out, 
						 "dcerpc_drsuapi_DsGetDomainControllerInfo level"); 

			switch (level) {
			case 1:
				for (k=0; k < r.out.ctr.ctr1.count; k++) {
					if (strcasecmp_m(r.out.ctr.ctr1.array[k].netbios_name, 
							 torture_join_netbios_name(priv->join)) == 0) {
						found = true;
						break;
					}
				}
				break;
			case 2:
				for (k=0; k < r.out.ctr.ctr2.count; k++) {
					if (strcasecmp_m(r.out.ctr.ctr2.array[k].netbios_name, 
							 torture_join_netbios_name(priv->join)) == 0) {
						found = true;
						priv->dcinfo	= r.out.ctr.ctr2.array[k];
						break;
					}
				}
				break;
			}
			torture_assert(torture, found,
				 "dcerpc_drsuapi_DsGetDomainControllerInfo: Failed to find the domain controller we just created during the join");
		}
	}

	r.in.bind_handle = &priv->bind_handle;
	r.in.level = 1;
	
	r.in.req.req1.domain_name = "__UNKNOWN_DOMAIN__"; /* This is clearly ignored for this level */
	r.in.req.req1.level = -1;
	
	torture_comment(torture,
		"testing DsGetDomainControllerInfo level %d on domainname '%s'\n",
	       r.in.req.req1.level, r.in.req.req1.domain_name);
	
	status = dcerpc_drsuapi_DsGetDomainControllerInfo(p, torture, &r);

	torture_assert_ntstatus_ok(torture, status, 
			"dcerpc_drsuapi_DsGetDomainControllerInfo with dns domain failed");
	torture_assert_werr_ok(torture, r.out.result, 
			   "DsGetDomainControllerInfo with dns domain failed");
	
	{
		const char *dc_account = talloc_asprintf(torture, "%s\\%s$",
							 torture_join_dom_netbios_name(priv->join), 
							 priv->dcinfo.netbios_name);
		for (k=0; k < r.out.ctr.ctr01.count; k++) {
			if (strcasecmp_m(r.out.ctr.ctr01.array[k].client_account, 
					 dc_account)) {
				found = true;
				break;
			}
		}
		torture_assert(torture, found,
			"dcerpc_drsuapi_DsGetDomainControllerInfo level: Failed to find the domain controller in last logon records");
	}


	return true;
}

static bool test_DsWriteAccountSpn(struct torture_context *tctx, 
				   struct dcerpc_pipe *p, 
				   struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsWriteAccountSpn r;
	struct drsuapi_DsNameString names[2];

	r.in.bind_handle		= &priv->bind_handle;
	r.in.level			= 1;

	r.in.req.req1.operation	= DRSUAPI_DS_SPN_OPERATION_ADD;
	r.in.req.req1.unknown1	= 0;
	r.in.req.req1.object_dn	= priv->dcinfo.computer_dn;
	r.in.req.req1.count	= 2;
	r.in.req.req1.spn_names	= names;
	names[0].str = talloc_asprintf(tctx, "smbtortureSPN/%s",priv->dcinfo.netbios_name);
	names[1].str = talloc_asprintf(tctx, "smbtortureSPN/%s",priv->dcinfo.dns_name);

	status = dcerpc_drsuapi_DsWriteAccountSpn(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, 
		"dcerpc_drsuapi_DsWriteAccountSpn failed");
	torture_assert_werr_ok(tctx, r.out.result, "DsWriteAccountSpn failed");

	r.in.req.req1.operation	= DRSUAPI_DS_SPN_OPERATION_DELETE;
	r.in.req.req1.unknown1	= 0;

	status = dcerpc_drsuapi_DsWriteAccountSpn(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, 
		"dcerpc_drsuapi_DsWriteAccountSpn failed");
	torture_assert_werr_ok(tctx, r.out.result, "DsWriteAccountSpn failed");

	return true;
}

static bool test_DsReplicaGetInfo(struct torture_context *tctx, 
				  struct dcerpc_pipe *p, 
				  struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_DsReplicaGetInfo r;
	int i;
	struct {
		int32_t level;
		int32_t infotype;
		const char *obj_dn;
	} array[] = {
		{	
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_NEIGHBORS,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_CURSORS,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_OBJ_METADATA,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_KCC_DSA_CONNECT_FAILURES,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_KCC_DSA_LINK_FAILURES,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO,
			DRSUAPI_DS_REPLICA_INFO_PENDING_OPS,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_ATTRIBUTE_VALUE_METADATA,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_CURSORS2,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_CURSORS3,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_OBJ_METADATA2,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_ATTRIBUTE_VALUE_METADATA2,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_NEIGHBORS02,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_CONNECTIONS04,
			"__IGNORED__"
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_CURSORS05,
			NULL
		},{
			DRSUAPI_DS_REPLICA_GET_INFO2,
			DRSUAPI_DS_REPLICA_INFO_06,
			NULL
		}
	};

	r.in.bind_handle	= &priv->bind_handle;

	for (i=0; i < ARRAY_SIZE(array); i++) {
		const char *object_dn;

		torture_comment(tctx, 
			"testing DsReplicaGetInfo level %d infotype %d\n",
			array[i].level, array[i].infotype);

		object_dn = (array[i].obj_dn ? array[i].obj_dn : priv->domain_obj_dn);

		r.in.level = array[i].level;
		switch(r.in.level) {
		case DRSUAPI_DS_REPLICA_GET_INFO:
			r.in.req.req1.info_type	= array[i].infotype;
			r.in.req.req1.object_dn	= object_dn;
			ZERO_STRUCT(r.in.req.req1.guid1);
			break;
		case DRSUAPI_DS_REPLICA_GET_INFO2:
			r.in.req.req2.info_type	= array[i].infotype;
			r.in.req.req2.object_dn	= object_dn;
			ZERO_STRUCT(r.in.req.req1.guid1);
			r.in.req.req2.unknown1	= 0;
			r.in.req.req2.string1	= NULL;
			r.in.req.req2.string2	= NULL;
			r.in.req.req2.unknown2	= 0;
			break;
		}

		status = dcerpc_drsuapi_DsReplicaGetInfo(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, 
			"dcerpc_drsuapi_DsReplicaGetInfo failed");
		torture_assert_werr_ok(tctx, r.out.result, 
				       "DsReplicaGetInfo failed");
	}

	return true;
}

static bool test_DsReplicaSync(struct torture_context *tctx,
			       struct dcerpc_pipe *p, 
			       struct DsPrivate *priv)
{
	NTSTATUS status;
	int i;
	struct drsuapi_DsReplicaSync r;
	struct drsuapi_DsReplicaObjectIdentifier nc;
	struct GUID null_guid;
	struct dom_sid null_sid;
	struct {
		int32_t level;
	} array[] = {
		{	
			1
		}
	};

	ZERO_STRUCT(null_guid);
	ZERO_STRUCT(null_sid);

	r.in.bind_handle	= &priv->bind_handle;

	for (i=0; i < ARRAY_SIZE(array); i++) {
		torture_comment(tctx, "testing DsReplicaSync level %d\n",
				array[i].level);

		r.in.level = array[i].level;
		switch(r.in.level) {
		case 1:
			nc.guid					= null_guid;
			nc.sid					= null_sid;
			nc.dn					= priv->domain_obj_dn?priv->domain_obj_dn:"";

			r.in.req.req1.naming_context		= &nc;
			r.in.req.req1.source_dsa_guid		= priv->dcinfo.ntds_guid;
			r.in.req.req1.other_info		= NULL;
			r.in.req.req1.options			= 16;
			break;
		}

		status = dcerpc_drsuapi_DsReplicaSync(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, 
			"dcerpc_drsuapi_DsReplicaSync failed");
		torture_assert_werr_ok(tctx, r.out.result, 
				       "DsReplicaSync failed");
	}

	return true;
}

static bool test_DsReplicaUpdateRefs(struct torture_context *tctx, 
				     struct dcerpc_pipe *p, 
				     struct DsPrivate *priv)
{
	NTSTATUS status;
	int i;
	struct drsuapi_DsReplicaUpdateRefs r;
	struct drsuapi_DsReplicaObjectIdentifier nc;
	struct GUID null_guid;
	struct dom_sid null_sid;
	struct {
		int32_t level;
	} array[] = {
		{	
			1
		}
	};

	ZERO_STRUCT(null_guid);
	ZERO_STRUCT(null_sid);

	r.in.bind_handle	= &priv->bind_handle;

	for (i=0; i < ARRAY_SIZE(array); i++) {
		torture_comment(tctx, "testing DsReplicaUpdateRefs level %d\n",
			array[i].level);

		r.in.level = array[i].level;
		switch(r.in.level) {
		case 1:
			nc.guid				= null_guid;
			nc.sid				= null_sid;
			nc.dn				= priv->domain_obj_dn?priv->domain_obj_dn:"";

			r.in.req.req1.naming_context	= &nc;
			r.in.req.req1.dest_dsa_dns_name	= talloc_asprintf(tctx, "__some_dest_dsa_guid_string._msdn.%s",
										priv->domain_dns_name);
			r.in.req.req1.dest_dsa_guid	= null_guid;
			r.in.req.req1.options		= 0;
			break;
		}

		status = dcerpc_drsuapi_DsReplicaUpdateRefs(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, 
			"dcerpc_drsuapi_DsReplicaUpdateRefs failed");
		torture_assert_werr_ok(tctx, r.out.result, 
			"DsReplicaUpdateRefs failed");
	}

	return true;
}

static bool test_DsGetNCChanges(struct torture_context *tctx, 
				struct dcerpc_pipe *p, 
				struct DsPrivate *priv)
{
	NTSTATUS status;
	int i;
	struct drsuapi_DsGetNCChanges r;
	struct drsuapi_DsReplicaObjectIdentifier nc;
	struct GUID null_guid;
	struct dom_sid null_sid;
	struct {
		int32_t level;
	} array[] = {
		{	
			5
		},
		{	
			8
		}
	};

	ZERO_STRUCT(null_guid);
	ZERO_STRUCT(null_sid);

	for (i=0; i < ARRAY_SIZE(array); i++) {
		torture_comment(tctx, "testing DsGetNCChanges level %d\n",
			array[i].level);

		r.in.bind_handle	= &priv->bind_handle;
		r.in.level		= &array[i].level;

		switch (*r.in.level) {
		case 5:
			nc.guid	= null_guid;
			nc.sid	= null_sid;
			nc.dn	= priv->domain_obj_dn?priv->domain_obj_dn:"";

			r.in.req.req5.destination_dsa_guid		= GUID_random();
			r.in.req.req5.source_dsa_invocation_id		= null_guid;
			r.in.req.req5.naming_context			= &nc;
			r.in.req.req5.highwatermark.tmp_highest_usn	= 0;
			r.in.req.req5.highwatermark.reserved_usn	= 0;
			r.in.req.req5.highwatermark.highest_usn		= 0;
			r.in.req.req5.uptodateness_vector		= NULL;
			r.in.req.req5.replica_flags			= 0;
			if (lp_parm_bool(-1, "drsuapi", "compression", false)) {
				r.in.req.req5.replica_flags		|= DRSUAPI_DS_REPLICA_NEIGHBOUR_COMPRESS_CHANGES;
			}
			r.in.req.req5.max_object_count			= 0;
			r.in.req.req5.max_ndr_size			= 0;
			r.in.req.req5.unknown4				= 0;
			r.in.req.req5.h1				= 0;

			break;
		case 8:
			nc.guid	= null_guid;
			nc.sid	= null_sid;
			nc.dn	= priv->domain_obj_dn?priv->domain_obj_dn:"";

			r.in.req.req8.destination_dsa_guid		= GUID_random();
			r.in.req.req8.source_dsa_invocation_id		= null_guid;
			r.in.req.req8.naming_context			= &nc;
			r.in.req.req8.highwatermark.tmp_highest_usn	= 0;
			r.in.req.req8.highwatermark.reserved_usn	= 0;
			r.in.req.req8.highwatermark.highest_usn		= 0;
			r.in.req.req8.uptodateness_vector		= NULL;
			r.in.req.req8.replica_flags			= 0;
			if (lp_parm_bool(-1, "drsuapi", "compression", false)) {
				r.in.req.req8.replica_flags		|= DRSUAPI_DS_REPLICA_NEIGHBOUR_COMPRESS_CHANGES;
			}
			if (lp_parm_bool(-1, "drsuapi", "neighbour_writeable",true)) {
				r.in.req.req8.replica_flags		|= DRSUAPI_DS_REPLICA_NEIGHBOUR_WRITEABLE;
			}
			r.in.req.req8.replica_flags			|= DRSUAPI_DS_REPLICA_NEIGHBOUR_SYNC_ON_STARTUP
									| DRSUAPI_DS_REPLICA_NEIGHBOUR_DO_SCHEDULED_SYNCS
									| DRSUAPI_DS_REPLICA_NEIGHBOUR_RETURN_OBJECT_PARENTS
									| DRSUAPI_DS_REPLICA_NEIGHBOUR_NEVER_SYNCED
									;
			r.in.req.req8.max_object_count			= 402;
			r.in.req.req8.max_ndr_size			= 402116;
			r.in.req.req8.unknown4				= 0;
			r.in.req.req8.h1				= 0;
			r.in.req.req8.unique_ptr1			= 0;
			r.in.req.req8.unique_ptr2			= 0;
			r.in.req.req8.mapping_ctr.num_mappings		= 0;
			r.in.req.req8.mapping_ctr.mappings		= NULL;

			break;
		}

		status = dcerpc_drsuapi_DsGetNCChanges(p, tctx, &r);
		torture_assert_ntstatus_ok(tctx, status, 
			"dcerpc_drsuapi_DsGetNCChanges failed");
		torture_assert_werr_ok(tctx, r.out.result, 
				       "DsGetNCChanges failed");
	}

	return true;
}

bool test_QuerySitesByCost(struct torture_context *tctx, struct dcerpc_pipe *p, 
			   struct DsPrivate *priv)
{
	NTSTATUS status;
	struct drsuapi_QuerySitesByCost r;

	const char *my_site = "Default-First-Site-Name";
	const char *remote_site1 = "smbtorture-nonexisting-site1";
	const char *remote_site2 = "smbtorture-nonexisting-site2";

	r.in.bind_handle = &priv->bind_handle;
	r.in.level = 1;
	r.in.req.req1.site_from = talloc_strdup(tctx, my_site);
	r.in.req.req1.num_req = 2;
	r.in.req.req1.site_to = talloc_zero_array(tctx, const char *, r.in.req.req1.num_req);
	r.in.req.req1.site_to[0] = talloc_strdup(tctx, remote_site1);
	r.in.req.req1.site_to[1] = talloc_strdup(tctx, remote_site2);
	r.in.req.req1.flags = 0;

	status = dcerpc_drsuapi_QuerySitesByCost(p, tctx, &r);
	torture_assert_ntstatus_ok(tctx, status, "drsuapi_QuerySitesByCost");
	torture_assert_werr_ok(tctx, r.out.result, "QuerySitesByCost failed");

	torture_assert_werr_equal(tctx, r.out.ctr.ctr1.info[0].error_code, 
				  WERR_DS_OBJ_NOT_FOUND, "expected not found error");
	torture_assert_werr_equal(tctx, r.out.ctr.ctr1.info[1].error_code, 
				  WERR_DS_OBJ_NOT_FOUND, "expected not found error");

	torture_assert_int_equal(tctx, r.out.ctr.ctr1.info[0].site_cost,
				 (uint32_t) -1, "unexpected site cost");
	  
	torture_assert_int_equal(tctx, r.out.ctr.ctr1.info[1].site_cost, 
				 (uint32_t) -1, "unexpected site cost");

	return true;
}

struct torture_suite *torture_rpc_drsuapi(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "DRSUAPI");
	struct torture_test *test;
	struct torture_rpc_tcase *tcase = torture_suite_add_machine_rpc_iface_tcase(suite, "drsuapi", 
									    &ndr_table_drsuapi, TEST_MACHINE_NAME);

	torture_rpc_tcase_add_drsuapi_test(tcase, "QuerySitesByCost", test_QuerySitesByCost);
	torture_rpc_tcase_add_drsuapi_test(tcase, "DsGetDomainControllerInfo", test_DsGetDomainControllerInfo);
	torture_rpc_tcase_add_drsuapi_test(tcase, "DsCrackNames", test_DsCrackNames);
	torture_rpc_tcase_add_drsuapi_test(tcase, "DsWriteAccountSpn", test_DsWriteAccountSpn);
	torture_rpc_tcase_add_drsuapi_test(tcase, "DsReplicaGetInfo", test_DsReplicaGetInfo);
	test = torture_rpc_tcase_add_drsuapi_test(tcase, "DsReplicaSync", test_DsReplicaSync);
	test->dangerous = true;
	torture_rpc_tcase_add_drsuapi_test(tcase, "DsReplicaUpdateRefs", test_DsReplicaUpdateRefs);
	torture_rpc_tcase_add_drsuapi_test(tcase, "DsGetNCChange", test_DsGetNCChanges);

	return suite;
}

struct torture_suite *torture_rpc_drsuapi_cracknames(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "CRACKNAMES");
	struct torture_rpc_tcase *tcase = torture_suite_add_machine_rpc_iface_tcase(suite, "drsuapi", 
									    &ndr_table_drsuapi, TEST_MACHINE_NAME);

	torture_rpc_tcase_add_drsuapi_test(tcase, "DsGetDomainControllerInfo", test_DsGetDomainControllerInfo);
	torture_rpc_tcase_add_drsuapi_test(tcase, "DsCrackNames", test_DsCrackNames);

	return suite;
}

