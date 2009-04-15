/* 
   Unix SMB/CIFS implementation.
   test suite for accessmasks on the SAMR pipe

   Copyright (C) Ronnie Sahlberg 2007
   
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
#include "librpc/gen_ndr/ndr_samr_c.h"
#include "torture/rpc/rpc.h"
#include "param/param.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"


/* test user created to test the ACLs associated to SAMR objects */
#define TEST_USER_NAME "samr_testuser"


static NTSTATUS torture_samr_Close(struct torture_context *tctx,
		struct dcerpc_pipe *p, 
		struct policy_handle *h)
{
	NTSTATUS status;
	struct samr_Close cl;

	cl.in.handle  = h;
	cl.out.handle = h;
	status = dcerpc_samr_Close(p, tctx, &cl);

	return status;
}

static NTSTATUS torture_samr_Connect5(struct torture_context *tctx,
		struct dcerpc_pipe *p, 
		uint32_t mask, struct policy_handle *h)
{
	NTSTATUS status;
	struct samr_Connect5 r5;
	union samr_ConnectInfo info;
	uint32_t level_out = 0;

	info.info1.client_version = 0;
	info.info1.unknown2 = 0;
	r5.in.system_name = "";
	r5.in.level_in = 1;
	r5.in.info_in = &info;
	r5.out.info_out = &info;
	r5.out.level_out = &level_out;
	r5.out.connect_handle = h;
	r5.in.access_mask = mask;

	status = dcerpc_samr_Connect5(p, tctx, &r5);

	return status;
}

/* check which bits in accessmask allows us to connect to the server */
static bool test_samr_accessmask_Connect5(struct torture_context *tctx, 
						   struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct policy_handle h;
	int i;
	uint32_t mask;

	printf("testing which bits in accessmask allows us to connect\n");
	mask = 1;
	for (i=0;i<33;i++) {	
		printf("testing Connect5 with access mask 0x%08x", mask);
		status = torture_samr_Connect5(tctx, p, mask, &h);
		mask <<= 1;

		switch (i) {
		case 6:
		case 7:
		case 8:
		case 9:
		case 10:
		case 11:
		case 12:
		case 13:
		case 14:
		case 15:
		case 20:
		case 21:
		case 22:
		case 23:
		case 26:
		case 27:
			printf(" expecting to fail");
			/* of only one of these bits are set we expect to
			   fail by default
			*/
			if(!NT_STATUS_EQUAL(NT_STATUS_ACCESS_DENIED, status)) {
				printf("Connect5 failed - %s\n", nt_errstr(status));
				return false;
			}
			break;
		default:
			/* these bits set are expected to succeed by default */
			if (!NT_STATUS_IS_OK(status)) {
				printf("Connect5 failed - %s\n", nt_errstr(status));
				return false;
			}

			status = torture_samr_Close(tctx, p, &h);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Close failed - %s\n", nt_errstr(status));
				return false;
			}
			break;
		}
		printf(" OK\n");
	}

	return true;
}

/* check which bits in accessmask allows us to EnumDomains()
   by default we must specify at least one of :
	SAMR/EnumDomains
	Maximum
	GenericAll
	GenericRead
   in the access mask to Connect5() in order to be allowed to perform
   EnumDomains() on the policy handle returned from Connect5()
*/
static bool test_samr_accessmask_EnumDomains(struct torture_context *tctx, 
						   struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct samr_EnumDomains ed;
	struct policy_handle ch;
	int i;
	uint32_t mask;
	uint32_t resume_handle = 0;
	struct samr_SamArray *sam = NULL;
	uint32_t num_entries = 0;

	printf("testing which bits in Connect5 accessmask allows us to EnumDomains\n");
	mask = 1;
	for (i=0;i<33;i++) {	
		printf("testing Connect5/EnumDomains with access mask 0x%08x", mask);
		status = torture_samr_Connect5(tctx, p, mask, &ch);
		mask <<= 1;

		switch (i) {
		case 4:	 /* SAMR/EnumDomains */
		case 25: /* Maximum */
		case 28: /* GenericAll */
		case 31: /* GenericRead */
			/* these bits set are expected to succeed by default */
			if (!NT_STATUS_IS_OK(status)) {
				printf("Connect5 failed - %s\n", nt_errstr(status));
				return false;
			}

			ed.in.connect_handle = &ch;
			ed.in.resume_handle = &resume_handle;
			ed.in.buf_size = (uint32_t)-1;
			ed.out.resume_handle = &resume_handle;
			ed.out.num_entries = &num_entries;
			ed.out.sam = &sam;

			status = dcerpc_samr_EnumDomains(p, tctx, &ed);
			if (!NT_STATUS_IS_OK(status)) {
				printf("EnumDomains failed - %s\n", nt_errstr(status));
				return false;
			}

			status = torture_samr_Close(tctx, p, &ch);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Close failed - %s\n", nt_errstr(status));
				return false;
			}
			break;
		default:
			printf(" expecting to fail");

			if (!NT_STATUS_IS_OK(status)) {
				printf(" OK\n");
				continue;
			}

			ed.in.connect_handle = &ch;
			ed.in.resume_handle = &resume_handle;
			ed.in.buf_size = (uint32_t)-1;
			ed.out.resume_handle = &resume_handle;
			ed.out.num_entries = &num_entries;
			ed.out.sam = &sam;

			status = dcerpc_samr_EnumDomains(p, tctx, &ed);
			if(!NT_STATUS_EQUAL(NT_STATUS_ACCESS_DENIED, status)) {
				printf("EnumDomains failed - %s\n", nt_errstr(status));
				return false;
			}

			status = torture_samr_Close(tctx, p, &ch);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Close failed - %s\n", nt_errstr(status));
				return false;
			}
			break;
		}
		printf(" OK\n");
	}

	return true;
}


/*
 * test how ACLs affect how/if a user can connect to the SAMR service 
 *
 * samr_SetSecurity() returns SUCCESS when changing the ACL for
 * a policy handle got from Connect5()   but the ACL is not changed on
 * the server
 */
static bool test_samr_connect_user_acl(struct torture_context *tctx, 
				   struct dcerpc_pipe *p,
				   struct cli_credentials *test_credentials,
				   const struct dom_sid *test_sid)

{
	NTSTATUS status;
	struct policy_handle ch;
	struct policy_handle uch;
	struct samr_QuerySecurity qs;
	struct samr_SetSecurity ss;
	struct security_ace ace;
	struct security_descriptor *sd;
	struct sec_desc_buf sdb, *sdbuf = NULL;
	bool ret = true;
	int sd_size;
	struct dcerpc_pipe *test_p;
	const char *binding = torture_setting_string(tctx, "binding", NULL);

	printf("testing ACLs to allow/prevent users to connect to SAMR");

	/* connect to SAMR */
	status = torture_samr_Connect5(tctx, p, SEC_FLAG_MAXIMUM_ALLOWED, &ch);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect5 failed - %s\n", nt_errstr(status));
		return false;
	}

	
	/* get the current ACL for the SAMR policy handle */
	qs.in.handle = &ch;
	qs.in.sec_info = SECINFO_DACL;
	qs.out.sdbuf = &sdbuf;
	status = dcerpc_samr_QuerySecurity(p, tctx, &qs);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecurity failed - %s\n", nt_errstr(status));
		ret = false;
	}

	/* how big is the security descriptor? */
	sd_size = sdbuf->sd_size;


	/* add an ACE to the security descriptor to deny the user the
	 * 'connect to server' right
	 */
	sd = sdbuf->sd;
	ace.type = SEC_ACE_TYPE_ACCESS_DENIED;
	ace.flags = 0;
	ace.access_mask = SAMR_ACCESS_CONNECT_TO_SERVER;
	ace.trustee = *test_sid;
	status = security_descriptor_dacl_add(sd, &ace);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to add ACE to security descriptor\n");
		ret = false;
	}
	ss.in.handle = &ch;
	ss.in.sec_info = SECINFO_DACL;
	ss.in.sdbuf = &sdb;
	sdb.sd = sd;
	status = dcerpc_samr_SetSecurity(p, tctx, &ss);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetSecurity failed - %s\n", nt_errstr(status));
		ret = false;
	}


	/* Try to connect as the test user */
	status = dcerpc_pipe_connect(tctx, 
			     &test_p, binding, &ndr_table_samr,
			     test_credentials, tctx->ev, tctx->lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_pipe_connect failed: %s\n", nt_errstr(status));
		return false;
	}

	/* connect to SAMR as the user */
	status = torture_samr_Connect5(tctx, test_p, SEC_FLAG_MAXIMUM_ALLOWED, &uch);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect5 failed - %s\n", nt_errstr(status));
		return false;
	}
	/* disconnec the user */
	talloc_free(test_p);


	/* read the sequrity descriptor back. it should not have changed 
	 * eventhough samr_SetSecurity returned SUCCESS
	 */
	status = dcerpc_samr_QuerySecurity(p, tctx, &qs);
	if (!NT_STATUS_IS_OK(status)) {
		printf("QuerySecurity failed - %s\n", nt_errstr(status));
		ret = false;
	}
	if (sd_size != sdbuf->sd_size) {
		printf("security descriptor changed\n");
		ret = false;
	}


	status = torture_samr_Close(tctx, p, &ch);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Close failed - %s\n", nt_errstr(status));
		ret = false;
	}

	if (ret == true) {
		printf(" OK\n");
	}
	return ret;
}

/*
 * test if the ACLs are enforced for users.
 * a normal testuser only gets the rights provided in hte ACL for
 * Everyone   which does not include the SAMR_ACCESS_SHUTDOWN_SERVER
 * right.  If the ACLs are checked when a user connects   
 * a testuser that requests the accessmask with only this bit set
 * the connect should fail.
 */
static bool test_samr_connect_user_acl_enforced(struct torture_context *tctx, 
				   struct dcerpc_pipe *p,
				   struct cli_credentials *test_credentials,
				   const struct dom_sid *test_sid)

{
	NTSTATUS status;
	struct policy_handle uch;
	bool ret = true;
	struct dcerpc_pipe *test_p;
	const char *binding = torture_setting_string(tctx, "binding", NULL);

	printf("testing if ACLs are enforced for non domain admin users when connecting to SAMR");


	status = dcerpc_pipe_connect(tctx, 
			     &test_p, binding, &ndr_table_samr,
			     test_credentials, tctx->ev, tctx->lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		printf("dcerpc_pipe_connect failed: %s\n", nt_errstr(status));
		return false;
	}

	/* connect to SAMR as the user */
	status = torture_samr_Connect5(tctx, test_p, SAMR_ACCESS_SHUTDOWN_SERVER, &uch);
	if (NT_STATUS_IS_OK(status)) {
		printf("Connect5 failed - %s\n", nt_errstr(status));
		return false;
	}
	printf(" OK\n");

	/* disconnec the user */
	talloc_free(test_p);

	return ret;
}

/* check which bits in accessmask allows us to LookupDomain()
   by default we must specify at least one of :
   in the access mask to Connect5() in order to be allowed to perform
		case 5:  samr/opendomain
		case 25: Maximum 
		case 28: GenericAll
		case 29: GenericExecute
   LookupDomain() on the policy handle returned from Connect5()
*/
static bool test_samr_accessmask_LookupDomain(struct torture_context *tctx, 
						   struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct samr_LookupDomain ld;
	struct dom_sid2 *sid = NULL;
	struct policy_handle ch;
	struct lsa_String dn;
	int i;
	uint32_t mask;

	printf("testing which bits in Connect5 accessmask allows us to LookupDomain\n");
	mask = 1;
	for (i=0;i<33;i++) {	
		printf("testing Connect5/LookupDomain with access mask 0x%08x", mask);
		status = torture_samr_Connect5(tctx, p, mask, &ch);
		mask <<= 1;

		switch (i) {
		case 5:  
		case 25: /* Maximum */
		case 28: /* GenericAll */
		case 29: /* GenericExecute */
			/* these bits set are expected to succeed by default */
			if (!NT_STATUS_IS_OK(status)) {
				printf("Connect5 failed - %s\n", nt_errstr(status));
				return false;
			}

			ld.in.connect_handle = &ch;
			ld.in.domain_name    = &dn;
			ld.out.sid           = &sid;
			dn.string            = lp_workgroup(tctx->lp_ctx);

			status = dcerpc_samr_LookupDomain(p, tctx, &ld);
			if (!NT_STATUS_IS_OK(status)) {
				printf("LookupDomain failed - %s\n", nt_errstr(status));
				return false;
			}

			status = torture_samr_Close(tctx, p, &ch);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Close failed - %s\n", nt_errstr(status));
				return false;
			}
			break;
		default:
			printf(" expecting to fail");

			if (!NT_STATUS_IS_OK(status)) {
				printf(" OK\n");
				continue;
			}

			ld.in.connect_handle = &ch;
			ld.in.domain_name    = &dn;
			ld.out.sid           = &sid;
			dn.string            = lp_workgroup(tctx->lp_ctx);

			status = dcerpc_samr_LookupDomain(p, tctx, &ld);
			if(!NT_STATUS_EQUAL(NT_STATUS_ACCESS_DENIED, status)) {
				printf("LookupDomain failed - %s\n", nt_errstr(status));
				return false;
			}

			status = torture_samr_Close(tctx, p, &ch);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Close failed - %s\n", nt_errstr(status));
				return false;
			}
			break;
		}
		printf(" OK\n");
	}

	return true;
}

/* check which bits in accessmask allows us to OpenDomain()
   by default we must specify at least one of :
	samr/opendomain
	Maximum 
	GenericAll
	GenericExecute
   in the access mask to Connect5() in order to be allowed to perform
   OpenDomain() on the policy handle returned from Connect5()
*/
static bool test_samr_accessmask_OpenDomain(struct torture_context *tctx, 
						   struct dcerpc_pipe *p)
{
	NTSTATUS status;
	struct samr_LookupDomain ld;
	struct dom_sid2 *sid = NULL;
	struct samr_OpenDomain od;
	struct policy_handle ch;
	struct policy_handle dh;
	struct lsa_String dn;
	int i;
	uint32_t mask;


	/* first we must grab the sid of the domain */
	status = torture_samr_Connect5(tctx, p, SEC_FLAG_MAXIMUM_ALLOWED, &ch);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Connect5 failed - %s\n", nt_errstr(status));
		return false;
	}

	ld.in.connect_handle = &ch;
	ld.in.domain_name    = &dn;
	ld.out.sid           = &sid;
	dn.string            = lp_workgroup(tctx->lp_ctx);
	status = dcerpc_samr_LookupDomain(p, tctx, &ld);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupDomain failed - %s\n", nt_errstr(status));
		return false;
	}



	printf("testing which bits in Connect5 accessmask allows us to OpenDomain\n");
	mask = 1;
	for (i=0;i<33;i++) {	
		printf("testing Connect5/OpenDomain with access mask 0x%08x", mask);
		status = torture_samr_Connect5(tctx, p, mask, &ch);
		mask <<= 1;

		switch (i) {
		case 5:  
		case 25: /* Maximum */
		case 28: /* GenericAll */
		case 29: /* GenericExecute */
			/* these bits set are expected to succeed by default */
			if (!NT_STATUS_IS_OK(status)) {
				printf("Connect5 failed - %s\n", nt_errstr(status));
				return false;
			}

			od.in.connect_handle = &ch;
			od.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
			od.in.sid = sid;
			od.out.domain_handle = &dh;

			status = dcerpc_samr_OpenDomain(p, tctx, &od);
			if (!NT_STATUS_IS_OK(status)) {
				printf("OpenDomain failed - %s\n", nt_errstr(status));
				return false;
			}

			status = torture_samr_Close(tctx, p, &dh);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Close failed - %s\n", nt_errstr(status));
				return false;
			}

			status = torture_samr_Close(tctx, p, &ch);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Close failed - %s\n", nt_errstr(status));
				return false;
			}
			break;
		default:
			printf(" expecting to fail");

			if (!NT_STATUS_IS_OK(status)) {
				printf(" OK\n");
				continue;
			}

			status = torture_samr_Close(tctx, p, &ch);
			if (!NT_STATUS_IS_OK(status)) {
				printf("Close failed - %s\n", nt_errstr(status));
				return false;
			}
			break;
		}
		printf(" OK\n");
	}

	return true;
}

static bool test_samr_connect(struct torture_context *tctx, 
						   struct dcerpc_pipe *p)
{
	void *testuser;
	const char *testuser_passwd;
	struct cli_credentials *test_credentials;
	bool ret = true;
	const struct dom_sid *test_sid;

	/* create a test user */
	testuser = torture_create_testuser(tctx, TEST_USER_NAME, lp_workgroup(tctx->lp_ctx), 
					   ACB_NORMAL, &testuser_passwd);
	if (!testuser) {
		printf("Failed to create test user\n");
		return false;
	}
	test_credentials = cli_credentials_init(tctx);
	cli_credentials_set_workstation(test_credentials, "localhost", CRED_SPECIFIED);
	cli_credentials_set_domain(test_credentials, lp_workgroup(tctx->lp_ctx), 
				   CRED_SPECIFIED);
	cli_credentials_set_username(test_credentials, TEST_USER_NAME, CRED_SPECIFIED);
	cli_credentials_set_password(test_credentials, testuser_passwd, CRED_SPECIFIED);
	test_sid = torture_join_user_sid(testuser);


	/* test which bits in the accessmask to Connect5 
	   will allow us to connect to the server 
	*/
	if (!test_samr_accessmask_Connect5(tctx, p)) {
		ret = false;
	}


	/* test which bits in the accessmask to Connect5 will allow
	 * us to call EnumDomains() 
	 */
	if (!test_samr_accessmask_EnumDomains(tctx, p)) {
		ret = false;
	}

	/* test which bits in the accessmask to Connect5 will allow
	 * us to call LookupDomain()
	 */
	if (!test_samr_accessmask_LookupDomain(tctx, p)) {
		ret = false;
	}


	/* test which bits in the accessmask to Connect5 will allow
	 * us to call OpenDomain()
	 */
	if (!test_samr_accessmask_OpenDomain(tctx, p)) {
		ret = false;
	}

	if (!torture_setting_bool(tctx, "samba3", false)) {

	/* test if ACLs can be changed for the policy handle
	 * returned by Connect5
	 */
	if (!test_samr_connect_user_acl(tctx, p, test_credentials, test_sid)) {
		ret = false;
	}

	/* test if the ACLs that are reported from the Connect5 
	 * policy handle is enforced.
	 * i.e. an ordinary user only has the same rights as Everybody
	 *   ReadControl
	 *   Samr/OpenDomain
	 *   Samr/EnumDomains
	 *   Samr/ConnectToServer
	 * is granted and should therefore not be able to connect when
	 * requesting SAMR_ACCESS_SHUTDOWN_SERVER
	 */
	if (!test_samr_connect_user_acl_enforced(tctx, p, test_credentials, test_sid)) {
		ret = false;
	}

	}

	/* remove the test user */
	torture_leave_domain(tctx, testuser);

	return ret;
}

struct torture_suite *torture_rpc_samr_accessmask(TALLOC_CTX *mem_ctx)
{
	struct torture_suite *suite = torture_suite_create(mem_ctx, "SAMR_ACCESSMASK");
	struct torture_rpc_tcase *tcase;

	tcase = torture_suite_add_rpc_iface_tcase(suite, "samr", 
											  &ndr_table_samr);
	
	torture_rpc_tcase_add_test(tcase, "CONNECT", test_samr_connect);

	return suite;
}
