/* 
   Unix SMB/CIFS implementation.

   utility code to join/leave a domain

   Copyright (C) Andrew Tridgell 2004
   
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

/*
  this code is used by other torture modules to join/leave a domain
  as either a member, bdc or thru a trust relationship
*/

#include "includes.h"
#include "librpc/gen_ndr/ndr_samr.h"

struct test_join {
	struct dcerpc_pipe *p;
	const char *machine_password;
	struct policy_handle user_handle;
};


static NTSTATUS DeleteUser_byname(struct dcerpc_pipe *p, TALLOC_CTX *mem_ctx, 
				  struct policy_handle *handle, const char *name)
{
	NTSTATUS status;
	struct samr_DeleteUser d;
	struct policy_handle user_handle;
	uint32_t rid;
	struct samr_LookupNames n;
	struct samr_String sname;
	struct samr_OpenUser r;

	sname.string = name;

	n.in.domain_handle = handle;
	n.in.num_names = 1;
	n.in.names = &sname;

	status = dcerpc_samr_LookupNames(p, mem_ctx, &n);
	if (NT_STATUS_IS_OK(status)) {
		rid = n.out.rids.ids[0];
	} else {
		return status;
	}

	r.in.domain_handle = handle;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.in.rid = rid;
	r.out.user_handle = &user_handle;

	status = dcerpc_samr_OpenUser(p, mem_ctx, &r);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenUser(%s) failed - %s\n", name, nt_errstr(status));
		return status;
	}

	d.in.user_handle = &user_handle;
	d.out.user_handle = &user_handle;
	status = dcerpc_samr_DeleteUser(p, mem_ctx, &d);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

/*
  join the domain as a test machine
  an opaque pointer is returned. Pass it to torture_leave_domain() 
  when finished
*/
struct test_join *torture_join_domain(const char *machine_name, 
				      const char *domain,
				      uint16 acct_flags,
				      const char **machine_password)
{
	NTSTATUS status;
	struct samr_Connect c;
	struct samr_CreateUser2 r;
	struct samr_OpenDomain o;
	struct samr_LookupDomain l;
	struct samr_GetUserPwInfo pwp;
	struct samr_SetUserInfo s;
	union samr_UserInfo u;
	struct policy_handle handle;
	struct policy_handle domain_handle;
	uint32_t access_granted;
	uint32_t rid;
	DATA_BLOB session_key;
	struct samr_String name;
	int policy_min_pw_len = 0;
	struct test_join *join;

	join = talloc_p(NULL, struct test_join);
	if (join == NULL) {
		return NULL;
	}

	ZERO_STRUCTP(join);

	printf("Connecting to SAMR\n");

	status = torture_rpc_connection(&join->p, 
					DCERPC_SAMR_NAME,
					DCERPC_SAMR_UUID,
					DCERPC_SAMR_VERSION);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	c.in.system_name = NULL;
	c.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	c.out.connect_handle = &handle;

	status = dcerpc_samr_Connect(join->p, join, &c);
	if (!NT_STATUS_IS_OK(status)) {
		const char *errstr = nt_errstr(status);
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			errstr = dcerpc_errstr(join, join->p->last_fault_code);
		}
		printf("samr_Connect failed - %s\n", errstr);
		goto failed;
	}

	printf("Opening domain %s\n", domain);

	name.string = domain;
	l.in.connect_handle = &handle;
	l.in.domain = &name;

	status = dcerpc_samr_LookupDomain(join->p, join, &l);
	if (!NT_STATUS_IS_OK(status)) {
		printf("LookupDomain failed - %s\n", nt_errstr(status));
		goto failed;
	}

	o.in.connect_handle = &handle;
	o.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	o.in.sid = l.out.sid;
	o.out.domain_handle = &domain_handle;

	status = dcerpc_samr_OpenDomain(join->p, join, &o);
	if (!NT_STATUS_IS_OK(status)) {
		printf("OpenDomain failed - %s\n", nt_errstr(status));
		goto failed;
	}

	printf("Creating machine account %s\n", machine_name);

again:
	name.string = talloc_asprintf(join, "%s$", machine_name);
	r.in.domain_handle = &domain_handle;
	r.in.account_name = &name;
	r.in.acct_flags = acct_flags;
	r.in.access_mask = SEC_RIGHTS_MAXIMUM_ALLOWED;
	r.out.user_handle = &join->user_handle;
	r.out.access_granted = &access_granted;
	r.out.rid = &rid;

	status = dcerpc_samr_CreateUser2(join->p, join, &r);

	if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
		status = DeleteUser_byname(join->p, join, &domain_handle, name.string);
		if (NT_STATUS_IS_OK(status)) {
			goto again;
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		printf("CreateUser2 failed - %s\n", nt_errstr(status));
		goto failed;
	}

	pwp.in.user_handle = &join->user_handle;

	status = dcerpc_samr_GetUserPwInfo(join->p, join, &pwp);
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = pwp.out.info.min_password_length;
	}

	join->machine_password = generate_random_str(join, MAX(8, policy_min_pw_len));

	printf("Setting machine account password '%s'\n", join->machine_password);

	s.in.user_handle = &join->user_handle;
	s.in.info = &u;
	s.in.level = 24;

	encode_pw_buffer(u.info24.password.data, join->machine_password, STR_UNICODE);
	u.info24.pw_len = strlen(join->machine_password);

	status = dcerpc_fetch_session_key(join->p, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo level %u - no session key - %s\n",
		       s.in.level, nt_errstr(status));
		torture_leave_domain(join);
		goto failed;
	}

	arcfour_crypt_blob(u.info24.password.data, 516, &session_key);

	status = dcerpc_samr_SetUserInfo(join->p, join, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo failed - %s\n", nt_errstr(status));
		goto failed;
	}

	s.in.user_handle = &join->user_handle;
	s.in.info = &u;
	s.in.level = 16;

	u.info16.acct_flags = acct_flags;

	printf("Resetting ACB flags\n");

	status = dcerpc_samr_SetUserInfo(join->p, join, &s);
	if (!NT_STATUS_IS_OK(status)) {
		printf("SetUserInfo failed - %s\n", nt_errstr(status));
		goto failed;
	}

	if (machine_password) {
		*machine_password = join->machine_password;
	}

	return join;

failed:
	torture_leave_domain(join);
	return NULL;
}

struct dcerpc_pipe *torture_join_samr_pipe(struct test_join *join) 
{
	return join->p;
}

/*
  leave the domain, deleting the machine acct
*/
void torture_leave_domain(struct test_join *join)
{
	struct samr_DeleteUser d;
	NTSTATUS status;

	if (!GUID_all_zero(&join->user_handle.uuid)) {
		d.in.user_handle = &join->user_handle;
		d.out.user_handle = &join->user_handle;
		
		status = dcerpc_samr_DeleteUser(join->p, join, &d);
		if (!NT_STATUS_IS_OK(status)) {
			printf("Delete of machine account failed\n");
		}
	}

	if (join->p) {
		torture_rpc_close(join->p);
	}

	talloc_free(join);
}


struct test_join_ads_dc {
	struct test_join *join;
};

struct test_join_ads_dc *torture_join_domain_ads_dc(const char *machine_name, 
						    const char *domain,
						    const char **machine_password)
{
	struct test_join_ads_dc *join;

	join = talloc_p(NULL, struct test_join_ads_dc);
	if (join == NULL) {
		return NULL;
	}

	join->join = torture_join_domain(machine_name, domain,
					ACB_SVRTRUST,
					machine_password);

	if (!join->join) {
		return NULL;
	}

	/* do netlogon DrsEnumerateDomainTrusts */

	/* modify userAccountControl from 4096 to 532480 */
	
	/* modify RDN to OU=Domain Controllers and skip the $ from server name */

	/* ask objectVersion of Schema Partition */

	/* ask rIDManagerReferenz of the Domain Partition */

	/* ask fsMORoleOwner of the RID-Manager$ object
	 * returns CN=NTDS Settings,CN=<DC>,CN=Servers,CN=Default-First-Site-Name, ...
	 */

	/* ask for dnsHostName of CN=<DC>,CN=Servers,CN=Default-First-Site-Name, ... */

	/* ask for objectGUID of CN=NTDS Settings,CN=<DC>,CN=Servers,CN=Default-First-Site-Name, ... */

	/* ask for * of CN=Default-First-Site-Name, ... */

	/* search (&(|(objectClass=user)(objectClass=computer))(sAMAccountName=<machine_name>$)) in Domain Partition 
	 * attributes : distinguishedName, userAccountControl
	 */

	/* ask * for CN=<machine_name>,CN=Servers,CN=Default-First-Site-Name,... 
	 * should fail with noSuchObject
	 */

	/* add CN=<machine_name>,CN=Servers,CN=Default-First-Site-Name,... 
	 *
	 * objectClass = server
	 * systemFlags = 50000000
	 * serverReferenz = CN=<machine_name>,OU=Domain Controllers,...
	 */

	/* ask for * of CN=NTDS Settings,CN=<machine_name>,CN=Servers,CN=Default-First-Site-Name, ...
	 * should fail with noSuchObject
	 */

	/* search for (ncname=<domain_nc>) in CN=Partitions,CN=Configuration,... 
	 * attributes: ncName, dnsRoot
	 */

	/* modify add CN=<machine_name>,CN=Servers,CN=Default-First-Site-Name,...
	 * serverReferenz = CN=<machine_name>,OU=Domain Controllers,...
	 * should fail with attributeOrValueExists
	 */

	/* modify replace CN=<machine_name>,CN=Servers,CN=Default-First-Site-Name,...
	 * serverReferenz = CN=<machine_name>,OU=Domain Controllers,...
	 */

	/* DsReplicaAdd to create the CN=NTDS Settings,CN=<machine_name>,CN=Servers,CN=Default-First-Site-Name, ...
	 * needs to be tested
	 */

	return join;
}
		
void torture_leave_domain_ads_dc(struct test_join_ads_dc *join)
{

	if (join->join) {
		torture_leave_domain(join->join);
	}

	talloc_free(join);
}
