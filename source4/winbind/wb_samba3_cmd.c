/* 
   Unix SMB/CIFS implementation.
   Main winbindd samba3 server routines

   Copyright (C) Stefan Metzmacher	2005
   Copyright (C) Volker Lendecke	2005
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005

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
#include "nsswitch/winbind_nss_config.h"
#include "nsswitch/winbindd_nss.h"
#include "winbind/wb_server.h"
#include "winbind/wb_async_helpers.h"
#include "winbind/wb_helper.h"
#include "libcli/composite/composite.h"
#include "version.h"
#include "librpc/gen_ndr/netlogon.h"
#include "libcli/security/security.h"
#include "auth/pam_errors.h"

/* 
   Send off the reply to an async Samba3 query, handling filling in the PAM, NTSTATUS and string errors.
*/

static void wbsrv_samba3_async_auth_epilogue(NTSTATUS status,
					     struct wbsrv_samba3_call *s3call)
{
	struct winbindd_response *resp = &s3call->response;
	if (!NT_STATUS_IS_OK(status)) {
		resp->result = WINBINDD_ERROR;
		WBSRV_SAMBA3_SET_STRING(resp->data.auth.nt_status_string,
					nt_errstr(status));
		WBSRV_SAMBA3_SET_STRING(resp->data.auth.error_string,
					get_friendly_nt_error_msg(status));
	} else {
		resp->result = WINBINDD_OK;
	}

	resp->data.auth.pam_error = nt_status_to_pam(status);
	resp->data.auth.nt_status = NT_STATUS_V(status);

	wbsrv_samba3_send_reply(s3call);
}

/* 
   Send of a generic reply to a Samba3 query
*/

static void wbsrv_samba3_async_epilogue(NTSTATUS status,
					struct wbsrv_samba3_call *s3call)
{
	struct winbindd_response *resp = &s3call->response;
	if (NT_STATUS_IS_OK(status)) {
		resp->result = WINBINDD_OK;
	} else {
		resp->result = WINBINDD_ERROR;
	}

	wbsrv_samba3_send_reply(s3call);
}

/* 
   Boilerplate commands, simple queries without network traffic 
*/

NTSTATUS wbsrv_samba3_interface_version(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	s3call->response.data.interface_version	= WINBIND_INTERFACE_VERSION;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_info(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	s3call->response.data.info.winbind_separator = *lp_winbind_separator();
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.info.samba_version,
				SAMBA_VERSION_STRING);
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_domain_name(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.domain_name,
				lp_workgroup());
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_netbios_name(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.netbios_name,
				lp_netbios_name());
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_priv_pipe_dir(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	s3call->response.extra_data.data =
		smbd_tmp_path(s3call, WINBINDD_SAMBA3_PRIVILEGED_SOCKET);
	NT_STATUS_HAVE_NO_MEMORY(s3call->response.extra_data.data);
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_ping(struct wbsrv_samba3_call *s3call)
{
	s3call->response.result			= WINBINDD_OK;
	return NT_STATUS_OK;
}

#if 0
/* 
   Validate that we have a working pipe to the domain controller.
   Return any NT error found in the process
*/

static void checkmachacc_recv_creds(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_check_machacc(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;

	DEBUG(5, ("wbsrv_samba3_check_machacc called\n"));

	ctx = wb_cmd_checkmachacc_send(s3call->call);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = checkmachacc_recv_creds;
	ctx->async.private_data = s3call;
	s3call->call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}
	
static void checkmachacc_recv_creds(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	NTSTATUS status;

	status = wb_cmd_checkmachacc_recv(ctx);

	wbsrv_samba3_async_auth_epilogue(status, s3call);
}
#endif

/*
  Find the name of a suitable domain controller, by query on the
  netlogon pipe to the DC.  
*/

static void getdcname_recv_dc(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_getdcname(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct wbsrv_service *service =
		s3call->wbconn->listen_socket->service;

	DEBUG(5, ("wbsrv_samba3_getdcname called\n"));

	ctx = wb_cmd_getdcname_send(s3call, service,
				    s3call->request.domain_name);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = getdcname_recv_dc;
	ctx->async.private_data = s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}

static void getdcname_recv_dc(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	const char *dcname;
	NTSTATUS status;

	status = wb_cmd_getdcname_recv(ctx, s3call, &dcname);
	if (!NT_STATUS_IS_OK(status)) goto done;

	s3call->response.result = WINBINDD_OK;
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.dc_name, dcname);

 done:
	wbsrv_samba3_async_epilogue(status, s3call);
}

/* 
   Lookup a user's domain groups
*/

static void userdomgroups_recv_groups(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_userdomgroups(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct dom_sid *sid;

	DEBUG(5, ("wbsrv_samba3_userdomgroups called\n"));

	sid = dom_sid_parse_talloc(s3call, s3call->request.data.sid);
	if (sid == NULL) {
		DEBUG(5, ("Could not parse sid %s\n",
			  s3call->request.data.sid));
		return NT_STATUS_NO_MEMORY;
	}

	ctx = wb_cmd_userdomgroups_send(
		s3call, s3call->wbconn->listen_socket->service, sid);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = userdomgroups_recv_groups;
	ctx->async.private_data = s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}

static void userdomgroups_recv_groups(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	int i, num_sids;
	struct dom_sid **sids;
	char *sids_string;
	NTSTATUS status;

	status = wb_cmd_userdomgroups_recv(ctx, s3call, &num_sids, &sids);
	if (!NT_STATUS_IS_OK(status)) goto done;

	sids_string = talloc_strdup(s3call, "");
	if (sids_string == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<num_sids; i++) {
		sids_string = talloc_asprintf_append(
			sids_string, "%s\n", dom_sid_string(s3call, sids[i]));
	}

	if (sids_string == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	s3call->response.result = WINBINDD_OK;
	s3call->response.extra_data.data = sids_string;
	s3call->response.length += strlen(sids_string)+1;
	s3call->response.data.num_entries = num_sids;

 done:
	wbsrv_samba3_async_epilogue(status, s3call);
}

/* 
   Lookup the list of SIDs for a user 
*/
static void usersids_recv_sids(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_usersids(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct dom_sid *sid;

	DEBUG(5, ("wbsrv_samba3_usersids called\n"));

	sid = dom_sid_parse_talloc(s3call, s3call->request.data.sid);
	if (sid == NULL) {
		DEBUG(5, ("Could not parse sid %s\n",
			  s3call->request.data.sid));
		return NT_STATUS_NO_MEMORY;
	}

	ctx = wb_cmd_usersids_send(
		s3call, s3call->wbconn->listen_socket->service, sid);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = usersids_recv_sids;
	ctx->async.private_data = s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}

static void usersids_recv_sids(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	int i, num_sids;
	struct dom_sid **sids;
	char *sids_string;
	NTSTATUS status;

	status = wb_cmd_usersids_recv(ctx, s3call, &num_sids, &sids);
	if (!NT_STATUS_IS_OK(status)) goto done;

	sids_string = talloc_strdup(s3call, "");
	if (sids_string == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<num_sids; i++) {
		sids_string = talloc_asprintf_append(
			sids_string, "%s\n", dom_sid_string(s3call, sids[i]));
		if (sids_string == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

	s3call->response.result = WINBINDD_OK;
	s3call->response.extra_data.data = sids_string;
	s3call->response.length += strlen(sids_string);
	s3call->response.data.num_entries = num_sids;

	/* Hmmmm. Nasty protocol -- who invented the zeros between the
	 * SIDs? Hmmm. Could have been me -- vl */

	while (*sids_string != '\0') {
		if ((*sids_string) == '\n') {
			*sids_string = '\0';
		}
		sids_string += 1;
	}

 done:
	wbsrv_samba3_async_epilogue(status, s3call);
}

/* 
   Lookup a DOMAIN\\user style name, and return a SID
*/

static void lookupname_recv_sid(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_lookupname(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct wbsrv_service *service =
		s3call->wbconn->listen_socket->service;

	DEBUG(5, ("wbsrv_samba3_lookupname called\n"));

	ctx = wb_cmd_lookupname_send(s3call, service,
				     s3call->request.data.name.dom_name,
				     s3call->request.data.name.name);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	/* setup the callbacks */
	ctx->async.fn = lookupname_recv_sid;
	ctx->async.private_data	= s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}

static void lookupname_recv_sid(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	struct wb_sid_object *sid;
	NTSTATUS status;

	status = wb_cmd_lookupname_recv(ctx, s3call, &sid);
	if (!NT_STATUS_IS_OK(status)) goto done;

	s3call->response.result = WINBINDD_OK;
	s3call->response.data.sid.type = sid->type;
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.sid.sid,
				dom_sid_string(s3call, sid->sid));

 done:
	wbsrv_samba3_async_epilogue(status, s3call);
}

/* 
   Lookup a SID, and return a DOMAIN\\user style name
*/

static void lookupsid_recv_name(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_lookupsid(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct wbsrv_service *service =
		s3call->wbconn->listen_socket->service;
	struct dom_sid *sid;

	DEBUG(5, ("wbsrv_samba3_lookupsid called\n"));

	sid = dom_sid_parse_talloc(s3call, s3call->request.data.sid);
	if (sid == NULL) {
		DEBUG(5, ("Could not parse sid %s\n",
			  s3call->request.data.sid));
		return NT_STATUS_NO_MEMORY;
	}

	ctx = wb_cmd_lookupsid_send(s3call, service, sid);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	/* setup the callbacks */
	ctx->async.fn = lookupsid_recv_name;
	ctx->async.private_data	= s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}

static void lookupsid_recv_name(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	struct wb_sid_object *sid;
	NTSTATUS status;

	status = wb_cmd_lookupsid_recv(ctx, s3call, &sid);
	if (!NT_STATUS_IS_OK(status)) goto done;

	s3call->response.result = WINBINDD_OK;
	s3call->response.data.name.type = sid->type;
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.name.dom_name,
				sid->domain);
	WBSRV_SAMBA3_SET_STRING(s3call->response.data.name.name, sid->name);

 done:
	wbsrv_samba3_async_epilogue(status, s3call);
}

/*
  Challenge-response authentication.  This interface is used by
  ntlm_auth and the smbd auth subsystem to pass NTLM authentication
  requests along a common pipe to the domain controller.  

  The return value (in the async reply) may include the 'info3'
  (effectivly most things you would want to know about the user), or
  the NT and LM session keys seperated.
*/

static void pam_auth_crap_recv(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_pam_auth_crap(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct wbsrv_service *service =
		s3call->wbconn->listen_socket->service;
	DATA_BLOB chal, nt_resp, lm_resp;

	DEBUG(5, ("wbsrv_samba3_pam_auth_crap called\n"));

	chal.data       = s3call->request.data.auth_crap.chal;
	chal.length     = sizeof(s3call->request.data.auth_crap.chal);
	nt_resp.data    = (uint8_t *)s3call->request.data.auth_crap.nt_resp;
	nt_resp.length  = s3call->request.data.auth_crap.nt_resp_len;
	lm_resp.data    = (uint8_t *)s3call->request.data.auth_crap.lm_resp;
	lm_resp.length  = s3call->request.data.auth_crap.lm_resp_len;

	ctx = wb_cmd_pam_auth_crap_send(
		s3call, service,
		s3call->request.data.auth_crap.logon_parameters,
		s3call->request.data.auth_crap.domain,
		s3call->request.data.auth_crap.user,
		s3call->request.data.auth_crap.workstation,
		chal, nt_resp, lm_resp);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = pam_auth_crap_recv;
	ctx->async.private_data = s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}

static void pam_auth_crap_recv(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	NTSTATUS status;
	DATA_BLOB info3;
	struct netr_UserSessionKey user_session_key;
	struct netr_LMSessionKey lm_key;
	char *unix_username;
	
	status = wb_cmd_pam_auth_crap_recv(ctx, s3call, &info3,
					   &user_session_key, &lm_key, &unix_username);
	if (!NT_STATUS_IS_OK(status)) goto done;

	if (s3call->request.flags & WBFLAG_PAM_USER_SESSION_KEY) {
		memcpy(s3call->response.data.auth.user_session_key, 
		       &user_session_key.key,
		       sizeof(s3call->response.data.auth.user_session_key));
	}

	if (s3call->request.flags & WBFLAG_PAM_INFO3_NDR) {
		s3call->response.extra_data.data = info3.data;
		s3call->response.length += info3.length;
	}

	if (s3call->request.flags & WBFLAG_PAM_LMKEY) {
		memcpy(s3call->response.data.auth.first_8_lm_hash, 
		       lm_key.key,
		       sizeof(s3call->response.data.auth.first_8_lm_hash));
	}
	
	if (s3call->request.flags & WBFLAG_PAM_UNIX_NAME) {
		s3call->response.extra_data.data = unix_username;
		s3call->response.length += strlen(unix_username)+1;
	}

 done:
	wbsrv_samba3_async_auth_epilogue(status, s3call);
}

/* Plaintext authentication 
   
   This interface is used by ntlm_auth in it's 'basic' authentication
   mode, as well as by pam_winbind to authenticate users where we are
   given a plaintext password.
*/

static void pam_auth_recv(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_pam_auth(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct wbsrv_service *service =
		s3call->wbconn->listen_socket->service;
	char *user, *domain;

	if (!wb_samba3_split_username(s3call,
				 s3call->request.data.auth.user,
				 &domain, &user)) {
		return NT_STATUS_NO_SUCH_USER;
	}

	ctx = wb_cmd_pam_auth_send(s3call, service, domain, user,
				   s3call->request.data.auth.pass);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = pam_auth_recv;
	ctx->async.private_data = s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}

static void pam_auth_recv(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	NTSTATUS status;

	status = wb_cmd_pam_auth_recv(ctx);

	if (!NT_STATUS_IS_OK(status)) goto done;

 done:
	wbsrv_samba3_async_auth_epilogue(status, s3call);
}

/* 
   List trusted domains
*/

static void list_trustdom_recv_doms(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_list_trustdom(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct wbsrv_service *service =
		s3call->wbconn->listen_socket->service;

	DEBUG(5, ("wbsrv_samba3_list_trustdom called\n"));

	ctx = wb_cmd_list_trustdoms_send(s3call, service);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = list_trustdom_recv_doms;
	ctx->async.private_data = s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}

static void list_trustdom_recv_doms(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	int i, num_domains;
	struct wb_dom_info **domains;
	NTSTATUS status;
	char *result;

	status = wb_cmd_list_trustdoms_recv(ctx, s3call, &num_domains,
					    &domains);
	if (!NT_STATUS_IS_OK(status)) goto done;

	result = talloc_strdup(s3call, "");
	if (result == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<num_domains; i++) {
		result = talloc_asprintf_append(
			result, "%s\\%s\\%s",
			domains[i]->name, domains[i]->name,
			dom_sid_string(s3call, domains[i]->sid));
	}

	if (result == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	s3call->response.result = WINBINDD_OK;
	if (num_domains > 0) {
		s3call->response.extra_data.data = result;
		s3call->response.length += strlen(result)+1;
	}

 done:
	wbsrv_samba3_async_epilogue(status, s3call);
}

/* NSS calls */

static void getpwnam_recv(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_getpwnam(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct wbsrv_service *service =
		s3call->wbconn->listen_socket->service;

	DEBUG(5, ("wbsrv_samba3_getpwnam called\n"));

	ctx = wb_cmd_getpwnam_send(s3call, service,
			s3call->request.data.username);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = getpwnam_recv;
	ctx->async.private_data = s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;
}

static void getpwnam_recv(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	NTSTATUS status;
	struct winbindd_pw *pw;

	DEBUG(5, ("getpwnam_recv called\n"));

	status = wb_cmd_getpwnam_recv(ctx, s3call, &pw);
	if(NT_STATUS_IS_OK(status))
		s3call->response.data.pw = *pw;

	wbsrv_samba3_async_epilogue(status, s3call);
}

NTSTATUS wbsrv_samba3_getpwuid(struct wbsrv_samba3_call *s3call)
{
	DEBUG(5, ("wbsrv_samba3_getpwuid called\n"));
	s3call->response.result = WINBINDD_ERROR;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_setpwent(struct wbsrv_samba3_call *s3call)
{
	DEBUG(5, ("wbsrv_samba3_setpwent called\n"));
	s3call->response.result = WINBINDD_OK;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_getpwent(struct wbsrv_samba3_call *s3call)
{
	DEBUG(5, ("wbsrv_samba3_getpwent called\n"));
	s3call->response.result = WINBINDD_ERROR;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_endpwent(struct wbsrv_samba3_call *s3call)
{
	DEBUG(5, ("wbsrv_samba3_endpwent called\n"));
	s3call->response.result = WINBINDD_OK;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_getgrnam(struct wbsrv_samba3_call *s3call)
{
	DEBUG(5, ("wbsrv_samba3_getgrnam called\n"));
	s3call->response.result = WINBINDD_ERROR;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_getgrgid(struct wbsrv_samba3_call *s3call)
{
	DEBUG(5, ("wbsrv_samba3_getgrgid called\n"));
	s3call->response.result = WINBINDD_ERROR;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_getgroups(struct wbsrv_samba3_call *s3call)
{
	DEBUG(5, ("wbsrv_samba3_getgroups called\n"));
	s3call->response.result = WINBINDD_ERROR;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_setgrent(struct wbsrv_samba3_call *s3call)
{
	DEBUG(5, ("wbsrv_samba3_setgrent called\n"));
	s3call->response.result = WINBINDD_OK;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_getgrent(struct wbsrv_samba3_call *s3call)
{
	DEBUG(5, ("wbsrv_samba3_getgrent called\n"));
	s3call->response.result = WINBINDD_ERROR;
	return NT_STATUS_OK;
}

NTSTATUS wbsrv_samba3_endgrent(struct wbsrv_samba3_call *s3call)
{
	DEBUG(5, ("wbsrv_samba3_endgrent called\n"));
	s3call->response.result = WINBINDD_OK;
	return NT_STATUS_OK;
}

static void sid2uid_recv(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_sid2uid(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct wbsrv_service *service =
		s3call->wbconn->listen_socket->service;
	struct dom_sid *sid;

	DEBUG(1, ("wbsrv_samba3_sid2uid called\n"));

	sid = dom_sid_parse_talloc(s3call, s3call->request.data.sid);
	NT_STATUS_HAVE_NO_MEMORY(sid);

	ctx = wb_sid2uid_send(s3call, service, sid);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = sid2uid_recv;
	ctx->async.private_data = s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;

}

static void sid2uid_recv(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	NTSTATUS status;

	DEBUG(1, ("sid2uid_recv called\n"));

	status = wb_sid2uid_recv(ctx, &s3call->response.data.uid);

	wbsrv_samba3_async_epilogue(status, s3call);
}

static void sid2gid_recv(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_sid2gid(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct wbsrv_service *service =
		s3call->wbconn->listen_socket->service;
	struct dom_sid *sid;

	DEBUG(1, ("wbsrv_samba3_sid2gid called\n"));

	sid = dom_sid_parse_talloc(s3call, s3call->request.data.sid);
	NT_STATUS_HAVE_NO_MEMORY(sid);

	ctx = wb_sid2gid_send(s3call, service, sid);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = sid2gid_recv;
	ctx->async.private_data = s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;

}

static void sid2gid_recv(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	NTSTATUS status;

	DEBUG(1, ("sid2gid_recv called\n"));

	status = wb_sid2gid_recv(ctx, &s3call->response.data.gid);

	wbsrv_samba3_async_epilogue(status, s3call);
}

static void uid2sid_recv(struct composite_context *ctx);

NTSTATUS wbsrv_samba3_uid2sid(struct wbsrv_samba3_call *s3call)
{
	struct composite_context *ctx;
	struct wbsrv_service *service =
		s3call->wbconn->listen_socket->service;

	DEBUG(5, ("wbsrv_samba3_uid2sid called\n"));

	ctx = wb_uid2sid_send(s3call, service, s3call->request.data.uid);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	ctx->async.fn = uid2sid_recv;
	ctx->async.private_data = s3call;
	s3call->flags |= WBSRV_CALL_FLAGS_REPLY_ASYNC;
	return NT_STATUS_OK;

}

static void uid2sid_recv(struct composite_context *ctx)
{
	struct wbsrv_samba3_call *s3call =
		talloc_get_type(ctx->async.private_data,
				struct wbsrv_samba3_call);
	NTSTATUS status;
	struct dom_sid *sid;
	char *sid_str;

	DEBUG(5, ("uid2sid_recv called\n"));

	status = wb_uid2sid_recv(ctx, s3call, &sid);
	if(NT_STATUS_IS_OK(status)) {
		sid_str = dom_sid_string(s3call, sid);

		/* If the conversion failed, bail out with a failure. */
		if (sid_str == NULL)
			wbsrv_samba3_async_epilogue(NT_STATUS_NO_MEMORY,s3call);

		/* But we assume this worked, so we'll set the string. Work
		 * done. */
		WBSRV_SAMBA3_SET_STRING(s3call->response.data.sid.sid, sid_str);
		s3call->response.data.sid.type = SID_NAME_USER;
	}

	wbsrv_samba3_async_epilogue(status, s3call);
}

