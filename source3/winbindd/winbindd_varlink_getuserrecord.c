/*
   Unix SMB/CIFS implementation.

   Copyright (C) Samuel Cabrero <scabrero@samba.org> 2023

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "winbindd.h"
#include "lib/util/string_wrappers.h"
#include "winbindd_varlink.h"

static void
user_record_reply(VarlinkCall *call, struct winbindd_pw *pw, bool continues)
{
	VarlinkObject *record = NULL;
	VarlinkObject *out = NULL;
	const char *service_name = NULL;

	service_name = lp_parm_const_string(-1,
					    "winbind varlink",
					    "service name",
					    WB_VL_SERVICE_NAME);

	WB_VL_ERR_CHECK_GOTO(varlink_object_new(&record), err_free_record);
	WB_VL_ERR_CHECK_GOTO(varlink_object_set_string(record, "service", service_name), err_free_record);
	WB_VL_ERR_CHECK_GOTO(varlink_object_set_string(record, "userName", pw->pw_name), err_free_record);
	WB_VL_ERR_CHECK_GOTO(varlink_object_set_int(record, "uid", pw->pw_uid), err_free_record);
	WB_VL_ERR_CHECK_GOTO(varlink_object_set_int(record, "gid", pw->pw_gid), err_free_record);
	if (strlen(pw->pw_dir) > 0) {
		WB_VL_ERR_CHECK_GOTO(varlink_object_set_string(
			record, "homeDirectory", pw->pw_dir), err_free_record);
	}
	if (strlen(pw->pw_shell) > 0) {
		WB_VL_ERR_CHECK_GOTO(varlink_object_set_string(
			record, "shell", pw->pw_shell), err_free_record);
	}
	if (strlen(pw->pw_gecos) > 0) {
		WB_VL_ERR_CHECK_GOTO(varlink_object_set_string(
			record, "realName", pw->pw_gecos), err_free_record);
	}

	WB_VL_ERR_CHECK_GOTO(varlink_object_new(&out), err_free_out);
	WB_VL_ERR_CHECK_GOTO(varlink_object_set_bool(out, "incomplete", false), err_free_out);
	WB_VL_ERR_CHECK_GOTO(varlink_object_set_object(out, "record", record), err_free_out);

	varlink_call_reply(call, out, continues ? VARLINK_REPLY_CONTINUES : 0);
	varlink_object_unref(out);
	return;
err_free_out:
	if (out != NULL) {
		varlink_object_unref(out);
	}
err_free_record:
	if (record != NULL) {
		varlink_object_unref(record);
	}
}

/******************************************************************************
 * User enumeration
 *****************************************************************************/

struct user_enum_state {
	struct tevent_context *ev_ctx;
	struct winbindd_request *fake_req;
	struct winbindd_cli_state *fake_cli;
	VarlinkCall *call;

	struct winbindd_pw *last_pw;
};

static int user_enum_state_destructor(struct user_enum_state *s)
{
	if (s->call != NULL) {
		s->call = varlink_call_unref(s->call);
	}

	vl_active = 0;

	return 0;
}

static void user_enum_endpwent_done(struct tevent_req *req)
{
	struct user_enum_state *s =
		tevent_req_callback_data(req, struct user_enum_state);
	struct winbindd_response *response = NULL;
	NTSTATUS status;

	/* winbindd_*_recv functions expect a talloc-allocated response */
	response = talloc_zero(s, struct winbindd_response);
	if (response == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	status = winbindd_endpwent_recv(req, response);
	TALLOC_FREE(req);

	if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_endpwent failed: %s\n", nt_errstr(status));
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	if (s->last_pw == NULL) {
		varlink_call_reply_error(s->call,
					 WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
					 NULL);
		goto out;
	}

	user_record_reply(s->call, s->last_pw, false);

out:
	TALLOC_FREE(s);
}

static void user_enum_getpwent_done(struct tevent_req *req)
{
	struct user_enum_state *s =
		tevent_req_callback_data(req, struct user_enum_state);
	struct winbindd_response *response = NULL;
	struct winbindd_pw *pws = NULL;
	NTSTATUS status;
	uint32_t i;

	/* winbindd_*_recv functions expect a talloc-allocated response */
	response = talloc_zero(s, struct winbindd_response);
	if (response == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	status = winbindd_getpwent_recv(req, response);
	TALLOC_FREE(req);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
		ZERO_STRUCTP(s->fake_req);
		s->fake_req->cmd = WINBINDD_ENDPWENT;
		req = winbindd_endpwent_send(s,
					     s->ev_ctx,
					     s->fake_cli,
					     s->fake_req);
		if (req == NULL) {
			DBG_ERR("No memory\n");
			varlink_call_reply_error(
				s->call,
				WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
				NULL);
			goto out;
		}
		tevent_req_set_callback(req, user_enum_endpwent_done, s);
		return;
	} else if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_getpwent failed: %s\n", nt_errstr(status));
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	if (response->data.num_entries == 0) {
		varlink_call_reply_error(s->call,
					 WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
					 NULL);
		goto out;
	}

	/*
	 * We got a new chunk, send the last entry from previous chunk with
	 * continue flag set
	 */
	if (s->last_pw != NULL) {
		user_record_reply(s->call, s->last_pw, true);
	}

	/*
	 * Send returned records except last one because we don't know if
	 * will be more coming and the continue flag must be set
	 *
	 * The returned winbindd_pw structs start at the beginning of the
	 * extra data.
	 */
	pws = (struct winbindd_pw *)response->extra_data.data;

	for (i = 0; i < response->data.num_entries - 1; i++) {
		struct winbindd_pw *pw = &pws[i];
		user_record_reply(s->call, pw, true);
	}

	s->last_pw = talloc_zero(s, struct winbindd_pw);
	if (s->last_pw == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	/* Save last one */
	*s->last_pw = pws[i];

	/* Get next chunk */
	TALLOC_FREE(response);
	ZERO_STRUCTP(s->fake_req);
	s->fake_req->cmd = WINBINDD_GETPWENT;
	s->fake_req->data.num_entries = 500;
	req = winbindd_getpwent_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}
	tevent_req_set_callback(req, user_enum_getpwent_done, s);
	return;
out:
	TALLOC_FREE(s);
}

static void user_enum_setpwent_done(struct tevent_req *req)
{
	struct user_enum_state *s =
		tevent_req_callback_data(req, struct user_enum_state);
	struct winbindd_response *response = NULL;
	NTSTATUS status;

	/* winbindd_*_recv functions expect a talloc-allocated response */
	response = talloc_zero(s, struct winbindd_response);
	if (response == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	status = winbindd_setpwent_recv(req, response);
	TALLOC_FREE(req);
	TALLOC_FREE(response);

	if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_setpwent failed: %s\n", nt_errstr(status));
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	ZERO_STRUCTP(s->fake_req);
	s->fake_req->cmd = WINBINDD_GETPWENT;
	s->fake_req->data.num_entries = 500;

	req = winbindd_getpwent_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}
	tevent_req_set_callback(req, user_enum_getpwent_done, s);
	return;
out:
	TALLOC_FREE(s);
}

static void user_enum_conn_closed(VarlinkCall *call, void *userdata)
{
	struct user_enum_state *s =
		talloc_get_type_abort(userdata, struct user_enum_state);
	TALLOC_FREE(s);
}

NTSTATUS wb_vl_user_enumerate(TALLOC_CTX *mem_ctx,
			      struct tevent_context *ev_ctx,
			      VarlinkCall *call,
			      uint64_t flags,
			      const char *service)
{
	struct user_enum_state *s = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	s = talloc_zero(mem_ctx, struct user_enum_state);
	if (s == NULL) {
		DBG_ERR("No memory\n");
		vl_active = 0;
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(s, user_enum_state_destructor);

	/* Check if enumeration enabled */
	if (!lp_winbind_enum_users()) {
		varlink_call_reply_error(
			call,
			WB_VL_REPLY_ERROR_ENUMERATION_NOT_SUPPORTED,
			NULL);
		status = NT_STATUS_OK;
		goto fail;
	}

	/* Check more flag is set */
	if (!(flags & VARLINK_CALL_MORE)) {
		DBG_WARNING("Enum request without more flag set\n");
		status = NT_STATUS_INVALID_PARAMETER;
		goto fail;
	}

	s->fake_cli = talloc_zero(s, struct winbindd_cli_state);
	if (s->fake_cli == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	s->fake_req = talloc_zero(s, struct winbindd_request);
	if (s->fake_req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	s->ev_ctx = ev_ctx;
	s->call = varlink_call_ref(call);

	status = wb_vl_fake_cli_state(call, service, s->fake_cli);
	if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("Failed to create fake winbindd_cli_state: %s\n",
			nt_errstr(status));
		goto fail;
	}

	s->fake_req->cmd = WINBINDD_SETPWENT;
	req = winbindd_setpwent_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	tevent_req_set_callback(req, user_enum_setpwent_done, s);

	varlink_call_set_connection_closed_callback(call,
						    user_enum_conn_closed,
						    s);

	return NT_STATUS_OK;
fail:
	TALLOC_FREE(s);
	return status;
}

/******************************************************************************
 * User by uid
 *****************************************************************************/

struct user_by_uid_state {
	struct tevent_context *ev_ctx;
	struct winbindd_request *fake_req;
	struct winbindd_cli_state *fake_cli;
	VarlinkCall *call;
};

static int user_by_uid_state_destructor(struct user_by_uid_state *s)
{
	if (s->call != NULL) {
		s->call = varlink_call_unref(s->call);
	}

	vl_active = 0;

	return 0;
}

static void user_by_uid_getpwuid_done(struct tevent_req *req)
{
	struct user_by_uid_state *s =
		tevent_req_callback_data(req, struct user_by_uid_state);
	struct winbindd_response *response = NULL;
	NTSTATUS status;

	/* winbindd_*_recv functions expect a talloc-allocated response */
	response = talloc_zero(s, struct winbindd_response);
	if (response == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	status = winbindd_getpwuid_recv(req, response);
	TALLOC_FREE(req);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		varlink_call_reply_error(s->call,
					 WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
					 NULL);
		goto out;
	} else if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_getgrgid failed: %s\n", nt_errstr(status));
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	user_record_reply(s->call, &response->data.pw, false);

out:
	TALLOC_FREE(s);
}

static void user_by_uid_conn_closed(VarlinkCall *call, void *userdata)
{
	struct user_by_uid_state *s =
		talloc_get_type_abort(userdata, struct user_by_uid_state);
	TALLOC_FREE(s);
}

NTSTATUS wb_vl_user_by_uid(TALLOC_CTX *mem_ctx,
			   struct tevent_context *ev_ctx,
			   VarlinkCall *call,
			   uint64_t flags,
			   const char *service,
			   int64_t uid)
{
	struct user_by_uid_state *s = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	s = talloc_zero(mem_ctx, struct user_by_uid_state);
	if (s == NULL) {
		DBG_ERR("No memory\n");
		vl_active = 0;
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(s, user_by_uid_state_destructor);

	s->fake_cli = talloc_zero(s, struct winbindd_cli_state);
	if (s->fake_cli == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	s->fake_req = talloc_zero(s, struct winbindd_request);
	if (s->fake_req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	s->ev_ctx = ev_ctx;
	s->call = varlink_call_ref(call);

	status = wb_vl_fake_cli_state(call, service, s->fake_cli);
	if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("Failed to create fake winbindd_cli_state: %s\n",
			nt_errstr(status));
		goto fail;
	}

	s->fake_req->cmd = WINBINDD_GETPWUID;
	s->fake_req->data.uid = uid;

	req = winbindd_getpwuid_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	tevent_req_set_callback(req, user_by_uid_getpwuid_done, s);

	varlink_call_set_connection_closed_callback(call,
						    user_by_uid_conn_closed,
						    s);

	return NT_STATUS_OK;
fail:
	TALLOC_FREE(s);
	return status;
}

/******************************************************************************
 * User by name
 *****************************************************************************/

struct user_by_name_state {
	struct tevent_context *ev_ctx;
	struct winbindd_request *fake_req;
	struct winbindd_cli_state *fake_cli;
	VarlinkCall *call;
};

static int user_by_name_state_destructor(struct user_by_name_state *s)
{
	if (s->call != NULL) {
		s->call = varlink_call_unref(s->call);
	}

	vl_active = 0;

	return 0;
}

static void user_by_name_getpwnam_done(struct tevent_req *req)
{
	struct user_by_name_state *s =
		tevent_req_callback_data(req, struct user_by_name_state);
	struct winbindd_response *response = NULL;
	NTSTATUS status;

	/* winbindd_*_recv functions expect a talloc-allocated response */
	response = talloc_zero(s, struct winbindd_response);
	if (response == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	status = winbindd_getpwnam_recv(req, response);
	TALLOC_FREE(req);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		varlink_call_reply_error(s->call,
					 WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
					 NULL);
		goto out;
	} else if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_getpwnam failed: %s\n", nt_errstr(status));
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	user_record_reply(s->call, &response->data.pw, false);
out:
	TALLOC_FREE(s);
}

static void user_by_name_conn_closed(VarlinkCall *call, void *userdata)
{
	struct user_by_name_state *s =
		talloc_get_type_abort(userdata, struct user_by_name_state);
	TALLOC_FREE(s);
}

NTSTATUS wb_vl_user_by_name(TALLOC_CTX *mem_ctx,
			    struct tevent_context *ev_ctx,
			    VarlinkCall *call,
			    uint64_t flags,
			    const char *service,
			    const char *user_name)
{
	struct user_by_name_state *s = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	s = talloc_zero(mem_ctx, struct user_by_name_state);
	if (s == NULL) {
		DBG_ERR("No memory\n");
		vl_active = 0;
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(s, user_by_name_state_destructor);

	s->fake_cli = talloc_zero(s, struct winbindd_cli_state);
	if (s->fake_cli == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	s->fake_req = talloc_zero(s, struct winbindd_request);
	if (s->fake_req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	s->ev_ctx = ev_ctx;
	s->call = varlink_call_ref(call);

	status = wb_vl_fake_cli_state(call, service, s->fake_cli);
	if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("Failed to create fake winbindd_cli_state: %s\n",
			nt_errstr(status));
		goto fail;
	}

	s->fake_req->cmd = WINBINDD_GETPWNAM;
	fstrcpy(s->fake_req->data.username, user_name);

	req = winbindd_getpwnam_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	tevent_req_set_callback(req, user_by_name_getpwnam_done, s);

	varlink_call_set_connection_closed_callback(call,
						    user_by_name_conn_closed,
						    s);

	return NT_STATUS_OK;
fail:
	TALLOC_FREE(s);
	return status;
}

/******************************************************************************
 * User by name and uid
 * Search by name first, if found, check uid matches.
 * If not found, search by uid and check name.
 *****************************************************************************/

struct user_by_name_uid_state {
	struct tevent_context *ev_ctx;
	struct winbindd_request *fake_req;
	struct winbindd_cli_state *fake_cli;
	VarlinkCall *call;
	const char *name;
	uid_t uid;
};

static int user_by_name_uid_state_destructor(struct user_by_name_uid_state *s)
{
	if (s->call != NULL) {
		s->call = varlink_call_unref(s->call);
	}

	vl_active = false;

	return 0;
}

static void user_by_name_uid_getpwnamuid_done(struct tevent_req *req)
{
	struct user_by_name_uid_state *s =
		tevent_req_callback_data(req, struct user_by_name_uid_state);
	struct winbindd_response *response = NULL;
	NTSTATUS status;

	/* winbindd_*_recv functions expect a talloc-allocated response */
	response = talloc_zero(s, struct winbindd_response);
	if (response == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	switch (s->fake_req->cmd) {
	case WINBINDD_GETPWNAM:
		status = winbindd_getpwnam_recv(req, response);
		break;
	case WINBINDD_GETPWUID:
		status = winbindd_getpwuid_recv(req, response);
		break;
	default:
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		TALLOC_FREE(req);
		goto out;
	}
	TALLOC_FREE(req);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		/*
		 * If name search did not find the user, fall back to uid.
		 * If uid search fails too no record found will be returned.
		 */
		if (s->fake_req->cmd == WINBINDD_GETPWNAM) {
			ZERO_STRUCTP(s->fake_req);
			s->fake_req->cmd = WINBINDD_GETPWUID;
			s->fake_req->data.uid = s->uid;
			req = winbindd_getpwuid_send(s,
						     s->ev_ctx,
						     s->fake_cli,
						     s->fake_req);
			if (req == NULL) {
				DBG_ERR("No memory\n");
				varlink_call_reply_error(
					s->call,
					WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
					NULL);
				goto out;
			}
			tevent_req_set_callback(
				req,
				user_by_name_uid_getpwnamuid_done,
				s);
			return;
		}
		varlink_call_reply_error(s->call,
					 WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
					 NULL);
		goto out;
	} else if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_getpw[nam|sid] failed: %s\n",
			nt_errstr(status));
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	if (response->data.pw.pw_uid != s->uid ||
	    !strequal(response->data.pw.pw_name, s->name)) {
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_CONFLICTING_RECORD_FOUND,
			NULL);
		goto out;
	}

	user_record_reply(s->call, &response->data.pw, false);
out:
	TALLOC_FREE(s);
}

static void user_by_name_uid_conn_closed(VarlinkCall *call, void *userdata)
{
	struct user_by_name_uid_state *s =
		talloc_get_type_abort(userdata, struct user_by_name_uid_state);
	TALLOC_FREE(s);
}

NTSTATUS wb_vl_user_by_name_and_uid(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev_ctx,
				    VarlinkCall *call,
				    uint64_t flags,
				    const char *service,
				    const char *user_name,
				    int64_t uid)
{
	struct user_by_name_uid_state *s = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	s = talloc_zero(mem_ctx, struct user_by_name_uid_state);
	if (s == NULL) {
		DBG_ERR("No memory\n");
		vl_active = 0;
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(s, user_by_name_uid_state_destructor);

	s->fake_cli = talloc_zero(s, struct winbindd_cli_state);
	if (s->fake_cli == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	s->fake_req = talloc_zero(s, struct winbindd_request);
	if (s->fake_req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	s->name = talloc_strdup(s, user_name);
	if (s->name == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	s->ev_ctx = ev_ctx;
	s->uid = uid;
	s->call = varlink_call_ref(call);

	status = wb_vl_fake_cli_state(call, service, s->fake_cli);
	if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("Failed to create fake winbindd_cli_state: %s\n",
			nt_errstr(status));
		goto fail;
	}

	s->fake_req->cmd = WINBINDD_GETPWNAM;
	fstrcpy(s->fake_req->data.username, user_name);

	req = winbindd_getpwnam_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	tevent_req_set_callback(req, user_by_name_uid_getpwnamuid_done, s);

	varlink_call_set_connection_closed_callback(
		call,
		user_by_name_uid_conn_closed,
		s);

	return NT_STATUS_OK;
fail:
	TALLOC_FREE(s);
	return status;
}
