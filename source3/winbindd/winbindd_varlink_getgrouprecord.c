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

static void group_record_reply(VarlinkCall *call,
			       struct winbindd_gr *gr,
			       char *gr_members,
			       bool continues)
{
	VarlinkObject *record = NULL;
	VarlinkArray *members = NULL;
	VarlinkObject *out = NULL;
	const char *service_name = NULL;
	char *p = NULL;
	char *name = NULL;
	int i;

	service_name = lp_parm_const_string(-1,
					    "winbind varlink",
					    "service name",
					    WB_VL_SERVICE_NAME);

	varlink_object_new(&record);
	varlink_object_set_string(record, "service", service_name);
	varlink_object_set_string(record, "groupName", gr->gr_name);
	varlink_object_set_int(record, "gid", gr->gr_gid);

	if (gr->num_gr_mem > 0 && gr_members != NULL) {
		varlink_array_new(&members);
		for ((name = strtok_r(gr_members, ",", &p)), i = 0;
		     name != NULL;
		     name = strtok_r(NULL, ",", &p), i++) {
			if (i == gr->num_gr_mem) {
				break;
			}
			varlink_array_append_string(members, name);
		}
		varlink_object_set_array(record, "members", members);
	}

	varlink_object_new(&out);
	varlink_object_set_object(out, "record", record);
	varlink_object_set_bool(out, "incomplete", false);

	varlink_call_reply(call, out, continues ? VARLINK_REPLY_CONTINUES : 0);
	varlink_object_unref(out);
}

/******************************************************************************
 * Group enumeration
 *****************************************************************************/

struct group_enum_state {
	struct tevent_context *ev_ctx;
	struct winbindd_request *fake_req;
	struct winbindd_cli_state *fake_cli;
	VarlinkCall *call;

	struct winbindd_gr *last_gr;
	char *last_members;
};

static int group_enum_state_destructor(struct group_enum_state *s)
{
	if (s->call != NULL) {
		s->call = varlink_call_unref(s->call);
	}

	return 0;
}

static void group_enum_endgrent_done(struct tevent_req *req)
{
	struct group_enum_state *s =
		tevent_req_callback_data(req, struct group_enum_state);
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

	status = winbindd_endgrent_recv(req, response);
	TALLOC_FREE(req);

	if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_endgrent failed: %s\n", nt_errstr(status));
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	if (s->last_gr == NULL) {
		varlink_call_reply_error(s->call,
					 WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
					 NULL);
		goto out;
	}

	group_record_reply(s->call, s->last_gr, s->last_members, false);

out:
	TALLOC_FREE(s);
}

static void group_enum_getgrent_done(struct tevent_req *req)
{
	struct group_enum_state *s =
		tevent_req_callback_data(req, struct group_enum_state);
	struct winbindd_response *response = NULL;
	struct winbindd_gr *grs = NULL;
	char *member_data = NULL;
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

	status = winbindd_getgrent_recv(req, response);
	TALLOC_FREE(req);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MORE_ENTRIES)) {
		ZERO_STRUCTP(s->fake_req);
		s->fake_req->cmd = WINBINDD_ENDGRENT;
		req = winbindd_endgrent_send(s,
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
		tevent_req_set_callback(req, group_enum_endgrent_done, s);
		return;
	} else if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_getgrent failed: %s\n", nt_errstr(status));
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
	if (s->last_gr != NULL) {
		group_record_reply(s->call, s->last_gr, s->last_members, true);
	}

	/*
	 * Send returned records except last one because we don't know if
	 * will be more coming and the continue flag must be set
	 *
	 * The returned winbindd_gr structs start at the beginning of the
	 * extra data.
	 */
	grs = (struct winbindd_gr *)response->extra_data.data;

	/* The memberships stats after all returned winbindd_gr structs */
	member_data = (char *)response->extra_data.data +
		      response->data.num_entries * sizeof(struct winbindd_gr);

	for (i = 0; i < response->data.num_entries - 1; i++) {
		struct winbindd_gr *gr = &grs[i];
		char *gr_members = &member_data[gr->gr_mem_ofs];
		group_record_reply(s->call, gr, gr_members, true);
	}

	s->last_gr = talloc_zero(s, struct winbindd_gr);
	if (s->last_gr == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	/* Save last one */
	*s->last_gr = grs[i];
	s->last_members =
		talloc_strdup(s, &member_data[s->last_gr->gr_mem_ofs]);
	if (s->last_members == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	/* Get next chunk */
	TALLOC_FREE(response);
	ZERO_STRUCTP(s->fake_req);
	s->fake_req->cmd = WINBINDD_GETGRENT;
	s->fake_req->data.num_entries = 500;
	req = winbindd_getgrent_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}
	tevent_req_set_callback(req, group_enum_getgrent_done, s);
	return;
out:
	TALLOC_FREE(s);
}

static void group_enum_setgrent_done(struct tevent_req *req)
{
	struct group_enum_state *s =
		tevent_req_callback_data(req, struct group_enum_state);
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

	status = winbindd_setgrent_recv(req, response);
	TALLOC_FREE(req);
	TALLOC_FREE(response);

	if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_setgrent failed: %s\n", nt_errstr(status));
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	ZERO_STRUCTP(s->fake_req);
	s->fake_req->cmd = WINBINDD_GETGRENT;
	s->fake_req->data.num_entries = 500;

	req = winbindd_getgrent_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}
	tevent_req_set_callback(req, group_enum_getgrent_done, s);
	return;
out:
	TALLOC_FREE(s);
}

NTSTATUS wb_vl_group_enumerate(TALLOC_CTX *mem_ctx,
			       struct tevent_context *ev_ctx,
			       VarlinkCall *call,
			       uint64_t flags,
			       const char *service)
{
	struct group_enum_state *s = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	/* Check if enumeration enabled */
	if (!lp_winbind_enum_groups()) {
		varlink_call_reply_error(
			call,
			WB_VL_REPLY_ERROR_ENUMERATION_NOT_SUPPORTED,
			NULL);
		return NT_STATUS_OK;
	}

	/* Check more flag is set */
	if (!(flags & VARLINK_CALL_MORE)) {
		DBG_WARNING("Enum request without more flag set\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	s = talloc_zero(mem_ctx, struct group_enum_state);
	if (s == NULL) {
		DBG_ERR("No memory\n");
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(s, group_enum_state_destructor);

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

	s->fake_req->cmd = WINBINDD_SETGRENT;
	req = winbindd_setgrent_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	tevent_req_set_callback(req, group_enum_setgrent_done, s);

	return NT_STATUS_OK;
fail:
	TALLOC_FREE(s);
	return status;
}

/******************************************************************************
 * Group by gid
 *****************************************************************************/

struct group_by_gid_state {
	struct tevent_context *ev_ctx;
	struct winbindd_request *fake_req;
	struct winbindd_cli_state *fake_cli;
	VarlinkCall *call;
};

static int group_by_gid_state_destructor(struct group_by_gid_state *s)
{
	if (s->call != NULL) {
		s->call = varlink_call_unref(s->call);
	}

	return 0;
}

static void group_by_gid_getgrgid_done(struct tevent_req *req)
{
	struct group_by_gid_state *s =
		tevent_req_callback_data(req, struct group_by_gid_state);
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

	status = winbindd_getgrgid_recv(req, response);
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

	group_record_reply(s->call,
			   &response->data.gr,
			   response->extra_data.data,
			   false);
out:
	TALLOC_FREE(s);
}

NTSTATUS wb_vl_group_by_gid(TALLOC_CTX *mem_ctx,
			    struct tevent_context *ev_ctx,
			    VarlinkCall *call,
			    uint64_t flags,
			    const char *service,
			    int64_t gid)
{
	struct group_by_gid_state *s = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	s = talloc_zero(mem_ctx, struct group_by_gid_state);
	if (s == NULL) {
		DBG_ERR("No memory\n");
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(s, group_by_gid_state_destructor);

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

	s->fake_req->cmd = WINBINDD_GETGRGID;
	s->fake_req->data.uid = gid;

	req = winbindd_getgrgid_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	tevent_req_set_callback(req, group_by_gid_getgrgid_done, s);

	return NT_STATUS_OK;
fail:
	TALLOC_FREE(s);
	return status;
}

/******************************************************************************
 * Group by name
 *****************************************************************************/

struct group_by_name_state {
	struct tevent_context *ev_ctx;
	struct winbindd_request *fake_req;
	struct winbindd_cli_state *fake_cli;
	VarlinkCall *call;
};

static int group_by_name_state_destructor(struct group_by_name_state *s)
{
	if (s->call != NULL) {
		s->call = varlink_call_unref(s->call);
	}

	return 0;
}

static void group_by_name_getgrnam_done(struct tevent_req *req)
{
	struct group_by_name_state *s =
		tevent_req_callback_data(req, struct group_by_name_state);
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

	status = winbindd_getgrnam_recv(req, response);
	TALLOC_FREE(req);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		varlink_call_reply_error(s->call,
					 WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
					 NULL);
		goto out;
	} else if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_getgrnam failed: %s\n", nt_errstr(status));
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	group_record_reply(s->call,
			   &response->data.gr,
			   response->extra_data.data,
			   false);

out:
	TALLOC_FREE(s);
}

NTSTATUS wb_vl_group_by_name(TALLOC_CTX *mem_ctx,
			     struct tevent_context *ev_ctx,
			     VarlinkCall *call,
			     uint64_t flags,
			     const char *service,
			     const char *group_name)
{
	struct group_by_name_state *s = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	s = talloc_zero(mem_ctx, struct group_by_name_state);
	if (s == NULL) {
		DBG_ERR("No memory\n");
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(s, group_by_name_state_destructor);

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

	s->fake_req->cmd = WINBINDD_GETGRNAM;
	fstrcpy(s->fake_req->data.username, group_name);

	req = winbindd_getgrnam_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	tevent_req_set_callback(req, group_by_name_getgrnam_done, s);

	return NT_STATUS_OK;
fail:
	TALLOC_FREE(s);
	return status;
}
