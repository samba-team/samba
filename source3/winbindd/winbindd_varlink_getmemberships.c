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

static void membership_reply(VarlinkCall *call,
			     const char *username,
			     const char *groupname,
			     bool continues)
{
	VarlinkObject *out = NULL;

	varlink_object_new(&out);
	varlink_object_set_string(out, "userName", username);
	varlink_object_set_string(out, "groupName", groupname);

	varlink_call_reply(call, out, continues ? VARLINK_REPLY_CONTINUES : 0);
	varlink_object_unref(out);
}

static void member_list_reply(VarlinkCall *call,
			      struct winbindd_gr *gr,
			      char *gr_members,
			      bool continues)
{
	char *name = NULL;
	char *p = NULL;
	int i;

	for ((name = strtok_r(gr_members, ",", &p)), i = 0; name != NULL;
	     name = strtok_r(NULL, ",", &p), i++) {
		if (i == gr->num_gr_mem) {
			break;
		}
		membership_reply(call,
				 name,
				 gr->gr_name,
				 continues || ((i + 1) < gr->num_gr_mem));
	}
}

/******************************************************************************
 * Membership enumeration
 *****************************************************************************/

struct membership_enum_state {
	struct tevent_context *ev_ctx;
	struct winbindd_request *fake_req;
	struct winbindd_cli_state *fake_cli;
	VarlinkCall *call;

	struct winbindd_gr *last_gr;
	char *last_members;
};

static int membership_enum_state_destructor(struct membership_enum_state *s)
{
	if (s->call != NULL) {
		s->call = varlink_call_unref(s->call);
	}

	return 0;
}

static void membership_enum_endgrent_done(struct tevent_req *req)
{
	struct membership_enum_state *s =
		tevent_req_callback_data(req, struct membership_enum_state);
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

	if (s->last_gr == NULL || s->last_gr->num_gr_mem == 0) {
		varlink_call_reply_error(s->call,
					 WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
					 NULL);
		goto out;
	}

	member_list_reply(s->call, s->last_gr, s->last_members, false);
out:
	TALLOC_FREE(s);
}

static void membership_enum_getgrent_done(struct tevent_req *req)
{
	struct membership_enum_state *s =
		tevent_req_callback_data(req, struct membership_enum_state);
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
		tevent_req_set_callback(req, membership_enum_endgrent_done, s);
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
	 * The returned winbindd_gr structs start at the beginning of the
	 * extra data.
	 */
	grs = (struct winbindd_gr *)response->extra_data.data;

	/* The memberships stats after all returned winbindd_gr structs */
	member_data = (char *)response->extra_data.data +
		      response->data.num_entries * sizeof(struct winbindd_gr);

	/*
	 * Advance to the first group with members and save it, sending the
	 * previously saved if there was one.
	 */
	for (i = 0; i < response->data.num_entries; i++) {
		struct winbindd_gr *gr = &grs[i];
		if (gr->num_gr_mem != 0) {
			break;
		}
	}

	if (i == response->data.num_entries) {
		/* No group with members in this chunk, get next */
		goto next_getgrent;
	}

	/*
	 * There is at least one group with members in this chunk. If we have a
	 * saved one from the previous chunk, send it with continue flag set
	 * and save this one. It will be sent either in the endgrent callback
	 * or in the next getgrent batch if there is a group with members in
	 * that batch.
	 */
	if (s->last_gr != NULL) {
		member_list_reply(s->call,
				s->last_gr,
				s->last_members,
				true);
		TALLOC_FREE(s->last_gr);
		TALLOC_FREE(s->last_members);
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
	*s->last_gr = grs[i];
	s->last_members = talloc_strdup(
			s,
			&member_data[s->last_gr->gr_mem_ofs]);
	if (s->last_members == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
				s->call,
				WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
				NULL);
		goto out;
	}

	/* Advance to the next group */
	i++;

	/* and send the rest of groups with members in this chunk */
	for (; i < response->data.num_entries; i++) {
		struct winbindd_gr *gr = &grs[i];
		char *gr_members = &member_data[gr->gr_mem_ofs];

		/* Skip groups without members */
		if (gr->num_gr_mem == 0) {
			continue;
		}


		member_list_reply(s->call, gr, gr_members, true);
	}

next_getgrent:
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
	tevent_req_set_callback(req, membership_enum_getgrent_done, s);
	return;
out:
	TALLOC_FREE(s);
}

static void membership_enum_setgrent_done(struct tevent_req *req)
{
	struct membership_enum_state *s =
		tevent_req_callback_data(req, struct membership_enum_state);
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
	tevent_req_set_callback(req, membership_enum_getgrent_done, s);
	return;
out:
	TALLOC_FREE(s);
}

static void memberships_enumerate_conn_closed(VarlinkCall *call, void *userdata)
{
	struct memberships_enum_state *s =
		talloc_get_type_abort(userdata, struct memberships_enum_state);
	TALLOC_FREE(s);
}

NTSTATUS wb_vl_memberships_enumerate(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev_ctx,
				     VarlinkCall *call,
				     uint64_t flags,
				     const char *service)
{
	struct membership_enum_state *s = NULL;
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

	/* Check if group expansion is enabled */
	if (!lp_winbind_expand_groups()) {
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

	s = talloc_zero(mem_ctx, struct membership_enum_state);
	if (s == NULL) {
		DBG_ERR("No memory\n");
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(s, membership_enum_state_destructor);

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
	tevent_req_set_callback(req, membership_enum_setgrent_done, s);

	varlink_call_set_connection_closed_callback(
		call,
		memberships_enumerate_conn_closed,
		s);

	return NT_STATUS_OK;
fail:
	TALLOC_FREE(s);
	return status;
}

/******************************************************************************
 * List user groups
 *****************************************************************************/

struct memberships_by_user_state {
	struct winbindd_cli_state *fake_cli;
	struct winbindd_request *fake_req;
	struct tevent_context *ev_ctx;
	VarlinkCall *call;
	const char *username;

	uint32_t num_gids;
	gid_t *gids;
};

static int
memberships_by_user_state_destructor(struct memberships_by_user_state *s)
{
	if (s->call != NULL) {
		s->call = varlink_call_unref(s->call);
	}

	return 0;
}

static void memberships_by_user_getgrgid_done(struct tevent_req *req)
{
	struct memberships_by_user_state *s =
		tevent_req_callback_data(req, struct memberships_by_user_state);
	struct winbindd_response *response = NULL;
	NTSTATUS status;

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

	if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_getgrgid failed: %s\n", nt_errstr(status));
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	if (s->gids == NULL) {
		/*
		 * We freed the array in the last winbindd_getgrgid_send
		 * call to flag it was the last one
		 */
		membership_reply(s->call,
				 s->username,
				 response->data.gr.gr_name,
				 false);
		goto out;
	}

	membership_reply(s->call, s->username, response->data.gr.gr_name, true);
	TALLOC_FREE(response);

	s->num_gids--;

	ZERO_STRUCTP(s->fake_req);
	s->fake_req->cmd = WINBINDD_GETGRGID;
	s->fake_req->data.uid = s->gids[s->num_gids - 1];

	if (s->num_gids - 1 == 0) {
		/* Flag this is the last winbindd_getgrgid_send call */
		TALLOC_FREE(s->gids);
	}

	req = winbindd_getgrgid_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}
	tevent_req_set_callback(req, memberships_by_user_getgrgid_done, s);
	return;
out:
	TALLOC_FREE(s);
}

static void memberships_by_user_getgroups_done(struct tevent_req *req)
{
	struct memberships_by_user_state *s =
		tevent_req_callback_data(req, struct memberships_by_user_state);
	struct winbindd_response *response = NULL;
	NTSTATUS status;

	response = talloc_zero(s, struct winbindd_response);
	if (response == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}

	status = winbindd_getgroups_recv(req, response);
	TALLOC_FREE(req);

	if (NT_STATUS_IS_ERR(status)) {
		DBG_ERR("winbindd_getgroups failed: %s\n", nt_errstr(status));
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

	s->num_gids = response->data.num_entries;
	s->gids = talloc_move(s, &response->extra_data.data);
	TALLOC_FREE(response);

	ZERO_STRUCTP(s->fake_req);
	s->fake_req->cmd = WINBINDD_GETGRGID;
	s->fake_req->data.uid = s->gids[s->num_gids - 1];

	req = winbindd_getgrgid_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		varlink_call_reply_error(
			s->call,
			WB_VL_REPLY_ERROR_SERVICE_NOT_AVAILABLE,
			NULL);
		goto out;
	}
	tevent_req_set_callback(req, memberships_by_user_getgrgid_done, s);
	return;
out:
	TALLOC_FREE(s);
}

static void memberships_by_user_conn_closed(VarlinkCall *call, void *userdata)
{
	struct memberships_by_user_state *s =
		talloc_get_type_abort(userdata,
				      struct memberships_by_user_state);
	TALLOC_FREE(s);
}

NTSTATUS wb_vl_memberships_by_user(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev_ctx,
				   VarlinkCall *call,
				   uint64_t flags,
				   const char *service,
				   const char *user_name)
{
	struct memberships_by_user_state *s = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	/* Check if group expansion is enabled */
	if (!lp_winbind_expand_groups()) {
		varlink_call_reply_error(
			call,
			WB_VL_REPLY_ERROR_ENUMERATION_NOT_SUPPORTED,
			NULL);
		return NT_STATUS_OK;
	}

	/* Check more flag is set */
	if (!(flags & VARLINK_CALL_MORE)) {
		DBG_WARNING("Request without more flag set\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	s = talloc_zero(mem_ctx, struct memberships_by_user_state);
	if (s == NULL) {
		DBG_ERR("No memory\n");
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(s, memberships_by_user_state_destructor);

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

	s->username = talloc_strdup(s, user_name);
	if (s->username == NULL) {
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

	s->fake_req->cmd = WINBINDD_GETGROUPS;
	fstrcpy(s->fake_req->data.username, user_name);
	req = winbindd_getgroups_send(s, s->ev_ctx, s->fake_cli, s->fake_req);
	if (req == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}
	tevent_req_set_callback(req, memberships_by_user_getgroups_done, s);

	varlink_call_set_connection_closed_callback(
		call,
		memberships_by_user_conn_closed,
		s);

	return NT_STATUS_OK;
fail:
	TALLOC_FREE(s);
	return status;
}

/******************************************************************************
 * Memberships by group name
 *****************************************************************************/

struct memberships_by_group_state {
	struct tevent_context *ev_ctx;
	struct winbindd_request *fake_req;
	struct winbindd_cli_state *fake_cli;
	const char *groupname;
	VarlinkCall *call;
};

static int
memberships_by_group_state_destructor(struct memberships_by_group_state *s)
{
	if (s->call != NULL) {
		s->call = varlink_call_unref(s->call);
	}

	return 0;
}

static void memberships_by_group_getgrnam_done(struct tevent_req *req)
{
	struct memberships_by_group_state *s =
		tevent_req_callback_data(req,
					 struct memberships_by_group_state);
	struct winbindd_response *response = NULL;
	struct winbindd_gr *gr = NULL;
	char *gr_members = NULL;
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

	gr = &response->data.gr;
	gr_members = (char *)response->extra_data.data;

	if (gr->num_gr_mem == 0 || gr_members == NULL) {
		varlink_call_reply_error(s->call,
					 WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
					 NULL);
		goto out;
	}

	member_list_reply(s->call, gr, gr_members, false);
out:
	TALLOC_FREE(s);
}

static void memberships_by_group_conn_closed(VarlinkCall *call, void *userdata)
{
	struct memberships_by_group_state *s =
		talloc_get_type_abort(userdata,
				      struct memberships_by_group_state);
	TALLOC_FREE(s);
}

NTSTATUS wb_vl_memberships_by_group(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev_ctx,
				    VarlinkCall *call,
				    uint64_t flags,
				    const char *service,
				    const char *group_name)
{
	struct memberships_by_group_state *s = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	/* Check if group expansion is enabled */
	if (!lp_winbind_expand_groups()) {
		varlink_call_reply_error(
			call,
			WB_VL_REPLY_ERROR_ENUMERATION_NOT_SUPPORTED,
			NULL);
		return NT_STATUS_OK;
	}

	/* Check more flag is set */
	if (!(flags & VARLINK_CALL_MORE)) {
		DBG_WARNING("Request without more flag set\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	s = talloc_zero(mem_ctx, struct memberships_by_group_state);
	if (s == NULL) {
		DBG_ERR("No memory\n");
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(s, memberships_by_group_state_destructor);

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

	s->groupname = talloc_strdup(s, group_name);
	if (s->groupname == NULL) {
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
	tevent_req_set_callback(req, memberships_by_group_getgrnam_done, s);

	varlink_call_set_connection_closed_callback(
		call,
		memberships_by_group_conn_closed,
		s);

	return NT_STATUS_OK;
fail:
	TALLOC_FREE(s);
	return status;
}

/******************************************************************************
 * Check membership
 *****************************************************************************/

struct membership_check_state {
	struct tevent_context *ev_ctx;
	struct winbindd_request *fake_req;
	struct winbindd_cli_state *fake_cli;
	const char *username;
	const char *groupname;
	VarlinkCall *call;
};

static int membership_check_state_destructor(struct membership_check_state *s)
{
	if (s->call != NULL) {
		s->call = varlink_call_unref(s->call);
	}

	return 0;
}

static void membership_check_getgrnam_done(struct tevent_req *req)
{
	struct membership_check_state *s =
		tevent_req_callback_data(req, struct membership_check_state);
	struct winbindd_response *response = NULL;
	struct winbindd_gr *gr = NULL;
	char *gr_members = NULL;
	char *name = NULL;
	char *p = NULL;
	uint32_t i;
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

	gr = &response->data.gr;
	gr_members = (char *)response->extra_data.data;

	if (gr->num_gr_mem == 0 || gr_members == NULL) {
		varlink_call_reply_error(s->call,
					 WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
					 NULL);
		goto out;
	}

	for ((name = strtok_r(gr_members, ",", &p)), i = 0; name != NULL;
	     name = strtok_r(NULL, ",", &p), i++) {
		if (i == gr->num_gr_mem) {
			break;
		}
		if (strequal(name, s->username)) {
			membership_reply(s->call,
					 s->username,
					 s->groupname,
					 false);
			return;
		}
	}

	varlink_call_reply_error(s->call,
				 WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
				 NULL);
out:
	TALLOC_FREE(s);
}

static void membership_check_conn_closed(VarlinkCall *call, void *userdata)
{
	struct membership_check_state *s =
		talloc_get_type_abort(userdata, struct membership_check_state);
	TALLOC_FREE(s);
}

NTSTATUS wb_vl_membership_check(TALLOC_CTX *mem_ctx,
				struct tevent_context *ev_ctx,
				VarlinkCall *call,
				uint64_t flags,
				const char *service,
				const char *user_name,
				const char *group_name)
{
	struct membership_check_state *s = NULL;
	struct tevent_req *req = NULL;
	NTSTATUS status;

	/* Check if group expansion is enabled */
	if (!lp_winbind_expand_groups()) {
		varlink_call_reply_error(
			call,
			WB_VL_REPLY_ERROR_ENUMERATION_NOT_SUPPORTED,
			NULL);
		return NT_STATUS_OK;
	}

	/* Check more flag is set */
	if (!(flags & VARLINK_CALL_MORE)) {
		DBG_WARNING("Request without more flag set\n");
		return NT_STATUS_INVALID_PARAMETER;
	}

	s = talloc_zero(mem_ctx, struct membership_check_state);
	if (s == NULL) {
		DBG_ERR("No memory\n");
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(s, membership_check_state_destructor);

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

	s->username = talloc_strdup(s, user_name);
	if (s->username == NULL) {
		DBG_ERR("No memory\n");
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	s->groupname = talloc_strdup(s, group_name);
	if (s->groupname == NULL) {
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
	tevent_req_set_callback(req, membership_check_getgrnam_done, s);

	varlink_call_set_connection_closed_callback(
		call,
		membership_check_conn_closed,
		s);

	return NT_STATUS_OK;
fail:
	TALLOC_FREE(s);
	return status;
}
