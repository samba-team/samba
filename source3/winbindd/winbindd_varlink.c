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
#include "lib/util/mkdir_p.h"
#include "winbindd_varlink.h"

#define WB_VL_SOCKET_DIR  "/run/systemd/userdb"

static const char s_interface[] =
"interface io.systemd.UserDatabase\n"
""
"method GetUserRecord("
"  uid: ?int,"
"  userName: ?string,"
"  service: string"
") -> (record: object, incomplete: bool)\n"
""
"method GetGroupRecord("
"  gid: ?int,"
"  groupName: ?string,"
"  service: string"
") -> (record: object, incomplete: bool)\n"
""
"method GetMemberships("
"  userName: ?string,"
"  groupName: ?string,"
"  service: string"
") -> (userName: string, groupName: string)\n"
""
"error NoRecordFound ()\n"
"error BadService ()\n"
"error ServiceNotAvailable ()\n"
"error ConflictingRecordFound ()\n"
"error EnumerationNotSupported ()\n";

struct wb_vl_state {
	VarlinkService *service;
	struct tevent_context *ev_ctx;
	struct tevent_fd *fde;
	int fd;
};

static long io_systemd_getuserrecord(VarlinkService *service,
				     VarlinkCall *call,
				     VarlinkObject *parameters,
				     uint64_t flags,
				     void *userdata)
{
	return varlink_call_reply_error(call,
			WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
			NULL);
}

static long io_systemd_getgrouprecord(VarlinkService *service,
				      VarlinkCall *call,
				      VarlinkObject *parameters,
				      uint64_t flags,
				      void *userdata)
{
	return varlink_call_reply_error(call,
			WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
			NULL);
}

static long io_systemd_getmemberships(VarlinkService *service,
				      VarlinkCall *call,
				      VarlinkObject *parameters,
				      uint64_t flags,
				      void *userdata)
{
	return varlink_call_reply_error(call,
			WB_VL_REPLY_ERROR_NO_RECORD_FOUND,
			NULL);
}

static void varlink_listen_fde_handler(struct tevent_context *ev,
				       struct tevent_fd *fde,
				       uint16_t flags,
				       void *private_data)
{
	struct wb_vl_state *s = talloc_get_type_abort(
			private_data, struct wb_vl_state);
	long rc;

	rc = varlink_service_process_events(s->service);
	if (rc < 0) {
		DBG_WARNING("Failed to process events: %s\n",
			    varlink_error_string(rc));
	}
}

static int wb_vl_state_destructor(struct wb_vl_state *s)
{
	if (s->service != NULL) {
		s->service = varlink_service_free(s->service);
	}
	if (s->service != NULL) {
		DBG_WARNING("Failed to free Varlink service\n");
	}
	return 0;
}

bool winbind_setup_varlink(TALLOC_CTX *mem_ctx,
			   struct tevent_context *ev_ctx)
{
	struct wb_vl_state *state = NULL;
	const char *socket_dir = NULL;
	const char *socket_name = NULL;
	char *uri = NULL;
	long rc;

	state = talloc_zero(mem_ctx, struct wb_vl_state);
	if (state == NULL) {
		DBG_ERR("No memory");
		goto fail;
	}
	talloc_set_destructor(state, wb_vl_state_destructor);

	state->ev_ctx = ev_ctx;

	socket_dir = lp_parm_const_string(-1,
					  "winbind varlink",
					  "socket directory",
					  WB_VL_SOCKET_DIR);

	socket_name = lp_parm_const_string(-1,
					   "winbind varlink",
					   "service name",
					   WB_VL_SERVICE_NAME);

	/* Create socket directory, useful in containers */
	rc = mkdir_p(socket_dir,
		     S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (rc && errno != EEXIST) {
		DBG_ERR("Could not create socket directory %s: %s\n",
			socket_dir, strerror(errno));
		goto fail;
	}

	uri = talloc_asprintf(state, "unix:%s/%s", socket_dir, socket_name);

	rc = varlink_service_new(&state->service,
				 "Samba",
				 "Winbind",
				 "1",
				 "https://samba.org",
				 uri,
				 -1);
	TALLOC_FREE(uri);
	if (rc < 0) {
		DBG_ERR("Failed to create Varlink service: %s\n",
			varlink_error_string(rc));
		goto fail;
	}

	rc = varlink_service_add_interface(state->service, s_interface,
			"GetUserRecord", io_systemd_getuserrecord, state,
			"GetGroupRecord", io_systemd_getgrouprecord, state,
			"GetMemberships", io_systemd_getmemberships, state,
			NULL);
	if (rc < 0) {
		DBG_ERR("Failed to add Varlink interface: %s\n",
			varlink_error_string(rc));
		goto fail;
	}

	state->fd = varlink_service_get_fd(state->service);
	if (state->fd < 0) {
		DBG_ERR("Failed to get varlink fd: %s\n",
			varlink_error_string(rc));
		goto fail;
	}

	state->fde = tevent_add_fd(state->ev_ctx,
				   state,
				   state->fd,
				   TEVENT_FD_READ,
				   varlink_listen_fde_handler,
				   state);
	if (state->fde == NULL) {
		DBG_ERR("Failed to create tevent fd event handler\n");
		close(state->fd);
		goto fail;
	}

	return true;
fail:
	TALLOC_FREE(state);
	return false;
}
