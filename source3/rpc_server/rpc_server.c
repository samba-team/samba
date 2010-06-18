/*
   Unix SMB/Netbios implementation.
   Generic infrstructure for RPC Daemons
   Copyright (C) Simo Sorce 2010

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
#include "rpc_server/rpc_server.h"

struct named_pipe_listen_state {
	int fd;
};

static void named_pipe_listener(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags,
				void *private_data)
{
	return;
}

bool setup_named_pipe_socket(const char *pipe_name,
			     struct tevent_context *ev_ctx)
{
	struct named_pipe_listen_state *state;
	struct tevent_fd *fde;
	char *np_dir;

	state = talloc(ev_ctx, struct named_pipe_listen_state);
	if (!state) {
		DEBUG(0, ("Out of memory\n"));
		return false;
	}
	state->fd = -1;

	np_dir = talloc_asprintf(state, "%s/np", lp_ncalrpc_dir());
	if (!np_dir) {
		DEBUG(0, ("Out of memory\n"));
		goto out;
	}

	if (!directory_create_or_exist(np_dir, geteuid(), 0700)) {
		DEBUG(0, ("Failed to create pipe directory %s - %s\n",
			  np_dir, strerror(errno)));
		goto out;
	}

	state->fd = create_pipe_sock(np_dir, pipe_name, 0700);
	if (state->fd == -1) {
		DEBUG(0, ("Failed to create pipe socket! [%s/%s]\n",
			  np_dir, pipe_name));
		goto out;
	}

	DEBUG(10, ("Openened pipe socket fd %d for %s\n",
		   state->fd, pipe_name));

	fde = tevent_add_fd(ev_ctx,
			    state, state->fd, TEVENT_FD_READ,
			    named_pipe_listener, state);
	if (!fde) {
		DEBUG(0, ("Failed to add event handler!\n"));
		goto out;
	}

	tevent_fd_set_auto_close(fde);
	return true;

out:
	if (state->fd != -1) {
		close(state->fd);
	}
	TALLOC_FREE(state);
	return false;
}
