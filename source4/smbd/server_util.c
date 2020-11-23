/*
   Unix SMB/CIFS implementation.

   Utility routines

   Copyright (C) 2020 Ralph Boehme <slow@samba.org>

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
#include "lib/tevent/tevent.h"
#include "lib/util/unix_privs.h"
#include "server_util.h"

struct samba_tevent_trace_state {
	size_t events;
	time_t last_logsize_check;
};

struct samba_tevent_trace_state *create_samba_tevent_trace_state(
	TALLOC_CTX *mem_ctx)
{
	return talloc_zero(mem_ctx, struct samba_tevent_trace_state);
}

void samba_tevent_trace_callback(enum tevent_trace_point point,
				 void *private_data)
{
	struct samba_tevent_trace_state *state =
		talloc_get_type_abort(private_data,
				      struct samba_tevent_trace_state);
	time_t now = time(NULL);
	bool do_check_logs = false;
	void *priv = NULL;

	switch (point) {
	case TEVENT_TRACE_BEFORE_WAIT:
		break;
	default:
		return;
	}

	state->events++;

	/*
	 * Throttling by some random numbers. smbd uses a similar logic
	 * checking every 50 SMB requests. Assuming 4 events per request
	 * we get to the number of 200.
	 */
	if ((state->events % 200) == 0) {
		do_check_logs = true;
	}
	/*
	 * Throttling by some delay, choosing 29 to avoid lockstep with
	 * the default tevent tickle timer.
	 */
	if ((state->last_logsize_check + 29) < now) {
		do_check_logs = true;
	}

	if (!do_check_logs) {
		return;
	}

	/*
	 * need_to_check_log_size() checks both the number of messages
	 * that have been logged and if the logging backend is actually
	 * going to file. We want to bypass the "number of messages"
	 * check, so we have to call force_check_log_size() before.
	 */
	force_check_log_size();
	if (!need_to_check_log_size()) {
		return;
	}

	priv = root_privileges();
	check_log_size();
	TALLOC_FREE(priv);

	state->last_logsize_check = now;
	return;
}
