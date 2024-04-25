/*
 * Unix SMB/CIFS implementation.
 * Wait for process death
 * Copyright (C) Volker Lendecke 2016
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "serverid.h"
#include "server_id_watch.h"
#include "lib/util/server_id.h"
#include "lib/util/tevent_unix.h"

struct server_id_watch_state {
	struct tevent_context *ev;
	struct server_id pid;
	struct timeval start;
	struct timeval warn;
	bool debug;
};

static void server_id_watch_waited(struct tevent_req *subreq);

struct tevent_req *server_id_watch_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct server_id pid)
{
	struct tevent_req *req, *subreq;
	struct server_id_watch_state *state;
	struct timeval next;

	req = tevent_req_create(mem_ctx, &state, struct server_id_watch_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->pid = pid;
	state->start = tevent_timeval_current();
	state->warn = tevent_timeval_add(&state->start, 10, 0);

	state->debug = lp_parm_bool(GLOBAL_SECTION_SNUM,
				    "serverid watch",
				    "debug",
				    CHECK_DEBUGLVL(DBGLVL_DEBUG));

	if (!serverid_exists(&state->pid)) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	next = tevent_timeval_add(&state->start, 0, 500000);
	subreq = tevent_wakeup_send(state, ev, next);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, server_id_watch_waited, req);

	return req;
}

static void server_id_watch_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct server_id_watch_state *state = tevent_req_data(
		req, struct server_id_watch_state);
	struct timeval now;
	struct timeval next;
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		tevent_req_oom(req);
		return;
	}

	if (!serverid_exists(&state->pid)) {
		tevent_req_done(req);
		return;
	}

	now = tevent_timeval_current();

	if (!state->debug) {
		goto next;
	}

	if (timeval_compare(&state->warn, &now) == -1) {
		double duration = timeval_elapsed2(&state->start, &now);
		const char *cmd = NULL;
		char proc_path[64] = { 0, };
		char *kstack = NULL;
		struct server_id_buf buf;
		const char *pid = server_id_str_buf(state->pid, &buf);
		int ret;

		state->warn = tevent_timeval_add(&now, 10, 0);

		cmd = lp_parm_const_string(GLOBAL_SECTION_SNUM,
					   "serverid watch",
					   "debug script",
					   NULL);
		if (cmd != NULL) {
			char *cmdstr = NULL;
			char *output = NULL;
			int fd;

			/*
			 * Note in a cluster setup pid will be
			 * a NOTE:PID like '1:3978365'
			 *
			 * Without clustering it is just '3978365'
			 */
			cmdstr = talloc_asprintf(state, "%s %s", cmd, pid);
			if (cmdstr == NULL) {
				DBG_ERR("Process %s hanging for %f seconds?\n"
					"talloc_asprintf failed\n",
					pid, duration);
				goto next;
			}

			become_root();
			ret = smbrun(cmdstr, &fd, NULL);
			unbecome_root();
			if (ret != 0) {
				DBG_ERR("Process %s hanging for %f seconds?\n"
					"smbrun('%s') failed\n",
					pid, duration, cmdstr);
				TALLOC_FREE(cmdstr);
				goto next;
			}

			output = fd_load(fd, NULL, 0, state);
			close(fd);
			if (output == NULL) {
				DBG_ERR("Process %s hanging for %f seconds?\n"
					"fd_load() of smbrun('%s') failed\n",
					pid, duration, cmdstr);
				TALLOC_FREE(cmdstr);
				goto next;
			}
			DBG_ERR("Process %s hanging for %f seconds?\n"
				"%s returned:\n%s",
				pid, duration, cmdstr, output);
			TALLOC_FREE(cmdstr);
			TALLOC_FREE(output);
			goto next;
		}

		if (!procid_is_local(&state->pid) || !sys_have_proc_fds()) {
			DBG_ERR("Process %s hanging for %f seconds?\n",
				pid, duration);
			goto next;
		}

		ret = snprintf(proc_path,
			       ARRAY_SIZE(proc_path),
			       "/proc/%" PRIu64 "/stack",
			       state->pid.pid);
		if (ret < 0) {
			DBG_ERR("Process %s hanging for %f seconds?\n"
				"snprintf failed\n",
				pid, duration);
			goto next;
		}

		become_root();
		kstack = file_load(proc_path, NULL, 0, state);
		unbecome_root();
		if (kstack == NULL) {
			DBG_ERR("Process %s hanging for %f seconds?\n"
				"file_load [%s] failed\n",
				pid, duration, proc_path);
			goto next;
		}

		DBG_ERR("Process %s hanging for %f seconds?\n"
			"%s:\n%s",
			pid, duration, proc_path, kstack);
		TALLOC_FREE(kstack);
	}

next:
	next = tevent_timeval_add(&now, 0, 500000);
	subreq = tevent_wakeup_send(state, state->ev, next);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, server_id_watch_waited, req);
}

int server_id_watch_recv(struct tevent_req *req, struct server_id *pid)
{
	struct server_id_watch_state *state = tevent_req_data(
		req, struct server_id_watch_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	if (pid) {
		*pid = state->pid;
	}
	return 0;
}
