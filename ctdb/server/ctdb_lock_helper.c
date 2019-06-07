/*
   ctdb lock helper

   Copyright (C) Amitay Isaacs  2013

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>
#include <tdb.h>

#include "lib/util/sys_rw.h"
#include "lib/util/tevent_unix.h"

#include "protocol/protocol.h"

#include "common/system.h"

static bool realtime = true;

struct lock_state {
	struct tdb_context *tdb;
	TDB_DATA key;
};

static void set_priority(void)
{
	const char *ptr;

	ptr = getenv("CTDB_NOSETSCHED");
	if (ptr != NULL) {
		realtime = false;
	}

	if (! realtime) {
		return;
	}

	realtime = set_scheduler();
	if (! realtime) {
		fprintf(stderr,
			"locking: Unable to set real-time scheduler priority\n");
	}
}

static void reset_priority(void)
{
	if (realtime) {
		reset_scheduler();
	}
}

static void send_result(int fd, char result)
{
	sys_write(fd, &result, 1);
	if (result == 1) {
		exit(1);
	}
}


static void usage(const char *progname)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "Usage: %s <ctdbd-pid> <output-fd> RECORD <db-path> <db-flags> <db-key>\n", progname);
	fprintf(stderr, "       %s <ctdbd-pid> <output-fd> DB <db-path> <db-flags>\n", progname);
}

static uint8_t *hex_decode_talloc(TALLOC_CTX *mem_ctx,
				  const char *hex_in, size_t *len)
{
	unsigned int i;
	int num;
	uint8_t *buffer;

	*len = strlen(hex_in) / 2;
	buffer = talloc_array(mem_ctx, unsigned char, *len);

	for (i=0; i<*len; i++) {
		sscanf(&hex_in[i*2], "%02X", &num);
		buffer[i] = (uint8_t)num;
	}

	return buffer;
}

static int lock_record(const char *dbpath, const char *dbflags,
		       const char *dbkey, struct lock_state *state)
{
	int tdb_flags;

	/* No error checking since CTDB always passes sane values */
	tdb_flags = strtol(dbflags, NULL, 0);

	/* Convert hex key to key */
	if (strcmp(dbkey, "NULL") == 0) {
		state->key.dptr = NULL;
		state->key.dsize = 0;
	} else {
		state->key.dptr = hex_decode_talloc(NULL, dbkey,
						    &state->key.dsize);
	}

	state->tdb = tdb_open(dbpath, 0, tdb_flags, O_RDWR, 0600);
	if (state->tdb == NULL) {
		fprintf(stderr, "locking: Error opening database %s\n", dbpath);
		return 1;
	}

	set_priority();

	if (tdb_chainlock(state->tdb, state->key) < 0) {
		fprintf(stderr, "locking: Error getting record lock (%s)\n",
			tdb_errorstr(state->tdb));
		return 1;
	}

	reset_priority();

	return 0;

}

static int lock_db(const char *dbpath, const char *dbflags,
		   struct lock_state *state)
{
	int tdb_flags;

	/* No error checking since CTDB always passes sane values */
	tdb_flags = strtol(dbflags, NULL, 0);

	state->tdb = tdb_open(dbpath, 0, tdb_flags, O_RDWR, 0600);
	if (state->tdb == NULL) {
		fprintf(stderr, "locking: Error opening database %s\n", dbpath);
		return 1;
	}

	set_priority();

	if (tdb_lockall(state->tdb) < 0) {
		fprintf(stderr, "locking: Error getting db lock (%s)\n",
			tdb_errorstr(state->tdb));
		return 1;
	}

	reset_priority();

	return 0;
}

struct wait_for_parent_state {
	struct tevent_context *ev;
	pid_t ppid;
};

static void wait_for_parent_check(struct tevent_req *subreq);

static struct tevent_req *wait_for_parent_send(TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       pid_t ppid)
{
	struct tevent_req *req, *subreq;
	struct wait_for_parent_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wait_for_parent_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->ppid = ppid;

	if (ppid == 1) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	subreq = tevent_wakeup_send(state, ev,
				    tevent_timeval_current_ofs(5,0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wait_for_parent_check, req);

	return req;
}

static void wait_for_parent_check(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wait_for_parent_state *state = tevent_req_data(
		req, struct wait_for_parent_state);
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		/* Ignore error */
		fprintf(stderr, "locking: tevent_wakeup_recv() failed\n");
	}

	if (kill(state->ppid, 0) == -1 && errno == ESRCH) {
		tevent_req_done(req);
		return;
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    tevent_timeval_current_ofs(5,0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wait_for_parent_check, req);
}

static bool wait_for_parent_recv(struct tevent_req *req)
{
	if (tevent_req_is_unix_error(req, NULL)) {
		return false;
	}

	return true;
}

static void cleanup(struct lock_state *state)
{
	if (state->tdb != NULL) {
		if (state->key.dsize == 0) {
			tdb_unlockall(state->tdb);
		} else {
			tdb_chainunlock(state->tdb, state->key);
		}
		tdb_close(state->tdb);
	}
}

static void signal_handler(struct tevent_context *ev,
			   struct tevent_signal *se,
			   int signum, int count, void *siginfo,
			   void *private_data)
{
	struct lock_state *state = (struct lock_state *)private_data;

	cleanup(state);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct tevent_context *ev;
	struct tevent_signal *se;
	struct tevent_req *req;
	struct lock_state state = { 0 };
	int write_fd;
	char result = 0;
	int ppid;
	const char *lock_type;
	bool status;

	reset_scheduler();

	if (argc < 4) {
		usage(argv[0]);
		exit(1);
	}

	ppid = atoi(argv[1]);
	write_fd = atoi(argv[2]);
	lock_type = argv[3];

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		fprintf(stderr, "locking: tevent_context_init() failed\n");
		exit(1);
	}

	se = tevent_add_signal(ev, ev, SIGTERM, 0,
			       signal_handler, &state);
	if (se == NULL) {
		fprintf(stderr, "locking: tevent_add_signal() failed\n");
		talloc_free(ev);
		exit(1);
	}

	if (strcmp(lock_type, "RECORD") == 0) {
		if (argc != 7) {
			fprintf(stderr,
				"locking: Invalid number of arguments (%d)\n",
				argc);
			usage(argv[0]);
			exit(1);
		}
		result = lock_record(argv[4], argv[5], argv[6], &state);

	} else if (strcmp(lock_type, "DB") == 0) {
		if (argc != 6) {
			fprintf(stderr,
				"locking: Invalid number of arguments (%d)\n",
				argc);
			usage(argv[0]);
			exit(1);
		}
		result = lock_db(argv[4], argv[5], &state);

	} else {
		fprintf(stderr, "locking: Invalid lock-type '%s'\n", lock_type);
		usage(argv[0]);
		exit(1);
	}

	send_result(write_fd, result);

	req = wait_for_parent_send(ev, ev, ppid);
	if (req == NULL) {
		fprintf(stderr, "locking: wait_for_parent_send() failed\n");
		cleanup(&state);
		exit(1);
	}

	tevent_req_poll(req, ev);

	status = wait_for_parent_recv(req);
	if (! status) {
		fprintf(stderr, "locking: wait_for_parent_recv() failed\n");
	}

	talloc_free(ev);
	cleanup(&state);
	return 0;
}
