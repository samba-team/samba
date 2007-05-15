/* 
   Unix SMB/CIFS implementation.

   locking benchmark

   Copyright (C) Andrew Tridgell 2006
   
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

#include "includes.h"
#include "torture/torture.h"
#include "libcli/raw/libcliraw.h"
#include "system/time.h"
#include "system/filesys.h"
#include "libcli/libcli.h"
#include "torture/util.h"
#include "lib/events/events.h"
#include "lib/cmdline/popt_common.h"
#include "libcli/composite/composite.h"
#include "libcli/smb_composite/smb_composite.h"

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		printf("(%s) Incorrect status %s - should be %s\n", \
		       __location__, nt_errstr(status), nt_errstr(correct)); \
		goto failed; \
	}} while (0)

#define BASEDIR "\\benchlock"
#define FNAME BASEDIR "\\lock.dat"

static int nprocs;
static int lock_failed;
static int num_connected;

struct benchlock_state {
	struct event_context *ev;
	struct smbcli_tree *tree;
	TALLOC_CTX *mem_ctx;
	int client_num;
	int fnum;
	int offset;
	int count;
	union smb_lock io;
	struct smb_lock_entry lock[2];
	struct smbcli_request *req;
	struct smb_composite_connect reconnect;

	/* these are used for reconnections */
	int dest_port;
	const char *dest_host;
	const char *called_name;
	const char *service_type;
};

static void lock_completion(struct smbcli_request *);

/*
  send the next lock request
*/
static void lock_send(struct benchlock_state *state)
{
	state->io.lockx.in.file.fnum = state->fnum;
	state->io.lockx.in.ulock_cnt = 1;
	state->lock[0].pid = state->tree->session->pid;
	state->lock[1].pid = state->tree->session->pid;
	state->lock[0].offset = state->offset;
	state->lock[1].offset = (state->offset+1)%nprocs;
	state->req = smb_raw_lock_send(state->tree, &state->io);
	if (state->req == NULL) {
		DEBUG(0,("Failed to setup lock\n"));
		lock_failed++;
	}
	state->req->async.private = state;
	state->req->async.fn      = lock_completion;
	state->offset = (state->offset+1)%nprocs;
}

static void reopen_connection(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private_data);


static void reopen_file(struct event_context *ev, struct timed_event *te, 
				      struct timeval t, void *private_data)
{
	struct benchlock_state *state = (struct benchlock_state *)private_data;

	/* reestablish our open file */
	state->fnum = smbcli_open(state->tree, FNAME, O_RDWR|O_CREAT, DENY_NONE);
	if (state->fnum == -1) {
		printf("Failed to open %s on connection %d\n", FNAME, state->client_num);
		exit(1);
	}

	/* reestablish one lock, preparing for the async lock loop */
	state->lock[0].offset = state->offset;
	state->io.lockx.in.ulock_cnt = 0;
	state->io.lockx.in.file.fnum = state->fnum;
	state->req = smb_raw_lock_send(state->tree, &state->io);
	if (state->req == NULL) {
		DEBUG(0,("Failed to setup lock\n"));
		lock_failed++;
	}
	state->req->async.private = state;
	state->req->async.fn      = lock_completion;

	num_connected++;

	DEBUG(0,("reconnect to %s finished (%u connected)\n", state->dest_host,
		 num_connected));
}

/*
  complete an async reconnect
 */
static void reopen_connection_complete(struct composite_context *ctx)
{
	struct benchlock_state *state = (struct benchlock_state *)ctx->async.private_data;
	NTSTATUS status;
	struct smb_composite_connect *io = &state->reconnect;

	status = smb_composite_connect_recv(ctx, state->mem_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		event_add_timed(state->ev, state->mem_ctx, 
				timeval_current_ofs(1,0), 
				reopen_connection, state);
		return;
	}

	talloc_free(state->tree);
	state->tree = io->out.tree;

	/* do the reopen as a separate event */
	event_add_timed(state->ev, state->mem_ctx, timeval_zero(), reopen_file, state);
}

	

/*
  reopen a connection
 */
static void reopen_connection(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private_data)
{
	struct benchlock_state *state = (struct benchlock_state *)private_data;
	struct composite_context *ctx;
	struct smb_composite_connect *io = &state->reconnect;
	char *host, *share;

	if (!torture_get_conn_index(state->client_num, state->mem_ctx, &host, &share)) {
		DEBUG(0,("Can't find host/share for reconnect?!\n"));
		exit(1);
	}

	io->in.dest_host    = state->dest_host;
	io->in.port         = state->dest_port;
	io->in.called_name  = state->called_name;
	io->in.service      = share;
	io->in.service_type = state->service_type;
	io->in.credentials  = cmdline_credentials;
	io->in.fallback_to_anonymous = False;
	io->in.workgroup    = lp_workgroup();

	/* kill off the remnants of the old connection */
	talloc_free(state->tree);
	state->tree = NULL;

	ctx = smb_composite_connect_send(io, state->mem_ctx, state->ev);
	if (ctx == NULL) {
		DEBUG(0,("Failed to setup async reconnect\n"));
		exit(1);
	}

	ctx->async.fn = reopen_connection_complete;
	ctx->async.private_data = state;
}


/*
  called when a lock completes
*/
static void lock_completion(struct smbcli_request *req)
{
	struct benchlock_state *state = (struct benchlock_state *)req->async.private;
	NTSTATUS status = smbcli_request_simple_recv(req);
	state->req = NULL;
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE)) {
			talloc_free(state->tree);
			state->tree = NULL;
			num_connected--;	
			DEBUG(0,("reopening connection to %s\n", state->dest_host));
			event_add_timed(state->ev, state->mem_ctx, 
					timeval_current_ofs(1,0), 
					reopen_connection, state);
		} else {
			DEBUG(0,("Lock failed - %s\n", nt_errstr(status)));
			lock_failed++;
		}
	} else {
		state->count++;
		lock_send(state);
	}
}

/* 
   benchmark locking calls
*/
BOOL torture_bench_lock(struct torture_context *torture)
{
	BOOL ret = True;
	TALLOC_CTX *mem_ctx = talloc_new(torture);
	int i;
	int timelimit = torture_setting_int(torture, "timelimit", 10);
	struct timeval tv;
	struct event_context *ev = event_context_find(mem_ctx);
	struct benchlock_state *state;
	int total = 0, loops=0, minops=0;
	NTSTATUS status;
	struct smbcli_state *cli;
	
	nprocs = lp_parm_int(-1, "torture", "nprocs", 4);

	state = talloc_zero_array(mem_ctx, struct benchlock_state, nprocs);

	printf("Opening %d connections\n", nprocs);
	for (i=0;i<nprocs;i++) {
		state[i].mem_ctx = talloc_new(state);
		state[i].client_num = i;
		state[i].ev = ev;
		if (!torture_open_connection_ev(&cli, i, ev)) {
			return False;
		}
		talloc_steal(mem_ctx, state);
		state[i].tree = cli->tree;
		state[i].dest_host = talloc_strdup(state[i].mem_ctx, 
						   cli->tree->session->transport->socket->hostname);
		state[i].dest_port = cli->tree->session->transport->socket->port;
		state[i].called_name  = talloc_strdup(state[i].mem_ctx,
						      cli->tree->session->transport->called.name);
		state[i].service_type = talloc_strdup(state[i].mem_ctx,
						      cli->tree->device);
	}

	num_connected = i;

	if (!torture_setup_dir(cli, BASEDIR)) {
		goto failed;
	}

	for (i=0;i<nprocs;i++) {
		state[i].fnum = smbcli_open(state[i].tree, 
					    FNAME, 
					    O_RDWR|O_CREAT, DENY_NONE);
		if (state[i].fnum == -1) {
			printf("Failed to open %s on connection %d\n", FNAME, i);
			goto failed;
		}

		state[i].io.lockx.level = RAW_LOCK_LOCKX;
		state[i].io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
		state[i].io.lockx.in.timeout = 100000;
		state[i].io.lockx.in.ulock_cnt = 0;
		state[i].io.lockx.in.lock_cnt = 1;
		state[i].lock[0].count = 1;
		state[i].lock[1].count = 1;
		state[i].io.lockx.in.locks = &state[i].lock[0];

		state[i].offset = i;
		state[i].io.lockx.in.file.fnum = state[i].fnum;
		state[i].lock[0].offset = state[i].offset;
		state[i].lock[0].pid    = state[i].tree->session->pid;
		status = smb_raw_lock(state[i].tree, &state[i].io);
		CHECK_STATUS(status, NT_STATUS_OK);
	}

	for (i=0;i<nprocs;i++) {
		lock_send(&state[i]);
	}

	tv = timeval_current();	

	printf("Running for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		event_loop_once(ev);

		if (lock_failed) {
			DEBUG(0,("locking failed\n"));
			goto failed;
		}

		if (loops++ % 10 != 0) continue;

		total = 0;
		for (i=0;i<nprocs;i++) {
			total += state[i].count;
		}
		if (torture_setting_bool(torture, "progress", true)) {
			printf("%.2f ops/second (remaining=%u)\r", 
			       total/timeval_elapsed(&tv), 
			       (unsigned)(timelimit - timeval_elapsed(&tv)));
			fflush(stdout);
		}
	}

	printf("%.2f ops/second\n", total/timeval_elapsed(&tv));
	minops = state[0].count;
	for (i=0;i<nprocs;i++) {
		printf("[%d] %u ops\n", i, state[i].count);
		if (state[i].count < minops) minops = state[i].count;
	}
	if (minops < 0.5*total/nprocs) {
		printf("Failed: unbalanced locking\n");
		goto failed;
	}

	for (i=0;i<nprocs;i++) {
		talloc_free(state[i].req);
		smb_raw_exit(state[i].tree->session);
	}

	smbcli_deltree(state[0].tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;

failed:
	talloc_free(mem_ctx);
	return False;
}
