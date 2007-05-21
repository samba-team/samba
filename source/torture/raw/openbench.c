/* 
   Unix SMB/CIFS implementation.

   open benchmark

   Copyright (C) Andrew Tridgell 2007
   
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

#define BASEDIR "\\benchopen"

static int nprocs;
static int open_failed;
static int open_retries;
static char **fnames;
static int num_connected;

struct benchopen_state {
	TALLOC_CTX *mem_ctx;
	struct event_context *ev;
	struct smbcli_state *cli;
	struct smbcli_tree *tree;
	int client_num;
	int fnum;
	int file_num;
	int count;
	int lastcount;
	BOOL waiting_open, waiting_close;
	union smb_open open_parms;
	union smb_close close_parms;
	struct smbcli_request *req_open;
	struct smbcli_request *req_close;
	struct smb_composite_connect reconnect;

	/* these are used for reconnections */
	int dest_port;
	const char *dest_host;
	const char *called_name;
	const char *service_type;
};

static void next_open(struct benchopen_state *state);
static void reopen_connection(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private_data);


/*
  complete an async reconnect
 */
static void reopen_connection_complete(struct composite_context *ctx)
{
	struct benchopen_state *state = (struct benchopen_state *)ctx->async.private_data;
	NTSTATUS status;
	struct smb_composite_connect *io = &state->reconnect;

	status = smb_composite_connect_recv(ctx, state->mem_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		event_add_timed(state->ev, state->mem_ctx, 
				timeval_current_ofs(1,0), 
				reopen_connection, state);
		return;
	}

	state->tree = io->out.tree;

	num_connected++;

	DEBUG(0,("reconnect to %s finished (%u connected)\n", state->dest_host,
		 num_connected));

	next_open(state);
}

	

/*
  reopen a connection
 */
static void reopen_connection(struct event_context *ev, struct timed_event *te, 
			      struct timeval t, void *private_data)
{
	struct benchopen_state *state = (struct benchopen_state *)private_data;
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
	state->fnum = -1;
	state->waiting_open = False;
	state->waiting_close = False;

	ctx = smb_composite_connect_send(io, state->mem_ctx, state->ev);
	if (ctx == NULL) {
		DEBUG(0,("Failed to setup async reconnect\n"));
		exit(1);
	}

	ctx->async.fn = reopen_connection_complete;
	ctx->async.private_data = state;
}

static void open_completed(struct smbcli_request *req);
static void close_completed(struct smbcli_request *req);


static void next_open(struct benchopen_state *state)
{
	state->count++;

	state->file_num = (state->file_num+1) % (nprocs+1);
	state->open_parms.ntcreatex.level = RAW_OPEN_NTCREATEX;
	state->open_parms.ntcreatex.in.flags = 0;
	state->open_parms.ntcreatex.in.root_fid = 0;
	state->open_parms.ntcreatex.in.access_mask = SEC_RIGHTS_FILE_ALL;
	state->open_parms.ntcreatex.in.file_attr = FILE_ATTRIBUTE_NORMAL;
	state->open_parms.ntcreatex.in.alloc_size = 0;
	state->open_parms.ntcreatex.in.share_access = 0;
	state->open_parms.ntcreatex.in.open_disposition = NTCREATEX_DISP_OVERWRITE_IF;
	state->open_parms.ntcreatex.in.create_options = 0;
	state->open_parms.ntcreatex.in.impersonation = 0;
	state->open_parms.ntcreatex.in.security_flags = 0;
	state->open_parms.ntcreatex.in.fname = fnames[state->file_num];

	state->req_open = smb_raw_open_send(state->tree, &state->open_parms);
	state->req_open->async.fn = open_completed;
	state->req_open->async.private = state;
	state->waiting_open = True;

	if (state->fnum == -1) {
		return;
	}

	state->close_parms.close.level = RAW_CLOSE_CLOSE;
	state->close_parms.close.in.file.fnum = state->fnum;
	state->close_parms.close.in.write_time = 0;

	state->req_close = smb_raw_close_send(state->tree, &state->close_parms);
	state->req_close->async.fn = close_completed;
	state->req_close->async.private = state;
	state->waiting_close = True;
}

/*
  called when a open completes
*/
static void open_completed(struct smbcli_request *req)
{
	struct benchopen_state *state = (struct benchopen_state *)req->async.private;
	TALLOC_CTX *tmp_ctx = talloc_new(state->mem_ctx);
	NTSTATUS status;

	status = smb_raw_open_recv(req, tmp_ctx, &state->open_parms);

	talloc_free(tmp_ctx);

	state->req_open = NULL;

	if (NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_LOCAL_DISCONNECT)) {
		talloc_free(state->tree);
		talloc_free(state->cli);
		state->tree = NULL;
		state->cli = NULL;
		num_connected--;	
		DEBUG(0,("reopening connection to %s\n", state->dest_host));
		event_add_timed(state->ev, state->mem_ctx, 
				timeval_current_ofs(1,0), 
				reopen_connection, state);
		return;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
		open_retries++;
		state->req_open = smb_raw_open_send(state->tree, &state->open_parms);
		state->req_open->async.fn = open_completed;
		state->req_open->async.private = state;
		return;
	}

	if (!NT_STATUS_IS_OK(status)) {
		open_failed++;
		DEBUG(0,("open failed - %s\n", nt_errstr(status)));
		return;
	}

	state->fnum = state->open_parms.ntcreatex.out.file.fnum;
	state->waiting_open = False;

	if (!state->waiting_close) {
		next_open(state);
	}
}	

/*
  called when a close completes
*/
static void close_completed(struct smbcli_request *req)
{
	struct benchopen_state *state = (struct benchopen_state *)req->async.private;
	NTSTATUS status = smbcli_request_simple_recv(req);

	state->req_close = NULL;

	if (NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_LOCAL_DISCONNECT)) {
		talloc_free(state->tree);
		talloc_free(state->cli);
		state->tree = NULL;
		state->cli = NULL;
		num_connected--;	
		DEBUG(0,("reopening connection to %s\n", state->dest_host));
		event_add_timed(state->ev, state->mem_ctx, 
				timeval_current_ofs(1,0), 
				reopen_connection, state);
		return;
	}

	if (!NT_STATUS_IS_OK(status)) {
		open_failed++;
		DEBUG(0,("close failed - %s\n", nt_errstr(status)));
		return;
	}

	state->waiting_close = False;

	if (!state->waiting_open) {
		next_open(state);
	}
}	


static void report_rate(struct event_context *ev, struct timed_event *te, 
			struct timeval t, void *private_data)
{
	struct benchopen_state *state = talloc_get_type(private_data, 
							struct benchopen_state);
	int i;
	for (i=0;i<nprocs;i++) {
		printf("%5u ", (unsigned)(state[i].count - state[i].lastcount));
		state[i].lastcount = state[i].count;
	}
	printf("\r");
	fflush(stdout);
	event_add_timed(ev, state, timeval_current_ofs(1, 0), report_rate, state);
}

/* 
   benchmark open calls
*/
BOOL torture_bench_open(struct torture_context *torture)
{
	BOOL ret = True;
	TALLOC_CTX *mem_ctx = talloc_new(torture);
	int i;
	int timelimit = torture_setting_int(torture, "timelimit", 10);
	struct timeval tv;
	struct event_context *ev = event_context_find(mem_ctx);
	struct benchopen_state *state;
	int total = 0, minops=0;
	bool progress;

	progress = torture_setting_bool(torture, "progress", true);
	
	nprocs = lp_parm_int(-1, "torture", "nprocs", 4);

	state = talloc_zero_array(mem_ctx, struct benchopen_state, nprocs);

	printf("Opening %d connections\n", nprocs);
	for (i=0;i<nprocs;i++) {
		state[i].mem_ctx = talloc_new(state);
		state[i].client_num = i;
		state[i].ev = ev;
		if (!torture_open_connection_ev(&state[i].cli, i, ev)) {
			return False;
		}
		talloc_steal(mem_ctx, state);
		state[i].tree = state[i].cli->tree;
		state[i].dest_host = talloc_strdup(state[i].mem_ctx, 
						   state[i].cli->tree->session->transport->socket->hostname);
		state[i].dest_port = state[i].cli->tree->session->transport->socket->port;
		state[i].called_name  = talloc_strdup(state[i].mem_ctx,
						      state[i].cli->tree->session->transport->called.name);
		state[i].service_type = talloc_strdup(state[i].mem_ctx,
						      state[i].cli->tree->device);
	}

	num_connected = i;

	if (!torture_setup_dir(state[0].cli, BASEDIR)) {
		goto failed;
	}

	fnames = talloc_array(mem_ctx, char *, nprocs+1);
	for (i=0;i<nprocs+1;i++) {
		fnames[i] = talloc_asprintf(fnames, "%s\\file%d.dat", BASEDIR, i);
	}

	for (i=0;i<nprocs;i++) {
		state[i].fnum = -1;
		state[i].file_num = i;		
		next_open(&state[i]);
	}

	tv = timeval_current();	

	if (progress) {
		event_add_timed(ev, state, timeval_current_ofs(1, 0), report_rate, state);
	}

	printf("Running for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		event_loop_once(ev);

		if (open_failed) {
			DEBUG(0,("open failed\n"));
			goto failed;
		}
	}

	printf("%.2f ops/second (%d retries)\n", 
	       total/timeval_elapsed(&tv), open_retries);
	minops = state[0].count;
	for (i=0;i<nprocs;i++) {
		printf("[%d] %u ops\n", i, state[i].count);
		if (state[i].count < minops) minops = state[i].count;
	}
	if (minops < 0.5*total/nprocs) {
		printf("Failed: unbalanced open\n");
		goto failed;
	}

	for (i=0;i<nprocs;i++) {
		talloc_free(state[i].req_open);
		talloc_free(state[i].req_close);
		smb_raw_exit(state[i].tree->session);
	}

	smbcli_deltree(state[0].tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;

failed:
	talloc_free(mem_ctx);
	return False;
}
