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

#define BASEDIR "\\benchopen"

static int nprocs;
static int open_failed;
static int open_retries;
static char **fnames;

struct benchopen_state {
	struct smbcli_state *cli;
	int fnum;
	int file_num;
	int count;
	BOOL waiting_open, waiting_close;
	union smb_open open_parms;
	union smb_close close_parms;
	struct smbcli_request *req_open;
	struct smbcli_request *req_close;
};

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

	state->req_open = smb_raw_open_send(state->cli->tree, &state->open_parms);
	state->req_open->async.fn = open_completed;
	state->req_open->async.private = state;
	state->waiting_open = True;

	if (state->fnum == -1) {
		return;
	}

	state->close_parms.close.level = RAW_CLOSE_CLOSE;
	state->close_parms.close.in.file.fnum = state->fnum;
	state->close_parms.close.in.write_time = 0;

	state->req_close = smb_raw_close_send(state->cli->tree, &state->close_parms);
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
	TALLOC_CTX *tmp_ctx = talloc_new(state->cli);
	NTSTATUS status;

	status = smb_raw_open_recv(req, tmp_ctx, &state->open_parms);

	talloc_free(tmp_ctx);

	state->req_open = NULL;

	if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
		open_retries++;
		state->req_open = smb_raw_open_send(state->cli->tree, &state->open_parms);
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
	int total = 0, loops=0, minops=0;
	
	nprocs = lp_parm_int(-1, "torture", "nprocs", 4);

	state = talloc_zero_array(mem_ctx, struct benchopen_state, nprocs);

	printf("Opening %d connections\n", nprocs);
	for (i=0;i<nprocs;i++) {
		if (!torture_open_connection_ev(&state[i].cli, i, ev)) {
			return False;
		}
		talloc_steal(mem_ctx, state);
	}

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

	printf("Running for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		event_loop_once(ev);

		total = 0;
		for (i=0;i<nprocs;i++) {
			total += state[i].count;
		}

		if (open_failed) {
			DEBUG(0,("open failed after %d opens\n", total));
			goto failed;
		}

		if (loops++ % 1000 != 0) continue;

		if (torture_setting_bool(torture, "progress", true)) {
			printf("%.2f ops/second (%d retries)\r", 
			       total/timeval_elapsed(&tv), open_retries);
			fflush(stdout);
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
		smb_raw_exit(state[i].cli->session);
	}

	smbcli_deltree(state[0].cli->tree, BASEDIR);
	talloc_free(mem_ctx);
	return ret;

failed:
	for (i=0;i<nprocs;i++) {
		talloc_free(state[i].req_open);
		talloc_free(state[i].req_close);
		smb_raw_exit(state[i].cli->session);
	}
	smbcli_deltree(state[0].cli->tree, BASEDIR);
	talloc_free(mem_ctx);
	return False;
}
