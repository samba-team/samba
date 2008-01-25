/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2008
   
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

/*
  test offline files
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
#include "libcli/resolve/resolve.h"
#include "param/param.h"

#define BASEDIR "\\testoffline"

static int nconnections;
static int numstates;
static int num_connected;
static int test_failed;
extern int torture_numops;
static bool test_finished;

#define FILE_SIZE 8192

enum offline_op {OP_LOADFILE, OP_SAVEFILE, OP_SETOFFLINE, OP_GETOFFLINE, OP_ENDOFLIST};

struct offline_state {
	struct torture_context *tctx;
	struct event_context *ev;
	struct smbcli_tree *tree;
	TALLOC_CTX *mem_ctx;
	int fnum;
	uint32_t count;
	uint32_t lastcount;
	uint32_t fnumber;
	char *fname;
	struct smb_composite_loadfile *loadfile;
	struct smb_composite_savefile *savefile;
	struct smbcli_request *req;
	enum offline_op op;
};

static void test_offline(struct offline_state *state);


static char *filename(TALLOC_CTX *ctx, int i)
{
	char *s = talloc_asprintf(ctx, BASEDIR "\\file%u.dat", i);
	return s;
}


/*
  called when a loadfile completes
 */
static void loadfile_callback(struct composite_context *ctx) 
{
	struct offline_state *state = ctx->async.private_data;
	NTSTATUS status;
	int i;

	status = smb_composite_loadfile_recv(ctx, state->mem_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to read file '%s' - %s\n", 
		       state->loadfile->in.fname, nt_errstr(status));
		test_failed++;
	}

	/* check the data is correct */
	if (state->loadfile->out.size != FILE_SIZE) {
		printf("Wrong file size %u - expected %u\n", 
		       state->loadfile->out.size, FILE_SIZE);
		test_failed++;
		return;
	}

	for (i=0;i<FILE_SIZE;i++) {
		if (state->loadfile->out.data[i] != state->fnumber % 256) {
			printf("Bad data in file %u\n", state->fnumber);
			test_failed++;
			return;
		}
	}
	
	talloc_steal(state->loadfile, state->loadfile->out.data);

	state->count++;
	talloc_free(state->loadfile);
	state->loadfile = NULL;

	if (!test_finished) {
		test_offline(state);
	}
}


/*
  called when a savefile completes
 */
static void savefile_callback(struct composite_context *ctx) 
{
	struct offline_state *state = ctx->async.private_data;
	NTSTATUS status;

	status = smb_composite_savefile_recv(ctx);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to save file '%s' - %s\n", 
		       state->savefile->in.fname, nt_errstr(status));
		test_failed++;
	}

	state->count++;
	talloc_free(state->savefile);
	state->savefile = NULL;

	if (!test_finished) {
		test_offline(state);
	}
}


/*
  called when a setoffline completes
 */
static void setoffline_callback(struct smbcli_request *req) 
{
	struct offline_state *state = req->async.private;
	NTSTATUS status;

	status = smbcli_request_simple_recv(req);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to set offline file '%s' - %s\n", 
		       state->fname, nt_errstr(status));
		test_failed++;
	}

	state->req = NULL;
	state->count++;

	if (!test_finished) {
		test_offline(state);
	}
}


/*
  called when a getoffline completes
 */
static void getoffline_callback(struct smbcli_request *req) 
{
	struct offline_state *state = req->async.private;
	NTSTATUS status;
	union smb_fileinfo io;

	io.standard.level = RAW_FILEINFO_GETATTR;
	
	status = smb_raw_pathinfo_recv(req, state->mem_ctx, &io);
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to get offline file '%s' - %s\n", 
		       state->fname, nt_errstr(status));
		test_failed++;
	}

	state->req = NULL;
	state->count++;

	if (!test_finished) {
		test_offline(state);
	}
}


/*
  send the next offline file fetch request
*/
static void test_offline(struct offline_state *state)
{
	struct composite_context *ctx;

	state->op = (enum offline_op) (random() % OP_ENDOFLIST);
	
	state->fnumber = random() % torture_numops;
	talloc_free(state->fname);
	state->fname = filename(state->mem_ctx, state->fnumber);

	switch (state->op) {
	case OP_LOADFILE:
		state->loadfile = talloc_zero(state->mem_ctx, struct smb_composite_loadfile);
		state->loadfile->in.fname = state->fname;
	
		ctx = smb_composite_loadfile_send(state->tree, state->loadfile);
		if (ctx == NULL) {
			printf("Failed to setup loadfile for %s\n", state->fname);
			test_failed = true;
		}

		talloc_steal(state->loadfile, ctx);

		ctx->async.fn = loadfile_callback;
		ctx->async.private_data = state;
		break;

	case OP_SAVEFILE:
		state->savefile = talloc_zero(state->mem_ctx, struct smb_composite_savefile);

		state->savefile->in.fname = state->fname;
		state->savefile->in.data  = talloc_size(state->savefile, FILE_SIZE);
		state->savefile->in.size  = FILE_SIZE;
		memset(state->savefile->in.data, state->fnumber, FILE_SIZE);
	
		ctx = smb_composite_savefile_send(state->tree, state->savefile);
		if (ctx == NULL) {
			printf("Failed to setup savefile for %s\n", state->fname);
			test_failed = true;
		}

		talloc_steal(state->savefile, ctx);

		ctx->async.fn = savefile_callback;
		ctx->async.private_data = state;
		break;

	case OP_SETOFFLINE: {
		union smb_setfileinfo io;
		ZERO_STRUCT(io);
		io.setattr.level = RAW_SFILEINFO_SETATTR;
		io.setattr.in.attrib = FILE_ATTRIBUTE_OFFLINE;
		io.setattr.in.file.path = state->fname;

		state->req = smb_raw_setpathinfo_send(state->tree, &io);
		if (state->req == NULL) {
			printf("Failed to setup setoffline for %s\n", state->fname);
			test_failed = true;
		}
		
		state->req->async.fn = setoffline_callback;
		state->req->async.private = state;
		break;
	}

	case OP_GETOFFLINE: {
		union smb_fileinfo io;
		ZERO_STRUCT(io);
		io.standard.level = RAW_FILEINFO_GETATTR;
		io.standard.in.file.path = state->fname;

		state->req = smb_raw_pathinfo_send(state->tree, &io);
		if (state->req == NULL) {
			printf("Failed to setup getoffline for %s\n", state->fname);
			test_failed = true;
		}
		
		state->req->async.fn = getoffline_callback;
		state->req->async.private = state;
		break;
	}

	default:
		printf("bad operation??\n");
		break;
	}
}




static void echo_completion(struct smbcli_request *req)
{
	struct offline_state *state = (struct offline_state *)req->async.private;
	NTSTATUS status = smbcli_request_simple_recv(req);
	if (NT_STATUS_EQUAL(status, NT_STATUS_END_OF_FILE) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_LOCAL_DISCONNECT)) {
		talloc_free(state->tree);
		state->tree = NULL;
		num_connected--;	
		DEBUG(0,("lost connection\n"));
		test_failed++;
	}
}

static void report_rate(struct event_context *ev, struct timed_event *te, 
			struct timeval t, void *private_data)
{
	struct offline_state *state = talloc_get_type(private_data, 
							struct offline_state);
	int i;
	for (i=0;i<numstates;i++) {
		printf("%5u ", (unsigned)(state[i].count - state[i].lastcount));
		state[i].lastcount = state[i].count;
	}
	printf("\r");
	fflush(stdout);
	event_add_timed(ev, state, timeval_current_ofs(1, 0), report_rate, state);

	/* send an echo on each interface to ensure it stays alive - this helps
	   with IP takeover */
	for (i=0;i<numstates;i++) {
		struct smb_echo p;
		struct smbcli_request *req;

		if (!state[i].tree) {
			continue;
		}

		p.in.repeat_count = 1;
		p.in.size = 0;
		p.in.data = NULL;
		req = smb_raw_echo_send(state[i].tree->session->transport, &p);
		req->async.private = &state[i];
		req->async.fn      = echo_completion;
	}
}

/* 
   test offline file handling
*/
bool torture_test_offline(struct torture_context *torture)
{
	bool ret = true;
	TALLOC_CTX *mem_ctx = talloc_new(torture);
	int i;
	int timelimit = torture_setting_int(torture, "timelimit", 10);
	struct timeval tv;
	struct event_context *ev = event_context_find(mem_ctx);
	struct offline_state *state;
	int total = 0;
	struct smbcli_state *cli;
	bool progress;
	progress = torture_setting_bool(torture, "progress", true);

	nconnections = torture_setting_int(torture, "nconnections", 4);
	numstates = nconnections * 5;

	state = talloc_zero_array(mem_ctx, struct offline_state, numstates);

	printf("Opening %d connections with %d simultaneous operations\n", nconnections, numstates);
	for (i=0;i<nconnections;i++) {
		state[i].tctx = torture;
		state[i].mem_ctx = talloc_new(state);
		state[i].ev = ev;
		if (!torture_open_connection_ev(&cli, i, torture, ev)) {
			return false;
		}
		state[i].tree = cli->tree;
	}

	/* the others are repeats on the earlier connections */
	for (i=nconnections;i<numstates;i++) {
		state[i].tctx = torture;
		state[i].mem_ctx = talloc_new(state);
		state[i].ev = ev;
		state[i].tree = state[i % nconnections].tree;
	}

	num_connected = i;

	if (!torture_setup_dir(cli, BASEDIR)) {
		goto failed;
	}

	/* pre-create files */
	for (i=0;i<torture_numops;i++) {
		int fnum;
		char *fname = filename(mem_ctx, i);
		char buf[FILE_SIZE];
		NTSTATUS status;

		memset(buf, i % 256, sizeof(buf));

		fnum = smbcli_open(state[0].tree, fname, O_RDWR|O_CREAT, DENY_NONE);
		if (fnum == -1) {
			printf("Failed to open %s on connection %d\n", fname, i);
			goto failed;
		}

		if (smbcli_write(state[0].tree, fnum, 0, buf, 0, sizeof(buf)) != sizeof(buf)) {
			printf("Failed to write file of size %u\n", FILE_SIZE);
			goto failed;
		}

		status = smbcli_close(state[0].tree, fnum);
		if (!NT_STATUS_IS_OK(status)) {
			printf("Close failed - %s\n", nt_errstr(status));
			goto failed;
		}

		talloc_free(fname);
	}

	/* start the async ops */
	for (i=0;i<numstates;i++) {
		test_offline(&state[i]);
	}

	tv = timeval_current();	

	if (progress) {
		event_add_timed(ev, state, timeval_current_ofs(1, 0), report_rate, state);
	}

	printf("Running for %d seconds\n", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		event_loop_once(ev);

		if (test_failed) {
			DEBUG(0,("test failed\n"));
			goto failed;
		}
	}

	printf("%.2f ops/second\n", total/timeval_elapsed(&tv));

	printf("Waiting for completion\n");
	test_finished = true;
	for (i=0;i<numstates;i++) {
		while (state[i].loadfile || 
		       state[i].savefile ||
		       state[i].req) {
			event_loop_once(ev);
		}
	}	

	smbcli_deltree(state[0].tree, BASEDIR);
	talloc_free(mem_ctx);
	printf("\n");
	return ret;

failed:
	talloc_free(mem_ctx);
	return false;
}
