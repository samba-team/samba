/* 
   Unix SMB/CIFS implementation.

   ping pong test
   filename is specified by
	 --option=torture:filename=...

   number of locks is specified by
	 --option=torture:num_locks=...

   locktimeout is specified in ms by
	 --option=torture:locktimeout=...

       default is 100 seconds
       if set to 0 pingpong will instead loop trying the lock operation
       over and over until it completes.

   reading from the file can be enabled with
	 --option=torture:read=True

   writing to the file can be enabled with
	 --option=torture:write=True


   Copyright (C) Ronnie Sahlberg

   Significantly based on and borrowed from lockbench.c by
   Copyright (C) Andrew Tridgell 2006
   
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


static BOOL do_reads;
static BOOL do_writes;

static int lock_failed;

enum lock_stage {LOCK_INITIAL, LOCK_LOCK, LOCK_UNLOCK};

struct pingpong_state {
	struct event_context *ev;
	struct smbcli_tree *tree;
	TALLOC_CTX *mem_ctx;
	int fnum;
	enum lock_stage stage;
	int num_locks;
	int lock_offset;
	int unlock_offset;
	struct smbcli_request *req;
	int count;
	int lastcount;
	int lock_timeout;
	uint8_t c;
	uint8_t incr;
	uint8_t last_incr;
	uint8_t *val;
};



static void lock_completion(struct smbcli_request *);

/*
  send the next lock request
*/
static void lock_send(struct pingpong_state *state, BOOL retry_lock)
{
	union smb_lock io;
	struct smb_lock_entry lock;


	/* we have completed one lock/unlock pair */
	if (state->stage == LOCK_UNLOCK) {
		if ( (state->count > state->num_locks)
		   &&(state->incr != state->last_incr) ) {
			state->last_incr = state->incr;
			printf("data increment = %u\n", state->incr);
		}
	}

	switch (state->stage) {
	case LOCK_INITIAL:
		io.lockx.in.ulock_cnt = 0;
		io.lockx.in.lock_cnt = 1;
		state->lock_offset = -1;
		state->unlock_offset = 0;
		lock.offset = (state->lock_offset+1)%state->num_locks;
		break;
	case LOCK_LOCK:
		io.lockx.in.ulock_cnt = 0;
		io.lockx.in.lock_cnt = 1;
		if (!retry_lock) {
			state->lock_offset = (state->lock_offset+1)%state->num_locks;
		}
		lock.offset = (state->lock_offset+1)%state->num_locks;
		break;
	case LOCK_UNLOCK:
		state->count++;
		io.lockx.in.ulock_cnt = 1;
		io.lockx.in.lock_cnt = 0;
		lock.offset = state->lock_offset;
		break;
	}

	lock.count = 1;
	lock.pid = state->tree->session->pid;

	io.lockx.level = RAW_LOCK_LOCKX;
	io.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
	io.lockx.in.timeout = state->lock_timeout;
	io.lockx.in.locks = &lock;
	io.lockx.in.file.fnum = state->fnum;

	state->req = smb_raw_lock_send(state->tree, &io);
	if (state->req == NULL) {
		DEBUG(0,("Failed to setup lock\n"));
		lock_failed++;
	}
	state->req->async.private = state;
	state->req->async.fn      = lock_completion;
}


/*
  called when a write completes
*/
static void write_completion(struct smbcli_request *req)
{
	struct pingpong_state *state = (struct pingpong_state *)req->async.private;
	NTSTATUS status = smbcli_request_simple_recv(req);

	if (!NT_STATUS_IS_OK(status)) {
		printf("write failed\n");
		exit(1);
	}

	lock_send(state, False);
}


static void write_send(struct pingpong_state *state) 
{
	union smb_write io;

	io.generic.level = RAW_WRITE_WRITEX;
	io.writex.in.file.fnum = state->fnum;
	io.writex.in.offset = state->lock_offset;
	io.writex.in.wmode = 0;
	io.writex.in.remaining = 0;
	io.writex.in.count = 1;
	state->c = state->val[state->lock_offset]+1;
	io.writex.in.data = &state->c;

	state->req = smb_raw_write_send(state->tree, &io);
	if (state->req == NULL) {
		DEBUG(0,("Failed to setup write\n"));
		exit(1);
	}
	state->req->async.private = state;
	state->req->async.fn      = write_completion;
}
	

/*
  called when a read completes
*/
static void read_completion(struct smbcli_request *req)
{
	struct pingpong_state *state = (struct pingpong_state *)req->async.private;
	NTSTATUS status = smbcli_request_simple_recv(req);

	if (!NT_STATUS_IS_OK(status)) {
		printf("read failed\n");
		exit(1);
	}

	state->req = NULL;

	state->incr = state->c - state->val[state->lock_offset];
	state->val[state->lock_offset] = state->c;

	/* a read just completed, now spawn off to the write handler, if 
	   write is enabled.   othervise spawn off to the lock handler
	   to proceed to unlock the previous lock
	*/
	if (do_writes) {
		write_send(state);
		return;
	}
	lock_send(state, False);
}


static void read_send(struct pingpong_state *state) 
{
	union smb_read io;

	io.generic.level = RAW_READ_READX;
	io.readx.in.file.fnum = state->fnum;
	io.readx.in.mincnt = 1;
	io.readx.in.maxcnt = 1;
	io.readx.in.offset = state->lock_offset;
	io.readx.in.remaining = 0;
	io.readx.in.read_for_execute = False;
	io.readx.out.data = &state->c;

	state->req = smb_raw_read_send(state->tree, &io);
	if (state->req == NULL) {
		DEBUG(0,("Failed to setup read\n"));
		exit(1);
	}
	state->req->async.private = state;
	state->req->async.fn      = read_completion;
}


/*
  called when a lock completes
*/
static void lock_completion(struct smbcli_request *req)
{
	struct pingpong_state *state = (struct pingpong_state *)req->async.private;
	NTSTATUS status = smbcli_request_simple_recv(req);
	state->req = NULL;
	/* If we dont use timeouts and we got file lock conflict
	   just try the lock again.
	*/
	if (state->lock_timeout==0) {
		if ( (NT_STATUS_EQUAL(NT_STATUS_FILE_LOCK_CONFLICT, status))
		   ||(NT_STATUS_EQUAL(NT_STATUS_LOCK_NOT_GRANTED, status)) ) {
			lock_send(state, True);
			return;
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		lock_failed++;
		return;
	}

	switch (state->stage) {
	case LOCK_INITIAL:
		state->stage = LOCK_LOCK;
		break;
	case LOCK_LOCK:
		state->stage = LOCK_UNLOCK;
		break;
	case LOCK_UNLOCK:
		state->stage = LOCK_LOCK;
		break;
	}

	/* if we just completed a lock  and we have read enabled
	   then spawn off to the read handler instead of sending an unlock
	*/
	if ( (state->stage == LOCK_UNLOCK)
	   &&(do_reads) ){
		read_send(state);
		return;
	}
	/* if we just completed a lock  and we we didnt have reads enabled
	   but we do have write enabled, thenspawn off to the write handler
	   instead of sending an unlock
	*/
	if ( (state->stage == LOCK_UNLOCK)
	   &&(do_writes) ){
		write_send(state);
		return;
	}

	lock_send(state, False);
}

static void report_rate(struct event_context *ev, struct timed_event *te, 
			struct timeval t, void *private_data)
{
	struct pingpong_state *state = talloc_get_type(private_data, 
							struct pingpong_state);
	printf("%5u ", 2*(unsigned)(state->count - state->lastcount));
	state->lastcount = state->count;

	printf("\r");
	fflush(stdout);
	event_add_timed(ev, state, timeval_current_ofs(1, 0), report_rate, state);
}

/* 
   ping pong
*/
BOOL torture_ping_pong(struct torture_context *torture)
{
	const char *fn;
	TALLOC_CTX *mem_ctx = talloc_new(torture);
	struct event_context *ev = event_context_find(mem_ctx);
	int timelimit = torture_setting_int(torture, "timelimit", 10);
	struct timeval tv;
	struct pingpong_state *state;
	struct smbcli_state *cli;
	int num_locks;

	fn = lp_parm_string(-1, "torture", "filename");
	if (fn == NULL) {
		DEBUG(0,("You must specify the filename using --option=torture:filename=...\n"));
		return false;
	}

	num_locks = lp_parm_int(-1, "torture", "num_locks", -1);
	if (num_locks == -1) {
		DEBUG(0,("You must specify num_locks using --option=torture:num_locks=...\n"));
		return false;
	}

	do_reads  = lp_parm_bool(-1, "torture", "read", False);
	do_writes = lp_parm_bool(-1, "torture", "write", False);

	if (!torture_open_connection_ev(&cli, 0, ev)) {
		DEBUG(0,("Could not open connection to share\n"));
		return False;
	}

	
	state            = talloc_zero(mem_ctx, struct pingpong_state);
	state->ev        = ev;
	state->tree      = cli->tree;
	state->num_locks = num_locks;
	state->lock_timeout =  lp_parm_int(-1, "torture", "lock_timeout", 100000);
	state->fnum      = smbcli_open(state->tree, fn, O_RDWR|O_CREAT, DENY_NONE);
	if (state->fnum == -1) {
		printf("Failed to open %s\n", fn);
		exit(1);
	}
	state->val = talloc_zero_array(state, uint8_t, state->num_locks+1);
	state->stage = LOCK_INITIAL;
	lock_send(state, False);

	tv = timeval_current();	

	printf("Running for %d seconds\n", timelimit);
	event_add_timed(ev, state, timeval_current_ofs(1, 0), report_rate, state);
	while (timeval_elapsed(&tv) < timelimit) {
		event_loop_once(ev);

		if (lock_failed) {
			DEBUG(0,("locking failed\n"));
			goto failed;
		}
	}


failed:
	talloc_free(mem_ctx);
	return true;
}
