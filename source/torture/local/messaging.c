/* 
   Unix SMB/CIFS implementation.

   local test for messaging code

   Copyright (C) Andrew Tridgell 2004
   
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
#include "lib/events/events.h"
#include "lib/messaging/irpc.h"
#include "torture/torture.h"
#include "torture/ui.h"


static uint32_t msg_pong;

static void ping_message(struct messaging_context *msg, void *private, 
			 uint32_t msg_type, uint32_t src, DATA_BLOB *data)
{
	NTSTATUS status;
	status = messaging_send(msg, src, msg_pong, data);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pong failed - %s\n", nt_errstr(status));
	}
}

static void pong_message(struct messaging_context *msg, void *private, 
			 uint32_t msg_type, uint32_t src, DATA_BLOB *data)
{
	int *count = private;
	(*count)++;
}

static void exit_message(struct messaging_context *msg, void *private, 
			 uint32_t msg_type, uint32_t src, DATA_BLOB *data)
{
	talloc_free(private);
	exit(0);
}

/*
  test ping speed
*/
static void test_ping_speed(struct torture_context *torture)
{
	struct event_context *ev;
	struct messaging_context *msg_client_ctx;
	struct messaging_context *msg_server_ctx;
	int ping_count = 0;
	int pong_count = 0;
	struct timeval tv;
	int timelimit = lp_parm_int(-1, "torture", "timelimit", 10);
	uint32_t msg_ping, msg_exit;
	struct torture_test *test = torture_test(torture, "ping_speed", "ping speed");

	lp_set_cmdline("lock dir", "lockdir.tmp");

	ev = event_context_init(test);

	msg_server_ctx = messaging_init(test, 1, ev);
	
	if (!msg_server_ctx) {
		torture_fail(test, "Failed to init ping messaging context");
		talloc_free(test);
		return;
	}
		
	messaging_register_tmp(msg_server_ctx, NULL, ping_message, &msg_ping);
	messaging_register_tmp(msg_server_ctx, test, exit_message, &msg_exit);

	msg_client_ctx = messaging_init(test, 2, ev);

	if (!msg_client_ctx) {
		torture_fail(test, "msg_client_ctx messaging_init() failed");
		talloc_free(test);
		return;
	}

	messaging_register_tmp(msg_client_ctx, &pong_count, pong_message, &msg_pong);

	tv = timeval_current();

	torture_comment(test, "Sending pings for %d seconds", timelimit);
	while (timeval_elapsed(&tv) < timelimit) {
		DATA_BLOB data;
		NTSTATUS status1, status2;

		data.data = discard_const_p(uint8_t, "testing");
		data.length = strlen((const char *)data.data);

		status1 = messaging_send(msg_client_ctx, 1, msg_ping, &data);
		status2 = messaging_send(msg_client_ctx, 1, msg_ping, NULL);

		if (!NT_STATUS_IS_OK(status1)) {
			torture_fail(test, "msg1 failed - %s", nt_errstr(status1));
		} else {
			ping_count++;
		}

		if (!NT_STATUS_IS_OK(status2)) {
			torture_fail(test, "msg2 failed - %s", nt_errstr(status2));
		} else {
			ping_count++;
		}

		while (ping_count > pong_count + 20) {
			event_loop_once(ev);
		}
	}

	torture_comment(test, "waiting for %d remaining replies (done %d)", 
	       ping_count - pong_count, pong_count);
	while (timeval_elapsed(&tv) < 30 && pong_count < ping_count) {
		event_loop_once(ev);
	}

	torture_comment(test, "sending exit");
	messaging_send(msg_client_ctx, 1, msg_exit, NULL);

	if (ping_count != pong_count) {
		torture_fail(test, "ping test failed! received %d, sent %d", 
		       pong_count, ping_count);
	}

	torture_comment(test, "ping rate of %.0f messages/sec", 
	       (ping_count+pong_count)/timeval_elapsed(&tv));

	talloc_free(msg_client_ctx);
	talloc_free(msg_server_ctx);

	talloc_free(ev);
}

BOOL torture_local_messaging(struct torture_context *torture) 
{
	test_ping_speed(torture);
	return torture_result(torture);
}
