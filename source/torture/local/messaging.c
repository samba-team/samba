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

enum {MY_PING=1000, MY_PONG, MY_EXIT};

static void ping_message(struct messaging_context *msg, void *private, 
			 uint32_t msg_type, servid_t src, DATA_BLOB *data)
{
	NTSTATUS status;
	status = messaging_send(msg, src, MY_PONG, data);
	if (!NT_STATUS_IS_OK(status)) {
		printf("pong failed - %s\n", nt_errstr(status));
	}
}

static void pong_message(struct messaging_context *msg, void *private, 
			 uint32_t msg_type, servid_t src, DATA_BLOB *data)
{
	int *count = private;
	(*count)++;
}

static void exit_message(struct messaging_context *msg, void *private, 
			 uint32_t msg_type, servid_t src, DATA_BLOB *data)
{
	talloc_free(private);
	exit(0);
}

/*
  test ping speed
*/
static BOOL test_ping_speed(TALLOC_CTX *mem_ctx)
{
	struct event_context *ev = event_context_init(mem_ctx);
	struct messaging_context *msg_ctx;
	int ping_count = 0;
	int pong_count = 0;
	BOOL ret = True;

	if (fork() == 0) {
		struct messaging_context *msg_ctx2 = messaging_init(mem_ctx, 1, ev);
	
		if (!msg_ctx2) {
			exit(1);
		}
		
		messaging_register(msg_ctx2, NULL, MY_PING, ping_message);
		messaging_register(msg_ctx2, mem_ctx, MY_EXIT, exit_message);
		event_loop_wait(ev);
		exit(0);
	}

	sleep(2);

	msg_ctx = messaging_init(mem_ctx, 2, ev);

	if (!msg_ctx) {
		printf("messaging_init() failed\n");
		return False;
	}

	messaging_register(msg_ctx, &pong_count, MY_PONG, pong_message);

	start_timer();

	printf("Sending pings for 10 seconds\n");
	while (end_timer() < 10.0) {
		DATA_BLOB data;
		NTSTATUS status1, status2;

		data.data = discard_const_p(char, "testing");
		data.length = strlen(data.data);

		status1 = messaging_send(msg_ctx, 1, MY_PING, &data);
		status2 = messaging_send(msg_ctx, 1, MY_PING, NULL);

		if (!NT_STATUS_IS_OK(status1)) {
			printf("msg1 failed - %s\n", nt_errstr(status1));
		}

		if (!NT_STATUS_IS_OK(status2)) {
			printf("msg2 failed - %s\n", nt_errstr(status2));
		}

		ping_count += 2;

		while (ping_count > pong_count + 20) {
			event_loop_once(ev);
		}
	}

	printf("waiting for %d remaining replies (done %d)\n", 
	       ping_count - pong_count, pong_count);
	while (end_timer() < 30 && pong_count < ping_count) {
		event_loop_once(ev);
	}

	printf("sending exit\n");
	messaging_send(msg_ctx, 1, MY_EXIT, NULL);

	if (ping_count != pong_count) {
		printf("ping test failed! received %d, sent %d\n", pong_count, ping_count);
		ret = False;
	}

	printf("ping rate of %.0f messages/sec\n", (ping_count+pong_count)/end_timer());

	talloc_free(msg_ctx);

	event_context_destroy(ev);
	return ret;
}

BOOL torture_local_messaging(int dummy) 
{
	TALLOC_CTX *mem_ctx = talloc_init("torture_local_messaging");
	BOOL ret = True;

	ret &= test_ping_speed(mem_ctx);

	talloc_free(mem_ctx);

	return True;
}
