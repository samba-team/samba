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

static void pong_message(void *msg_ctx, void *private, 
			 uint32_t msg_type, servid_t src, DATA_BLOB *data)
{
	int *count = private;
	(*count)++;
}

/*
  test ping speed
*/
static BOOL test_ping_speed(TALLOC_CTX *mem_ctx)
{
	struct event_context *ev = event_context_init(mem_ctx);
	void *msg_ctx1, *msg_ctx2;
	int ping_count = 0;
	int pong_count = 0;
	BOOL ret = True;

	msg_ctx1 = messaging_init(mem_ctx, 1, ev);
	msg_ctx2 = messaging_init(mem_ctx, 2, ev);

	messaging_register(msg_ctx2, &pong_count, MSG_PONG, pong_message);

	start_timer();

	printf("Sending pings for 10 seconds\n");
	while (end_timer() < 10.0) {
		DATA_BLOB data;
		data.data = "testing";
		data.length = strlen(data.data);

		messaging_send(msg_ctx2, 1, MSG_PING, &data);
		messaging_send(msg_ctx2, 1, MSG_PING, NULL);
		ping_count += 2;
		event_loop_once(ev);
		event_loop_once(ev);
	}

	printf("waiting for %d remaining replies\n", ping_count - pong_count);
	while (end_timer() < 30 && pong_count < ping_count) {
		event_loop_once(ev);
	}

	if (ping_count != pong_count) {
		printf("ping test failed! received %d, sent %d\n", pong_count, ping_count);
		ret = False;
	}

	printf("ping rate of %.0f messages/sec\n", (ping_count+pong_count)/end_timer());

	talloc_free(msg_ctx1);
	talloc_free(msg_ctx2);

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
