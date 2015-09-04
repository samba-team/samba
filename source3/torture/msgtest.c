/* 
   Unix SMB/CIFS implementation.
   Copyright (C) Andrew Tridgell 2000

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
  test code for internal messaging
 */

#include "includes.h"
#include "messages.h"

static int pong_count;


/****************************************************************************
a useful function for testing the message system
****************************************************************************/
static void pong_message(struct messaging_context *msg_ctx,
			 void *private_data, 
			 uint32_t msg_type, 
			 struct server_id pid,
			 DATA_BLOB *data)
{
	pong_count++;
}

 int main(int argc, char *argv[])
{
	struct tevent_context *evt_ctx;
	struct messaging_context *msg_ctx;
	pid_t pid;
	int i, n;
	char buf[12];
	int ret;
	TALLOC_CTX *frame = talloc_stackframe();

	smb_init_locale();

	setup_logging(argv[0], DEBUG_STDOUT);

	lp_load_global(get_dyn_CONFIGFILE());

	if (!(evt_ctx = samba_tevent_context_init(NULL)) ||
	    !(msg_ctx = messaging_init(NULL, evt_ctx))) {
		fprintf(stderr, "could not init messaging context\n");
		TALLOC_FREE(frame);
		exit(1);
	}

	if (argc != 3) {
		fprintf(stderr, "%s: Usage - %s pid count\n", argv[0],
			argv[0]);
		TALLOC_FREE(frame);
		exit(1);
	}

	pid = atoi(argv[1]);
	n = atoi(argv[2]);

	messaging_register(msg_ctx, NULL, MSG_PONG, pong_message);

	for (i=0;i<n;i++) {
		messaging_send(msg_ctx, pid_to_procid(pid), MSG_PING,
			       &data_blob_null);
	}

	while (pong_count < i) {
		ret = tevent_loop_once(evt_ctx);
		if (ret != 0) {
			break;
		}
	}

	/* Ensure all messages get through to ourselves. */
	pong_count = 0;

	strlcpy(buf, "1234567890", sizeof(buf));

	for (i=0;i<n;i++) {
		messaging_send(msg_ctx, messaging_server_id(msg_ctx), MSG_PING,
			       &data_blob_null);
		messaging_send_buf(msg_ctx, messaging_server_id(msg_ctx),
				   MSG_PING,(uint8_t *)buf, 11);
	}

	/*
	 * We have to loop at least 2 times for
	 * each message as local ping messages are
	 * handled by an immediate callback, that
	 * has to be dispatched, which sends a pong
	 * message, which also has to be dispatched.
	 * Above we sent 2*n messages, which means
	 * we have to dispatch 4*n times.
	 */

	while (pong_count < n*2) {
		ret = tevent_loop_once(evt_ctx);
		if (ret != 0) {
			break;
		}
	}

	if (pong_count != 2*n) {
		fprintf(stderr, "Message count failed (%d).\n", pong_count);
	}

	/* Speed testing */

	pong_count = 0;

	{
		struct timeval tv = timeval_current();
		size_t timelimit = n;
		size_t ping_count = 0;

		printf("Sending pings for %d seconds\n", (int)timelimit);
		while (timeval_elapsed(&tv) < timelimit) {		
			if(NT_STATUS_IS_OK(messaging_send_buf(
						   msg_ctx, pid_to_procid(pid),
						   MSG_PING,
						   (uint8_t *)buf, 11)))
			   ping_count++;
			if(NT_STATUS_IS_OK(messaging_send(
						   msg_ctx, pid_to_procid(pid),
						   MSG_PING, &data_blob_null)))
			   ping_count++;

			while (ping_count > pong_count + 20) {
				ret = tevent_loop_once(evt_ctx);
				if (ret != 0) {
					break;
				}
			}
		}

		printf("waiting for %d remaining replies (done %d)\n", 
		       (int)(ping_count - pong_count), pong_count);
		while (timeval_elapsed(&tv) < 30 && pong_count < ping_count) {
			ret = tevent_loop_once(evt_ctx);
			if (ret != 0) {
				break;
			}
		}

		if (ping_count != pong_count) {
			fprintf(stderr, "ping test failed! received %d, sent "
				"%d\n", pong_count, (int)ping_count);
		}

		printf("ping rate of %.0f messages/sec\n", 
		       (ping_count+pong_count)/timeval_elapsed(&tv));
	}

	TALLOC_FREE(frame);
	return (0);
}

