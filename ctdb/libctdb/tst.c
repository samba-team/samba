#include <stdio.h>
#include <stdint.h>
#include <poll.h>
#include <fcntl.h>
#include "lib/tdb/include/tdb.h"
#include "include/ctdb.h"

void msg_h(struct ctdb_context *ctdb, uint64_t srvid, TDB_DATA data, void *private_data)
{
	printf("Message received on port %d : %s\n", (int)srvid, data.dptr);
}


void rm_cb(int32_t status, int32_t recmaster, void *private_data)
{
	printf("recmaster:%d\n", recmaster);
}

int main(int argc, char *argv[])
{
	struct ctdb_context *ctdb_context;
	ctdb_handle *handle;
	struct pollfd pfd;
	int ret;
	TDB_DATA msg;

	ctdb_context = ctdb_connect("/tmp/ctdb.socket");


	pfd.fd = ctdb_get_fd(ctdb_context);

	handle = ctdb_set_message_handler_send(ctdb_context, 55, NULL, msg_h, NULL);
	if (handle == NULL) {
		printf("Failed to register message port\n");
		exit(10);
	}
	ret = ctdb_set_message_handler_recv(ctdb_context, ctdb_handle);
	if (ret != 0) {
		printf("Failed to receive set_message_handler reply\n");
		exit(10);
	}

	msg.dptr="HelloWorld";
	msg.dsize = strlen(msg.dptr);

	ret = ctdb_send_message(ctdb_context, 0, 55, msg);
	if (ret != 0) {
		printf("Failed to send message. Aborting\n");
		exit(10);
	}

	handle = ctdb_getrecmaster_send(ctdb_context, 0, rm_cb, NULL);
	if (handle == NULL) {
		printf("Failed to send get_recmaster control\n");
		exit(10);
	}


	for (;;) {

	  pfd.events = ctdb_which_events(ctdb_context);
	  if (poll(&pfd, 1, -1) < 0) {
	    printf("Poll failed");
	    exit(10);
	  }
	  ctdb_service(ctdb_context);
	}

	return 0;
}
