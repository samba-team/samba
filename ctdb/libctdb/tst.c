#include <stdio.h>
#include <stdint.h>
#include <poll.h>
#include <fcntl.h>
#include <stdlib.h>
#include <err.h>
#include "lib/tdb/include/tdb.h"
#include "include/ctdb.h"

void msg_h(struct ctdb_connection *ctdb, uint64_t srvid, TDB_DATA data, void *private_data)
{
	printf("Message received on port %d : %s\n", (int)srvid, data.dptr);
}

void message_handler_cb(int status, void *private_data)
{
	printf("Message handler registered: %i\n", status);
}

void rm_cb(int status, uint32_t recmaster, void *private_data)
{
	printf("recmaster:%d\n", recmaster);
}

int main(int argc, char *argv[])
{
	struct ctdb_connection *ctdb_connection;
	struct ctdb_request *handle;
	struct pollfd pfd;
	int ret;
	TDB_DATA msg;

	ctdb_connection = ctdb_connect("/tmp/ctdb.socket");
	if (!ctdb_connection)
		err(1, "Connecting to /tmp/ctdb.socket");

	pfd.fd = ctdb_get_fd(ctdb_connection);

	handle = ctdb_set_message_handler_send(ctdb_connection, 55, message_handler_cb, msg_h, NULL);
	if (handle == NULL) {
		printf("Failed to register message port\n");
		exit(10);
	}

	msg.dptr="HelloWorld";
	msg.dsize = strlen(msg.dptr);

	ret = ctdb_send_message(ctdb_connection, 0, 55, msg);
	if (ret != 0) {
		printf("Failed to send message. Aborting\n");
		exit(10);
	}

	handle = ctdb_getrecmaster_send(ctdb_connection, 0, rm_cb, NULL);
	if (handle == NULL) {
		printf("Failed to send get_recmaster control\n");
		exit(10);
	}


	for (;;) {

	  pfd.events = ctdb_which_events(ctdb_connection);
	  if (poll(&pfd, 1, -1) < 0) {
	    printf("Poll failed");
	    exit(10);
	  }
	  if (ctdb_service(ctdb_connection, pfd.revents) < 0) {
		  err(1, "Failed to service");
	  }
	}

	return 0;
}
