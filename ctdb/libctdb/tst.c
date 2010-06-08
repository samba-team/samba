/*
 * Example program to demonstrate the libctdb api
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This program needs to be linked with libtdb and libctdb
 * (You need these packages installed: libtdb libtdb-devel
 *  ctdb and ctdb-devel)
 *
 * This program can then be compiled using
 *    gcc -o tst tst.c -ltdb -lctdb
 *
 *
 */
#include <stdio.h>
#include <stdint.h>
#include <poll.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <err.h>
#include <stdbool.h>
#include <syslog.h>
#include <tdb.h>
#include <ctdb.h>

TDB_DATA key;

void msg_h(struct ctdb_connection *ctdb, uint64_t srvid, TDB_DATA data, void *private_data)
{
	printf("Message received on port %d : %s\n", (int)srvid, data.dptr);
}

static void pnn_cb(struct ctdb_connection *ctdb,
		   struct ctdb_request *req, void *private)
{
	bool status;
	uint32_t pnn;

	status = ctdb_getpnn_recv(ctdb, req, &pnn);
	ctdb_request_free(ctdb, req);
	if (!status) {
		printf("Error reading PNN\n");
		return;
	}
	printf("pnn:%d\n", pnn);
}

static void rm_cb(struct ctdb_connection *ctdb,
		  struct ctdb_request *req, void *private)
{
	bool status;
	uint32_t rm;

	status = ctdb_getrecmaster_recv(ctdb, req, &rm);
	ctdb_request_free(ctdb, req);
	if (!status) {
		printf("Error reading RECMASTER\n");
		return;
	}

	printf("GETRECMASTER ASYNC: recmaster:%d\n", rm);
}

/*
 * example on how to first read(non-existing recortds are implicitely created
 * on demand) a record and change it in the callback.
 * This forms the atom for the read-modify-write cycle.
 *
 * Pure read, or pure write are just special cases of this cycle.
 */
static void rrl_cb(struct ctdb_db *ctdb_db,
		   struct ctdb_lock *lock, TDB_DATA outdata, void *private)
{
	TDB_DATA data;
	char tmp[256];
	bool *rrl_cb_called = private;

	*rrl_cb_called = true;

	if (!lock) {
		printf("rrl_cb returned error\n");
		return;
	}

	printf("rrl size:%d data:%.*s\n", outdata.dsize,
	       outdata.dsize, outdata.dptr);
	if (outdata.dsize == 0) {
		tmp[0] = 0;
	} else {
		strcpy(tmp, outdata.dptr);
	}
	strcat(tmp, "*");

	data.dptr  = tmp;
	data.dsize = strlen(tmp) + 1;
	if (!ctdb_writerecord(ctdb_db, lock, data))
		printf("Error writing data!\n");

	/* Release the lock as quickly as possible */
	ctdb_release_lock(ctdb_db, lock);

	printf("Wrote new record : %s\n", tmp);

}

static bool registered = false;
void message_handler_cb(struct ctdb_connection *ctdb,
			struct ctdb_request *req, void *private)
{
	if (!ctdb_set_message_handler_recv(ctdb, req)) {
		err(1, "registering message");
	}
	ctdb_request_free(ctdb, req);
	printf("Message handler registered\n");
	registered = true;
}

int main(int argc, char *argv[])
{
	struct ctdb_connection *ctdb_connection;
	struct ctdb_request *handle;
	struct ctdb_db *ctdb_db_context;
	struct pollfd pfd;
	uint32_t recmaster;
	TDB_DATA msg;
	bool rrl_cb_called = false;

	ctdb_log_level = LOG_DEBUG;
	ctdb_connection = ctdb_connect("/tmp/ctdb.socket",
				       ctdb_log_file, stderr);
	if (!ctdb_connection)
		err(1, "Connecting to /tmp/ctdb.socket");

	pfd.fd = ctdb_get_fd(ctdb_connection);

	handle = ctdb_set_message_handler_send(ctdb_connection, 55, msg_h,
					       message_handler_cb, NULL);
	if (handle == NULL) {
		printf("Failed to register message port\n");
		exit(10);
	}

	/* Hack for testing: this makes sure registration goes out. */
	while (!registered) {
		ctdb_service(ctdb_connection, POLLIN|POLLOUT);
	}

	msg.dptr="HelloWorld";
	msg.dsize = strlen(msg.dptr);

	if (!ctdb_send_message(ctdb_connection, 0, 55, msg)) {
		printf("Failed to send message. Aborting\n");
		exit(10);
	}

	handle = ctdb_getrecmaster_send(ctdb_connection, 0, rm_cb, NULL);
	if (handle == NULL) {
		printf("Failed to send get_recmaster control\n");
		exit(10);
	}

	ctdb_db_context = ctdb_attachdb(ctdb_connection, "test_test.tdb",
					false, 0);
	if (!ctdb_db_context) {
		printf("Failed to attach to database\n");
		exit(10);
	}

	/*
	 * SYNC call with callback to read the recmaster
	 * calls the blocking sync function.
	 * Avoid this mode for performance critical tasks
	 */
	if (!ctdb_getrecmaster(ctdb_connection, CTDB_CURRENT_NODE, &recmaster)) {
		printf("Failed to receive response to getrecmaster\n");
		exit(10);
	}
	printf("GETRECMASTER SYNC: recmaster:%d\n", recmaster);


	handle = ctdb_getpnn_send(ctdb_connection, CTDB_CURRENT_NODE,
				  pnn_cb, NULL);
	if (handle == NULL) {
		printf("Failed to send get_pnn control\n");
		exit(10);
	}

	/* In the non-contended case the callback might be invoked
	 * immediately, before ctdb_readrecordlock_async() returns.
	 * In the contended case the callback will be invoked later.
	 *
	 * Normally an application would not care whether the callback
	 * has already been invoked here or not, but if the application
	 * needs to know, it can use the *private_data pointer
	 * to pass data through to the callback and back.
	 */
	if (!ctdb_readrecordlock_async(ctdb_db_context, key,
				       rrl_cb, &rrl_cb_called)) {
		printf("Failed to send READRECORDLOCK\n");
		exit(10);
	}
	if (!rrl_cb_called) {
		printf("READRECORDLOCK is async\n");
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
