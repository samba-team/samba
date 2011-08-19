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
#include <ctdb_protocol.h>

TDB_DATA key;


char *ctdb_addr_to_str(ctdb_sock_addr *addr)
{
	static char cip[128] = "";

	switch (addr->sa.sa_family) {
	case AF_INET:
		inet_ntop(addr->ip.sin_family, &addr->ip.sin_addr, cip, sizeof(cip));
		break;
	case AF_INET6:
		inet_ntop(addr->ip6.sin6_family, &addr->ip6.sin6_addr, cip, sizeof(cip));
		break;
	default:
		printf("ERROR, unknown family %u\n", addr->sa.sa_family);
	}

	return cip;
}

void print_nodemap(struct ctdb_node_map *nodemap)
{
	int i;

	printf("number of nodes:%d\n", nodemap->num);
	for (i=0;i<nodemap->num;i++) {
		printf("Node:%d Address:%s Flags:%s%s%s%s%s%s\n",
			nodemap->nodes[i].pnn,
			ctdb_addr_to_str(&nodemap->nodes[i].addr),
			nodemap->nodes[i].flags&NODE_FLAGS_DISCONNECTED?"DISCONNECTED ":"",
			nodemap->nodes[i].flags&NODE_FLAGS_UNHEALTHY?"UNHEALTHY ":"",
			nodemap->nodes[i].flags&NODE_FLAGS_PERMANENTLY_DISABLED?"ADMIN DISABLED ":"",
			nodemap->nodes[i].flags&NODE_FLAGS_BANNED?"BANNED ":"",
			nodemap->nodes[i].flags&NODE_FLAGS_DELETED?"DELETED ":"",
			nodemap->nodes[i].flags&NODE_FLAGS_STOPPED?"STOPPED ":"");
	}
}

void msg_h(struct ctdb_connection *ctdb, uint64_t srvid, TDB_DATA data, void *private_data)
{
	printf("Message received on port %llx : %s\n", srvid, data.dptr);
}

void rip_h(struct ctdb_connection *ctdb, uint64_t srvid, TDB_DATA data, void *private_data)
{
	printf("RELEASE IP message for %s\n", data.dptr);
}

void tip_h(struct ctdb_connection *ctdb, uint64_t srvid, TDB_DATA data, void *private_data)
{
	printf("TAKE IP message for %s\n", data.dptr);
}

static void gnm_cb(struct ctdb_connection *ctdb,
		   struct ctdb_request *req, void *private)
{
	bool status;
	struct ctdb_node_map *nodemap;

	status = ctdb_getnodemap_recv(ctdb, req, &nodemap);
	ctdb_request_free(req);
	if (!status) {
		printf("Error reading NODEMAP\n");
		return;
	}
	printf("ASYNC response to getnodemap:\n");
	print_nodemap(nodemap);
	ctdb_free_nodemap(nodemap);
}

void print_ips(struct ctdb_all_public_ips *ips)
{
	int i;
	
	printf("Num public ips:%d\n", ips->num);
	for (i=0; i<ips->num;i++) {
		printf("%s    hosted on node %d\n",
			ctdb_addr_to_str(&ips->ips[i].addr),
			ips->ips[i].pnn);
	}
}

static void ips_cb(struct ctdb_connection *ctdb,
		   struct ctdb_request *req, void *private)
{
	bool status;
	struct ctdb_all_public_ips *ips;

	status = ctdb_getpublicips_recv(ctdb, req, &ips);
	ctdb_request_free(req);
	if (!status) {
		printf("Error reading PUBLIC IPS\n");
		return;
	}
	printf("ASYNC response to getpublicips:\n");
	print_ips(ips);
	ctdb_free_publicips(ips);
}

static void pnn_cb(struct ctdb_connection *ctdb,
		   struct ctdb_request *req, void *private)
{
	bool status;
	uint32_t pnn;

	status = ctdb_getpnn_recv(ctdb, req, &pnn);
	ctdb_request_free(req);
	if (!status) {
		printf("Error reading PNN\n");
		return;
	}
	printf("ASYNC RESPONSE TO GETPNN:  pnn:%d\n", pnn);
}

static void rm_cb(struct ctdb_connection *ctdb,
		  struct ctdb_request *req, void *private)
{
	bool status;
	uint32_t rm;

	status = ctdb_getrecmaster_recv(ctdb, req, &rm);
	ctdb_request_free(req);
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
	ctdb_request_free(req);
	printf("Message handler registered\n");
	registered = true;
}

static int traverse_callback(struct ctdb_connection *ctdb_connection, struct ctdb_db *ctdb_db, int status, TDB_DATA key, TDB_DATA data, void *private_data)
{
	if (status == TRAVERSE_STATUS_FINISHED) {
		printf("Traverse finished\n");
		return 0;
	}
	if (status == TRAVERSE_STATUS_ERROR) {
		printf("Traverse failed\n");
		return 1;
	}

	printf("traverse callback   status:%d\n", status);
	printf("key: %d [%s]\n", key.dsize, key.dptr);
	printf("data:%d [%s]\n", data.dsize, data.dptr);

	return 0;
}


int main(int argc, char *argv[])
{
	struct ctdb_connection *ctdb_connection;
	struct ctdb_request *handle;
	struct ctdb_db *ctdb_db_context;
	struct ctdb_node_map *nodemap;
	struct pollfd pfd;
	uint32_t recmaster;
	TDB_DATA msg;
	bool rrl_cb_called = false;
	uint64_t srvid;

	ctdb_log_level = LOG_DEBUG;
	ctdb_connection = ctdb_connect("/tmp/ctdb.socket",
				       ctdb_log_file, stderr);
	if (!ctdb_connection)
		err(1, "Connecting to /tmp/ctdb.socket");

	pfd.fd = ctdb_get_fd(ctdb_connection);

	srvid = CTDB_SRVID_TEST_RANGE|55;
	handle = ctdb_set_message_handler_send(ctdb_connection, srvid,
					       msg_h, NULL,
					       message_handler_cb, &srvid);
	if (handle == NULL) {
		printf("Failed to register message port\n");
		exit(10);
	}

	/* Hack for testing: this makes sure registrations went out. */
	while (!registered) {
		ctdb_service(ctdb_connection, POLLIN|POLLOUT);
	}

	handle = ctdb_set_message_handler_send(ctdb_connection,
					       CTDB_SRVID_RELEASE_IP,
					       rip_h, NULL,
					       message_handler_cb, NULL);
	if (handle == NULL) {
		printf("Failed to register message port for RELEASE IP\n");
		exit(10);
	}

	handle = ctdb_set_message_handler_send(ctdb_connection,
					       CTDB_SRVID_TAKE_IP,
					       tip_h, NULL,
					       message_handler_cb, NULL);
	if (handle == NULL) {
		printf("Failed to register message port for TAKE IP\n");
		exit(10);
	}

	msg.dptr="HelloWorld";
	msg.dsize = strlen(msg.dptr);

	srvid = CTDB_SRVID_TEST_RANGE|55;
	if (!ctdb_send_message(ctdb_connection, 0, srvid, msg)) {
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

	/*
	 * Read the nodemap from a node (async)
	 */
	handle = ctdb_getnodemap_send(ctdb_connection, CTDB_CURRENT_NODE,
				  gnm_cb, NULL);
	if (handle == NULL) {
		printf("Failed to send get_nodemap control\n");
		exit(10);
	}

	/*
	 * Read the list of public ips from a node (async)
	 */
	handle = ctdb_getpublicips_send(ctdb_connection, CTDB_CURRENT_NODE,
				  ips_cb, NULL);
	if (handle == NULL) {
		printf("Failed to send getpublicips control\n");
		exit(10);
	}

	/*
	 * Read the nodemap from a node (sync)
	 */
	if (!ctdb_getnodemap(ctdb_connection, CTDB_CURRENT_NODE,
			     &nodemap)) {
		printf("Failed to receive response to getrecmaster\n");
		exit(10);
	}
	printf("SYNC response to getnodemap:\n");
	print_nodemap(nodemap);
	ctdb_free_nodemap(nodemap);

	printf("Traverse the test_test.tdb database\n");
	ctdb_traverse_async(ctdb_db_context, traverse_callback, NULL);

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
