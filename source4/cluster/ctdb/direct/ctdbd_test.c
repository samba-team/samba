/* 
   test of messaging

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "system/network.h"
#include "../include/ctdb.h"
#include "../include/ctdb_private.h"

#define CTDB_SOCKET "/tmp/ctdb.socket.127.0.0.1"


/*
  connect to the unix domain socket
*/
static int ux_socket_connect(const char *name)
{
	struct sockaddr_un addr;
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, name, sizeof(addr.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		return -1;
	}
	
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		close(fd);
		return -1;
	}

	return fd;
}

void register_pid_with_daemon(int fd, int pid)
{
	struct ctdb_req_register r;

	bzero(&r, sizeof(r));
	r.hdr.length       = sizeof(r);
	r.hdr.ctdb_magic   = CTDB_MAGIC;
	r.hdr.ctdb_version = CTDB_VERSION;
	r.hdr.operation    = CTDB_REQ_REGISTER;
	r.srvid            = pid;

	/* XXX must deal with partial writes here */
	write(fd, &r, sizeof(r));
}

/* send a command to the cluster to wait until all nodes are connected
   and the cluster is fully operational
 */
int wait_for_cluster(int fd)
{
	struct ctdb_req_connect_wait req;
	struct ctdb_reply_connect_wait rep;
	int cnt, tot;

	/* send a connect wait command to the local node */
	bzero(&req, sizeof(req));
	req.hdr.length       = sizeof(req);
	req.hdr.ctdb_magic   = CTDB_MAGIC;
	req.hdr.ctdb_version = CTDB_VERSION;
	req.hdr.operation    = CTDB_REQ_CONNECT_WAIT;

	/* XXX must deal with partial writes here */
	write(fd, &req, sizeof(req));


	/* read the 4 bytes of length for the pdu */
	cnt=0;
	tot=4;
	while(cnt!=tot){
		int numread;
		numread=read(fd, ((char *)&rep)+cnt, tot-cnt);
		if(numread>0){
			cnt+=numread;
		}
	}
	/* read the rest of the pdu */
	tot=rep.hdr.length;
	while(cnt!=tot){
		int numread;
		numread=read(fd, ((char *)&rep)+cnt, tot-cnt);
		if(numread>0){
			cnt+=numread;
		}
	}

	return rep.vnn;
}


int send_a_message(int fd, int ourvnn, int vnn, int pid, TDB_DATA data)
{
	struct ctdb_req_message r;
	int len, cnt;

	len = offsetof(struct ctdb_req_message, data) + data.dsize;
	r.hdr.length     = len;
	r.hdr.ctdb_magic = CTDB_MAGIC;
	r.hdr.ctdb_version = CTDB_VERSION;
	r.hdr.operation  = CTDB_REQ_MESSAGE;
	r.hdr.destnode   = vnn;
	r.hdr.srcnode    = ourvnn;
	r.hdr.reqid      = 0;
	r.srvid          = pid;
	r.datalen        = data.dsize;
	
	/* write header */
	cnt=write(fd, &r, offsetof(struct ctdb_req_message, data));
	/* write data */
	if(data.dsize){
	    cnt=write(fd, data.dptr, data.dsize);
	}
	return 0;
}

int receive_a_message(int fd, struct ctdb_req_message **preply)
{
	int cnt,tot;
	struct ctdb_req_message *rep;
	uint32_t length;

	/* read the 4 bytes of length for the pdu */
	cnt=0;
	tot=4;
	while(cnt!=tot){
		int numread;
		numread=read(fd, ((char *)&length)+cnt, tot-cnt);
		if(numread>0){
			cnt+=numread;
		}
	}
	
	/* read the rest of the pdu */
	rep = malloc(length);
	rep->hdr.length = length;
	cnt = 0;
	tot = length-4;
	while(cnt!=tot){
		int numread;
		numread=read(fd, ((char *)rep)+cnt, tot-cnt);
		if(numread>0){
			cnt+=numread;
		}
	}

	*preply = rep;
	return 0;
}

/*
  hash function for mapping data to a VNN - taken from tdb
*/
uint32_t ctdb_hash(const TDB_DATA *key)
{
	uint32_t value;	/* Used to compute the hash value.  */
	uint32_t i;	/* Used to cycle through random values. */

	/* Set the initial value from the key size. */
	for (value = 0x238F13AF * key->dsize, i=0; i < key->dsize; i++)
		value = (value + (key->dptr[i] << (i*5 % 24)));

	return (1103515243 * value + 12345);  
}

void fetch_lock(int fd, uint32_t db_id, TDB_DATA key)
{
	struct ctdb_req_fetch_lock *req;
	struct ctdb_reply_fetch_lock *rep;
	uint32_t length;
	int len, cnt, tot;

	len = offsetof(struct ctdb_req_fetch_lock, key) + key.dsize;
	req = malloc(len);

	req->hdr.length      = len;
	req->hdr.ctdb_magic  = CTDB_MAGIC;
	req->hdr.ctdb_version = CTDB_VERSION;
	req->hdr.operation   = CTDB_REQ_FETCH_LOCK;
	req->hdr.reqid       = 1;
	req->db_id           = db_id;
	req->keylen          = key.dsize;
	memcpy(&req->key[0], key.dptr, key.dsize);

	cnt=write(fd, req, len);


	/* wait fot the reply */
	/* read the 4 bytes of length for the pdu */
	cnt=0;
	tot=4;
	while(cnt!=tot){
		int numread;
		numread=read(fd, ((char *)&length)+cnt, tot-cnt);
		if(numread>0){
			cnt+=numread;
		}
	}
	/* read the rest of the pdu */
	rep = malloc(length);
	tot=length;
	while(cnt!=tot){
		int numread;
		numread=read(fd, ((char *)rep)+cnt, tot-cnt);
		if(numread>0){
			cnt+=numread;
		}
	}
	printf("fetch lock reply: state:%d datalen:%d\n",rep->state,rep->datalen);
	if(!rep->datalen){
		printf("no data\n");
	} else {
		printf("data:[%s]\n",rep->data);
	}

}

void store_unlock(int fd, uint32_t db_id, TDB_DATA key, TDB_DATA data)
{
	struct ctdb_req_store_unlock *req;
	struct ctdb_reply_store_unlock *rep;
	uint32_t length;
	int len, cnt, tot;

	len = offsetof(struct ctdb_req_store_unlock, data) + key.dsize + data.dsize;
	req = malloc(len);

	req->hdr.length      = len;
	req->hdr.ctdb_magic  = CTDB_MAGIC;
	req->hdr.ctdb_version = CTDB_VERSION;
	req->hdr.operation   = CTDB_REQ_STORE_UNLOCK;
	req->hdr.reqid       = 1;
	req->db_id           = db_id;
	req->keylen          = key.dsize;
	req->datalen         = data.dsize;
	memcpy(&req->data[0], key.dptr, key.dsize);
	memcpy(&req->data[key.dsize], data.dptr, data.dsize);

	cnt=write(fd, req, len);


	/* wait fot the reply */
	/* read the 4 bytes of length for the pdu */
	cnt=0;
	tot=4;
	while(cnt!=tot){
		int numread;
		numread=read(fd, ((char *)&length)+cnt, tot-cnt);
		if(numread>0){
			cnt+=numread;
		}
	}
	/* read the rest of the pdu */
	rep = malloc(length);
	tot=length;
	while(cnt!=tot){
		int numread;
		numread=read(fd, ((char *)rep)+cnt, tot-cnt);
		if(numread>0){
			cnt+=numread;
		}
	}
	printf("store unlock reply: state:%d\n",rep->state);
}

int main(int argc, const char *argv[])
{
	int fd, pid, vnn, dstvnn, dstpid;
	TDB_DATA message;
	struct ctdb_req_message *reply;
	TDB_DATA dbname;
	uint32_t db_id;
	TDB_DATA key, data;
	char str[256];

	/* open the socket to talk to the local ctdb daemon */
	fd=ux_socket_connect(CTDB_SOCKET);
	if (fd==-1) {
		printf("failed to open domain socket\n");
		exit(10);
	}


	/* register our local server id with the daemon so that it knows
	   where to send messages addressed to our local pid.
	 */
	pid=getpid();
	register_pid_with_daemon(fd, pid);


	/* do a connect wait to ensure that all nodes in the cluster are up 
	   and operational.
	   this also tells us the vnn of the local cluster.
	   If someone wants to send us a emssage they should send it to
	   this vnn and our pid
	 */
	vnn=wait_for_cluster(fd);
	printf("our address is vnn:%d pid:%d  if someone wants to send us a message!\n",vnn,pid);


	/* send a message to ourself */
	dstvnn=vnn;
	dstpid=pid;
	message.dptr=discard_const("Test message");
	message.dsize=strlen((const char *)message.dptr)+1;
	printf("sending test message [%s] to ourself\n", message.dptr);
	send_a_message(fd, vnn, dstvnn, dstpid, message);

	/* wait for the message to come back */
	receive_a_message(fd, &reply);
	printf("received message: [%s]\n",&reply->data[0]);

	/* create the db id for "test.tdb" */
	dbname.dptr = discard_const("test.tdb");
	dbname.dsize = strlen((const char *)(dbname.dptr));
	db_id = ctdb_hash(&dbname);
	printf("the has for the database id is 0x%08x\n",db_id);
	printf("\n");

	/* send a fetch lock */
	key.dptr=discard_const("TestKey");
	key.dsize=strlen((const char *)(key.dptr));
	printf("fetch the test key:[%s]\n",key.dptr);
	fetch_lock(fd, db_id, key);
	printf("\n");


	/* send a store unlock */
	sprintf(str,"TestData_%d",getpid());
	data.dptr=discard_const(str);
	data.dsize=strlen((const char *)(data.dptr));
	printf("store new data==[%s] for this record\n",data.dptr);
	store_unlock(fd, db_id, key, data);
	printf("\n");

	/* send a fetch lock */
	printf("fetch the test key:[%s]\n",key.dptr);
	fetch_lock(fd, db_id, key);
	printf("\n");


	return 0;
}
