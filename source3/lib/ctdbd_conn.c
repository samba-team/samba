/* 
   Unix SMB/CIFS implementation.
   Samba internal messaging functions
   Copyright (C) 2007 by Volker Lendecke
   Copyright (C) 2007 by Andrew Tridgell

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
#include "util_tdb.h"
#include "serverid.h"
#include "ctdbd_conn.h"
#include "system/select.h"
#include "lib/util/sys_rw_data.h"
#include "lib/util/iov_buf.h"

#include "messages.h"

/* paths to these include files come from --with-ctdb= in configure */

#include "ctdb_private.h"

struct ctdbd_srvid_cb {
	uint64_t srvid;
	int (*cb)(uint32_t src_vnn, uint32_t dst_vnn,
		  uint64_t dst_srvid,
		  const uint8_t *msg, size_t msglen,
		  void *private_data);
	void *private_data;
};

struct ctdbd_connection {
	const char *sockname;	/* Needed in ctdbd_traverse */
	struct messaging_context *msg_ctx;
	uint32_t reqid;
	uint32_t our_vnn;
	uint64_t rand_srvid;
	struct ctdbd_srvid_cb *callbacks;
	int fd;
	struct tevent_fd *fde;
	int timeout;
};

static uint32_t ctdbd_next_reqid(struct ctdbd_connection *conn)
{
	conn->reqid += 1;
	if (conn->reqid == 0) {
		conn->reqid += 1;
	}
	return conn->reqid;
}

static int ctdbd_control(struct ctdbd_connection *conn,
			 uint32_t vnn, uint32_t opcode,
			 uint64_t srvid, uint32_t flags,
			 TDB_DATA data,
			 TALLOC_CTX *mem_ctx, TDB_DATA *outdata,
			 int *cstatus);

/*
 * exit on fatal communications errors with the ctdbd daemon
 */
static void cluster_fatal(const char *why)
{
	DEBUG(0,("cluster fatal event: %s - exiting immediately\n", why));
	/* we don't use smb_panic() as we don't want to delay to write
	   a core file. We need to release this process id immediately
	   so that someone else can take over without getting sharing
	   violations */
	_exit(1);
}

/*
 *
 */
static void ctdb_packet_dump(struct ctdb_req_header *hdr)
{
	if (DEBUGLEVEL < 11) {
		return;
	}
	DEBUGADD(11, ("len=%d, magic=%x, vers=%d, gen=%d, op=%d, reqid=%d\n",
		      (int)hdr->length, (int)hdr->ctdb_magic,
		      (int)hdr->ctdb_version, (int)hdr->generation,
		      (int)hdr->operation, (int)hdr->reqid));
}

/*
 * Register a srvid with ctdbd
 */
int register_with_ctdbd(struct ctdbd_connection *conn, uint64_t srvid,
			int (*cb)(uint32_t src_vnn, uint32_t dst_vnn,
				  uint64_t dst_srvid,
				  const uint8_t *msg, size_t msglen,
				  void *private_data),
			void *private_data)
{

	int ret, cstatus;
	size_t num_callbacks;
	struct ctdbd_srvid_cb *tmp;

	ret = ctdbd_control(conn, CTDB_CURRENT_NODE,
			    CTDB_CONTROL_REGISTER_SRVID, srvid, 0,
			    tdb_null, NULL, NULL, &cstatus);
	if (ret != 0) {
		return ret;
	}

	num_callbacks = talloc_array_length(conn->callbacks);

	tmp = talloc_realloc(conn, conn->callbacks, struct ctdbd_srvid_cb,
			     num_callbacks + 1);
	if (tmp == NULL) {
		return ENOMEM;
	}
	conn->callbacks = tmp;

	conn->callbacks[num_callbacks] = (struct ctdbd_srvid_cb) {
		.srvid = srvid, .cb = cb, .private_data = private_data
	};

	return 0;
}

static int ctdbd_msg_call_back(struct ctdbd_connection *conn,
			       struct ctdb_req_message_old *msg)
{
	size_t msg_len;
	size_t i, num_callbacks;

	msg_len = msg->hdr.length;
	if (msg_len < offsetof(struct ctdb_req_message_old, data)) {
		DEBUG(10, ("%s: len %u too small\n", __func__,
			   (unsigned)msg_len));
		return 0;
	}
	msg_len -= offsetof(struct ctdb_req_message_old, data);

	if (msg_len < msg->datalen) {
		DEBUG(10, ("%s: msg_len=%u < msg->datalen=%u\n", __func__,
			   (unsigned)msg_len, (unsigned)msg->datalen));
		return 0;
	}

	num_callbacks = talloc_array_length(conn->callbacks);

	for (i=0; i<num_callbacks; i++) {
		struct ctdbd_srvid_cb *cb = &conn->callbacks[i];

		if ((cb->srvid == msg->srvid) && (cb->cb != NULL)) {
			int ret;

			ret = cb->cb(msg->hdr.srcnode, msg->hdr.destnode,
				     msg->srvid, msg->data, msg->datalen,
				     cb->private_data);
			if (ret != 0) {
				return ret;
			}
		}
	}
	return 0;
}

/*
 * get our vnn from the cluster
 */
static int get_cluster_vnn(struct ctdbd_connection *conn, uint32_t *vnn)
{
	int32_t cstatus=-1;
	int ret;
	ret = ctdbd_control(conn,
			    CTDB_CURRENT_NODE, CTDB_CONTROL_GET_PNN, 0, 0,
			    tdb_null, NULL, NULL, &cstatus);
	if (ret != 0) {
		DEBUG(1, ("ctdbd_control failed: %s\n", strerror(ret)));
		return ret;
	}
	*vnn = (uint32_t)cstatus;
	return ret;
}

/*
 * Are we active (i.e. not banned or stopped?)
 */
static bool ctdbd_working(struct ctdbd_connection *conn, uint32_t vnn)
{
	int32_t cstatus=-1;
	TDB_DATA outdata;
	struct ctdb_node_map_old *m;
	uint32_t failure_flags;
	bool ok = false;
	int i, ret;

	ret = ctdbd_control(conn, CTDB_CURRENT_NODE,
			    CTDB_CONTROL_GET_NODEMAP, 0, 0,
			    tdb_null, talloc_tos(), &outdata, &cstatus);
	if (ret != 0) {
		DEBUG(1, ("ctdbd_control failed: %s\n", strerror(ret)));
		return false;
	}
	if ((cstatus != 0) || (outdata.dptr == NULL)) {
		DEBUG(2, ("Received invalid ctdb data\n"));
		return false;
	}

	m = (struct ctdb_node_map_old *)outdata.dptr;

	for (i=0; i<m->num; i++) {
		if (vnn == m->nodes[i].pnn) {
			break;
		}
	}

	if (i == m->num) {
		DEBUG(2, ("Did not find ourselves (node %d) in nodemap\n",
			  (int)vnn));
		goto fail;
	}

	failure_flags = NODE_FLAGS_BANNED | NODE_FLAGS_DISCONNECTED
		| NODE_FLAGS_PERMANENTLY_DISABLED | NODE_FLAGS_STOPPED;

	if ((m->nodes[i].flags & failure_flags) != 0) {
		DEBUG(2, ("Node has status %x, not active\n",
			  (int)m->nodes[i].flags));
		goto fail;
	}

	ok = true;
fail:
	TALLOC_FREE(outdata.dptr);
	return ok;
}

uint32_t ctdbd_vnn(const struct ctdbd_connection *conn)
{
	return conn->our_vnn;
}

/*
 * Get us a ctdb connection
 */

static int ctdbd_connect(const char *sockname, int *pfd)
{
	struct sockaddr_un addr = { 0, };
	int fd;
	socklen_t salen;
	size_t namelen;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		int err = errno;
		DEBUG(3, ("Could not create socket: %s\n", strerror(err)));
		return err;
	}

	addr.sun_family = AF_UNIX;

	namelen = strlcpy(addr.sun_path, sockname, sizeof(addr.sun_path));
	if (namelen >= sizeof(addr.sun_path)) {
		DEBUG(3, ("%s: Socket name too long: %s\n", __func__,
			  sockname));
		close(fd);
		return ENAMETOOLONG;
	}

	salen = sizeof(struct sockaddr_un);

	if (connect(fd, (struct sockaddr *)(void *)&addr, salen) == -1) {
		int err = errno;
		DEBUG(1, ("connect(%s) failed: %s\n", sockname,
			  strerror(err)));
		close(fd);
		return err;
	}

	*pfd = fd;
	return 0;
}

static int ctdb_read_packet(int fd, int timeout, TALLOC_CTX *mem_ctx,
			    struct ctdb_req_header **result)
{
	struct ctdb_req_header *req;
	int ret, revents;
	uint32_t msglen;
	ssize_t nread;

	if (timeout != -1) {
		ret = poll_intr_one_fd(fd, POLLIN, timeout, &revents);
		if (ret == -1) {
			return errno;
		}
		if (ret == 0) {
			return ETIMEDOUT;
		}
		if (ret != 1) {
			return EIO;
		}
	}

	nread = read_data(fd, &msglen, sizeof(msglen));
	if (nread == -1) {
		return errno;
	}
	if (nread == 0) {
		return EIO;
	}

	if (msglen < sizeof(struct ctdb_req_header)) {
		return EIO;
	}

	req = talloc_size(mem_ctx, msglen);
	if (req == NULL) {
		return ENOMEM;
	}
	talloc_set_name_const(req, "struct ctdb_req_header");

	req->length = msglen;

	nread = read_data(fd, ((char *)req) + sizeof(msglen),
			  msglen - sizeof(msglen));
	if (nread == -1) {
		TALLOC_FREE(req);
		return errno;
	}
	if (nread == 0) {
		TALLOC_FREE(req);
		return EIO;
	}

	*result = req;
	return 0;
}

/*
 * Read a full ctdbd request. If we have a messaging context, defer incoming
 * messages that might come in between.
 */

static int ctdb_read_req(struct ctdbd_connection *conn, uint32_t reqid,
			 TALLOC_CTX *mem_ctx, struct ctdb_req_header **result)
{
	struct ctdb_req_header *hdr;
	int ret;

 next_pkt:

	ret = ctdb_read_packet(conn->fd, conn->timeout, mem_ctx, &hdr);
	if (ret != 0) {
		DEBUG(0, ("ctdb_read_packet failed: %s\n", strerror(ret)));
		cluster_fatal("ctdbd died\n");
	}

	DEBUG(11, ("Received ctdb packet\n"));
	ctdb_packet_dump(hdr);

	if (hdr->operation == CTDB_REQ_MESSAGE) {
		struct ctdb_req_message_old *msg = (struct ctdb_req_message_old *)hdr;

		if (conn->msg_ctx == NULL) {
			DEBUG(1, ("Got a message without having a msg ctx, "
				  "dropping msg %llu\n",
				  (long long unsigned)msg->srvid));
			TALLOC_FREE(hdr);
			goto next_pkt;
		}

		ret = ctdbd_msg_call_back(conn, msg);
		if (ret != 0) {
			TALLOC_FREE(hdr);
			return ret;
		}

		TALLOC_FREE(hdr);
		goto next_pkt;
	}

	if ((reqid != 0) && (hdr->reqid != reqid)) {
		/* we got the wrong reply */
		DEBUG(0,("Discarding mismatched ctdb reqid %u should have "
			 "been %u\n", hdr->reqid, reqid));
		TALLOC_FREE(hdr);
		goto next_pkt;
	}

	*result = talloc_move(mem_ctx, &hdr);

	return 0;
}

static int ctdbd_connection_destructor(struct ctdbd_connection *c)
{
	TALLOC_FREE(c->fde);
	if (c->fd != -1) {
		close(c->fd);
		c->fd = -1;
	}
	return 0;
}
/*
 * Get us a ctdbd connection
 */

static int ctdbd_init_connection(TALLOC_CTX *mem_ctx,
				 const char *sockname, int timeout,
				 struct ctdbd_connection **pconn)
{
	struct ctdbd_connection *conn;
	int ret;

	if (!(conn = talloc_zero(mem_ctx, struct ctdbd_connection))) {
		DEBUG(0, ("talloc failed\n"));
		return ENOMEM;
	}

	conn->sockname = talloc_strdup(conn, sockname);
	if (conn->sockname == NULL) {
		DBG_ERR("talloc failed\n");
		ret = ENOMEM;
		goto fail;
	}

	conn->timeout = timeout;

	if (conn->timeout == 0) {
		conn->timeout = -1;
	}

	ret = ctdbd_connect(conn->sockname, &conn->fd);
	if (ret != 0) {
		DEBUG(1, ("ctdbd_connect failed: %s\n", strerror(ret)));
		goto fail;
	}
	talloc_set_destructor(conn, ctdbd_connection_destructor);

	ret = get_cluster_vnn(conn, &conn->our_vnn);

	if (ret != 0) {
		DEBUG(10, ("get_cluster_vnn failed: %s\n", strerror(ret)));
		goto fail;
	}

	if (!ctdbd_working(conn, conn->our_vnn)) {
		DEBUG(2, ("Node is not working, can not connect\n"));
		ret = EIO;
		goto fail;
	}

	generate_random_buffer((unsigned char *)&conn->rand_srvid,
			       sizeof(conn->rand_srvid));

	ret = register_with_ctdbd(conn, conn->rand_srvid, NULL, NULL);

	if (ret != 0) {
		DEBUG(5, ("Could not register random srvid: %s\n",
			  strerror(ret)));
		goto fail;
	}

	*pconn = conn;
	return 0;

 fail:
	TALLOC_FREE(conn);
	return ret;
}

/*
 * Get us a ctdbd connection and register us as a process
 */

int ctdbd_messaging_connection(TALLOC_CTX *mem_ctx,
			       const char *sockname, int timeout,
			       struct ctdbd_connection **pconn)
{
        struct ctdbd_connection *conn;
	int ret;

	ret = ctdbd_init_connection(mem_ctx, sockname, timeout, &conn);

	if (ret != 0) {
		return ret;
	}

	ret = register_with_ctdbd(conn, MSG_SRVID_SAMBA, NULL, NULL);
	if (ret != 0) {
		goto fail;
	}

	*pconn = conn;
	return 0;

 fail:
	TALLOC_FREE(conn);
	return ret;
}

struct messaging_context *ctdb_conn_msg_ctx(struct ctdbd_connection *conn)
{
	return conn->msg_ctx;
}

int ctdbd_conn_get_fd(struct ctdbd_connection *conn)
{
	return conn->fd;
}

/*
 * Packet handler to receive and handle a ctdb message
 */
static int ctdb_handle_message(struct ctdbd_connection *conn,
			       struct ctdb_req_header *hdr)
{
	struct ctdb_req_message_old *msg;

	if (hdr->operation != CTDB_REQ_MESSAGE) {
		DEBUG(0, ("Received async msg of type %u, discarding\n",
			  hdr->operation));
		return EINVAL;
	}

	msg = (struct ctdb_req_message_old *)hdr;

	ctdbd_msg_call_back(conn, msg);

	return 0;
}

/*
 * The ctdbd socket is readable asynchronuously
 */

static void ctdbd_socket_handler(struct tevent_context *event_ctx,
				 struct tevent_fd *event,
				 uint16_t flags,
				 void *private_data)
{
	struct ctdbd_connection *conn = talloc_get_type_abort(
		private_data, struct ctdbd_connection);
	struct ctdb_req_header *hdr = NULL;
	int ret;

	ret = ctdb_read_packet(conn->fd, conn->timeout, talloc_tos(), &hdr);
	if (ret != 0) {
		DEBUG(0, ("ctdb_read_packet failed: %s\n", strerror(ret)));
		cluster_fatal("ctdbd died\n");
	}

	ret = ctdb_handle_message(conn, hdr);

	TALLOC_FREE(hdr);

	if (ret != 0) {
		DEBUG(10, ("could not handle incoming message: %s\n",
			   strerror(ret)));
	}
}

/*
 * Prepare a ctdbd connection to receive messages
 */

int ctdbd_register_msg_ctx(struct ctdbd_connection *conn,
			   struct messaging_context *msg_ctx,
			   struct tevent_context *ev)
{
	SMB_ASSERT(conn->msg_ctx == NULL);
	SMB_ASSERT(conn->fde == NULL);

	conn->fde = tevent_add_fd(ev, conn, conn->fd, TEVENT_FD_READ,
				  ctdbd_socket_handler, conn);
	if (conn->fde == NULL) {
		DEBUG(0, ("event_add_fd failed\n"));
		return ENOMEM;
	}

	conn->msg_ctx = msg_ctx;

	return 0;
}

int ctdbd_messaging_send_iov(struct ctdbd_connection *conn,
			     uint32_t dst_vnn, uint64_t dst_srvid,
			     const struct iovec *iov, int iovlen)
{
	struct ctdb_req_message_old r;
	struct iovec iov2[iovlen+1];
	size_t buflen = iov_buflen(iov, iovlen);
	ssize_t nwritten;

	r.hdr.length = offsetof(struct ctdb_req_message_old, data) + buflen;
	r.hdr.ctdb_magic = CTDB_MAGIC;
	r.hdr.ctdb_version = CTDB_PROTOCOL;
	r.hdr.generation = 1;
	r.hdr.operation  = CTDB_REQ_MESSAGE;
	r.hdr.destnode   = dst_vnn;
	r.hdr.srcnode    = conn->our_vnn;
	r.hdr.reqid      = 0;
	r.srvid          = dst_srvid;
	r.datalen        = buflen;

	DEBUG(10, ("ctdbd_messaging_send: Sending ctdb packet\n"));
	ctdb_packet_dump(&r.hdr);

	iov2[0].iov_base = &r;
	iov2[0].iov_len = offsetof(struct ctdb_req_message_old, data);
	memcpy(&iov2[1], iov, iovlen * sizeof(struct iovec));

	nwritten = write_data_iov(conn->fd, iov2, iovlen+1);
	if (nwritten == -1) {
		DEBUG(3, ("write_data_iov failed: %s\n", strerror(errno)));
		cluster_fatal("cluster dispatch daemon msg write error\n");
	}

	return 0;
}

/*
 * send/recv a generic ctdb control message
 */
static int ctdbd_control(struct ctdbd_connection *conn,
			 uint32_t vnn, uint32_t opcode,
			 uint64_t srvid, uint32_t flags,
			 TDB_DATA data,
			 TALLOC_CTX *mem_ctx, TDB_DATA *outdata,
			 int *cstatus)
{
	struct ctdb_req_control_old req;
	struct ctdb_req_header *hdr;
	struct ctdb_reply_control_old *reply = NULL;
	struct iovec iov[2];
	ssize_t nwritten;
	int ret;

	ZERO_STRUCT(req);
	req.hdr.length = offsetof(struct ctdb_req_control_old, data) + data.dsize;
	req.hdr.ctdb_magic   = CTDB_MAGIC;
	req.hdr.ctdb_version = CTDB_PROTOCOL;
	req.hdr.operation    = CTDB_REQ_CONTROL;
	req.hdr.reqid        = ctdbd_next_reqid(conn);
	req.hdr.destnode     = vnn;
	req.opcode           = opcode;
	req.srvid            = srvid;
	req.datalen          = data.dsize;
	req.flags            = flags;

	DEBUG(10, ("ctdbd_control: Sending ctdb packet\n"));
	ctdb_packet_dump(&req.hdr);

	iov[0].iov_base = &req;
	iov[0].iov_len = offsetof(struct ctdb_req_control_old, data);
	iov[1].iov_base = data.dptr;
	iov[1].iov_len = data.dsize;

	nwritten = write_data_iov(conn->fd, iov, ARRAY_SIZE(iov));
	if (nwritten == -1) {
		DEBUG(3, ("write_data_iov failed: %s\n", strerror(errno)));
		cluster_fatal("cluster dispatch daemon msg write error\n");
	}

	if (flags & CTDB_CTRL_FLAG_NOREPLY) {
		if (cstatus) {
			*cstatus = 0;
		}
		return 0;
	}

	ret = ctdb_read_req(conn, req.hdr.reqid, NULL, &hdr);
	if (ret != 0) {
		DEBUG(10, ("ctdb_read_req failed: %s\n", strerror(ret)));
		return ret;
	}

	if (hdr->operation != CTDB_REPLY_CONTROL) {
		DEBUG(0, ("received invalid reply\n"));
		TALLOC_FREE(hdr);
		return EIO;
	}
	reply = (struct ctdb_reply_control_old *)hdr;

	if (outdata) {
		if (!(outdata->dptr = (uint8_t *)talloc_memdup(
			      mem_ctx, reply->data, reply->datalen))) {
			TALLOC_FREE(reply);
			return ENOMEM;
		}
		outdata->dsize = reply->datalen;
	}
	if (cstatus) {
		(*cstatus) = reply->status;
	}

	TALLOC_FREE(reply);
	return ret;
}

/*
 * see if a remote process exists
 */
bool ctdbd_process_exists(struct ctdbd_connection *conn, uint32_t vnn, pid_t pid)
{
	struct server_id id;
	bool result;

	id.pid = pid;
	id.vnn = vnn;

	if (!ctdb_processes_exist(conn, &id, 1, &result)) {
		DEBUG(10, ("ctdb_processes_exist failed\n"));
		return false;
	}
	return result;
}

bool ctdb_processes_exist(struct ctdbd_connection *conn,
			  const struct server_id *pids, int num_pids,
			  bool *results)
{
	TALLOC_CTX *frame = talloc_stackframe();
	int i, num_received;
	uint32_t *reqids;
	bool result = false;

	reqids = talloc_array(talloc_tos(), uint32_t, num_pids);
	if (reqids == NULL) {
		goto fail;
	}

	for (i=0; i<num_pids; i++) {
		struct ctdb_req_control_old req;
		pid_t pid;
		struct iovec iov[2];
		ssize_t nwritten;

		results[i] = false;
		reqids[i] = ctdbd_next_reqid(conn);

		ZERO_STRUCT(req);

		/*
		 * pids[i].pid is uint64_t, scale down to pid_t which
		 * is the wire protocol towards ctdb.
		 */
		pid = pids[i].pid;

		DEBUG(10, ("Requesting PID %d/%d, reqid=%d\n",
			   (int)pids[i].vnn, (int)pid,
			   (int)reqids[i]));

		req.hdr.length = offsetof(struct ctdb_req_control_old, data);
		req.hdr.length += sizeof(pid);
		req.hdr.ctdb_magic   = CTDB_MAGIC;
		req.hdr.ctdb_version = CTDB_PROTOCOL;
		req.hdr.operation    = CTDB_REQ_CONTROL;
		req.hdr.reqid        = reqids[i];
		req.hdr.destnode     = pids[i].vnn;
		req.opcode           = CTDB_CONTROL_PROCESS_EXISTS;
		req.srvid            = 0;
		req.datalen          = sizeof(pid);
		req.flags            = 0;

		DEBUG(10, ("ctdbd_control: Sending ctdb packet\n"));
		ctdb_packet_dump(&req.hdr);

		iov[0].iov_base = &req;
		iov[0].iov_len = offsetof(struct ctdb_req_control_old, data);
		iov[1].iov_base = &pid;
		iov[1].iov_len = sizeof(pid);

		nwritten = write_data_iov(conn->fd, iov, ARRAY_SIZE(iov));
		if (nwritten == -1) {
			DEBUG(10, ("write_data_iov failed: %s\n",
				   strerror(errno)));
			goto fail;
		}
	}

	num_received = 0;

	while (num_received < num_pids) {
		struct ctdb_req_header *hdr;
		struct ctdb_reply_control_old *reply;
		uint32_t reqid;
		int ret;

		ret = ctdb_read_req(conn, 0, talloc_tos(), &hdr);
		if (ret != 0) {
			DEBUG(10, ("ctdb_read_req failed: %s\n",
				   strerror(ret)));
			goto fail;
		}

		if (hdr->operation != CTDB_REPLY_CONTROL) {
			DEBUG(10, ("Received invalid reply\n"));
			goto fail;
		}
		reply = (struct ctdb_reply_control_old *)hdr;

		reqid = reply->hdr.reqid;

		DEBUG(10, ("Received reqid %d\n", (int)reqid));

		for (i=0; i<num_pids; i++) {
			if (reqid == reqids[i]) {
				break;
			}
		}
		if (i == num_pids) {
			DEBUG(10, ("Received unknown record number %u\n",
				   (unsigned)reqid));
			goto fail;
		}
		results[i] = ((reply->status) == 0);
		TALLOC_FREE(reply);
		num_received += 1;
	}

	result = true;
fail:
	TALLOC_FREE(frame);
	return result;
}

/*
 * Get a db path
 */
char *ctdbd_dbpath(struct ctdbd_connection *conn,
		   TALLOC_CTX *mem_ctx, uint32_t db_id)
{
	int ret;
	TDB_DATA data;
	TDB_DATA rdata = {0};
	int32_t cstatus = 0;

	data.dptr = (uint8_t*)&db_id;
	data.dsize = sizeof(db_id);

	ret = ctdbd_control(conn, CTDB_CURRENT_NODE,
			    CTDB_CONTROL_GETDBPATH, 0, 0, data,
			    mem_ctx, &rdata, &cstatus);
	if ((ret != 0) || cstatus != 0) {
		DEBUG(0, (__location__ " ctdb_control for getdbpath failed: %s\n",
			  strerror(ret)));
		return NULL;
	}

	return (char *)rdata.dptr;
}

/*
 * attach to a ctdb database
 */
int ctdbd_db_attach(struct ctdbd_connection *conn,
		    const char *name, uint32_t *db_id, int tdb_flags)
{
	int ret;
	TDB_DATA data;
	int32_t cstatus;
	bool persistent = (tdb_flags & TDB_CLEAR_IF_FIRST) == 0;

	data = string_term_tdb_data(name);

	ret = ctdbd_control(conn, CTDB_CURRENT_NODE,
			    persistent
			    ? CTDB_CONTROL_DB_ATTACH_PERSISTENT
			    : CTDB_CONTROL_DB_ATTACH,
			    tdb_flags, 0, data, NULL, &data, &cstatus);
	if (ret != 0) {
		DEBUG(0, (__location__ " ctdb_control for db_attach "
			  "failed: %s\n", strerror(ret)));
		return ret;
	}

	if (cstatus != 0 || data.dsize != sizeof(uint32_t)) {
		DEBUG(0,(__location__ " ctdb_control for db_attach failed\n"));
		return EIO;
	}

	*db_id = *(uint32_t *)data.dptr;
	talloc_free(data.dptr);

	if (!(tdb_flags & TDB_SEQNUM)) {
		return 0;
	}

	data.dptr = (uint8_t *)db_id;
	data.dsize = sizeof(*db_id);

	ret = ctdbd_control(conn, CTDB_CURRENT_NODE,
			    CTDB_CONTROL_ENABLE_SEQNUM, 0, 0, data,
			    NULL, NULL, &cstatus);
	if ((ret != 0) || cstatus != 0) {
		DEBUG(0, (__location__ " ctdb_control for enable seqnum "
			  "failed: %s\n", strerror(ret)));
		return (ret == 0) ? EIO : ret;
	}

	return 0;
}

/*
 * force the migration of a record to this node
 */
int ctdbd_migrate(struct ctdbd_connection *conn, uint32_t db_id, TDB_DATA key)
{
	struct ctdb_req_call_old req;
	struct ctdb_req_header *hdr;
	struct iovec iov[2];
	ssize_t nwritten;
	int ret;

	ZERO_STRUCT(req);

	req.hdr.length = offsetof(struct ctdb_req_call_old, data) + key.dsize;
	req.hdr.ctdb_magic   = CTDB_MAGIC;
	req.hdr.ctdb_version = CTDB_PROTOCOL;
	req.hdr.operation    = CTDB_REQ_CALL;
	req.hdr.reqid        = ctdbd_next_reqid(conn);
	req.flags            = CTDB_IMMEDIATE_MIGRATION;
	req.callid           = CTDB_NULL_FUNC;
	req.db_id            = db_id;
	req.keylen           = key.dsize;

	DEBUG(10, ("ctdbd_migrate: Sending ctdb packet\n"));
	ctdb_packet_dump(&req.hdr);

	iov[0].iov_base = &req;
	iov[0].iov_len = offsetof(struct ctdb_req_call_old, data);
	iov[1].iov_base = key.dptr;
	iov[1].iov_len = key.dsize;

	nwritten = write_data_iov(conn->fd, iov, ARRAY_SIZE(iov));
	if (nwritten == -1) {
		DEBUG(3, ("write_data_iov failed: %s\n", strerror(errno)));
		cluster_fatal("cluster dispatch daemon msg write error\n");
	}

	ret = ctdb_read_req(conn, req.hdr.reqid, NULL, &hdr);
	if (ret != 0) {
		DEBUG(10, ("ctdb_read_req failed: %s\n", strerror(ret)));
		goto fail;
	}

	if (hdr->operation != CTDB_REPLY_CALL) {
		DEBUG(0, ("received invalid reply\n"));
		goto fail;
	}

 fail:

	TALLOC_FREE(hdr);
	return ret;
}

/*
 * Fetch a record and parse it
 */
int ctdbd_parse(struct ctdbd_connection *conn, uint32_t db_id,
		TDB_DATA key, bool local_copy,
		void (*parser)(TDB_DATA key, TDB_DATA data,
			       void *private_data),
		void *private_data)
{
	struct ctdb_req_call_old req;
	struct ctdb_req_header *hdr = NULL;
	struct ctdb_reply_call_old *reply;
	struct iovec iov[2];
	ssize_t nwritten;
	uint32_t flags;
	int ret;

	flags = local_copy ? CTDB_WANT_READONLY : 0;

	ZERO_STRUCT(req);

	req.hdr.length = offsetof(struct ctdb_req_call_old, data) + key.dsize;
	req.hdr.ctdb_magic   = CTDB_MAGIC;
	req.hdr.ctdb_version = CTDB_PROTOCOL;
	req.hdr.operation    = CTDB_REQ_CALL;
	req.hdr.reqid        = ctdbd_next_reqid(conn);
	req.flags            = flags;
	req.callid           = CTDB_FETCH_FUNC;
	req.db_id            = db_id;
	req.keylen           = key.dsize;

	iov[0].iov_base = &req;
	iov[0].iov_len = offsetof(struct ctdb_req_call_old, data);
	iov[1].iov_base = key.dptr;
	iov[1].iov_len = key.dsize;

	nwritten = write_data_iov(conn->fd, iov, ARRAY_SIZE(iov));
	if (nwritten == -1) {
		DEBUG(3, ("write_data_iov failed: %s\n", strerror(errno)));
		cluster_fatal("cluster dispatch daemon msg write error\n");
	}

	ret = ctdb_read_req(conn, req.hdr.reqid, NULL, &hdr);
	if (ret != 0) {
		DEBUG(10, ("ctdb_read_req failed: %s\n", strerror(ret)));
		goto fail;
	}

	if ((hdr == NULL) || (hdr->operation != CTDB_REPLY_CALL)) {
		DEBUG(0, ("received invalid reply\n"));
		ret = EIO;
		goto fail;
	}
	reply = (struct ctdb_reply_call_old *)hdr;

	if (reply->datalen == 0) {
		/*
		 * Treat an empty record as non-existing
		 */
		ret = ENOENT;
		goto fail;
	}

	parser(key, make_tdb_data(&reply->data[0], reply->datalen),
	       private_data);

	ret = 0;
 fail:
	TALLOC_FREE(hdr);
	return ret;
}

/*
  Traverse a ctdb database. This uses a kind-of hackish way to open a second
  connection to ctdbd to avoid the hairy recursive and async problems with
  everything in-line.
*/

int ctdbd_traverse(struct ctdbd_connection *master, uint32_t db_id,
			void (*fn)(TDB_DATA key, TDB_DATA data,
				   void *private_data),
			void *private_data)
{
	struct ctdbd_connection *conn;
	int ret;
	TDB_DATA key, data;
	struct ctdb_traverse_start t;
	int cstatus;

	become_root();
	ret = ctdbd_init_connection(NULL, master->sockname, master->timeout,
				    &conn);
	unbecome_root();
	if (ret != 0) {
		DEBUG(0, ("ctdbd_init_connection failed: %s\n",
			  strerror(ret)));
		return ret;
	}

	t.db_id = db_id;
	t.srvid = conn->rand_srvid;
	t.reqid = ctdbd_next_reqid(conn);

	data.dptr = (uint8_t *)&t;
	data.dsize = sizeof(t);

	ret = ctdbd_control(conn, CTDB_CURRENT_NODE,
			    CTDB_CONTROL_TRAVERSE_START, conn->rand_srvid,
			    0, data, NULL, NULL, &cstatus);

	if ((ret != 0) || (cstatus != 0)) {
		DEBUG(0,("ctdbd_control failed: %s, %d\n", strerror(ret),
			 cstatus));

		if (ret == 0) {
			/*
			 * We need a mapping here
			 */
			ret = EIO;
		}
		TALLOC_FREE(conn);
		return ret;
	}

	while (True) {
		struct ctdb_req_header *hdr = NULL;
		struct ctdb_req_message_old *m;
		struct ctdb_rec_data_old *d;

		ret = ctdb_read_packet(conn->fd, conn->timeout, conn, &hdr);
		if (ret != 0) {
			DEBUG(0, ("ctdb_read_packet failed: %s\n",
				  strerror(ret)));
			cluster_fatal("ctdbd died\n");
		}

		if (hdr->operation != CTDB_REQ_MESSAGE) {
			DEBUG(0, ("Got operation %u, expected a message\n",
				  (unsigned)hdr->operation));
			TALLOC_FREE(conn);
			return EIO;
		}

		m = (struct ctdb_req_message_old *)hdr;
		d = (struct ctdb_rec_data_old *)&m->data[0];
		if (m->datalen < sizeof(uint32_t) || m->datalen != d->length) {
			DEBUG(0, ("Got invalid traverse data of length %d\n",
				  (int)m->datalen));
			TALLOC_FREE(conn);
			return EIO;
		}

		key.dsize = d->keylen;
		key.dptr  = &d->data[0];
		data.dsize = d->datalen;
		data.dptr = &d->data[d->keylen];

		if (key.dsize == 0 && data.dsize == 0) {
			/* end of traverse */
			TALLOC_FREE(conn);
			return 0;
		}

		if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(0, ("Got invalid ltdb header length %d\n",
				  (int)data.dsize));
			TALLOC_FREE(conn);
			return EIO;
		}
		data.dsize -= sizeof(struct ctdb_ltdb_header);
		data.dptr += sizeof(struct ctdb_ltdb_header);

		if (fn != NULL) {
			fn(key, data, private_data);
		}
	}
	return 0;
}

/*
   This is used to canonicalize a ctdb_sock_addr structure.
*/
static void smbd_ctdb_canonicalize_ip(const struct sockaddr_storage *in,
				      struct sockaddr_storage *out)
{
	memcpy(out, in, sizeof (*out));

#ifdef HAVE_IPV6
	if (in->ss_family == AF_INET6) {
		const char prefix[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
		const struct sockaddr_in6 *in6 =
			(const struct sockaddr_in6 *)in;
		struct sockaddr_in *out4 = (struct sockaddr_in *)out;
		if (memcmp(&in6->sin6_addr, prefix, 12) == 0) {
			memset(out, 0, sizeof(*out));
#ifdef HAVE_SOCK_SIN_LEN
			out4->sin_len = sizeof(*out);
#endif
			out4->sin_family = AF_INET;
			out4->sin_port   = in6->sin6_port;
			memcpy(&out4->sin_addr, &in6->sin6_addr.s6_addr[12], 4);
		}
	}
#endif
}

/*
 * Register us as a server for a particular tcp connection
 */

int ctdbd_register_ips(struct ctdbd_connection *conn,
		       const struct sockaddr_storage *_server,
		       const struct sockaddr_storage *_client,
		       int (*cb)(uint32_t src_vnn, uint32_t dst_vnn,
				 uint64_t dst_srvid,
				 const uint8_t *msg, size_t msglen,
				 void *private_data),
		       void *private_data)
{
	struct ctdb_connection p;
	TDB_DATA data = { .dptr = (uint8_t *)&p, .dsize = sizeof(p) };
	int ret;
	struct sockaddr_storage client;
	struct sockaddr_storage server;

	/*
	 * Only one connection so far
	 */

	smbd_ctdb_canonicalize_ip(_client, &client);
	smbd_ctdb_canonicalize_ip(_server, &server);

	switch (client.ss_family) {
	case AF_INET:
		memcpy(&p.dst.ip, &server, sizeof(p.dst.ip));
		memcpy(&p.src.ip, &client, sizeof(p.src.ip));
		break;
	case AF_INET6:
		memcpy(&p.dst.ip6, &server, sizeof(p.dst.ip6));
		memcpy(&p.src.ip6, &client, sizeof(p.src.ip6));
		break;
	default:
		return EIO;
	}

	/*
	 * We want to be told about IP releases
	 */

	ret = register_with_ctdbd(conn, CTDB_SRVID_RELEASE_IP,
				  cb, private_data);
	if (ret != 0) {
		return ret;
	}

	/*
	 * inform ctdb of our tcp connection, so if IP takeover happens ctdb
	 * can send an extra ack to trigger a reset for our client, so it
	 * immediately reconnects
	 */
	ret = ctdbd_control(conn, CTDB_CURRENT_NODE,
			    CTDB_CONTROL_TCP_CLIENT, 0,
			    CTDB_CTRL_FLAG_NOREPLY, data, NULL, NULL,
			    NULL);
	if (ret != 0) {
		return ret;
	}
	return 0;
}

/*
  call a control on the local node
 */
int ctdbd_control_local(struct ctdbd_connection *conn, uint32_t opcode,
			uint64_t srvid, uint32_t flags, TDB_DATA data,
			TALLOC_CTX *mem_ctx, TDB_DATA *outdata,
			int *cstatus)
{
	return ctdbd_control(conn, CTDB_CURRENT_NODE, opcode, srvid, flags, data,
			     mem_ctx, outdata, cstatus);
}

int ctdb_watch_us(struct ctdbd_connection *conn)
{
	struct ctdb_notify_data_old reg_data;
	size_t struct_len;
	int ret;
	int cstatus;

	reg_data.srvid = CTDB_SRVID_SAMBA_NOTIFY;
	reg_data.len = 1;
	reg_data.notify_data[0] = 0;

	struct_len = offsetof(struct ctdb_notify_data_old,
			      notify_data) + reg_data.len;

	ret = ctdbd_control_local(
		conn, CTDB_CONTROL_REGISTER_NOTIFY, conn->rand_srvid, 0,
		make_tdb_data((uint8_t *)&reg_data, struct_len),
		NULL, NULL, &cstatus);
	if (ret != 0) {
		DEBUG(1, ("ctdbd_control_local failed: %s\n",
			  strerror(ret)));
	}
	return ret;
}

int ctdb_unwatch(struct ctdbd_connection *conn)
{
	uint64_t srvid = CTDB_SRVID_SAMBA_NOTIFY;
	int ret;
	int cstatus;

	ret = ctdbd_control_local(
		conn, CTDB_CONTROL_DEREGISTER_NOTIFY, conn->rand_srvid, 0,
		make_tdb_data((uint8_t *)&srvid, sizeof(srvid)),
		NULL, NULL, &cstatus);
	if (ret != 0) {
		DEBUG(1, ("ctdbd_control_local failed: %s\n",
			  strerror(ret)));
	}
	return ret;
}

int ctdbd_probe(const char *sockname, int timeout)
{
	/*
	 * Do a very early check if ctdbd is around to avoid an abort and core
	 * later
	 */
	struct ctdbd_connection *conn = NULL;
	int ret;

	ret = ctdbd_messaging_connection(talloc_tos(), sockname, timeout,
					 &conn);

	/*
	 * We only care if we can connect.
	 */
	TALLOC_FREE(conn);

	return ret;
}
