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

#include "replace.h"
#include <tevent.h>
#include "util_tdb.h"
#include "serverid.h"
#include "ctdbd_conn.h"
#include "system/select.h"
#include "lib/util/sys_rw_data.h"
#include "lib/util/iov_buf.h"
#include "lib/util/select.h"
#include "lib/util/debug.h"
#include "lib/util/talloc_stack.h"
#include "lib/util/genrand.h"
#include "lib/util/fault.h"
#include "lib/util/dlinklist.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/sys_rw.h"
#include "lib/util/blocking.h"
#include "ctdb/include/ctdb_protocol.h"

/* paths to these include files come from --with-ctdb= in configure */

struct ctdbd_srvid_cb {
	uint64_t srvid;
	int (*cb)(struct tevent_context *ev,
		  uint32_t src_vnn, uint32_t dst_vnn,
		  uint64_t dst_srvid,
		  const uint8_t *msg, size_t msglen,
		  void *private_data);
	void *private_data;
};

struct ctdb_pkt_send_state;
struct ctdb_pkt_recv_state;

struct ctdbd_connection {
	uint32_t reqid;
	uint32_t our_vnn;
	uint64_t rand_srvid;
	struct ctdbd_srvid_cb *callbacks;
	int fd;
	int timeout;

	/* For async connections, enabled via ctdbd_setup_fde() */
	struct tevent_fd *fde;

	/* State to track in-progress read */
	struct ctdb_read_state {
		/* Receive buffer for the initial packet length */
		uint32_t msglen;

		/* iovec state for current read */
		struct iovec iov;
		struct iovec *iovs;
		int iovcnt;

		/* allocated receive buffer based on packet length */
		struct ctdb_req_header *hdr;
	} read_state;

	/* Lists of pending async reads and writes */
	struct ctdb_pkt_recv_state *recv_list;
	struct ctdb_pkt_send_state *send_list;
};

static void ctdbd_async_socket_handler(struct tevent_context *ev,
				       struct tevent_fd *fde,
				       uint16_t flags,
				       void *private_data);

static bool ctdbd_conn_has_async_sends(struct ctdbd_connection *conn)
{
	return (conn->send_list != NULL);
}

static bool ctdbd_conn_has_async_reqs(struct ctdbd_connection *conn)
{
	return (conn->fde != NULL);
}

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
			 int32_t *cstatus);

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
			int (*cb)(struct tevent_context *ev,
				  uint32_t src_vnn, uint32_t dst_vnn,
				  uint64_t dst_srvid,
				  const uint8_t *msg, size_t msglen,
				  void *private_data),
			void *private_data)
{

	int ret;
	int32_t cstatus;
	size_t num_callbacks;
	struct ctdbd_srvid_cb *tmp;

	ret = ctdbd_control_local(conn, CTDB_CONTROL_REGISTER_SRVID, srvid, 0,
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

static int ctdbd_msg_call_back(struct tevent_context *ev,
			       struct ctdbd_connection *conn,
			       struct ctdb_req_message_old *msg)
{
	uint32_t msg_len;
	size_t i, num_callbacks;

	msg_len = msg->hdr.length;
	if (msg_len < offsetof(struct ctdb_req_message_old, data)) {
		DBG_DEBUG("len %"PRIu32" too small\n", msg_len);
		return 0;
	}
	msg_len -= offsetof(struct ctdb_req_message_old, data);

	if (msg_len < msg->datalen) {
		DBG_DEBUG("msg_len=%"PRIu32" < msg->datalen=%"PRIu32"\n",
			  msg_len, msg->datalen);
		return 0;
	}

	num_callbacks = talloc_array_length(conn->callbacks);

	for (i=0; i<num_callbacks; i++) {
		struct ctdbd_srvid_cb *cb = &conn->callbacks[i];

		if ((cb->srvid == msg->srvid) && (cb->cb != NULL)) {
			int ret;

			ret = cb->cb(ev,
				     msg->hdr.srcnode, msg->hdr.destnode,
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
	ret = ctdbd_control_local(conn, CTDB_CONTROL_GET_PNN, 0, 0,
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
	bool ok = false;
	uint32_t i;
	int ret;

	ret = ctdbd_control_local(conn, CTDB_CONTROL_GET_NODEMAP, 0, 0,
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

	if ((m->nodes[i].flags & NODE_FLAGS_INACTIVE) != 0) {
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
	uint32_t msglen;
	ssize_t nread;

	if (timeout != -1) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int ret;

		ret = sys_poll_intr(&pfd, 1, timeout);
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
		DBG_ERR("ctdb_read_packet failed: %s\n", strerror(ret));
		cluster_fatal("failed to read data from ctdbd\n");
	}

	DEBUG(11, ("Received ctdb packet\n"));
	ctdb_packet_dump(hdr);

	if (hdr->operation == CTDB_REQ_MESSAGE) {
		struct ctdb_req_message_old *msg = (struct ctdb_req_message_old *)hdr;

		ret = ctdbd_msg_call_back(NULL, conn, msg);
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

/**
 * This prepares conn for handling async requests
 **/
int ctdbd_setup_fde(struct ctdbd_connection *conn, struct tevent_context *ev)
{
	int ret;

	ret = set_blocking(conn->fd, false);
	if (ret == -1) {
		return errno;
	}

	conn->fde = tevent_add_fd(ev,
				  conn,
				  conn->fd,
				  TEVENT_FD_READ,
				  ctdbd_async_socket_handler,
				  conn);
	if (conn->fde == NULL) {
		return ENOMEM;
	}

	return 0;
}

static int ctdbd_connection_destructor(struct ctdbd_connection *c);

/*
 * Get us a ctdbd connection
 */

static int ctdbd_init_connection_internal(TALLOC_CTX *mem_ctx,
					  const char *sockname, int timeout,
					  struct ctdbd_connection *conn)
{
	int ret;

	conn->timeout = timeout;
	if (conn->timeout == 0) {
		conn->timeout = -1;
	}

	ret = ctdbd_connect(sockname, &conn->fd);
	if (ret != 0) {
		DEBUG(1, ("ctdbd_connect failed: %s\n", strerror(ret)));
		return ret;
	}
	talloc_set_destructor(conn, ctdbd_connection_destructor);

	ret = get_cluster_vnn(conn, &conn->our_vnn);
	if (ret != 0) {
		DEBUG(10, ("get_cluster_vnn failed: %s\n", strerror(ret)));
		return ret;
	}

	if (!ctdbd_working(conn, conn->our_vnn)) {
		DEBUG(2, ("Node is not working, can not connect\n"));
		return EIO;
	}

	generate_random_buffer((unsigned char *)&conn->rand_srvid,
			       sizeof(conn->rand_srvid));

	ret = register_with_ctdbd(conn, conn->rand_srvid, NULL, NULL);
	if (ret != 0) {
		DEBUG(5, ("Could not register random srvid: %s\n",
			  strerror(ret)));
		return ret;
	}

	return 0;
}

int ctdbd_init_connection(TALLOC_CTX *mem_ctx,
			  const char *sockname, int timeout,
			  struct ctdbd_connection **pconn)
{
	struct ctdbd_connection *conn;
	int ret;

	if (!(conn = talloc_zero(mem_ctx, struct ctdbd_connection))) {
		DEBUG(0, ("talloc failed\n"));
		return ENOMEM;
	}

	ret = ctdbd_init_connection_internal(mem_ctx,
					     sockname,
					     timeout,
					     conn);
	if (ret != 0) {
		DBG_ERR("ctdbd_init_connection_internal failed (%s)\n",
			strerror(ret));
		goto fail;
	}

	*pconn = conn;
	return 0;

 fail:
	TALLOC_FREE(conn);
	return ret;
}

int ctdbd_reinit_connection(TALLOC_CTX *mem_ctx,
			    const char *sockname, int timeout,
			    struct ctdbd_connection *conn)
{
	int ret;

	ret = ctdbd_connection_destructor(conn);
	if (ret != 0) {
		DBG_ERR("ctdbd_connection_destructor failed\n");
		return ret;
	}

	ret = ctdbd_init_connection_internal(mem_ctx,
					     sockname,
					     timeout,
					     conn);
	if (ret != 0) {
		DBG_ERR("ctdbd_init_connection_internal failed (%s)\n",
			strerror(ret));
		return ret;
	}

	return 0;
}

int ctdbd_conn_get_fd(struct ctdbd_connection *conn)
{
	return conn->fd;
}

/*
 * Packet handler to receive and handle a ctdb message
 */
static int ctdb_handle_message(struct tevent_context *ev,
			       struct ctdbd_connection *conn,
			       struct ctdb_req_header *hdr)
{
	struct ctdb_req_message_old *msg;

	if (hdr->operation != CTDB_REQ_MESSAGE) {
		DEBUG(0, ("Received async msg of type %u, discarding\n",
			  hdr->operation));
		return EINVAL;
	}

	msg = (struct ctdb_req_message_old *)hdr;

	ctdbd_msg_call_back(ev, conn, msg);

	return 0;
}

void ctdbd_socket_readable(struct tevent_context *ev,
			   struct ctdbd_connection *conn)
{
	struct ctdb_req_header *hdr = NULL;
	int ret;

	ret = ctdb_read_packet(conn->fd, conn->timeout, talloc_tos(), &hdr);
	if (ret != 0) {
		DBG_ERR("ctdb_read_packet failed: %s\n", strerror(ret));
		cluster_fatal("failed to read data from ctdbd\n");
	}

	ret = ctdb_handle_message(ev, conn, hdr);

	TALLOC_FREE(hdr);

	if (ret != 0) {
		DEBUG(10, ("could not handle incoming message: %s\n",
			   strerror(ret)));
	}
}

static int ctdb_pkt_send_handler(struct ctdbd_connection *conn);
static int ctdb_pkt_recv_handler(struct ctdbd_connection *conn);

/* Used for async connection and async ctcb requests */
static void ctdbd_async_socket_handler(struct tevent_context *ev,
				       struct tevent_fd *fde,
				       uint16_t flags,
				       void *private_data)
{
	struct ctdbd_connection *conn = talloc_get_type_abort(
		private_data, struct ctdbd_connection);
	int ret;

	if ((flags & TEVENT_FD_READ) != 0) {
		ret = ctdb_pkt_recv_handler(conn);
		if (ret != 0) {
			DBG_DEBUG("ctdb_read_iov_handler returned %s\n",
				  strerror(ret));
		}
		return;
	}

	if ((flags & TEVENT_FD_WRITE) != 0) {
		ret = ctdb_pkt_send_handler(conn);
		if (ret != 0) {
			DBG_DEBUG("ctdb_write_iov_handler returned %s\n",
				  strerror(ret));
			return;
		}
		return;
	}

	return;
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
			 int32_t *cstatus)
{
	struct ctdb_req_control_old req;
	struct ctdb_req_header *hdr;
	struct ctdb_reply_control_old *reply = NULL;
	struct iovec iov[2];
	ssize_t nwritten;
	int ret;

	if (ctdbd_conn_has_async_reqs(conn)) {
		/*
		 * Can't use sync call while an async call is in flight. Adding
		 * this check as a safety net. We'll be using different
		 * connections for sync and async requests, so this shouldn't
		 * happen, but who knows...
		 */
		DBG_ERR("Async ctdb req on sync connection\n");
		return EINVAL;
	}

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

	DBG_DEBUG("Sending ctdb packet reqid=%"PRIu32", vnn=%"PRIu32", "
		  "opcode=%"PRIu32", srvid=%"PRIu64"\n", req.hdr.reqid,
		  req.hdr.destnode, req.opcode, req.srvid);
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
bool ctdbd_process_exists(struct ctdbd_connection *conn, uint32_t vnn,
			  pid_t pid, uint64_t unique_id)
{
	uint8_t buf[sizeof(pid)+sizeof(unique_id)];
	int32_t cstatus = 0;
	int ret;

	if (unique_id == SERVERID_UNIQUE_ID_NOT_TO_VERIFY) {
		ret = ctdbd_control(conn, vnn, CTDB_CONTROL_PROCESS_EXISTS,
				    0, 0,
				    (TDB_DATA) { .dptr = (uint8_t *)&pid,
						    .dsize = sizeof(pid) },
				    NULL, NULL, &cstatus);
		if (ret != 0) {
			return false;
		}
		return (cstatus == 0);
	}

	memcpy(buf, &pid, sizeof(pid));
	memcpy(buf+sizeof(pid), &unique_id, sizeof(unique_id));

	ret = ctdbd_control(conn, vnn, CTDB_CONTROL_CHECK_PID_SRVID, 0, 0,
			    (TDB_DATA) { .dptr = buf, .dsize = sizeof(buf) },
			    NULL, NULL, &cstatus);
	if (ret != 0) {
		return false;
	}
	return (cstatus == 0);
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

	ret = ctdbd_control_local(conn, CTDB_CONTROL_GETDBPATH, 0, 0, data,
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
		    const char *name, uint32_t *db_id, bool persistent)
{
	int ret;
	TDB_DATA data;
	int32_t cstatus;

	data = string_term_tdb_data(name);

	ret = ctdbd_control_local(conn,
				  persistent
				  ? CTDB_CONTROL_DB_ATTACH_PERSISTENT
				  : CTDB_CONTROL_DB_ATTACH,
				  0, 0, data, NULL, &data, &cstatus);
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

	return 0;
}

/*
 * force the migration of a record to this node
 */
int ctdbd_migrate(struct ctdbd_connection *conn, uint32_t db_id, TDB_DATA key)
{
	struct ctdb_req_call_old req;
	struct ctdb_req_header *hdr = NULL;
	struct iovec iov[2];
	ssize_t nwritten;
	int ret;

	if (ctdbd_conn_has_async_reqs(conn)) {
		/*
		 * Can't use sync call while an async call is in flight. Adding
		 * this check as a safety net. We'll be using different
		 * connections for sync and async requests, so this shouldn't
		 * happen, but who knows...
		 */
		DBG_ERR("Async ctdb req on sync connection\n");
		return EINVAL;
	}

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
		if (hdr->operation == CTDB_REPLY_ERROR) {
			DBG_ERR("received error from ctdb\n");
		} else {
			DBG_ERR("received invalid reply\n");
		}
		ret = EIO;
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

	if (ctdbd_conn_has_async_reqs(conn)) {
		/*
		 * Can't use sync call while an async call is in flight. Adding
		 * this check as a safety net. We'll be using different
		 * connections for sync and async requests, so this shouldn't
		 * happen, but who knows...
		 */
		DBG_ERR("Async ctdb req on sync connection\n");
		return EINVAL;
	}

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
  Traverse a ctdb database. "conn" must be an otherwise unused
  ctdb_connection where no other messages but the traverse ones are
  expected.
*/

int ctdbd_traverse(struct ctdbd_connection *conn, uint32_t db_id,
			void (*fn)(TDB_DATA key, TDB_DATA data,
				   void *private_data),
			void *private_data)
{
	int ret;
	TDB_DATA key, data;
	struct ctdb_traverse_start t;
	int32_t cstatus;

	if (ctdbd_conn_has_async_reqs(conn)) {
		/*
		 * Can't use sync call while an async call is in flight. Adding
		 * this check as a safety net. We'll be using different
		 * connections for sync and async requests, so this shouldn't
		 * happen, but who knows...
		 */
		DBG_ERR("Async ctdb req on sync connection\n");
		return EINVAL;
	}

	t.db_id = db_id;
	t.srvid = conn->rand_srvid;
	t.reqid = ctdbd_next_reqid(conn);

	data.dptr = (uint8_t *)&t;
	data.dsize = sizeof(t);

	ret = ctdbd_control_local(conn, CTDB_CONTROL_TRAVERSE_START,
				  conn->rand_srvid,
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
		return ret;
	}

	while (true) {
		struct ctdb_req_header *hdr = NULL;
		struct ctdb_req_message_old *m;
		struct ctdb_rec_data_old *d;

		ret = ctdb_read_packet(conn->fd, conn->timeout, conn, &hdr);
		if (ret != 0) {
			DBG_ERR("ctdb_read_packet failed: %s\n", strerror(ret));
			cluster_fatal("failed to read data from ctdbd\n");
		}

		if (hdr->operation != CTDB_REQ_MESSAGE) {
			DEBUG(0, ("Got operation %u, expected a message\n",
				  (unsigned)hdr->operation));
			return EIO;
		}

		m = (struct ctdb_req_message_old *)hdr;
		d = (struct ctdb_rec_data_old *)&m->data[0];
		if (m->datalen < sizeof(uint32_t) || m->datalen != d->length) {
			DEBUG(0, ("Got invalid traverse data of length %d\n",
				  (int)m->datalen));
			return EIO;
		}

		key.dsize = d->keylen;
		key.dptr  = &d->data[0];
		data.dsize = d->datalen;
		data.dptr = &d->data[d->keylen];

		if (key.dsize == 0 && data.dsize == 0) {
			/* end of traverse */
			return 0;
		}

		if (data.dsize < sizeof(struct ctdb_ltdb_header)) {
			DEBUG(0, ("Got invalid ltdb header length %d\n",
				  (int)data.dsize));
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
		       int (*cb)(struct tevent_context *ev,
				 uint32_t src_vnn, uint32_t dst_vnn,
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
			int32_t *cstatus)
{
	return ctdbd_control(conn, CTDB_CURRENT_NODE, opcode, srvid, flags, data,
			     mem_ctx, outdata, cstatus);
}

int ctdb_watch_us(struct ctdbd_connection *conn)
{
	struct ctdb_notify_data_old reg_data;
	size_t struct_len;
	int ret;
	int32_t cstatus;

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
	int32_t cstatus;

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

	ret = ctdbd_init_connection(talloc_tos(), sockname, timeout,
				    &conn);

	/*
	 * We only care if we can connect.
	 */
	TALLOC_FREE(conn);

	return ret;
}

struct ctdb_pkt_send_state {
	struct ctdb_pkt_send_state *prev, *next;
	struct tevent_context *ev;
	struct ctdbd_connection *conn;

	/* ctdb request id */
	uint32_t reqid;

	/* the associated tevent request */
	struct tevent_req *req;

	/* iovec array with data to send */
	struct iovec _iov;
	struct iovec *iov;
	int iovcnt;

	/* Initial packet length */
	size_t packet_len;
};

static void ctdb_pkt_send_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state);

/**
 * Asynchronously send a ctdb packet given as iovec array
 *
 * Note: the passed iov array is not const here. Similar
 * functions in samba take a const array and create a copy
 * before calling iov_advance() on the array.
 *
 * This function will modify the iov array! But
 * this is a static function and our only caller
 * ctdb_parse_send/recv is preparared for this to
 * happen!
 **/
static struct tevent_req *ctdb_pkt_send_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct ctdbd_connection *conn,
					     uint32_t reqid,
					     struct iovec *iov,
					     int iovcnt,
					     enum dbwrap_req_state *req_state)
{
	struct tevent_req *req = NULL;
	struct ctdb_pkt_send_state *state = NULL;
	ssize_t nwritten;
	bool ok;

	DBG_DEBUG("sending async ctdb reqid [%" PRIu32 "]\n", reqid);

	req = tevent_req_create(mem_ctx, &state, struct ctdb_pkt_send_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct ctdb_pkt_send_state) {
		.ev = ev,
		.conn = conn,
		.req = req,
		.reqid = reqid,
		.iov = iov,
		.iovcnt = iovcnt,
		.packet_len = iov_buflen(iov, iovcnt),
	};

	tevent_req_set_cleanup_fn(req, ctdb_pkt_send_cleanup);

	*req_state = DBWRAP_REQ_QUEUED;

	if (ctdbd_conn_has_async_sends(conn)) {
		/*
		 * Can't attempt direct write with messages already queued and
		 * possibly in progress
		 */
		DLIST_ADD_END(conn->send_list, state);
		return req;
	}

	/*
	 * Attempt a direct write. If this returns short, schedule the
	 * remaining data as an async write, otherwise we're already done.
	 */

	nwritten = writev(conn->fd, state->iov, state->iovcnt);
	if (nwritten == state->packet_len) {
		DBG_DEBUG("Finished sending reqid [%" PRIu32 "]\n", reqid);

		*req_state = DBWRAP_REQ_DISPATCHED;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (nwritten == -1) {
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
			cluster_fatal("cluster write error\n");
		}
		nwritten = 0;
	}

	DBG_DEBUG("Posting async write of reqid [%" PRIu32"]"
		  "after short write [%zd]\n", reqid, nwritten);

	ok = iov_advance(&state->iov, &state->iovcnt, nwritten);
	if (!ok) {
		*req_state = DBWRAP_REQ_ERROR;
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	/*
	 * As this is the first async write req we post, we must enable
	 * fd-writable events.
	 */
	TEVENT_FD_WRITEABLE(conn->fde);
	DLIST_ADD_END(conn->send_list, state);
	return req;
}

static int ctdb_pkt_send_state_destructor(struct ctdb_pkt_send_state *state)
{
	struct ctdbd_connection *conn = state->conn;

	if (conn == NULL) {
		return 0;
	}

	if (state->req == NULL) {
		DBG_DEBUG("Removing cancelled reqid [%" PRIu32"]\n",
			  state->reqid);
		state->conn = NULL;
		DLIST_REMOVE(conn->send_list, state);
		return 0;
	}

	DBG_DEBUG("Reparenting cancelled reqid [%" PRIu32"]\n",
		  state->reqid);

	talloc_reparent(state->req, conn, state);
	state->req = NULL;
	return -1;
}

static void ctdb_pkt_send_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state)
{
	struct ctdb_pkt_send_state *state = tevent_req_data(
		req, struct ctdb_pkt_send_state);
	struct ctdbd_connection *conn = state->conn;
	size_t missing_len = 0;

	if (conn == NULL) {
		return;
	}

	missing_len = iov_buflen(state->iov, state->iovcnt);
	if (state->packet_len == missing_len) {
		/*
		 * We haven't yet started sending this one, so we can just
		 * remove it from the pending list
		 */
		missing_len = 0;
	}
	if (missing_len != 0) {
		uint8_t *buf = NULL;

		if (req_state != TEVENT_REQ_RECEIVED) {
			/*
			 * Wait til the req_state is TEVENT_REQ_RECEIVED, as
			 * that will be the final state when the request state
			 * is talloc_free'd from tallloc_req_received(). Which
			 * ensures we only run the following code *ONCE*!
			 */
			return;
		}

		DBG_DEBUG("Cancelling in-flight reqid [%" PRIu32"]\n",
			  state->reqid);
		/*
		 * A request in progress of being sent. Reparent the iov buffer
		 * so we can continue sending the request. See also the comment
		 * in ctdbd_parse_send() when copying the key buffer.
		 */

		buf = iov_concat(state, state->iov, state->iovcnt);
		if (buf == NULL) {
			cluster_fatal("iov_concat error\n");
			return;
		}

		state->iovcnt = 1;
		state->_iov.iov_base = buf;
		state->_iov.iov_len = missing_len;
		state->iov = &state->_iov;

		talloc_set_destructor(state, ctdb_pkt_send_state_destructor);
		return;
	}

	DBG_DEBUG("Removing pending reqid [%" PRIu32"]\n", state->reqid);

	state->conn = NULL;
	DLIST_REMOVE(conn->send_list, state);

	if (!ctdbd_conn_has_async_sends(conn)) {
		DBG_DEBUG("No more sends, disabling fd-writable events\n");
		TEVENT_FD_NOT_WRITEABLE(conn->fde);
	}
}

static int ctdb_pkt_send_handler(struct ctdbd_connection *conn)
{
	struct ctdb_pkt_send_state *state = NULL;
	ssize_t nwritten;
	ssize_t iovlen;
	bool ok;

	DBG_DEBUG("send handler\n");

	if (!ctdbd_conn_has_async_sends(conn)) {
		DBG_WARNING("Writable fd-event without pending send\n");
		TEVENT_FD_NOT_WRITEABLE(conn->fde);
		return 0;
	}

	state = conn->send_list;
	iovlen = iov_buflen(state->iov, state->iovcnt);

	nwritten = writev(conn->fd, state->iov, state->iovcnt);
	if (nwritten == -1) {
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
			DBG_ERR("writev failed: %s\n", strerror(errno));
			cluster_fatal("cluster write error\n");
		}
		DBG_DEBUG("recoverable writev error, retry\n");
		return 0;
	}

	if (nwritten < iovlen) {
		DBG_DEBUG("short write\n");

		ok = iov_advance(&state->iov, &state->iovcnt, nwritten);
		if (!ok) {
			DBG_ERR("iov_advance failed\n");
			if (state->req == NULL) {
				TALLOC_FREE(state);
				return 0;
			}
			tevent_req_error(state->req, EIO);
			return 0;
		}
		return 0;
	}

	if (state->req == NULL) {
		DBG_DEBUG("Finished sending cancelled reqid [%" PRIu32 "]\n",
			  state->reqid);
		TALLOC_FREE(state);
		return 0;
	}

	DBG_DEBUG("Finished send request id [%" PRIu32 "]\n", state->reqid);

	tevent_req_done(state->req);
	return 0;
}

static int ctdb_pkt_send_recv(struct tevent_req *req)
{
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		tevent_req_received(req);
		return ret;
	}

	tevent_req_received(req);
	return 0;
}

struct ctdb_pkt_recv_state {
	struct ctdb_pkt_recv_state *prev, *next;
	struct tevent_context *ev;
	struct ctdbd_connection *conn;

	/* ctdb request id */
	uint32_t reqid;

	/* the associated tevent_req */
	struct tevent_req *req;

	/* pointer to allocated ctdb packet buffer */
	struct ctdb_req_header *hdr;
};

static void ctdb_pkt_recv_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state);

static struct tevent_req *ctdb_pkt_recv_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct ctdbd_connection *conn,
					     uint32_t reqid)
{
	struct tevent_req *req = NULL;
	struct ctdb_pkt_recv_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct ctdb_pkt_recv_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct ctdb_pkt_recv_state) {
		.ev = ev,
		.conn = conn,
		.reqid = reqid,
		.req = req,
	};

	tevent_req_set_cleanup_fn(req, ctdb_pkt_recv_cleanup);

	/*
	 * fd-readable event is always set for the fde, no need to deal with
	 * that here.
	 */

	DLIST_ADD_END(conn->recv_list, state);
	DBG_DEBUG("Posted receive reqid [%" PRIu32 "]\n", state->reqid);

	return req;
}

static void ctdb_pkt_recv_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state)
{
	struct ctdb_pkt_recv_state *state = tevent_req_data(
		req, struct ctdb_pkt_recv_state);
	struct ctdbd_connection *conn = state->conn;

	if (conn == NULL) {
		return;
	}
	state->conn = NULL;
	DLIST_REMOVE(conn->recv_list, state);
}

static int ctdb_pkt_recv_handler(struct ctdbd_connection *conn)
{
	struct ctdb_pkt_recv_state *state = NULL;
	ssize_t nread;
	ssize_t iovlen;
	bool ok;

	DBG_DEBUG("receive handler\n");

	if (conn->read_state.iovs == NULL) {
		conn->read_state.iov.iov_base = &conn->read_state.msglen;
		conn->read_state.iov.iov_len = sizeof(conn->read_state.msglen);
		conn->read_state.iovs = &conn->read_state.iov;
		conn->read_state.iovcnt = 1;
	}

	iovlen = iov_buflen(conn->read_state.iovs, conn->read_state.iovcnt);

	DBG_DEBUG("iovlen [%zd]\n", iovlen);

	nread = readv(conn->fd, conn->read_state.iovs, conn->read_state.iovcnt);
	if (nread == 0) {
		cluster_fatal("cluster read error, peer closed connection\n");
	}
	if (nread == -1) {
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
			cluster_fatal("cluster read error\n");
		}
		DBG_DEBUG("recoverable error from readv, retry\n");
		return 0;
	}

	if (nread < iovlen) {
		DBG_DEBUG("iovlen [%zd] nread [%zd]\n", iovlen, nread);
		ok = iov_advance(&conn->read_state.iovs,
				 &conn->read_state.iovcnt,
				 nread);
		if (!ok) {
			return EIO;
		}
		return 0;
	}

	conn->read_state.iovs = NULL;
	conn->read_state.iovcnt = 0;

	if (conn->read_state.hdr == NULL) {
		/*
		 * Going this way after reading the 4 initial byte message
		 * length
		 */
		uint32_t msglen = conn->read_state.msglen;
		uint8_t *readbuf = NULL;
		size_t readlen;

		DBG_DEBUG("msglen: %" PRIu32 "\n", msglen);

		if (msglen < sizeof(struct ctdb_req_header)) {
			DBG_ERR("short message %" PRIu32 "\n", msglen);
			return EIO;
		}

		conn->read_state.hdr = talloc_size(conn, msglen);
		if (conn->read_state.hdr == NULL) {
			return ENOMEM;
		}
		conn->read_state.hdr->length = msglen;
		talloc_set_name_const(conn->read_state.hdr,
				      "struct ctdb_req_header");

		readbuf = (uint8_t *)conn->read_state.hdr + sizeof(msglen);
		readlen = msglen - sizeof(msglen);

		conn->read_state.iov.iov_base = readbuf;
		conn->read_state.iov.iov_len = readlen;
		conn->read_state.iovs = &conn->read_state.iov;
		conn->read_state.iovcnt = 1;

		DBG_DEBUG("Scheduled packet read size %zd\n", readlen);
		return 0;
	}

	/*
	 * Searching a list here is expected to be cheap, as messages are
	 * exepcted to be coming in more or less ordered and we should find the
	 * waiting request near the beginning of the list.
	 */
	for (state = conn->recv_list; state != NULL; state = state->next) {
		if (state->reqid == conn->read_state.hdr->reqid) {
			break;
		}
	}

	if (state == NULL) {
		DBG_ERR("Discarding async ctdb reqid %u\n",
			conn->read_state.hdr->reqid);
		TALLOC_FREE(conn->read_state.hdr);
		ZERO_STRUCT(conn->read_state);
		return EINVAL;
	}

	DBG_DEBUG("Got reply for reqid [%" PRIu32 "]\n", state->reqid);

	state->hdr = talloc_move(state, &conn->read_state.hdr);
	ZERO_STRUCT(conn->read_state);
	tevent_req_done(state->req);
	return 0;
}

static int ctdb_pkt_recv_recv(struct tevent_req *req,
			      TALLOC_CTX *mem_ctx,
			      struct ctdb_req_header **_hdr)
{
	struct ctdb_pkt_recv_state *state = tevent_req_data(
		req, struct ctdb_pkt_recv_state);
	int error;

	if (tevent_req_is_unix_error(req, &error)) {
		DBG_ERR("ctdb_read_req failed %s\n", strerror(error));
		tevent_req_received(req);
		return error;
	}

	*_hdr = talloc_move(mem_ctx, &state->hdr);

	tevent_req_received(req);
	return 0;
}

static int ctdbd_connection_destructor(struct ctdbd_connection *c)
{
	TALLOC_FREE(c->fde);
	if (c->fd != -1) {
		close(c->fd);
		c->fd = -1;
	}

	TALLOC_FREE(c->read_state.hdr);
	ZERO_STRUCT(c->read_state);

	while (c->send_list != NULL) {
		struct ctdb_pkt_send_state *send_state = c->send_list;
		DLIST_REMOVE(c->send_list, send_state);
		send_state->conn = NULL;
		tevent_req_defer_callback(send_state->req, send_state->ev);
		tevent_req_error(send_state->req, EIO);
	}

	while (c->recv_list != NULL) {
		struct ctdb_pkt_recv_state *recv_state = c->recv_list;
		DLIST_REMOVE(c->recv_list, recv_state);
		recv_state->conn = NULL;
		tevent_req_defer_callback(recv_state->req, recv_state->ev);
		tevent_req_error(recv_state->req, EIO);
	}

	return 0;
}

struct ctdbd_parse_state {
	struct tevent_context *ev;
	struct ctdbd_connection *conn;
	uint32_t reqid;
	TDB_DATA key;
	uint8_t _keybuf[64];
	struct ctdb_req_call_old ctdb_req;
	struct iovec iov[2];
	void (*parser)(TDB_DATA key,
		       TDB_DATA data,
		       void *private_data);
	void *private_data;
	enum dbwrap_req_state *req_state;
};

static void ctdbd_parse_pkt_send_done(struct tevent_req *subreq);
static void ctdbd_parse_done(struct tevent_req *subreq);

struct tevent_req *ctdbd_parse_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct ctdbd_connection *conn,
				    uint32_t db_id,
				    TDB_DATA key,
				    bool local_copy,
				    void (*parser)(TDB_DATA key,
						   TDB_DATA data,
						   void *private_data),
				    void *private_data,
				    enum dbwrap_req_state *req_state)
{
	struct tevent_req *req = NULL;
	struct ctdbd_parse_state *state = NULL;
	uint32_t flags;
	uint32_t packet_length;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state, struct ctdbd_parse_state);
	if (req == NULL) {
		*req_state = DBWRAP_REQ_ERROR;
		return NULL;
	}

	*state = (struct ctdbd_parse_state) {
		.ev = ev,
		.conn = conn,
		.reqid = ctdbd_next_reqid(conn),
		.parser = parser,
		.private_data = private_data,
		.req_state = req_state,
	};

	flags = local_copy ? CTDB_WANT_READONLY : 0;
	packet_length = offsetof(struct ctdb_req_call_old, data) + key.dsize;

	/*
	 * Copy the key into our state, as ctdb_pkt_send_cleanup() requires that
	 * all passed iov elements have a lifetime longer that the tevent_req
	 * returned by ctdb_pkt_send_send(). This is required continue sending a
	 * the low level request into the ctdb socket, if a higher level
	 * ('this') request is canceled (or talloc free'd) by the application
	 * layer, without sending invalid packets to ctdb.
	 */
	if (key.dsize > sizeof(state->_keybuf)) {
		state->key.dptr = talloc_memdup(state, key.dptr, key.dsize);
		if (tevent_req_nomem(state->key.dptr, req)) {
			return tevent_req_post(req, ev);
		}
	} else {
		memcpy(state->_keybuf, key.dptr, key.dsize);
		state->key.dptr = state->_keybuf;
	}
	state->key.dsize = key.dsize;

	state->ctdb_req.hdr.length       = packet_length;
	state->ctdb_req.hdr.ctdb_magic   = CTDB_MAGIC;
	state->ctdb_req.hdr.ctdb_version = CTDB_PROTOCOL;
	state->ctdb_req.hdr.operation    = CTDB_REQ_CALL;
	state->ctdb_req.hdr.reqid        = state->reqid;
	state->ctdb_req.flags            = flags;
	state->ctdb_req.callid           = CTDB_FETCH_FUNC;
	state->ctdb_req.db_id            = db_id;
	state->ctdb_req.keylen           = state->key.dsize;

	state->iov[0].iov_base = &state->ctdb_req;
	state->iov[0].iov_len = offsetof(struct ctdb_req_call_old, data);
	state->iov[1].iov_base = state->key.dptr;
	state->iov[1].iov_len = state->key.dsize;

	/*
	 * Note that ctdb_pkt_send_send()
	 * will modify state->iov using
	 * iov_advance() without making a copy.
	 */
	subreq = ctdb_pkt_send_send(state,
				    ev,
				    conn,
				    state->reqid,
				    state->iov,
				    ARRAY_SIZE(state->iov),
				    req_state);
	if (tevent_req_nomem(subreq, req)) {
		*req_state = DBWRAP_REQ_ERROR;
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, ctdbd_parse_pkt_send_done, req);

	return req;
}

static void ctdbd_parse_pkt_send_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdbd_parse_state *state = tevent_req_data(
		req, struct ctdbd_parse_state);
	int ret;

	ret = ctdb_pkt_send_recv(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		DBG_DEBUG("ctdb_pkt_send_recv failed %s\n", strerror(ret));
		return;
	}

	subreq = ctdb_pkt_recv_send(state,
				    state->ev,
				    state->conn,
				    state->reqid);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	*state->req_state = DBWRAP_REQ_DISPATCHED;
	tevent_req_set_callback(subreq, ctdbd_parse_done, req);
	return;
}

static void ctdbd_parse_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct ctdbd_parse_state *state = tevent_req_data(
		req, struct ctdbd_parse_state);
	struct ctdb_req_header *hdr = NULL;
	struct ctdb_reply_call_old *reply = NULL;
	int ret;

	DBG_DEBUG("async parse request finished\n");

	ret = ctdb_pkt_recv_recv(subreq, state, &hdr);
	TALLOC_FREE(subreq);
	if (tevent_req_error(req, ret)) {
		DBG_ERR("ctdb_pkt_recv_recv returned %s\n", strerror(ret));
		return;
	}

	if (hdr->operation != CTDB_REPLY_CALL) {
		DBG_ERR("received invalid reply\n");
		ctdb_packet_dump(hdr);
		tevent_req_error(req, EIO);
		return;
	}

	reply = (struct ctdb_reply_call_old *)hdr;

	if (reply->datalen == 0) {
		/*
		 * Treat an empty record as non-existing
		 */
		tevent_req_error(req, ENOENT);
		return;
	}

	state->parser(state->key,
		      make_tdb_data(&reply->data[0], reply->datalen),
		      state->private_data);

	tevent_req_done(req);
	return;
}

int ctdbd_parse_recv(struct tevent_req *req)
{
	int error;

	if (tevent_req_is_unix_error(req, &error)) {
		DBG_DEBUG("async parse returned %s\n", strerror(error));
		tevent_req_received(req);
		return error;
	}

	tevent_req_received(req);
	return 0;
}
