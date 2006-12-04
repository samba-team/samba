/*
 * Unix SMB/CIFS implementation.
 * Wrap Infiniband calls.
 *
 * Copyright (C) Sven Oehme <oehmes@de.ibm.com> 2006
 *
 * Major code contributions by Peter Somogyi <psomogyi@gamax.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* Server communication state */
typedef enum {
	IBWS_INIT = 0, /* ctx start - after ibw_init */
	IBWS_READY, /* after ibw_bind & ibw_listen */
	IBWS_CONNECT_REQUEST, /* after [IBWS_READY + incoming request] */
		/* => [(ibw_accept)IBWS_READY | (ibw_disconnect)STOPPED | ERROR] */
	IBWS_STOPPED, /* normal stop <= ibw_disconnect+(IBWS_READY | IBWS_CONNECT_REQUEST) */
	IBWS_ERROR /* abnormal state; ibw_stop must be called after this */
} ibw_state_ctx;

/* Connection state */
typedef struct _ibw_ctx {
	void *ctx_userdata; /* see ibw_init */

	ibw_state_ctx state;
	void *internal;
} ibw_ctx;

typedef enum {
	IBWC_INIT = 0, /* conn start - internal state */
	IBWC_CONNECTED, /* after ibw_accept or ibw_connect */
	IBWC_DISCONNECTED, /* after ibw_disconnect */
	IBWC_ERROR
} ibw_state_conn;

typedef struct _ibw_conn {
	ibw_ctx *ctx;
	ibw_state_conn state;

	void *conn_userdata; /* see ibw_connect and ibw_accept */
	void *internal;
} ibw_conn;

/*
 * (name, value) pair for array param of ibw_init
 */
typedef struct _ibw_initattr {
	const char *name;
	const char *value;
} ibw_initattr;

/*
 * Callback function definition which should inform you about
 * connection state change
 * This callback is invoked from within ibw_process_event.
 * Both <conn> and <ctx> can be NULL if their state didn't change.
 * Return nonzero on error.
 */
typedef int (*ibw_connstate_fn_t)(ibw_ctx *ctx, ibw_conn *conn);

/*
 * Callback function definition which should process incoming packets
 * This callback is invoked from within ibw_process_event.
 * Return nonzero on error.
 *
 * Important: you mustn't store buf pointer for later use. Process its contents before returning.
 */
typedef int (*ibw_receive_fn_t)(ibw_conn *conn, void *buf, int n);

/*
 * settings: array of (name, value) pairs
 * where name is one of:
 *      dev_name [default is the first one]
 *      rx_depth [default is 500]
 *      mtu     [default is 1024]
 *      ib_port [default is 1]
 *
 * Must be called _ONCE_ for each node.
 *
 * returns non-NULL on success
 *
 * talloc_free must be called for the result in IBWS_STOPPED;
 *    it will close resources by destructor
 *    connections(ibw_conn *) must have been closed prior talloc_free
 */
ibw_ctx *ibw_init(ibw_initattr *attr, int nattr,
	void *ctx_userdata,
	ibw_connstate_fn_t ibw_connstate,
	ibw_receive_fn_t ibw_receive);

/*
 * Must be called in states of (IBWS_ERROR, IBWS_READY, IBWS_CONNECT_REQUEST)
 *
 * It will send out disconnect requests and free up ibw_conn structures.
 * The ctx->state will transit to IBWS_STOPPED after every conn are disconnected.
 * During that time, you mustn't send/recv/disconnect any more.
 * Only after ctx->state=IBWS_STOPPED you can talloc_free the ctx.
 */
int ibw_stop(ibw_ctx *ctx);

/*************** connection initiation - like stream sockets *****/

/*
 * works like socket bind
 * needs a normal internet address here
 *
 * return 0 on success
 */
int ibw_bind(ibw_ctx *ctx, struct sockaddr_in *my_addr);

/*
 * works like socket listen
 * non-blocking
 * enables accepting incoming connections (after IBWS_READY)
 * (it doesn't touch ctx->state by itself)
 *
 * returns 0 on success
 */
int ibw_listen(ibw_ctx *ctx, int backlog);

/*
 * works like socket accept
 * initializes a connection to a client
 * must be called when state=IBWS_CONNECT_REQUEST
 *
 * returns 0 on success
 *
 * You have +1 waiting here: you will get ibw_conn (having the
 * same <conn_userdata> member) structure in ibw_connstate_fn_t.
 *
 * Important: you won't get remote IP address (only internal conn info)
 */
int ibw_accept(ibw_ctx *ctx, void *conn_userdata);

/*
 * Needs a normal internet address here
 * can be called within IBWS_READY|IBWS_CONNECT_REQUEST
 *
 * returns non-NULL on success
 *
 * You have +1 waiting here: you will get ibw_conn (having the
 * same <conn_userdata> member) structure in ibw_connstate_fn_t.
 */
int ibw_connect(ibw_ctx *ctx, struct sockaddr_in *serv_addr, void *conn_userdata);

/*
 * Sends out a disconnect request.
 * You should process fds after calling this function
 * and then process it with ibw_process_event normally
 * until you get conn->state = IBWC_DISCONNECTED
 *
 * You mustn't talloc_free <conn> yet right after this,
 * first wait for IBWC_DISCONNECTED.
 */
void ibw_disconnect(ibw_conn *conn);

/************ Infiniband specific event loop wrapping ******************/

/*
 * You have to use this buf to fill in before send.
 * It's just to avoid memcpy.in ibw_send.
 * Use the same (buf, key) pair with ibw_send.
 *
 * Returns 0 on success.
 */
int ibw_alloc_send_buf(ibw_conn *conn, void **buf, void **key, int n);

/*
 * Send the message in one
 * Can be invoked any times (should fit into buffers) and at any time
 * (in conn->state=IBWC_CONNECTED)
 *
 * You mustn't use (buf, key) any more for sending.
 */
int ibw_send(ibw_conn *conn, void *buf, void *key, int n);

/*
 * Retrieves the last error
 * result: always non-zero, mustn't be freed (static)
 */
const char *ibw_getLastError();
