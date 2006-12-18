/*
 * Unix SMB/CIFS implementation.
 * Test the infiniband wrapper.
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>

#include "includes.h"
#include "lib/events/events.h"
#include "ib/ibwrapper.h"

struct ibwtest_ctx {
	int	is_server;
	char	*id; /* my id */

	struct ibw_initattr *attrs;
	int	nattrs;
	char	*opts; /* option string */

	struct sockaddr_in *addrs; /* dynamic array of dest addrs */
	int	naddrs;

	unsigned int	nsec; /* nanosleep between messages */

	int	cnt;

	int	kill_me;
	struct ibw_ctx	*ibwctx;
};

struct ibwtest_conn {
	char	*id;
};

enum testopcode {
	TESTOP_SEND_ID = 1,
	TESTOP_SEND_DATA = 2
};

int ibwtest_connect_everybody(struct ibwtest_ctx *tcx)
{
	struct ibwtest_conn	*pconn = talloc_zero(tcx, struct ibwtest_conn);
	int	i;

	for(i=0; i<tcx->naddrs; i++) {
		if (ibw_connect(tcx->ibwctx, &tcx->addrs[i], pconn)) {
			fprintf(stderr, "ibw_connect error at %d\n", i);
			return -1;
		}
	}
	DEBUG(10, ("sent %d connect request...\n", tcx->naddrs));

	return 0;
}

int ibwtest_send_id(struct ibw_conn *conn)
{
	char *buf;
	void *key;
	struct ibwtest_ctx *tcx = talloc_get_type(conn->ctx->ctx_userdata, struct ibwtest_ctx);

	DEBUG(10, ("test IBWC_CONNECTED\n"));
	if (ibw_alloc_send_buf(conn, (void **)&buf, &key, strlen(tcx->id)+2)) {
		DEBUG(0, ("send_id: ibw_alloc_send_buf failed\n"));
		return -1;
	}

	buf[0] = (char)TESTOP_SEND_ID;
	strcpy(buf+1, tcx->id);

	if (ibw_send(conn, buf, key, strlen(buf+1)+2)) {
		DEBUG(0, ("send_id: ibw_send error\n"));
		return -1;
	}
	return 0;
}

int ibwtest_send_test_msg(struct ibwtest_ctx *tcx, struct ibw_conn *conn, const char *msg)
{
	char *buf;
	void *key;

	if (ibw_alloc_send_buf(conn, (void **)&buf, &key, strlen(msg)+2)) {
		fprintf(stderr, "send_test_msg: ibw_alloc_send_buf failed\n");
		return -1;
	}

	buf[0] = (char)TESTOP_SEND_DATA;
	strcpy(buf+1, msg);
	
	if (ibw_send(conn, buf, key, strlen(buf+1)+2)) {
		DEBUG(0, ("send_test_msg: ibw_send error\n"));
		return -1;
	}
	return 0;
}

int ibwtest_connstate_handler(struct ibw_ctx *ctx, struct ibw_conn *conn)
{
	struct ibwtest_ctx	*tcx = NULL; /* userdata */
	struct ibwtest_conn	*pconn = NULL; /* userdata */

	if (ctx) {
		tcx = talloc_get_type(ctx->ctx_userdata, struct ibwtest_ctx);

		switch(ctx->state) {
		case IBWS_INIT:
			DEBUG(10, ("test IBWS_INIT\n"));
			break;
		case IBWS_READY:
			DEBUG(10, ("test IBWS_READY\n"));
			break;
		case IBWS_CONNECT_REQUEST:
			DEBUG(10, ("test IBWS_CONNECT_REQUEST\n"));
			pconn = talloc_zero(conn, struct ibwtest_conn);
			if (ibw_accept(ctx, conn, pconn)) {
				DEBUG(0, ("error accepting the connect request\n"));
			}
			break;
		case IBWS_STOPPED:
			DEBUG(10, ("test IBWS_STOPPED\n"));
			talloc_free(tcx->ibwctx);
			DEBUG(10, ("talloc_free(tcx->ibwctx) DONE\n"));
			tcx->kill_me = 1; /* main loop can exit */
			break;
		case IBWS_ERROR:
			DEBUG(10, ("test IBWS_ERROR\n"));
			ibw_stop(tcx->ibwctx);
			break;
		default:
			assert(0);
			break;
		}
	}

	if (conn) {
		pconn = talloc_get_type(conn->conn_userdata, struct ibwtest_conn);
		switch(conn->state) {
		case IBWC_INIT:
			DEBUG(10, ("test IBWC_INIT\n"));
			break;
		case IBWC_CONNECTED:
			ibwtest_send_id(conn);
			break;
		case IBWC_DISCONNECTED:
			DEBUG(10, ("test IBWC_DISCONNECTED\n"));
			break;
		case IBWC_ERROR:
			DEBUG(10, ("test IBWC_ERROR\n"));
			break;
		default:
			assert(0);
			break;
		}
	}
	return 0;
}

int ibwtest_receive_handler(struct ibw_conn *conn, void *buf, int n)
{
	struct ibwtest_conn *pconn;
	enum testopcode op;
	struct ibwtest_ctx *tcx = talloc_get_type(conn->ctx->ctx_userdata, struct ibwtest_ctx);

	assert(conn!=NULL);
	pconn = talloc_get_type(conn->conn_userdata, struct ibwtest_conn);

	op = (enum testopcode)((char *)buf)[0];
	DEBUG(11, ("[%d]msg from %s: \"%s\"(%d)\n", op,
		pconn->id ? pconn->id : NULL, ((char *)buf)+1, n));

	if (tcx->is_server) {
		char *buf2;
		void *key2;
		/* bounce message */
		if (ibw_alloc_send_buf(conn, (void **)&buf2, &key2, n)) {
			fprintf(stderr, "ibw_alloc_send_buf error #2\n");
			return -1;
		}
		memcpy(buf2, buf, n);
		if (ibw_send(conn, buf2, key2, n)) {
			fprintf(stderr, "ibw_send error #2\n");
			return -2;
		}
	}

	return 0;
}

void ibwtest_timeout_handler(struct event_context *ev, struct timed_event *te, 
	struct timeval t, void *private)
{
	struct ibwtest_ctx *tcx = talloc_get_type(private, struct ibwtest_ctx);

	if (!tcx->is_server) {
		struct ibw_conn *p;
		char	msg[50];

		/* fill it with something variable... */
		sprintf(msg, "hello world %d", tcx->cnt++);

		/* send something to everybody... */
		for(p=tcx->ibwctx->conn_list; p!=NULL; p=p->next) {
			ibwtest_send_test_msg(tcx, p, msg);
		}
	} /* else allow main loop run */
}

static struct ibwtest_ctx *testctx = NULL;

void ibwtest_sigquit_handler(int sig)
{
	DEBUG(0, ("got SIGQUIT\n"));
	if (testctx)
		ibw_stop(testctx->ibwctx);
}

int ibwtest_parse_attrs(struct ibwtest_ctx *tcx, char *optext,
	struct ibw_initattr **pattrs, int *nattrs, char op)
{
	int	i = 0, n = 1;
	int	porcess_next = 1;
	char	*p, *q;
	struct ibw_initattr *attrs = NULL;

	*pattrs = NULL;
	for(p = optext; *p!='\0'; p++) {
		if (*p==',')
			n++;
	}

	attrs = (struct ibw_initattr *)talloc_size(tcx,
		n * sizeof(struct ibw_initattr));
	for(p = optext; *p!='\0'; p++) {
		if (porcess_next) {
			attrs[i].name = p;
			q = strchr(p, ':');
			if (q==NULL) {
				fprintf(stderr, "-%c format error\n", op);
				return -1;
			}
			*q = '\0';
			attrs[i].value = q + 1;

			porcess_next = 0;
			i++;
		}
		if (*p==',') {
			*p = '\0';
			porcess_next = 1;
		}
	}
	*pattrs = attrs;
	*nattrs = n;

	return 0;
}

int ibwtest_getdests(struct ibwtest_ctx *tcx, char op)
{
	int	i;
	struct ibw_initattr	*attrs = NULL;
	struct sockaddr_in	*p;
	char	*tmp;

	tmp = talloc_strdup(tcx, optarg);
	/* hack to reuse the above ibw_initattr parser */
	if (ibwtest_parse_attrs(tcx, tmp, &attrs, &tcx->naddrs, op))
		return -1;

	tcx->addrs = talloc_size(tcx,
		tcx->naddrs * sizeof(struct sockaddr_in));
	for(i=0; i<tcx->naddrs; i++) {
		p = tcx->addrs + i;
		p->sin_addr.s_addr = inet_addr(attrs[i].name);
		p->sin_port = atoi(attrs[i].value);
		p->sin_family = AF_INET;
	}

	return 0;
}

int ibwtest_init_server(struct ibwtest_ctx *tcx)
{
	if (tcx->naddrs!=1) {
		fprintf(stderr, "incorrecr number of addrs(%d!=1)\n", tcx->naddrs);
		return -1;
	}

	if (ibw_bind(tcx->ibwctx, &tcx->addrs[0])) {
		DEBUG(0, ("ERROR: ibw_bind failed\n"));
		return -1;
	}

	/* continued at IBWS_READY */
	return 0;
}

void ibwtest_usage(struct ibwtest_ctx *tcx, char *name)
{
	printf("Usage:\n");
	printf("\t%s -i <id> -o {name:value} -d {addr:port} -t nsec -s\n", name);
	printf("\t-i <id> is a free text, acting as a server id, max 23 chars [mandatory]\n");
	printf("\t-o name1:value1,name2:value2,... is a list of (name, value) pairs\n");
	printf("\t-d addr1:port1,addr2:port2,... is a list of destination ip addresses\n");
	printf("\t-t nsec delta time between sends in nanosec [default %d]\n", tcx->nsec);
	printf("\t-s server mode (you have to give exactly one -d address:port in this case)\n");
	printf("Press ctrl+C to stop the program.\n");
}

int main(int argc, char *argv[])
{
	int	rc, op;
	int	result = 1;
	struct event_context *ev = NULL;
	struct ibwtest_ctx *tcx = NULL;

	tcx = talloc_zero(NULL, struct ibwtest_ctx);
	memset(tcx, 0, sizeof(struct ibwtest_ctx));
	tcx->nsec = 1000;

	/* here is the only case we can't avoid using global... */
	testctx = tcx;
	signal(SIGQUIT, ibwtest_sigquit_handler);

	while ((op=getopt(argc, argv, "i:o:d:m:s")) != -1) {
		switch (op) {
		case 'i':
			tcx->id = talloc_strdup(tcx, optarg);
			break;
		case 'o':
			tcx->opts = talloc_strdup(tcx, optarg);
			if (ibwtest_parse_attrs(tcx, tcx->opts, &tcx->attrs,
				&tcx->nattrs, op))
				goto cleanup;
			break;
		case 'd':
			if (ibwtest_getdests(tcx, op))
				goto cleanup;
			break;
		case 's':
			tcx->is_server = 1;
			break;
		default:
			fprintf(stderr, "ERROR: unknown option -%c\n", (char)op);
			ibwtest_usage(tcx, argv[0]);
			goto cleanup;
		}
	}
	if (tcx->id==NULL) {
		ibwtest_usage(tcx, argv[0]);
		goto cleanup;
	}

	ev = event_context_init(NULL);
	assert(ev);

	tcx->ibwctx = ibw_init(tcx->attrs, tcx->nattrs,
		tcx,
		ibwtest_connstate_handler,
		ibwtest_receive_handler,
		ev
	);
	if (!tcx->ibwctx)
		goto cleanup;

	if (tcx->is_server)
		rc = ibwtest_init_server(tcx);
	else
		rc = ibwtest_connect_everybody(tcx);
	if (rc)
		goto cleanup;

	while(!tcx->kill_me) {
		event_add_timed(ev, tcx, timeval_current_ofs(0, tcx->nsec),
			ibwtest_timeout_handler, tcx);
		event_loop_once(ev);
	}

	result = 0; /* everything OK */

cleanup:
	if (tcx)
		talloc_free(tcx);
	if (ev)
		talloc_free(ev);
	DEBUG(0, ("exited with code %d\n", result));
	return result;
}
