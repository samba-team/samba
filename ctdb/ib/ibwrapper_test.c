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
#include <sys/time.h>
#include <time.h>

#include "includes.h"
#include "ib/ibwrapper.h"

struct ibwtest_ctx {
	int	is_server;
	char	*id; /* my id */

	struct ibw_initattr *attrs;
	int	nattrs;
	char	*opts; /* option string */

	struct sockaddr_in *addrs; /* dynamic array of dest addrs */
	int	naddrs;

	unsigned int	nsec; /* delta times between messages in nanosec */
	unsigned int	sleep_usec; /* microsecs to sleep in the main loop to emulate overloading */
	uint32_t	maxsize; /* maximum variable message size */

	int	cnt;
	int	nsent;

	int	nmsg; /* number of messages to send (client) */

	int	kill_me;
	int	stopping;
	int	error;
	struct ibw_ctx	*ibwctx;

	struct timeval	start_time, end_time;
};

struct ibwtest_conn {
	char	*id;
};

enum testopcode {
	TESTOP_SEND_ID = 1,
	TESTOP_SEND_TEXT = 2,
	TESTOP_SEND_RND = 3
};

int ibwtest_connect_everybody(struct ibwtest_ctx *tcx)
{
	struct ibw_conn		*conn;
	struct ibwtest_conn	*tconn = talloc_zero(tcx, struct ibwtest_conn);
	int	i;

	for(i=0; i<tcx->naddrs; i++) {
		conn = ibw_conn_new(tcx->ibwctx, tconn);
		if (ibw_connect(conn, &tcx->addrs[i], tconn)) {
			fprintf(stderr, "ibw_connect error at %d\n", i);
			return -1;
		}
	}
	DEBUG(DEBUG_DEBUG, ("sent %d connect request...\n", tcx->naddrs));

	return 0;
}

int ibwtest_send_id(struct ibw_conn *conn)
{
	struct ibwtest_ctx *tcx = talloc_get_type(conn->ctx->ctx_userdata, struct ibwtest_ctx);
	char *buf;
	void *key;
	uint32_t	len;

	DEBUG(DEBUG_DEBUG, ("ibwtest_send_id\n"));
	len = sizeof(uint32_t)+strlen(tcx->id)+2;
	if (ibw_alloc_send_buf(conn, (void **)&buf, &key, len)) {
		DEBUG(DEBUG_ERR, ("send_id: ibw_alloc_send_buf failed\n"));
		return -1;
	}

	/* first sizeof(uint32_t) size bytes are for length */
	*((uint32_t *)buf) = len;
	buf[sizeof(uint32_t)] = (char)TESTOP_SEND_ID;
	strcpy(buf+sizeof(uint32_t)+1, tcx->id);

	if (ibw_send(conn, buf, key, len)) {
		DEBUG(DEBUG_ERR, ("send_id: ibw_send error\n"));
		return -1;
	}
	tcx->nsent++;

	return 0;
}

int ibwtest_send_test_msg(struct ibwtest_ctx *tcx, struct ibw_conn *conn, const char *msg)
{
	char *buf, *p;
	void *key;
	uint32_t len;

	if (conn->state!=IBWC_CONNECTED)
		return 0; /* not yet up */

	len = strlen(msg) + 2 + sizeof(uint32_t);
	if (ibw_alloc_send_buf(conn, (void **)&buf, &key, len)) {
		fprintf(stderr, "send_test_msg: ibw_alloc_send_buf failed\n");
		return -1;
	}

	*((uint32_t *)buf) = len;
	p = buf;
	p += sizeof(uint32_t);
	p[0] = (char)TESTOP_SEND_TEXT;
	p++;
	strcpy(p, msg);

	if (ibw_send(conn, buf, key, len)) {
		DEBUG(DEBUG_ERR, ("send_test_msg: ibw_send error\n"));
		return -1;
	}
	tcx->nsent++;

	return 0;
}

unsigned char ibwtest_fill_random(unsigned char *buf, uint32_t size)
{
	uint32_t	i = size;
	unsigned char	sum = 0;
	unsigned char	value;
	while(i) {
		i--;
		value = (unsigned char)(256.0 * (rand() / (RAND_MAX + 1.0)));
		buf[i] = value;
		sum += value;
	}
	return sum;
}

unsigned char ibwtest_get_sum(unsigned char *buf, uint32_t size)
{
	uint32_t	i = size;
	unsigned char	sum = 0;

	while(i) {
		i--;
		sum += buf[i];
	}
	return sum;
}

int ibwtest_do_varsize_scenario_conn_size(struct ibwtest_ctx *tcx, struct ibw_conn *conn, uint32_t size)
{
	unsigned char *buf;
	void	*key;
	uint32_t	len;
	unsigned char	sum;

	len = sizeof(uint32_t) + 1 + size + 1;
	if (ibw_alloc_send_buf(conn, (void **)&buf, &key, len)) {
		DEBUG(DEBUG_ERR, ("varsize/ibw_alloc_send_buf failed\n"));
		return -1;
	}
	*((uint32_t *)buf) = len;
	buf[sizeof(uint32_t)] = TESTOP_SEND_RND;
	sum = ibwtest_fill_random(buf + sizeof(uint32_t) + 1, size);
	buf[sizeof(uint32_t) + 1 + size] = sum;
	if (ibw_send(conn, buf, key, len)) {
		DEBUG(DEBUG_ERR, ("varsize/ibw_send failed\n"));
		return -1;
	}
	tcx->nsent++;

	return 0;
}

int ibwtest_do_varsize_scenario_conn(struct ibwtest_ctx *tcx, struct ibw_conn *conn)
{
	uint32_t	size;
	int	i;

	for(i=0; i<tcx->nmsg; i++)
	{
		//size = (uint32_t)((float)(tcx->maxsize) * (rand() / (RAND_MAX + 1.0)));
		size = (uint32_t)((float)(tcx->maxsize) * ((float)(i+1)/(float)tcx->nmsg));
		if (ibwtest_do_varsize_scenario_conn_size(tcx, conn, size))
			return -1;
	}
	return 0;
}

/*int ibwtest_do_varsize_scenario(ibwtest_ctx *tcx)
{
	int	rc;
	struct ibw_conn *conn;

	for(conn=tcx->ibwctx->conn_list; conn!=NULL; conn=conn->next) {
		if (conn->state==IBWC_CONNECTED) {
			rc = ibwtest_do_varsize_scenario_conn(tcx, conn);
			if (rc)
				tcx->error = rc;
		}
	}
}*/

int ibwtest_connstate_handler(struct ibw_ctx *ctx, struct ibw_conn *conn)
{
	struct ibwtest_ctx	*tcx = NULL; /* userdata */
	struct ibwtest_conn	*tconn = NULL; /* userdata */

	if (ctx) {
		tcx = talloc_get_type(ctx->ctx_userdata, struct ibwtest_ctx);

		switch(ctx->state) {
		case IBWS_INIT:
			DEBUG(DEBUG_DEBUG, ("test IBWS_INIT\n"));
			break;
		case IBWS_READY:
			DEBUG(DEBUG_DEBUG, ("test IBWS_READY\n"));
			break;
		case IBWS_CONNECT_REQUEST:
			DEBUG(DEBUG_DEBUG, ("test IBWS_CONNECT_REQUEST\n"));
			tconn = talloc_zero(conn, struct ibwtest_conn);
			if (ibw_accept(ctx, conn, tconn)) {
				DEBUG(DEBUG_ERR, ("error accepting the connect request\n"));
			}
			break;
		case IBWS_STOPPED:
			DEBUG(DEBUG_DEBUG, ("test IBWS_STOPPED\n"));
			tcx->kill_me = 1; /* main loop can exit */
			break;
		case IBWS_ERROR:
			DEBUG(DEBUG_DEBUG, ("test IBWS_ERROR\n"));
			ibw_stop(tcx->ibwctx);
			break;
		default:
			assert(0);
			break;
		}
	}

	if (conn) {
		tconn = talloc_get_type(conn->conn_userdata, struct ibwtest_conn);
		switch(conn->state) {
		case IBWC_INIT:
			DEBUG(DEBUG_DEBUG, ("test IBWC_INIT\n"));
			break;
		case IBWC_CONNECTED:
			if (gettimeofday(&tcx->start_time, NULL)) {
				DEBUG(DEBUG_ERR, ("gettimeofday error %d", errno));
				return -1;
			}
			ibwtest_send_id(conn);
			break;
		case IBWC_DISCONNECTED:
			DEBUG(DEBUG_DEBUG, ("test IBWC_DISCONNECTED\n"));
			talloc_free(conn);
			break;
		case IBWC_ERROR:
			DEBUG(DEBUG_DEBUG, ("test IBWC_ERROR %s\n", ibw_getLastError()));
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
	struct ibwtest_conn *tconn;
	enum testopcode op;
	struct ibwtest_ctx *tcx = talloc_get_type(conn->ctx->ctx_userdata, struct ibwtest_ctx);
	int	rc = 0;

	assert(conn!=NULL);
	assert(n>=sizeof(uint32_t)+1);
	tconn = talloc_get_type(conn->conn_userdata, struct ibwtest_conn);

	op = (enum testopcode)((char *)buf)[sizeof(uint32_t)];
	if (op==TESTOP_SEND_ID) {
		tconn->id = talloc_strdup(tconn, ((char *)buf)+sizeof(uint32_t)+1);
	}
	if (op==TESTOP_SEND_ID || op==TESTOP_SEND_TEXT) {
		DEBUG(DEBUG_DEBUG, ("[%d]msg from %s: \"%s\"(%d)\n", op,
			tconn->id ? tconn->id : "NULL", ((char *)buf)+sizeof(uint32_t)+1, n));
	}

	if (tcx->is_server) {
		if (op==TESTOP_SEND_RND) {
			unsigned char sum;
			sum = ibwtest_get_sum((unsigned char *)buf + sizeof(uint32_t) + 1,
				n - sizeof(uint32_t) - 2);
			DEBUG(DEBUG_DEBUG, ("[%d]msg varsize %u/sum %u from %s\n",
				op,
				(uint32_t)(n - sizeof(uint32_t) - 2),
				(uint32_t)sum,
				tconn->id ? tconn->id : "NULL"));
			if (sum!=((unsigned char *)buf)[n-1]) {
				DEBUG(DEBUG_ERR, ("ERROR: checksum mismatch %u!=%u\n",
					(uint32_t)sum, (uint32_t)((unsigned char *)buf)[n-1]));
				ibw_stop(tcx->ibwctx);
				goto error;
			}
		} else if (op!=TESTOP_SEND_ID) {
			char *buf2;
			void *key2;

			/* bounce message regardless what it is */
			if (ibw_alloc_send_buf(conn, (void **)&buf2, &key2, n)) {
				fprintf(stderr, "ibw_alloc_send_buf error #2\n");
				goto error;
			}
			memcpy(buf2, buf, n);
			if (ibw_send(conn, buf2, key2, n)) {
				fprintf(stderr, "ibw_send error #2\n");
				goto error;
			}
			tcx->nsent++;
		}
	} else { /* client: */
		if (op==TESTOP_SEND_ID && tcx->maxsize) {
			/* send them in one blow */
			rc = ibwtest_do_varsize_scenario_conn(tcx, conn);
		}

		if (tcx->nmsg) {
			char	msg[26];
			sprintf(msg, "hello world %d", tcx->nmsg--);
			rc = ibwtest_send_test_msg(tcx, conn, msg);
			if (tcx->nmsg==0) {
				ibw_stop(tcx->ibwctx);
				tcx->stopping = 1;
			}
		}
	}

	if (rc)
		tcx->error = rc;

	return rc;
error:
	return -1;
}

void ibwtest_timeout_handler(struct event_context *ev, struct timed_event *te, 
	struct timeval t, void *private_data)
{
	struct ibwtest_ctx *tcx = talloc_get_type(private_data, struct ibwtest_ctx);
	int	rc;

	if (!tcx->is_server) {
		struct ibw_conn *conn;
		char	msg[50];

		/* fill it with something variable... */
		sprintf(msg, "hello world %d", tcx->cnt++);

		/* send something to everybody... */
		for(conn=tcx->ibwctx->conn_list; conn!=NULL; conn=conn->next) {
			if (conn->state==IBWC_CONNECTED) {
				rc = ibwtest_send_test_msg(tcx, conn, msg);
				if (rc)
					tcx->error = rc;
			}
		}
	} /* else allow main loop run */
}

static struct ibwtest_ctx *testctx = NULL;

void ibwtest_sigint_handler(int sig)
{
	DEBUG(DEBUG_ERR, ("got SIGINT\n"));
	if (testctx) {
		if (testctx->ibwctx->state==IBWS_READY ||
			testctx->ibwctx->state==IBWS_CONNECT_REQUEST ||
			testctx->ibwctx->state==IBWS_ERROR)
		{
			if (testctx->stopping) {
				DEBUG(DEBUG_DEBUG, ("forcing exit...\n"));
				testctx->kill_me = 1;
			} else {
				/* mostly expected case */
				ibw_stop(testctx->ibwctx);
				testctx->stopping = 1;
			}
		} else
			testctx->kill_me = 1;
	}
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
			p = q; /* ++ at end */
		}
		if (*p==',') {
			*p = '\0'; /* ++ at end */
			porcess_next = 1;
		}
	}
	*pattrs = attrs;
	*nattrs = n;

	return 0;
}

static int ibwtest_get_address(const char *address, struct in_addr *addr)
{
	if (inet_pton(AF_INET, address, addr) <= 0) {
		struct hostent *he = gethostbyname(address);
		if (he == NULL || he->h_length > sizeof(*addr)) {
			DEBUG(DEBUG_ERR, ("invalid nework address '%s'\n", address));
			return -1;
		}
		memcpy(addr, he->h_addr, he->h_length);
	}
	return 0;
}

int ibwtest_getdests(struct ibwtest_ctx *tcx, char op)
{
	int	i;
	struct ibw_initattr	*attrs = NULL;
	struct sockaddr_in	*p;
	char	*tmp;

	tmp = talloc_strdup(tcx, optarg);
	if (tmp == NULL) return -1;
	/* hack to reuse the above ibw_initattr parser */
	if (ibwtest_parse_attrs(tcx, tmp, &attrs, &tcx->naddrs, op))
		return -1;

	tcx->addrs = talloc_size(tcx,
		tcx->naddrs * sizeof(struct sockaddr_in));
	for(i=0; i<tcx->naddrs; i++) {
		p = tcx->addrs + i;
		p->sin_family = AF_INET;
		if (ibwtest_get_address(attrs[i].name, &p->sin_addr))
			return -1;
		p->sin_port = htons(atoi(attrs[i].value));
	}

	return 0;
}

int ibwtest_init_server(struct ibwtest_ctx *tcx)
{
	if (tcx->naddrs!=1) {
		fprintf(stderr, "incorrect number of addrs(%d!=1)\n", tcx->naddrs);
		return -1;
	}

	if (ibw_bind(tcx->ibwctx, &tcx->addrs[0])) {
		DEBUG(DEBUG_ERR, ("ERROR: ibw_bind failed\n"));
		return -1;
	}
	
	if (ibw_listen(tcx->ibwctx, 1)) {
		DEBUG(DEBUG_ERR, ("ERROR: ibw_listen failed\n"));
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
	printf("\t-a addr1:port1,addr2:port2,... is a list of destination ip addresses\n");
	printf("\t-t nsec delta time between sends in nanosec [default %d]\n", tcx->nsec);
	printf("\t\t send message periodically and endless when nsec is non-zero\n");
	printf("\t-s server mode (you have to give exactly one -d address:port in this case)\n");
	printf("\t-n number of messages to send [default %d]\n", tcx->nmsg);
	printf("\t-l usec time to sleep in the main loop [default %d]\n", tcx->sleep_usec);
	printf("\t-v max variable msg size in bytes [default %d], 0=don't send var. size\n", tcx->maxsize);
	printf("\t-d LogLevel [default %d]\n", DEBUGLEVEL);
	printf("Press ctrl+C to stop the program.\n");
}

int main(int argc, char *argv[])
{
	int	rc, op;
	int	result = 1;
	struct tevent_context *ev = NULL;
	struct ibwtest_ctx *tcx = NULL;
	float	usec;

	tcx = talloc_zero(NULL, struct ibwtest_ctx);
	memset(tcx, 0, sizeof(struct ibwtest_ctx));
	tcx->nsec = 0;
	tcx->nmsg = 1000;
	DEBUGLEVEL = 0;

	/* here is the only case we can't avoid using global... */
	testctx = tcx;
	signal(SIGINT, ibwtest_sigint_handler);
	srand((unsigned)time(NULL));

	while ((op=getopt(argc, argv, "i:o:d:m:st:n:l:v:a:")) != -1) {
		switch (op) {
		case 'i':
			tcx->id = talloc_strdup(tcx, optarg);
			break;
		case 'o':
			tcx->opts = talloc_strdup(tcx, optarg);
			if (tcx->opts) goto cleanup;
			if (ibwtest_parse_attrs(tcx, tcx->opts, &tcx->attrs,
				&tcx->nattrs, op))
				goto cleanup;
			break;
		case 'a':
			if (ibwtest_getdests(tcx, op))
				goto cleanup;
			break;
		case 's':
			tcx->is_server = 1;
			break;
		case 't':
			tcx->nsec = (unsigned int)atoi(optarg);
			break;
		case 'n':
			tcx->nmsg = atoi(optarg);
			break;
		case 'l':
			tcx->sleep_usec = (unsigned int)atoi(optarg);
			break;
		case 'v':
			tcx->maxsize = (unsigned int)atoi(optarg);
			break;
		case 'd':
			DEBUGLEVEL = atoi(optarg);
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

	while(!tcx->kill_me && !tcx->error) {
		if (tcx->nsec) {
			event_add_timed(ev, tcx, timeval_current_ofs(0, tcx->nsec),
				ibwtest_timeout_handler, tcx);
		}

		event_loop_once(ev);

		if (tcx->sleep_usec)
			usleep(tcx->sleep_usec);
	}

	if (!tcx->is_server && tcx->nsent!=0 && !tcx->error) {
		if (gettimeofday(&tcx->end_time, NULL)) {
			DEBUG(DEBUG_ERR, ("gettimeofday error %d\n", errno));
			goto cleanup;
		}
		usec = (tcx->end_time.tv_sec - tcx->start_time.tv_sec) * 1000000 +
				(tcx->end_time.tv_usec - tcx->start_time.tv_usec);
		printf("usec: %f, nmsg: %d, usec/nmsg: %f\n",
			usec, tcx->nsent, usec/(float)tcx->nsent);
	}

	if (!tcx->error)
		result = 0; /* everything OK */

cleanup:
	if (tcx)
		talloc_free(tcx);
	if (ev)
		talloc_free(ev);
	DEBUG(DEBUG_ERR, ("exited with code %d\n", result));
	return result;
}
