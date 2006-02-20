/* 
   Unix SMB/CIFS implementation.

   winbind ldap proxy code

   Copyright (C) Volker Lendecke
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "winbindd.h"

/* This rw-buf api is made to avoid memcpy. For now do that like mad...  The
   idea is to write into a circular list of buffers where the ideal case is
   that a read(2) holds a complete request that is then thrown away
   completely. */

struct ldap_message_queue {
	struct ldap_message_queue *prev, *next;
	struct ldap_message *msg;
};

struct rw_buffer {
	uint8 *data;
	size_t ofs, length;
};

struct winbind_ldap_client {
	struct winbind_ldap_client *next, *prev;
	int sock;
	BOOL finished;
	struct rw_buffer in_buffer, out_buffer;
};

static struct winbind_ldap_client *ldap_clients;

struct winbind_ldap_server {
	struct winbind_ldap_server *next, *prev;
	int sock;
	BOOL ready;		/* Bind successful? */
	BOOL finished;
	struct rw_buffer in_buffer, out_buffer;
	int messageid;
};
	
static struct winbind_ldap_server *ldap_servers;

struct pending_ldap_message {
	struct pending_ldap_message *next, *prev;
	struct ldap_message *msg; /* The message the client sent us */
	int our_msgid;		/* The messageid we used */
	struct winbind_ldap_client *client;
};

struct pending_ldap_message *pending_messages;

static BOOL append_to_buf(struct rw_buffer *buf, uint8 *data, size_t length)
{
	buf->data = SMB_REALLOC(buf->data, buf->length+length);

	if (buf->data == NULL)
		return False;

	memcpy(buf->data+buf->length, data, length);

	buf->length += length;
	return True;
}

static BOOL read_into_buf(int fd, struct rw_buffer *buf)
{
	char tmp_buf[1024];
	int len;

	len = read(fd, tmp_buf, sizeof(tmp_buf));
	if (len == 0)
		return False;

	return append_to_buf(buf, tmp_buf, len);
}

static void peek_into_buf(struct rw_buffer *buf, uint8 **out,
			  size_t *out_length)
{
	*out = buf->data;
	*out_length = buf->length;
}

static void consumed_from_buf(struct rw_buffer *buf, size_t length)
{
	uint8 *new = memdup(buf->data+length, buf->length-length);
	free(buf->data);
	buf->data = new;
	buf->length -= length;
}

static BOOL write_out_of_buf(int fd, struct rw_buffer *buf)
{
	uint8 *tmp;
	size_t tmp_length, written;

	peek_into_buf(buf, &tmp, &tmp_length);
	if (tmp_length == 0)
		return True;

	written = write(fd, tmp, tmp_length);
	if (written < 0)
		return False;

	consumed_from_buf(buf, written);
	return True;
}

static BOOL ldap_append_to_buf(struct ldap_message *msg, struct rw_buffer *buf)
{
	DATA_BLOB blob;
	BOOL res;

	if (!ldap_encode(msg, &blob))
		return False;

	res = append_to_buf(buf, blob.data, blob.length);

	data_blob_free(&blob);
	return res;
}

static void new_ldap_client(int listen_sock)
{
	struct sockaddr_un sunaddr;
	struct winbind_ldap_client *client;
	socklen_t len;
	int sock;
	
	/* Accept connection */
	
	len = sizeof(sunaddr);

	do {
		sock = accept(listen_sock, (struct sockaddr *)&sunaddr, &len);
	} while (sock == -1 && errno == EINTR);

	if (sock == -1)
		return;
	
	DEBUG(6,("accepted socket %d\n", sock));
	
	/* Create new connection structure */

	client = SMB_MALLOC_P(struct winbind_ldap_client);

	if (client == NULL)
		return;

	ZERO_STRUCTP(client);
	
	client->sock = sock;
	client->finished = False;
	
	DLIST_ADD(ldap_clients, client);
}

static struct ldap_message *get_msg_from_buf(struct rw_buffer *buffer,
					     BOOL *error)
{
	uint8 *buf;
	int buf_length, msg_length;
	DATA_BLOB blob;
	ASN1_DATA data;
	struct ldap_message *msg;

	DEBUG(10,("ldapsrv_recv\n"));

	*error = False;

	peek_into_buf(buffer, &buf, &buf_length);

	if (buf_length < 8) {
		/* Arbitrary heuristics: ldap messages are longer than eight
		 * bytes, and their tag length fits into the eight bytes */
		return NULL;
	}

	/* LDAP Messages are always SEQUENCES */

	if (!asn1_object_length(buf, buf_length, ASN1_SEQUENCE(0),
				&msg_length))
		goto disconnect;

	if (buf_length < msg_length) {
		/* Not enough yet */
		return NULL;
	}

	/* We've got a complete LDAP request in the in-buffer */

	blob.data = buf;
	blob.length = msg_length;

	if (!asn1_load(&data, blob))
		goto disconnect;

	msg = new_ldap_message();

	if ((msg == NULL) || !ldap_decode(&data, msg)) {
		asn1_free(&data);
		goto disconnect;
	}

	asn1_free(&data);

	consumed_from_buf(buffer, msg_length);

	return msg;

 disconnect:

	*error = True;
	return NULL;
}

static int send_msg_to_server(struct ldap_message *msg,
			      struct winbind_ldap_server *server)
{
	int cli_messageid;

	cli_messageid = msg->messageid;
	msg->messageid = ldap_servers->messageid;

	if (!ldap_append_to_buf(msg, &ldap_servers->out_buffer))
		return -1;

	msg->messageid = cli_messageid;
	return ldap_servers->messageid++;
}

static int send_msg(struct ldap_message *msg)
{
	/* This is the scheduling routine that should decide where to send
	 * stuff. The first attempt is easy: We only have one server. This
	 * will change once we handle referrals etc. */

	SMB_ASSERT(ldap_servers != NULL);

	if (!ldap_servers->ready)
		return -1;

	return send_msg_to_server(msg, ldap_servers);
}

static void fake_bind_response(struct winbind_ldap_client *client,
			       int messageid)
{
	struct ldap_message *msg = new_ldap_message();

	if (msg == NULL) {
		client->finished = True;
		return;
	}

	msg->messageid = messageid;
	msg->type = LDAP_TAG_BindResponse;
	msg->r.BindResponse.response.resultcode = 0;
	msg->r.BindResponse.response.dn = "";
	msg->r.BindResponse.response.dn = "";
	msg->r.BindResponse.response.errormessage = "";
	msg->r.BindResponse.response.referral = "";
	ldap_append_to_buf(msg, &client->out_buffer);
	destroy_ldap_message(msg);
}

static int open_ldap_socket(void)
{
	static int fd = -1;

	if (fd >= 0)
		return fd;

	fd = create_pipe_sock(get_winbind_priv_pipe_dir(), "ldapi", 0750);
	return fd;
}

static BOOL do_sigterm = False;

static void ldap_termination_handler(int signum)
{
	do_sigterm = True;
	sys_select_signal();
}

static BOOL handled_locally(struct ldap_message *msg,
			    struct winbind_ldap_server *server)
{
	struct ldap_Result *r = &msg->r.BindResponse.response;

	if (msg->type != LDAP_TAG_BindResponse)
		return False;

	if (r->resultcode != 0) {
		destroy_ldap_message(msg);
		server->finished = True;
	}
	destroy_ldap_message(msg);
	server->ready = True;
	return True;
}

static void client_has_data(struct winbind_ldap_client *client)
{
			
	struct ldap_message *msg;

	if (!read_into_buf(client->sock, &client->in_buffer)) {
		client->finished = True;
		return;
	}

	while ((msg = get_msg_from_buf(&client->in_buffer,
				       &client->finished))) {
		struct pending_ldap_message *pending;

		if (msg->type == LDAP_TAG_BindRequest) {
			fake_bind_response(client, msg->messageid);
			destroy_ldap_message(msg);
			continue;
		}

		if (msg->type == LDAP_TAG_UnbindRequest) {
			destroy_ldap_message(msg);
			client->finished = True;
			break;
		}

		pending = SMB_MALLOC_P(struct pending_ldap_message);
		if (pending == NULL)
			continue;

		pending->msg = msg;
		pending->client = client;
		pending->our_msgid = send_msg(msg);

		if (pending->our_msgid < 0) {
			/* could not send */
			client->finished = True;
			free(pending);
		}
		DLIST_ADD(pending_messages, pending);
	}
}

static struct ldap_Result *ldap_msg2result(struct ldap_message *msg)
{
	switch(msg->type) {
	case LDAP_TAG_BindResponse:
		return &msg->r.BindResponse.response;
	case LDAP_TAG_SearchResultDone:
		return &msg->r.SearchResultDone;
	case LDAP_TAG_ModifyResponse:
		return &msg->r.ModifyResponse;
	case LDAP_TAG_AddResponse:
		return &msg->r.AddResponse;
	case LDAP_TAG_DelResponse:
		return &msg->r.DelResponse;
	case LDAP_TAG_ModifyDNResponse:
		return &msg->r.ModifyDNResponse;
	case LDAP_TAG_CompareResponse:
		return &msg->r.CompareResponse;
	case LDAP_TAG_ExtendedResponse:
		return &msg->r.ExtendedResponse.response;
	}
	return NULL;
}

static void server_has_data(struct winbind_ldap_server *server)
{
	struct ldap_message *msg;

	if (!read_into_buf(server->sock, &server->in_buffer)) {
		server->finished = True;
		return;
	}

	while ((msg = get_msg_from_buf(&server->in_buffer,
				       &server->finished))) {
		struct pending_ldap_message *pending;
		struct rw_buffer *buf;
		struct ldap_Result *res;

		if (handled_locally(msg, server))
			continue;

		res = ldap_msg2result(msg);

		if ( (res != NULL) && (res->resultcode == 10) )
			DEBUG(5, ("Got Referral %s\n", res->referral));

		for (pending = pending_messages;
		     pending != NULL;
		     pending = pending->next) {
			if (pending->our_msgid == msg->messageid)
				break;
		}

		if (pending == NULL) {
			talloc_destroy(msg->mem_ctx);
			continue;
		}

		msg->messageid = pending->msg->messageid;

		buf = &pending->client->out_buffer;
		ldap_append_to_buf(msg, buf);

		if ( (msg->type != LDAP_TAG_SearchResultEntry) &&
		     (msg->type != LDAP_TAG_SearchResultReference) ) {
			destroy_ldap_message(pending->msg);
			DLIST_REMOVE(pending_messages,
				     pending);
			SAFE_FREE(pending);
		}
		destroy_ldap_message(msg);
	}
}

static void process_ldap_loop(void)
{
	struct winbind_ldap_client *client;
	struct winbind_ldap_server *server;
	fd_set r_fds, w_fds;
	int maxfd, listen_sock, selret;
	struct timeval timeout;

	/* Free up temporary memory */

	lp_TALLOC_FREE();
	main_loop_TALLOC_FREE();

	if (do_sigterm) {
#if 0
		TALLOC_CTX *mem_ctx = talloc_init("describe");
		DEBUG(0, ("%s\n", talloc_describe_all(mem_ctx)));
		talloc_destroy(mem_ctx);
#endif
		exit(0);
	}

	/* Initialise fd lists for select() */

	listen_sock = open_ldap_socket();

	if (listen_sock == -1) {
		perror("open_ldap_socket");
		exit(1);
	}

	maxfd = listen_sock;

	FD_ZERO(&r_fds);
	FD_ZERO(&w_fds);
	FD_SET(listen_sock, &r_fds);

	timeout.tv_sec = WINBINDD_ESTABLISH_LOOP;
	timeout.tv_usec = 0;

	/* Set up client readers and writers */
	
	client = ldap_clients;

	while (client != NULL) {

		if (client->finished) {
			struct winbind_ldap_client *next = client->next;
			DLIST_REMOVE(ldap_clients, client);
			close(client->sock);
			SAFE_FREE(client->in_buffer.data);
			SAFE_FREE(client->out_buffer.data);
			SAFE_FREE(client);
			client = next;
			continue;
		}

		if (client->sock > maxfd)
			maxfd = client->sock;

		FD_SET(client->sock, &r_fds);

		if (client->out_buffer.length > 0)
			FD_SET(client->sock, &w_fds);

		client = client->next;
	}

	/* And now the servers */

	server = ldap_servers;

	while (server != NULL) {

		if (server->finished) {
			struct winbind_ldap_server *next = server->next;
			DLIST_REMOVE(ldap_servers, server);
			close(server->sock);
			SAFE_FREE(server);
			server = next;
			continue;
		}

		if (server->sock > maxfd)
			maxfd = server->sock;

		FD_SET(server->sock, &r_fds);

		if (server->out_buffer.length > 0)
			FD_SET(server->sock, &w_fds);

		server = server->next;
	}

	selret = sys_select(maxfd + 1, &r_fds, &w_fds, NULL, &timeout);

	if (selret == 0)
		return;

	if (selret == -1 && errno != EINTR) {
		perror("select");
		exit(1);
	}

	if (FD_ISSET(listen_sock, &r_fds))
		new_ldap_client(listen_sock);

	for (client = ldap_clients; client != NULL; client = client->next) {

		if (FD_ISSET(client->sock, &r_fds))
			client_has_data(client);

		if ((!client->finished) && FD_ISSET(client->sock, &w_fds))
			write_out_of_buf(client->sock, &client->out_buffer);
	}

	for (server = ldap_servers; server != NULL; server = server->next) {

		if (FD_ISSET(server->sock, &r_fds))
			server_has_data(server);

		if (!server->finished && FD_ISSET(server->sock, &w_fds))
			write_out_of_buf(server->sock, &server->out_buffer);
	}
}

static BOOL setup_ldap_serverconn(void)
{
	char *host;
	uint16 port;
	BOOL ldaps;
	struct hostent *hp;
	struct in_addr ip;
	TALLOC_CTX *mem_ctx = talloc_init("server");
	struct ldap_message *msg;
	char *dn, *pw;

	ldap_servers = SMB_MALLOC_P(struct winbind_ldap_server);

	if ((ldap_servers == NULL) || (mem_ctx == NULL))
		return False;

	if (!ldap_parse_basic_url(mem_ctx, "ldap://192.168.234.1:3899/",
				  &host, &port, &ldaps))
		return False;
	
	hp = sys_gethostbyname(host);

	if ((hp == NULL) || (hp->h_addr == NULL))
		return False;

	putip((char *)&ip, (char *)hp->h_addr);

	ZERO_STRUCTP(ldap_servers);
	ldap_servers->sock = open_socket_out(SOCK_STREAM, &ip, port, 10000);
	ldap_servers->messageid = 1;

	if (!fetch_ldap_pw(&dn, &pw))
		return False;

	msg = new_ldap_simple_bind_msg(dn, pw);

	SAFE_FREE(dn);
	SAFE_FREE(pw);

	if (msg == NULL)
		return False;

	msg->messageid = ldap_servers->messageid++;

	ldap_append_to_buf(msg, &ldap_servers->out_buffer);

	destroy_ldap_message(msg);

	return (ldap_servers->sock >= 0);
}

void do_ldap_proxy(void)
{
	int ldap_child;

	ldap_child = sys_fork();

	if (ldap_child != 0)
		return;

	/* tdb needs special fork handling */
	if (tdb_reopen_all() == -1) {
		DEBUG(0,("tdb_reopen_all failed.\n"));
		_exit(0);
	}

	if (!message_init()) {
		DEBUG(0, ("message_init failed\n"));
		_exit(0);
	}

	CatchSignal(SIGINT, ldap_termination_handler);
	CatchSignal(SIGQUIT, ldap_termination_handler);
	CatchSignal(SIGTERM, ldap_termination_handler);

	if (!setup_ldap_serverconn())
		return;

	while (1)
		process_ldap_loop();

	return;
}
