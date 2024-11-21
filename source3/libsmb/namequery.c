/*
   Unix SMB/CIFS implementation.
   name query routines
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Jeremy Allison 2007.

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
#include "libsmb/namequery.h"
#include "../lib/util/tevent_ntstatus.h"
#include "libads/sitename_cache.h"
#include "../lib/addns/dnsquery.h"
#include "../lib/addns/dnsquery_srv.h"
#include "../libcli/netlogon/netlogon.h"
#include "lib/async_req/async_sock.h"
#include "lib/tsocket/tsocket.h"
#include "libsmb/nmblib.h"
#include "libsmb/unexpected.h"
#include "../libcli/nbt/libnbt.h"
#include "lib/gencache.h"
#include "librpc/gen_ndr/dns.h"
#include "lib/util/util_net.h"
#include "lib/util/tsort.h"
#include "lib/util/string_wrappers.h"

/* nmbd.c sets this to True. */
bool global_in_nmbd = False;

/*
 * Utility function to convert from a sockaddr_storage
 * array to a struct samba_sockaddr array.
 */

static NTSTATUS sockaddr_array_to_samba_sockaddr_array(
				TALLOC_CTX *ctx,
				struct samba_sockaddr **sa_out,
				size_t *count_out,
				const struct sockaddr_storage *ss_in,
				size_t count_in)
{
	struct samba_sockaddr *sa = NULL;
	size_t i;
	size_t count = 0;

	if (count_in == 0) {
		/*
		 * Zero length arrays are returned as NULL.
		 * in the name resolution code.
		 */
		*count_out = 0;
		*sa_out = NULL;
		return NT_STATUS_OK;
	}
	sa = talloc_zero_array(ctx,
				struct samba_sockaddr,
				count_in);
	if (sa == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	count = 0;
	for (i = 0; i < count_in; i++) {
		bool ok;

		/* Filter out zero addresses. */
		if (is_zero_addr(&ss_in[i])) {
			continue;
		}
		ok = sockaddr_storage_to_samba_sockaddr(&sa[count],
							&ss_in[i]);
		if (!ok) {
			continue;
		}
		count++;
	}
	if (count == 0) {
		/*
		 * Zero length arrays are returned as NULL.
		 * in the name resolution code.
		 */
		TALLOC_FREE(sa);
	}
	*count_out = count;
	*sa_out = sa;
	return NT_STATUS_OK;
}

/****************************
 * SERVER AFFINITY ROUTINES *
 ****************************/

 /* Server affinity is the concept of preferring the last domain
    controller with whom you had a successful conversation */

/****************************************************************************
****************************************************************************/
#define SAFKEY_FMT	"SAF/DOMAIN/%s"
#define SAF_TTL		900
#define SAFJOINKEY_FMT	"SAFJOIN/DOMAIN/%s"
#define SAFJOIN_TTL	3600

static char *saf_key(TALLOC_CTX *mem_ctx, const char *domain)
{
	return talloc_asprintf_strupper_m(mem_ctx, SAFKEY_FMT, domain);
}

static char *saf_join_key(TALLOC_CTX *mem_ctx, const char *domain)
{
	return talloc_asprintf_strupper_m(mem_ctx, SAFJOINKEY_FMT, domain);
}

/****************************************************************************
****************************************************************************/

bool saf_store( const char *domain, const char *servername )
{
	char *key;
	time_t expire;
	bool ret = False;

	if ( !domain || !servername ) {
		DEBUG(2,("saf_store: "
			"Refusing to store empty domain or servername!\n"));
		return False;
	}

	if ( (strlen(domain) == 0) || (strlen(servername) == 0) ) {
		DEBUG(0,("saf_store: "
			"refusing to store 0 length domain or servername!\n"));
		return False;
	}

	key = saf_key(talloc_tos(), domain);
	if (key == NULL) {
		DEBUG(1, ("saf_key() failed\n"));
		return false;
	}
	expire = time( NULL ) + lp_parm_int(-1, "saf","ttl", SAF_TTL);

	DBG_DEBUG("domain = [%s], server = [%s], expire = [%" PRIu64 "]\n",
		  domain,
		  servername,
		  (uint64_t)expire);

	ret = gencache_set( key, servername, expire );

	TALLOC_FREE( key );

	return ret;
}

bool saf_join_store( const char *domain, const char *servername )
{
	char *key;
	time_t expire;
	bool ret = False;

	if ( !domain || !servername ) {
		DEBUG(2,("saf_join_store: Refusing to store empty domain or servername!\n"));
		return False;
	}

	if ( (strlen(domain) == 0) || (strlen(servername) == 0) ) {
		DEBUG(0,("saf_join_store: refusing to store 0 length domain or servername!\n"));
		return False;
	}

	key = saf_join_key(talloc_tos(), domain);
	if (key == NULL) {
		DEBUG(1, ("saf_join_key() failed\n"));
		return false;
	}
	expire = time( NULL ) + lp_parm_int(-1, "saf","join ttl", SAFJOIN_TTL);

	DEBUG(10,("saf_join_store: domain = [%s], server = [%s], expire = [%u]\n",
		domain, servername, (unsigned int)expire ));

	ret = gencache_set( key, servername, expire );

	TALLOC_FREE( key );

	return ret;
}

bool saf_delete( const char *domain )
{
	char *key;
	bool ret = False;

	if ( !domain ) {
		DEBUG(2,("saf_delete: Refusing to delete empty domain\n"));
		return False;
	}

	key = saf_join_key(talloc_tos(), domain);
	if (key == NULL) {
		DEBUG(1, ("saf_join_key() failed\n"));
		return false;
	}
	ret = gencache_del(key);
	TALLOC_FREE(key);

	if (ret) {
		DEBUG(10,("saf_delete[join]: domain = [%s]\n", domain ));
	}

	key = saf_key(talloc_tos(), domain);
	if (key == NULL) {
		DEBUG(1, ("saf_key() failed\n"));
		return false;
	}
	ret = gencache_del(key);
	TALLOC_FREE(key);

	if (ret) {
		DEBUG(10,("saf_delete: domain = [%s]\n", domain ));
	}

	return ret;
}

/****************************************************************************
****************************************************************************/

char *saf_fetch(TALLOC_CTX *mem_ctx, const char *domain )
{
	char *server = NULL;
	time_t timeout;
	bool ret = False;
	char *key = NULL;

	if ( !domain || strlen(domain) == 0) {
		DEBUG(2,("saf_fetch: Empty domain name!\n"));
		return NULL;
	}

	key = saf_join_key(talloc_tos(), domain);
	if (key == NULL) {
		DEBUG(1, ("saf_join_key() failed\n"));
		return NULL;
	}

	ret = gencache_get( key, mem_ctx, &server, &timeout );

	TALLOC_FREE( key );

	if ( ret ) {
		DEBUG(5,("saf_fetch[join]: Returning \"%s\" for \"%s\" domain\n",
			server, domain ));
		return server;
	}

	key = saf_key(talloc_tos(), domain);
	if (key == NULL) {
		DEBUG(1, ("saf_key() failed\n"));
		return NULL;
	}

	ret = gencache_get( key, mem_ctx, &server, &timeout );

	TALLOC_FREE( key );

	if ( !ret ) {
		DEBUG(5,("saf_fetch: failed to find server for \"%s\" domain\n",
					domain ));
	} else {
		DEBUG(5,("saf_fetch: Returning \"%s\" for \"%s\" domain\n",
			server, domain ));
	}

	return server;
}

static void set_socket_addr_v4(struct samba_sockaddr *addr)
{
	if (!interpret_string_addr(&addr->u.ss, lp_nbt_client_socket_address(),
				   AI_NUMERICHOST|AI_PASSIVE)) {
		zero_sockaddr(&addr->u.ss);
		/* zero_sockaddr sets family to AF_INET. */
		addr->sa_socklen = sizeof(struct sockaddr_in);
	}
	if (addr->u.ss.ss_family != AF_INET) {
		zero_sockaddr(&addr->u.ss);
		/* zero_sockaddr sets family to AF_INET. */
		addr->sa_socklen = sizeof(struct sockaddr_in);
	}
}

static struct in_addr my_socket_addr_v4(void)
{
	struct samba_sockaddr my_addr = {0};

	set_socket_addr_v4(&my_addr);
	return my_addr.u.in.sin_addr;
}

/****************************************************************************
 Generate a random trn_id.
****************************************************************************/

static int generate_trn_id(void)
{
	uint16_t id;

	generate_random_buffer((uint8_t *)&id, sizeof(id));

	return id % (unsigned)0x7FFF;
}

/****************************************************************************
 Parse a node status response into an array of structures.
****************************************************************************/

static struct node_status *parse_node_status(TALLOC_CTX *mem_ctx,
					     const char *rdata,
					     size_t rdlen,
					     size_t *num_names,
					     struct node_status_extra *extra)
{
	struct node_status *ret;
	size_t i;
	size_t len = 0;
	size_t result_count = 0;
	const size_t result_len = MAX_NETBIOSNAME_LEN + sizeof(uint8_t) +
				  sizeof(char);
	const char *r = NULL;

	*num_names = 0;
	if (rdlen == 0) {
		return NULL;
	}

	result_count = PULL_LE_U8(rdata, 0);
	if (result_count == 0) {
		return NULL;
	}
	r = rdata + 1;

	len = result_len * result_count + sizeof(uint8_t);
	if (len > rdlen) {
		return NULL;
	}

	ret = talloc_zero_array(mem_ctx, struct node_status, result_count);
	if (!ret)
		return NULL;

	for (i = 0; i < result_count; i++) {
		strlcpy(ret[i].name, r, MAX_NETBIOSNAME_LEN);
		trim_char(ret[i].name,'\0',' ');
		ret[i].type = PULL_LE_U8(r, 15);
		ret[i].flags = r[16];

		r += result_len;

		DEBUG(10, ("%s#%02x: flags = 0x%02x\n", ret[i].name,
			   ret[i].type, ret[i].flags));
	}

	/*
	 * Also, pick up the MAC address ...
	 */
	if (extra) {
		if (len + 6 > rdlen) {
			TALLOC_FREE(ret);
			return NULL;
		}
		memcpy(&extra->mac_addr, r, 6); /* Fill in the mac addr */
	}

	*num_names = result_count;
	return ret;
}

struct sock_packet_read_state {
	struct tevent_context *ev;
	enum packet_type type;
	int trn_id;

	struct nb_packet_reader *reader;
	struct tevent_req *reader_req;

	struct tdgram_context *sock;
	struct tevent_req *socket_req;
	uint8_t *buf;
	struct tsocket_address *addr;

	bool (*validator)(struct packet_struct *p,
			  void *private_data);
	void *private_data;

	struct packet_struct *packet;
};

static void sock_packet_read_got_packet(struct tevent_req *subreq);
static void sock_packet_read_got_socket(struct tevent_req *subreq);

static struct tevent_req *sock_packet_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct tdgram_context *sock,
	struct nb_packet_reader *reader,
	enum packet_type type,
	int trn_id,
	bool (*validator)(struct packet_struct *p, void *private_data),
	void *private_data)
{
	struct tevent_req *req;
	struct sock_packet_read_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct sock_packet_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->reader = reader;
	state->sock = sock;
	state->type = type;
	state->trn_id = trn_id;
	state->validator = validator;
	state->private_data = private_data;

	if (reader != NULL) {
		state->reader_req = nb_packet_read_send(state, ev, reader);
		if (tevent_req_nomem(state->reader_req, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(
			state->reader_req, sock_packet_read_got_packet, req);
	}

	state->socket_req = tdgram_recvfrom_send(state, ev, state->sock);
	if (tevent_req_nomem(state->socket_req, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(state->socket_req, sock_packet_read_got_socket,
				req);

	return req;
}

static void sock_packet_read_got_packet(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct sock_packet_read_state *state = tevent_req_data(
		req, struct sock_packet_read_state);
	NTSTATUS status;

	status = nb_packet_read_recv(subreq, state, &state->packet);

	TALLOC_FREE(state->reader_req);

	if (!NT_STATUS_IS_OK(status)) {
		if (state->socket_req != NULL) {
			/*
			 * Still waiting for socket
			 */
			return;
		}
		/*
		 * Both socket and packet reader failed
		 */
		tevent_req_nterror(req, status);
		return;
	}

	if ((state->validator != NULL) &&
	    !state->validator(state->packet, state->private_data)) {
		DEBUG(10, ("validator failed\n"));

		TALLOC_FREE(state->packet);

		state->reader_req = nb_packet_read_send(state, state->ev,
							state->reader);
		if (tevent_req_nomem(state->reader_req, req)) {
			return;
		}
		tevent_req_set_callback(
			state->reader_req, sock_packet_read_got_packet, req);
		return;
	}

	TALLOC_FREE(state->socket_req);
	tevent_req_done(req);
}

static void sock_packet_read_got_socket(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct sock_packet_read_state *state = tevent_req_data(
		req, struct sock_packet_read_state);
	struct samba_sockaddr addr = {0};
	ssize_t ret;
	ssize_t received;
	int err;
	bool ok;

	received = tdgram_recvfrom_recv(subreq, &err, state,
					&state->buf, &state->addr);

	TALLOC_FREE(state->socket_req);

	if (received == -1) {
		if (state->reader_req != NULL) {
			/*
			 * Still waiting for reader
			 */
			return;
		}
		/*
		 * Both socket and reader failed
		 */
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}
	ok = tsocket_address_is_inet(state->addr, "ipv4");
	if (!ok) {
		goto retry;
	}
	ret = tsocket_address_bsd_sockaddr(state->addr,
					&addr.u.sa,
					sizeof(addr.u.in));
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(errno));
		return;
	}

	state->packet = parse_packet_talloc(
		state, (char *)state->buf, received, state->type,
		addr.u.in.sin_addr, addr.u.in.sin_port);
	if (state->packet == NULL) {
		DEBUG(10, ("parse_packet failed\n"));
		goto retry;
	}
	if ((state->trn_id != -1) &&
	    (state->trn_id != packet_trn_id(state->packet))) {
		DEBUG(10, ("Expected transaction id %d, got %d\n",
			   state->trn_id, packet_trn_id(state->packet)));
		goto retry;
	}

	if ((state->validator != NULL) &&
	    !state->validator(state->packet, state->private_data)) {
		DEBUG(10, ("validator failed\n"));
		goto retry;
	}

	tevent_req_done(req);
	return;

retry:
	TALLOC_FREE(state->packet);
	TALLOC_FREE(state->buf);
	TALLOC_FREE(state->addr);

	state->socket_req = tdgram_recvfrom_send(state, state->ev, state->sock);
	if (tevent_req_nomem(state->socket_req, req)) {
		return;
	}
	tevent_req_set_callback(state->socket_req, sock_packet_read_got_socket,
				req);
}

static NTSTATUS sock_packet_read_recv(struct tevent_req *req,
				      TALLOC_CTX *mem_ctx,
				      struct packet_struct **ppacket)
{
	struct sock_packet_read_state *state = tevent_req_data(
		req, struct sock_packet_read_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*ppacket = talloc_move(mem_ctx, &state->packet);
	return NT_STATUS_OK;
}

struct nb_trans_state {
	struct tevent_context *ev;
	struct tdgram_context *sock;
	struct nb_packet_reader *reader;

	struct tsocket_address *src_addr;
	struct tsocket_address *dst_addr;
	uint8_t *buf;
	size_t buflen;
	enum packet_type type;
	int trn_id;

	bool (*validator)(struct packet_struct *p,
			  void *private_data);
	void *private_data;

	struct packet_struct *packet;
};

static void nb_trans_got_reader(struct tevent_req *subreq);
static void nb_trans_done(struct tevent_req *subreq);
static void nb_trans_sent(struct tevent_req *subreq);
static void nb_trans_send_next(struct tevent_req *subreq);

static struct tevent_req *nb_trans_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	const struct samba_sockaddr *_my_addr,
	const struct samba_sockaddr *_dst_addr,
	bool bcast,
	uint8_t *buf, size_t buflen,
	enum packet_type type, int trn_id,
	bool (*validator)(struct packet_struct *p,
			  void *private_data),
	void *private_data)
{
	const struct sockaddr *my_addr = &_my_addr->u.sa;
	size_t my_addr_len = sizeof(_my_addr->u.in); /*We know it's AF_INET.*/
	const struct sockaddr *dst_addr = &_dst_addr->u.sa;
	size_t dst_addr_len = sizeof(_dst_addr->u.in); /*We know it's AF_INET.*/
	struct tevent_req *req, *subreq;
	struct nb_trans_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct nb_trans_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->buf = buf;
	state->buflen = buflen;
	state->type = type;
	state->trn_id = trn_id;
	state->validator = validator;
	state->private_data = private_data;

	ret = tsocket_address_bsd_from_sockaddr(state,
						my_addr, my_addr_len,
						&state->src_addr);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(errno));
		return tevent_req_post(req, ev);
	}

	ret = tsocket_address_bsd_from_sockaddr(state,
						dst_addr, dst_addr_len,
						&state->dst_addr);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(errno));
		return tevent_req_post(req, ev);
	}

	ret = tdgram_inet_udp_broadcast_socket(state->src_addr, state,
					       &state->sock);
	if (ret == -1) {
		tevent_req_nterror(req, map_nt_error_from_unix(errno));
		return tevent_req_post(req, ev);
	}

	subreq = nb_packet_reader_send(state,
				       ev,
				       global_nmbd_socket_dir(),
				       type,
				       state->trn_id,
				       NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, nb_trans_got_reader, req);
	return req;
}

static void nb_trans_got_reader(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct nb_trans_state *state = tevent_req_data(
		req, struct nb_trans_state);
	NTSTATUS status;

	status = nb_packet_reader_recv(subreq, state, &state->reader);
	TALLOC_FREE(subreq);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("nmbd not around\n"));
		state->reader = NULL;
	}

	subreq = sock_packet_read_send(
		state, state->ev, state->sock,
		state->reader, state->type, state->trn_id,
		state->validator, state->private_data);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, nb_trans_done, req);

	subreq = tdgram_sendto_send(state, state->ev,
				    state->sock,
				    state->buf, state->buflen,
				    state->dst_addr);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, nb_trans_sent, req);
}

static void nb_trans_sent(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct nb_trans_state *state = tevent_req_data(
		req, struct nb_trans_state);
	ssize_t sent;
	int err;

	sent = tdgram_sendto_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (sent == -1) {
		DEBUG(10, ("sendto failed: %s\n", strerror(err)));
		tevent_req_nterror(req, map_nt_error_from_unix(err));
		return;
	}
	subreq = tevent_wakeup_send(state, state->ev,
				    timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, nb_trans_send_next, req);
}

static void nb_trans_send_next(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct nb_trans_state *state = tevent_req_data(
		req, struct nb_trans_state);
	bool ret;

	ret = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ret) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}
	subreq = tdgram_sendto_send(state, state->ev,
				    state->sock,
				    state->buf, state->buflen,
				    state->dst_addr);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, nb_trans_sent, req);
}

static void nb_trans_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct nb_trans_state *state = tevent_req_data(
		req, struct nb_trans_state);
	NTSTATUS status;

	status = sock_packet_read_recv(subreq, state, &state->packet);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS nb_trans_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			      struct packet_struct **ppacket)
{
	struct nb_trans_state *state = tevent_req_data(
		req, struct nb_trans_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*ppacket = talloc_move(mem_ctx, &state->packet);
	return NT_STATUS_OK;
}

/****************************************************************************
 Do a NBT node status query on an open socket and return an array of
 structures holding the returned names or NULL if the query failed.
**************************************************************************/

struct node_status_query_state {
	struct samba_sockaddr my_addr;
	struct samba_sockaddr addr;
	uint8_t buf[1024];
	ssize_t buflen;
	struct packet_struct *packet;
};

static bool node_status_query_validator(struct packet_struct *p,
					void *private_data);
static void node_status_query_done(struct tevent_req *subreq);

struct tevent_req *node_status_query_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct nmb_name *name,
					  const struct sockaddr_storage *addr)
{
	struct tevent_req *req, *subreq;
	struct node_status_query_state *state;
	struct packet_struct p;
	struct nmb_packet *nmb = &p.packet.nmb;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct node_status_query_state);
	if (req == NULL) {
		return NULL;
	}

	if (addr->ss_family != AF_INET) {
		/* Can't do node status to IPv6 */
		tevent_req_nterror(req, NT_STATUS_INVALID_ADDRESS);
		return tevent_req_post(req, ev);
	}

	ok = sockaddr_storage_to_samba_sockaddr(&state->addr, addr);
	if (!ok) {
		/* node status must be IPv4 */
		tevent_req_nterror(req, NT_STATUS_INVALID_ADDRESS);
		return tevent_req_post(req, ev);
	}
	state->addr.u.in.sin_port = htons(NMB_PORT);

	set_socket_addr_v4(&state->my_addr);

	ZERO_STRUCT(p);
	nmb->header.name_trn_id = generate_trn_id();
	nmb->header.opcode = 0;
	nmb->header.response = false;
	nmb->header.nm_flags.bcast = false;
	nmb->header.nm_flags.recursion_available = false;
	nmb->header.nm_flags.recursion_desired = false;
	nmb->header.nm_flags.trunc = false;
	nmb->header.nm_flags.authoritative = false;
	nmb->header.rcode = 0;
	nmb->header.qdcount = 1;
	nmb->header.ancount = 0;
	nmb->header.nscount = 0;
	nmb->header.arcount = 0;
	nmb->question.question_name = *name;
	nmb->question.question_type = 0x21;
	nmb->question.question_class = 0x1;

	state->buflen = build_packet((char *)state->buf, sizeof(state->buf),
				     &p);
	if (state->buflen == 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		DEBUG(10, ("build_packet failed\n"));
		return tevent_req_post(req, ev);
	}

	subreq = nb_trans_send(state,
				ev,
				&state->my_addr,
				&state->addr,
				false,
				state->buf,
				state->buflen,
				NMB_PACKET,
				nmb->header.name_trn_id,
				node_status_query_validator,
				NULL);
	if (tevent_req_nomem(subreq, req)) {
		DEBUG(10, ("nb_trans_send failed\n"));
		return tevent_req_post(req, ev);
	}
	if (!tevent_req_set_endtime(req, ev, timeval_current_ofs(10, 0))) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, node_status_query_done, req);
	return req;
}

static bool node_status_query_validator(struct packet_struct *p,
					void *private_data)
{
	struct nmb_packet *nmb = &p->packet.nmb;
	debug_nmb_packet(p);

	if (nmb->header.opcode != 0 ||
	    nmb->header.nm_flags.bcast ||
	    nmb->header.rcode ||
	    !nmb->header.ancount ||
	    nmb->answers->rr_type != 0x21) {
		/*
		 * XXXX what do we do with this? could be a redirect,
		 * but we'll discard it for the moment
		 */
		return false;
	}
	return true;
}

static void node_status_query_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct node_status_query_state *state = tevent_req_data(
		req, struct node_status_query_state);
	NTSTATUS status;

	status = nb_trans_recv(subreq, state, &state->packet);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS node_status_query_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				struct node_status **pnode_status,
				size_t *pnum_names,
				struct node_status_extra *extra)
{
	struct node_status_query_state *state = tevent_req_data(
		req, struct node_status_query_state);
	struct node_status *node_status;
	size_t num_names = 0;
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	node_status = parse_node_status(
		mem_ctx,
		state->packet->packet.nmb.answers->rdata,
		state->packet->packet.nmb.answers->rdlength,
		&num_names,
		extra);
	if (node_status == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	*pnode_status = node_status;
	*pnum_names = num_names;
	return NT_STATUS_OK;
}

NTSTATUS node_status_query(TALLOC_CTX *mem_ctx, struct nmb_name *name,
			   const struct sockaddr_storage *addr,
			   struct node_status **pnode_status,
			   size_t *pnum_names,
			   struct node_status_extra *extra)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = node_status_query_send(ev, ev, name, addr);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = node_status_query_recv(req, mem_ctx, pnode_status,
					pnum_names, extra);
 fail:
	TALLOC_FREE(frame);
	return status;
}

static bool name_status_lmhosts(const struct sockaddr_storage *paddr,
				int qname_type, fstring pname)
{
	FILE *f;
	char *name;
	int name_type;
	struct samba_sockaddr addr_in = {0};
	struct samba_sockaddr addr = {0};
	bool ok;

	ok = sockaddr_storage_to_samba_sockaddr(&addr_in, paddr);
	if (!ok) {
		return false;
	}
	if (addr_in.u.ss.ss_family != AF_INET) {
		return false;
	}

	f = startlmhosts(get_dyn_LMHOSTSFILE());
	if (f == NULL) {
		return false;
	}

	while (getlmhostsent(talloc_tos(), f, &name, &name_type, &addr.u.ss)) {
		if (addr.u.ss.ss_family != AF_INET) {
			continue;
		}
		if (name_type != qname_type) {
			continue;
		}
		if (sockaddr_equal(&addr_in.u.sa, &addr.u.sa)) {
			fstrcpy(pname, name);
			endlmhosts(f);
			return true;
		}
	}
	endlmhosts(f);
	return false;
}

/****************************************************************************
 Find the first type XX name in a node status reply - used for finding
 a servers name given its IP. Return the matched name in *name.
**************************************************************************/

bool name_status_find(const char *q_name,
			int q_type,
			int type,
			const struct sockaddr_storage *to_ss,
			fstring name)
{
	char addr[INET6_ADDRSTRLEN];
	struct node_status *addrs = NULL;
	struct nmb_name nname;
	size_t count = 0, i;
	bool result = false;
	NTSTATUS status;

	if (lp_disable_netbios()) {
		DEBUG(5,("name_status_find(%s#%02x): netbios is disabled\n",
					q_name, q_type));
		return False;
	}

	print_sockaddr(addr, sizeof(addr), to_ss);

	DEBUG(10, ("name_status_find: looking up %s#%02x at %s\n", q_name,
		   q_type, addr));

	/* Check the cache first. */

	if (namecache_status_fetch(q_name, q_type, type, to_ss, name)) {
		return True;
	}

	if (to_ss->ss_family != AF_INET) {
		/* Can't do node status to IPv6 */
		return false;
	}

	result = name_status_lmhosts(to_ss, type, name);
	if (result) {
		DBG_DEBUG("Found name %s in lmhosts\n", name);
		namecache_status_store(q_name, q_type, type, to_ss, name);
		return true;
	}

	/* W2K PDC's seem not to respond to '*'#0. JRA */
	make_nmb_name(&nname, q_name, q_type);
	status = node_status_query(talloc_tos(), &nname, to_ss,
				   &addrs, &count, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	for (i=0;i<count;i++) {
                /* Find first one of the requested type that's not a GROUP. */
		if (addrs[i].type == type && ! (addrs[i].flags & 0x80))
			break;
	}
	if (i == count)
		goto done;

	pull_ascii_nstring(name, sizeof(fstring), addrs[i].name);

	/* Store the result in the cache. */
	/* but don't store an entry for 0x1c names here.  Here we have
	   a single host and DOMAIN<0x1c> names should be a list of hosts */

	if ( q_type != 0x1c ) {
		namecache_status_store(q_name, q_type, type, to_ss, name);
	}

	result = true;

 done:
	TALLOC_FREE(addrs);

	DEBUG(10, ("name_status_find: name %sfound", result ? "" : "not "));

	if (result)
		DEBUGADD(10, (", name %s ip address is %s", name, addr));

	DEBUG(10, ("\n"));

	return result;
}

/*
 * comparison function used by sort_addr_list
 *
 * This comparison is intransitive in sort if a socket has an invalid
 * family (i.e., not IPv4 or IPv6), or an interface doesn't support
 * the family. Say we have sockaddrs with IP versions {4,5,6}, of
 * which 5 is invalid. By this function, 4 == 5 and 6 == 5, but 4 !=
 * 6. This is of course a consequence of cmp() being unable to
 * communicate error.
 */

static int addr_compare(const struct sockaddr_storage *ss1,
			const struct sockaddr_storage *ss2)
{
	int max_bits1=0, max_bits2=0;
	int num_interfaces = iface_count();
	int i;
	struct samba_sockaddr sa1;
	struct samba_sockaddr sa2;
	bool ok;

	ok = sockaddr_storage_to_samba_sockaddr(&sa1, ss1);
	if (!ok) {
		return 0; /* No change. */
	}

	ok = sockaddr_storage_to_samba_sockaddr(&sa2, ss2);
	if (!ok) {
		return 0; /* No change. */
	}

	/* Sort IPv4 addresses first. */
	if (sa1.u.ss.ss_family != sa2.u.ss.ss_family) {
		if (sa2.u.ss.ss_family == AF_INET) {
			return 1;
		} else {
			return -1;
		}
	}

	/* Here we know both addresses are of the same
	 * family. */

	for (i=0;i<num_interfaces;i++) {
		struct samba_sockaddr sif = {0};
		const unsigned char *p_ss1 = NULL;
		const unsigned char *p_ss2 = NULL;
		const unsigned char *p_if = NULL;
		size_t len = 0;
		int bits1, bits2;

		ok = sockaddr_storage_to_samba_sockaddr(&sif, iface_n_bcast(i));
		if (!ok) {
			return 0; /* No change. */
		}
		if (sif.u.ss.ss_family != sa1.u.ss.ss_family) {
			/* Ignore interfaces of the wrong type. */
			continue;
		}
		if (sif.u.ss.ss_family == AF_INET) {
			p_if = (const unsigned char *)&sif.u.in.sin_addr;
			p_ss1 = (const unsigned char *)&sa1.u.in.sin_addr;
			p_ss2 = (const unsigned char *)&sa2.u.in.sin_addr;
			len = 4;
		}
#if defined(HAVE_IPV6)
		if (sif.u.ss.ss_family == AF_INET6) {
			p_if = (const unsigned char *)&sif.u.in6.sin6_addr;
			p_ss1 = (const unsigned char *)&sa1.u.in6.sin6_addr;
			p_ss2 = (const unsigned char *)&sa2.u.in6.sin6_addr;
			len = 16;
		}
#endif
		if (!p_ss1 || !p_ss2 || !p_if || len == 0) {
			continue;
		}
		bits1 = matching_len_bits(p_ss1, p_if, len);
		bits2 = matching_len_bits(p_ss2, p_if, len);
		max_bits1 = MAX(bits1, max_bits1);
		max_bits2 = MAX(bits2, max_bits2);
	}

	/* Bias towards directly reachable IPs */
	if (iface_local(&sa1.u.sa)) {
		if (sa1.u.ss.ss_family == AF_INET) {
			max_bits1 += 32;
		} else {
			max_bits1 += 128;
		}
	}
	if (iface_local(&sa2.u.sa)) {
		if (sa2.u.ss.ss_family == AF_INET) {
			max_bits2 += 32;
		} else {
			max_bits2 += 128;
		}
	}
	return NUMERIC_CMP(max_bits2, max_bits1);
}

/*
  sort an IP list so that names that are close to one of our interfaces
  are at the top. This prevents the problem where a WINS server returns an IP
  that is not reachable from our subnet as the first match
*/

static void sort_addr_list(struct sockaddr_storage *sslist, size_t count)
{
	if (count <= 1) {
		return;
	}

	TYPESAFE_QSORT(sslist, count, addr_compare);
}

static int samba_sockaddr_compare(struct samba_sockaddr *sa1,
				struct samba_sockaddr *sa2)
{
	return addr_compare(&sa1->u.ss, &sa2->u.ss);
}

static void sort_sa_list(struct samba_sockaddr *salist, size_t count)
{
	if (count <= 1) {
		return;
	}

	TYPESAFE_QSORT(salist, count, samba_sockaddr_compare);
}

/**********************************************************************
 Remove any duplicate address/port pairs in the samba_sockaddr array.
 *********************************************************************/

size_t remove_duplicate_addrs2(struct samba_sockaddr *salist, size_t count )
{
	size_t i, j;

	DBG_DEBUG("looking for duplicate address/port pairs\n");

	/* One loop to set duplicates to a zero addr. */
	for (i=0; i < count; i++) {
		if (is_zero_addr(&salist[i].u.ss)) {
			continue;
		}

		for (j=i+1; j<count; j++) {
			if (sockaddr_equal(&salist[i].u.sa, &salist[j].u.sa)) {
				zero_sockaddr(&salist[j].u.ss);
			}
		}
	}

	/* Now remove any addresses set to zero above. */
	for (i = 0; i < count; i++) {
		while (i < count &&
				is_zero_addr(&salist[i].u.ss)) {
			ARRAY_DEL_ELEMENT(salist, i, count);
			count--;
		}
	}

	return count;
}

static bool prioritize_ipv4_list(struct samba_sockaddr *salist, size_t count)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct samba_sockaddr *salist_new = talloc_array(frame,
						struct samba_sockaddr,
						count);
	size_t i, j;

	if (salist_new == NULL) {
		TALLOC_FREE(frame);
		return false;
	}

	j = 0;

	/* Copy IPv4 first. */
	for (i = 0; i < count; i++) {
		if (salist[i].u.ss.ss_family == AF_INET) {
			salist_new[j++] = salist[i];
		}
	}

	/* Copy IPv6. */
	for (i = 0; i < count; i++) {
		if (salist[i].u.ss.ss_family != AF_INET) {
			salist_new[j++] = salist[i];
		}
	}

	memcpy(salist, salist_new, sizeof(struct samba_sockaddr)*count);
	TALLOC_FREE(frame);
	return true;
}

/****************************************************************************
 Do a netbios name query to find someones IP.
 Returns an array of IP addresses or NULL if none.
 *count will be set to the number of addresses returned.
 *timed_out is set if we failed by timing out
****************************************************************************/

struct name_query_state {
	struct samba_sockaddr my_addr;
	struct samba_sockaddr addr;
	bool bcast;
	bool bcast_star_query;


	uint8_t buf[1024];
	ssize_t buflen;

	NTSTATUS validate_error;
	uint8_t flags;

	struct sockaddr_storage *addrs;
	size_t num_addrs;
};

static bool name_query_validator(struct packet_struct *p, void *private_data);
static void name_query_done(struct tevent_req *subreq);

struct tevent_req *name_query_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   const char *name, int name_type,
				   bool bcast, bool recurse,
				   const struct sockaddr_storage *addr)
{
	struct tevent_req *req, *subreq;
	struct name_query_state *state;
	struct packet_struct p;
	struct nmb_packet *nmb = &p.packet.nmb;
	bool ok;

	req = tevent_req_create(mem_ctx, &state, struct name_query_state);
	if (req == NULL) {
		return NULL;
	}
	state->bcast = bcast;

	if (addr->ss_family != AF_INET) {
		/* Can't do node status to IPv6 */
		tevent_req_nterror(req, NT_STATUS_INVALID_ADDRESS);
		return tevent_req_post(req, ev);
	}

	if (lp_disable_netbios()) {
		DEBUG(5,("name_query(%s#%02x): netbios is disabled\n",
					name, name_type));
		tevent_req_nterror(req, NT_STATUS_NOT_SUPPORTED);
		return tevent_req_post(req, ev);
	}

	ok = sockaddr_storage_to_samba_sockaddr(&state->addr, addr);
	if (!ok) {
		/* Node status must be IPv4 */
		tevent_req_nterror(req, NT_STATUS_INVALID_ADDRESS);
		return tevent_req_post(req, ev);
	}
	state->addr.u.in.sin_port = htons(NMB_PORT);

	set_socket_addr_v4(&state->my_addr);

	ZERO_STRUCT(p);
	nmb->header.name_trn_id = generate_trn_id();
	nmb->header.opcode = 0;
	nmb->header.response = false;
	nmb->header.nm_flags.bcast = bcast;
	nmb->header.nm_flags.recursion_available = false;
	nmb->header.nm_flags.recursion_desired = recurse;
	nmb->header.nm_flags.trunc = false;
	nmb->header.nm_flags.authoritative = false;
	nmb->header.rcode = 0;
	nmb->header.qdcount = 1;
	nmb->header.ancount = 0;
	nmb->header.nscount = 0;
	nmb->header.arcount = 0;

	if (bcast && (strcmp(name, "*")==0)) {
		/*
		 * We're doing a broadcast query for all
		 * names in the area. Remember this so
		 * we will wait for all names within
		 * the timeout period.
		 */
		state->bcast_star_query = true;
	}

	make_nmb_name(&nmb->question.question_name,name,name_type);

	nmb->question.question_type = 0x20;
	nmb->question.question_class = 0x1;

	state->buflen = build_packet((char *)state->buf, sizeof(state->buf),
				     &p);
	if (state->buflen == 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		DEBUG(10, ("build_packet failed\n"));
		return tevent_req_post(req, ev);
	}

	subreq = nb_trans_send(state,
				ev,
				&state->my_addr,
				&state->addr,
				bcast,
				state->buf,
				state->buflen,
				NMB_PACKET,
				nmb->header.name_trn_id,
				name_query_validator,
				state);
	if (tevent_req_nomem(subreq, req)) {
		DEBUG(10, ("nb_trans_send failed\n"));
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, name_query_done, req);
	return req;
}

static bool name_query_validator(struct packet_struct *p, void *private_data)
{
	struct name_query_state *state = talloc_get_type_abort(
		private_data, struct name_query_state);
	struct nmb_packet *nmb = &p->packet.nmb;
	struct sockaddr_storage *tmp_addrs;
	bool got_unique_netbios_name = false;
	int i;

	debug_nmb_packet(p);

	/*
	 * If we get a Negative Name Query Response from a WINS
	 * server, we should report it and give up.
	 */
	if( 0 == nmb->header.opcode	/* A query response   */
	    && !state->bcast		/* from a WINS server */
	    && nmb->header.rcode	/* Error returned     */
		) {

		if( DEBUGLVL( 3 ) ) {
			/* Only executed if DEBUGLEVEL >= 3 */
			dbgtext( "Negative name query "
				 "response, rcode 0x%02x: ",
				 nmb->header.rcode );
			switch( nmb->header.rcode ) {
			case 0x01:
				dbgtext("Request was invalidly formatted.\n");
				break;
			case 0x02:
				dbgtext("Problem with NBNS, cannot process "
					"name.\n");
				break;
			case 0x03:
				dbgtext("The name requested does not "
					"exist.\n");
				break;
			case 0x04:
				dbgtext("Unsupported request error.\n");
				break;
			case 0x05:
				dbgtext("Query refused error.\n");
				break;
			default:
				dbgtext("Unrecognized error code.\n" );
				break;
			}
		}

		/*
		 * We accept this packet as valid, but tell the upper
		 * layers that it's a negative response.
		 */
		state->validate_error = NT_STATUS_NOT_FOUND;
		return true;
	}

	if (nmb->header.opcode != 0 ||
	    nmb->header.nm_flags.bcast ||
	    nmb->header.rcode ||
	    !nmb->header.ancount) {
		/*
		 * XXXX what do we do with this? Could be a redirect,
		 * but we'll discard it for the moment.
		 */
		return false;
	}

	tmp_addrs = talloc_realloc(
		state, state->addrs, struct sockaddr_storage,
		state->num_addrs + nmb->answers->rdlength/6);
	if (tmp_addrs == NULL) {
		state->validate_error = NT_STATUS_NO_MEMORY;
		return true;
	}
	state->addrs = tmp_addrs;

	DEBUG(2,("Got a positive name query response "
		 "from %s ( ", inet_ntoa(p->ip)));

	for (i=0; i<nmb->answers->rdlength/6; i++) {
		uint16_t flags;
		struct in_addr ip;
		struct sockaddr_storage addr;
		struct samba_sockaddr sa = {0};
		bool ok;
		size_t j;

		flags = RSVAL(&nmb->answers->rdata[i*6], 0);
		got_unique_netbios_name |= ((flags & 0x8000) == 0);

		putip((char *)&ip,&nmb->answers->rdata[2+i*6]);
		in_addr_to_sockaddr_storage(&addr, ip);

		ok = sockaddr_storage_to_samba_sockaddr(&sa, &addr);
		if (!ok) {
			continue;
		}

		if (is_zero_addr(&sa.u.ss)) {
			continue;
		}

		for (j=0; j<state->num_addrs; j++) {
			struct samba_sockaddr sa_j = {0};

			ok = sockaddr_storage_to_samba_sockaddr(&sa_j,
						&state->addrs[j]);
			if (!ok) {
				continue;
			}
			if (sockaddr_equal(&sa.u.sa, &sa_j.u.sa)) {
				break;
			}
		}
		if (j < state->num_addrs) {
			/* Already got it */
			continue;
		}

		DEBUGADD(2,("%s ",inet_ntoa(ip)));

		state->addrs[state->num_addrs] = addr;
		/* wrap check. */
		if (state->num_addrs + 1 < state->num_addrs) {
			return false;
		}
		state->num_addrs += 1;
	}
	DEBUGADD(2,(")\n"));

	/* We add the flags back ... */
	if (nmb->header.response)
		state->flags |= NM_FLAGS_RS;
	if (nmb->header.nm_flags.authoritative)
		state->flags |= NM_FLAGS_AA;
	if (nmb->header.nm_flags.trunc)
		state->flags |= NM_FLAGS_TC;
	if (nmb->header.nm_flags.recursion_desired)
		state->flags |= NM_FLAGS_RD;
	if (nmb->header.nm_flags.recursion_available)
		state->flags |= NM_FLAGS_RA;
	if (nmb->header.nm_flags.bcast)
		state->flags |= NM_FLAGS_B;

	if (state->bcast) {
		/*
		 * We have to collect all entries coming in from broadcast
		 * queries. If we got a unique name and we are not querying
		 * all names registered within broadcast area (query
		 * for the name '*', so state->bcast_star_query is set),
		 * we're done.
		 */
		return (got_unique_netbios_name && !state->bcast_star_query);
	}
	/*
	 * WINS responses are accepted when they are received
	 */
	return true;
}

static void name_query_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct name_query_state *state = tevent_req_data(
		req, struct name_query_state);
	NTSTATUS status;
	struct packet_struct *p = NULL;

	status = nb_trans_recv(subreq, state, &p);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	if (!NT_STATUS_IS_OK(state->validate_error)) {
		tevent_req_nterror(req, state->validate_error);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS name_query_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 struct sockaddr_storage **addrs, size_t *num_addrs,
			 uint8_t *flags)
{
	struct name_query_state *state = tevent_req_data(
		req, struct name_query_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		if (state->bcast &&
		    NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
			/*
			 * In the broadcast case we collect replies until the
			 * timeout.
			 */
			status = NT_STATUS_OK;
		}
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	if (state->num_addrs == 0) {
		return NT_STATUS_NOT_FOUND;
	}
	*addrs = talloc_move(mem_ctx, &state->addrs);
	sort_addr_list(*addrs, state->num_addrs);
	*num_addrs = state->num_addrs;
	if (flags != NULL) {
		*flags = state->flags;
	}
	return NT_STATUS_OK;
}

NTSTATUS name_query(const char *name, int name_type,
		    bool bcast, bool recurse,
		    const struct sockaddr_storage *to_ss,
		    TALLOC_CTX *mem_ctx,
		    struct sockaddr_storage **addrs,
		    size_t *num_addrs, uint8_t *flags)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	struct timeval timeout;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = name_query_send(ev, ev, name, name_type, bcast, recurse, to_ss);
	if (req == NULL) {
		goto fail;
	}
	if (bcast) {
		timeout = timeval_current_ofs(0, 250000);
	} else {
		timeout = timeval_current_ofs(2, 0);
	}
	if (!tevent_req_set_endtime(req, ev, timeout)) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = name_query_recv(req, mem_ctx, addrs, num_addrs, flags);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct name_queries_state {
	struct tevent_context *ev;
	const char *name;
	int name_type;
	bool bcast;
	bool recurse;
	const struct sockaddr_storage *addrs;
	size_t num_addrs;
	int wait_msec;
	int timeout_msec;

	struct tevent_req **subreqs;
	size_t num_received;
	size_t num_sent;

	size_t received_index;
	struct sockaddr_storage *result_addrs;
	size_t num_result_addrs;
	uint8_t flags;
};

static void name_queries_done(struct tevent_req *subreq);
static void name_queries_next(struct tevent_req *subreq);

/*
 * Send a name query to multiple destinations with a wait time in between
 */

static struct tevent_req *name_queries_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	const char *name, int name_type,
	bool bcast, bool recurse,
	const struct sockaddr_storage *addrs,
	size_t num_addrs, int wait_msec, int timeout_msec)
{
	struct tevent_req *req, *subreq;
	struct name_queries_state *state;

	if (num_addrs == 0) {
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state,
				struct name_queries_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->name = name;
	state->name_type = name_type;
	state->bcast = bcast;
	state->recurse = recurse;
	state->addrs = addrs;
	state->num_addrs = num_addrs;
	state->wait_msec = wait_msec;
	state->timeout_msec = timeout_msec;

	state->subreqs = talloc_zero_array(
		state, struct tevent_req *, num_addrs);
	if (tevent_req_nomem(state->subreqs, req)) {
		return tevent_req_post(req, ev);
	}
	state->num_sent = 0;

	subreq = name_query_send(
		state->subreqs, state->ev, name, name_type, bcast, recurse,
		&state->addrs[state->num_sent]);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	if (!tevent_req_set_endtime(
		    subreq, state->ev,
		    timeval_current_ofs(0, state->timeout_msec * 1000))) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, name_queries_done, req);

	state->subreqs[state->num_sent] = subreq;
	state->num_sent += 1;

	if (state->num_sent < state->num_addrs) {
		subreq = tevent_wakeup_send(
			state, state->ev,
			timeval_current_ofs(0, state->wait_msec * 1000));
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, name_queries_next, req);
	}
	return req;
}

static void name_queries_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct name_queries_state *state = tevent_req_data(
		req, struct name_queries_state);
	size_t i;
	NTSTATUS status;

	status = name_query_recv(subreq, state, &state->result_addrs,
				 &state->num_result_addrs, &state->flags);

	for (i=0; i<state->num_sent; i++) {
		if (state->subreqs[i] == subreq) {
			break;
		}
	}
	if (i == state->num_sent) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}
	TALLOC_FREE(state->subreqs[i]);

	/* wrap check. */
	if (state->num_received + 1 < state->num_received) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}
	state->num_received += 1;

	if (!NT_STATUS_IS_OK(status)) {

		if (state->num_received >= state->num_addrs) {
			tevent_req_nterror(req, status);
			return;
		}
		/*
		 * Still outstanding requests, just wait
		 */
		return;
	}
	state->received_index = i;
	tevent_req_done(req);
}

static void name_queries_next(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct name_queries_state *state = tevent_req_data(
		req, struct name_queries_state);

	if (!tevent_wakeup_recv(subreq)) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	subreq = name_query_send(
		state->subreqs, state->ev,
		state->name, state->name_type, state->bcast, state->recurse,
		&state->addrs[state->num_sent]);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, name_queries_done, req);
	if (!tevent_req_set_endtime(
		    subreq, state->ev,
		    timeval_current_ofs(0, state->timeout_msec * 1000))) {
		return;
	}
	state->subreqs[state->num_sent] = subreq;
	state->num_sent += 1;

	if (state->num_sent < state->num_addrs) {
		subreq = tevent_wakeup_send(
			state, state->ev,
			timeval_current_ofs(0, state->wait_msec * 1000));
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, name_queries_next, req);
	}
}

static NTSTATUS name_queries_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				  struct sockaddr_storage **result_addrs,
				  size_t *num_result_addrs, uint8_t *flags,
				  size_t *received_index)
{
	struct name_queries_state *state = tevent_req_data(
		req, struct name_queries_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (result_addrs != NULL) {
		*result_addrs = talloc_move(mem_ctx, &state->result_addrs);
	}
	if (num_result_addrs != NULL) {
		*num_result_addrs = state->num_result_addrs;
	}
	if (flags != NULL) {
		*flags = state->flags;
	}
	if (received_index != NULL) {
		*received_index = state->received_index;
	}
	return NT_STATUS_OK;
}

/********************************************************
 Resolve via "bcast" method.
*********************************************************/

struct name_resolve_bcast_state {
	struct sockaddr_storage *addrs;
	size_t num_addrs;
};

static void name_resolve_bcast_done(struct tevent_req *subreq);

struct tevent_req *name_resolve_bcast_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   const char *name,
					   int name_type)
{
	struct tevent_req *req, *subreq;
	struct name_resolve_bcast_state *state;
	struct sockaddr_storage *bcast_addrs;
	size_t i, num_addrs, num_bcast_addrs;

	req = tevent_req_create(mem_ctx, &state,
				struct name_resolve_bcast_state);
	if (req == NULL) {
		return NULL;
	}

	if (lp_disable_netbios()) {
		DEBUG(5, ("name_resolve_bcast(%s#%02x): netbios is disabled\n",
			  name, name_type));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	/*
	 * "bcast" means do a broadcast lookup on all the local interfaces.
	 */

	DEBUG(3, ("name_resolve_bcast: Attempting broadcast lookup "
		  "for name %s<0x%x>\n", name, name_type));

	num_addrs = iface_count();
	if (num_addrs == 0) {
		DBG_INFO("name_resolve_bcast(%s#%02x): no interfaces are available\n",
			 name,
			 name_type);
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	bcast_addrs = talloc_array(state, struct sockaddr_storage, num_addrs);
	if (tevent_req_nomem(bcast_addrs, req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * Lookup the name on all the interfaces, return on
	 * the first successful match.
	 */
	num_bcast_addrs = 0;

	for (i=0; i<num_addrs; i++) {
		const struct sockaddr_storage *pss = iface_n_bcast(i);

		if (pss->ss_family != AF_INET) {
			continue;
		}
		bcast_addrs[num_bcast_addrs] = *pss;
		num_bcast_addrs += 1;
	}

	subreq = name_queries_send(state, ev, name, name_type, true, true,
				   bcast_addrs, num_bcast_addrs, 0, 250);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, name_resolve_bcast_done, req);
	return req;
}

static void name_resolve_bcast_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct name_resolve_bcast_state *state = tevent_req_data(
		req, struct name_resolve_bcast_state);
	NTSTATUS status;

	status = name_queries_recv(subreq, state,
				   &state->addrs, &state->num_addrs,
				   NULL, NULL);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

NTSTATUS name_resolve_bcast_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
				 struct sockaddr_storage **addrs,
				 size_t *num_addrs)
{
	struct name_resolve_bcast_state *state = tevent_req_data(
		req, struct name_resolve_bcast_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	*addrs = talloc_move(mem_ctx, &state->addrs);
	*num_addrs = state->num_addrs;
	return NT_STATUS_OK;
}

NTSTATUS name_resolve_bcast(TALLOC_CTX *mem_ctx,
			const char *name,
			int name_type,
			struct sockaddr_storage **return_iplist,
			size_t *return_count)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = name_resolve_bcast_send(frame, ev, name, name_type);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = name_resolve_bcast_recv(req, mem_ctx, return_iplist,
					 return_count);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct query_wins_list_state {
	struct tevent_context *ev;
	const char *name;
	uint8_t name_type;
	struct in_addr *servers;
	size_t num_servers;
	struct sockaddr_storage server;
	size_t num_sent;

	struct sockaddr_storage *addrs;
	size_t num_addrs;
	uint8_t flags;
};

static void query_wins_list_done(struct tevent_req *subreq);

/*
 * Query a list of (replicating) wins servers in sequence, call them
 * dead if they don't reply
 */

static struct tevent_req *query_wins_list_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct in_addr src_ip, const char *name, uint8_t name_type,
	struct in_addr *servers, size_t num_servers)
{
	struct tevent_req *req, *subreq;
	struct query_wins_list_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct query_wins_list_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->name = name;
	state->name_type = name_type;
	state->servers = servers;
	state->num_servers = num_servers;

	if (state->num_servers == 0) {
		tevent_req_nterror(req, NT_STATUS_NOT_FOUND);
		return tevent_req_post(req, ev);
	}

	in_addr_to_sockaddr_storage(
		&state->server, state->servers[state->num_sent]);

	subreq = name_query_send(state, state->ev,
				 state->name, state->name_type,
				 false, true, &state->server);

	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	/* wrap check */
	if (state->num_sent + 1 < state->num_sent) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	state->num_sent += 1;
	if (!tevent_req_set_endtime(subreq, state->ev,
				    timeval_current_ofs(2, 0))) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, query_wins_list_done, req);
	return req;
}

static void query_wins_list_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct query_wins_list_state *state = tevent_req_data(
		req, struct query_wins_list_state);
	NTSTATUS status;

	status = name_query_recv(subreq, state,
				 &state->addrs, &state->num_addrs,
				 &state->flags);
	TALLOC_FREE(subreq);
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
		return;
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		tevent_req_nterror(req, status);
		return;
	}
	wins_srv_died(state->servers[state->num_sent-1],
		      my_socket_addr_v4());

	if (state->num_sent == state->num_servers) {
		tevent_req_nterror(req, NT_STATUS_NOT_FOUND);
		return;
	}

	in_addr_to_sockaddr_storage(
		&state->server, state->servers[state->num_sent]);

	subreq = name_query_send(state, state->ev,
				 state->name, state->name_type,
				 false, true, &state->server);
	state->num_sent += 1;
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	if (!tevent_req_set_endtime(subreq, state->ev,
				    timeval_current_ofs(2, 0))) {
		return;
	}
	tevent_req_set_callback(subreq, query_wins_list_done, req);
}

static NTSTATUS query_wins_list_recv(struct tevent_req *req,
				     TALLOC_CTX *mem_ctx,
				     struct sockaddr_storage **addrs,
				     size_t *num_addrs,
				     uint8_t *flags)
{
	struct query_wins_list_state *state = tevent_req_data(
		req, struct query_wins_list_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (addrs != NULL) {
		*addrs = talloc_move(mem_ctx, &state->addrs);
	}
	if (num_addrs != NULL) {
		*num_addrs = state->num_addrs;
	}
	if (flags != NULL) {
		*flags = state->flags;
	}
	return NT_STATUS_OK;
}

struct resolve_wins_state {
	size_t num_sent;
	size_t num_received;

	struct sockaddr_storage *addrs;
	size_t num_addrs;
	uint8_t flags;
};

static void resolve_wins_done(struct tevent_req *subreq);

struct tevent_req *resolve_wins_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     const char *name,
				     int name_type)
{
	struct tevent_req *req, *subreq;
	struct resolve_wins_state *state;
	char **wins_tags = NULL;
	struct sockaddr_storage src_ss;
	struct samba_sockaddr src_sa = {0};
	struct in_addr src_ip;
	size_t i, num_wins_tags;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct resolve_wins_state);
	if (req == NULL) {
		return NULL;
	}

	if (wins_srv_count() < 1) {
		DEBUG(3,("resolve_wins: WINS server resolution selected "
			"and no WINS servers listed.\n"));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto fail;
	}

	/* the address we will be sending from */
	if (!interpret_string_addr(&src_ss, lp_nbt_client_socket_address(),
				AI_NUMERICHOST|AI_PASSIVE)) {
		zero_sockaddr(&src_ss);
	}

	ok = sockaddr_storage_to_samba_sockaddr(&src_sa, &src_ss);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto fail;
	}

	if (src_sa.u.ss.ss_family != AF_INET) {
		char addr[INET6_ADDRSTRLEN];
		print_sockaddr(addr, sizeof(addr), &src_sa.u.ss);
		DEBUG(3,("resolve_wins: cannot receive WINS replies "
			"on IPv6 address %s\n",
			addr));
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto fail;
	}

	src_ip = src_sa.u.in.sin_addr;

	wins_tags = wins_srv_tags();
	if (wins_tags == NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		goto fail;
	}

	num_wins_tags = 0;
	while (wins_tags[num_wins_tags] != NULL) {
		/* wrap check. */
		if (num_wins_tags + 1 < num_wins_tags) {
			tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
			goto fail;
		}
		num_wins_tags += 1;
	}

	for (i=0; i<num_wins_tags; i++) {
		size_t num_servers, num_alive;
		struct in_addr *servers, *alive;
		size_t j;

		if (!wins_server_tag_ips(wins_tags[i], talloc_tos(),
					 &servers, &num_servers)) {
			DEBUG(10, ("wins_server_tag_ips failed for tag %s\n",
				   wins_tags[i]));
			continue;
		}

		alive = talloc_array(state, struct in_addr, num_servers);
		if (tevent_req_nomem(alive, req)) {
			goto fail;
		}

		num_alive = 0;
		for (j=0; j<num_servers; j++) {
			struct in_addr wins_ip = servers[j];

			if (global_in_nmbd && ismyip_v4(wins_ip)) {
				/* yikes! we'll loop forever */
				continue;
			}
			/* skip any that have been unresponsive lately */
			if (wins_srv_is_dead(wins_ip, src_ip)) {
				continue;
			}
			DEBUG(3, ("resolve_wins: using WINS server %s "
				 "and tag '%s'\n",
				  inet_ntoa(wins_ip), wins_tags[i]));
			alive[num_alive] = wins_ip;
			num_alive += 1;
		}
		TALLOC_FREE(servers);

		if (num_alive == 0) {
			continue;
		}

		subreq = query_wins_list_send(
			state, ev, src_ip, name, name_type,
			alive, num_alive);
		if (tevent_req_nomem(subreq, req)) {
			goto fail;
		}
		tevent_req_set_callback(subreq, resolve_wins_done, req);
		state->num_sent += 1;
	}

	if (state->num_sent == 0) {
		tevent_req_nterror(req, NT_STATUS_NOT_FOUND);
		goto fail;
	}

	wins_srv_tags_free(wins_tags);
	return req;
fail:
	wins_srv_tags_free(wins_tags);
	return tevent_req_post(req, ev);
}

static void resolve_wins_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct resolve_wins_state *state = tevent_req_data(
		req, struct resolve_wins_state);
	NTSTATUS status;

	status = query_wins_list_recv(subreq, state, &state->addrs,
				      &state->num_addrs, &state->flags);
	if (NT_STATUS_IS_OK(status)) {
		tevent_req_done(req);
		return;
	}

	/* wrap check. */
	if (state->num_received + 1 < state->num_received) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return;
	}

	state->num_received += 1;

	if (state->num_received < state->num_sent) {
		/*
		 * Wait for the others
		 */
		return;
	}
	tevent_req_nterror(req, status);
}

NTSTATUS resolve_wins_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct sockaddr_storage **addrs,
			   size_t *num_addrs, uint8_t *flags)
{
	struct resolve_wins_state *state = tevent_req_data(
		req, struct resolve_wins_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}
	if (addrs != NULL) {
		*addrs = talloc_move(mem_ctx, &state->addrs);
	}
	if (num_addrs != NULL) {
		*num_addrs = state->num_addrs;
	}
	if (flags != NULL) {
		*flags = state->flags;
	}
	return NT_STATUS_OK;
}

/********************************************************
 Resolve via "wins" method.
*********************************************************/

NTSTATUS resolve_wins(TALLOC_CTX *mem_ctx,
		const char *name,
		int name_type,
		struct sockaddr_storage **return_iplist,
		size_t *return_count)
{
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(talloc_tos());
	if (ev == NULL) {
		goto fail;
	}
	req = resolve_wins_send(ev, ev, name, name_type);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = resolve_wins_recv(req, mem_ctx, return_iplist, return_count,
				   NULL);
fail:
	TALLOC_FREE(ev);
	return status;
}


/********************************************************
 Resolve via "hosts" method.
*********************************************************/

static NTSTATUS resolve_hosts(TALLOC_CTX *mem_ctx,
			      const char *name,
			      int name_type,
			      struct sockaddr_storage **return_iplist,
			      size_t *return_count)
{
	/*
	 * "host" means do a localhost, or dns lookup.
	 */
	struct addrinfo hints;
	struct addrinfo *ailist = NULL;
	struct addrinfo *res = NULL;
	int ret = -1;
	size_t i = 0;
	size_t ret_count = 0;
	struct sockaddr_storage *iplist = NULL;

	if ( name_type != 0x20 && name_type != 0x0) {
		DEBUG(5, ("resolve_hosts: not appropriate "
			"for name type <0x%x>\n",
			name_type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(3,("resolve_hosts: Attempting host lookup for name %s<0x%x>\n",
				name, name_type));

	ZERO_STRUCT(hints);
	/* By default make sure it supports TCP. */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

#if !defined(HAVE_IPV6)
	/* Unless we have IPv6, we really only want IPv4 addresses back. */
	hints.ai_family = AF_INET;
#endif

	ret = getaddrinfo(name,
			NULL,
			&hints,
			&ailist);
	if (ret) {
		DEBUG(3,("resolve_hosts: getaddrinfo failed for name %s [%s]\n",
			name,
			gai_strerror(ret) ));
	}

	for (res = ailist; res; res = res->ai_next) {
		struct sockaddr_storage ss = {0};
		struct sockaddr_storage *tmp = NULL;

		if ((res->ai_addr == NULL) ||
		    (res->ai_addrlen == 0) ||
		    (res->ai_addrlen > sizeof(ss))) {
			continue;
		}

		memcpy(&ss, res->ai_addr, res->ai_addrlen);

		if (is_zero_addr(&ss)) {
			continue;
		}

		/* wrap check. */
		if (ret_count + 1 < ret_count) {
			freeaddrinfo(ailist);
			TALLOC_FREE(iplist);
			return NT_STATUS_INVALID_PARAMETER;
		}
		ret_count += 1;

		tmp = talloc_realloc(
			mem_ctx, iplist, struct sockaddr_storage,
			ret_count);
		if (tmp == NULL) {
			DEBUG(3,("resolve_hosts: malloc fail !\n"));
			freeaddrinfo(ailist);
			TALLOC_FREE(iplist);
			return NT_STATUS_NO_MEMORY;
		}
		iplist = tmp;
		iplist[i] = ss;
		i++;
	}
	if (ailist) {
		freeaddrinfo(ailist);
	}
	if (ret_count == 0) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	*return_count = ret_count;
	*return_iplist = iplist;
	return NT_STATUS_OK;
}

/********************************************************
 Resolve via "ADS" method.
*********************************************************/

/* Special name type used to cause a _kerberos DNS lookup. */
#define KDC_NAME_TYPE 0xDCDC

static NTSTATUS resolve_ads(TALLOC_CTX *ctx,
			    const char *name,
			    int name_type,
			    const char *sitename,
			    struct sockaddr_storage **return_addrs,
			    size_t *return_count)
{
	size_t 			i;
	NTSTATUS  		status;
	struct dns_rr_srv	*dcs = NULL;
	size_t			numdcs = 0;
	size_t num_srv_addrs = 0;
	struct sockaddr_storage *srv_addrs = NULL;
	char *query = NULL;

	if ((name_type != 0x1c) && (name_type != KDC_NAME_TYPE) &&
	    (name_type != 0x1b)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = NT_STATUS_OK;

	switch (name_type) {
		case 0x1b:
			DEBUG(5,("resolve_ads: Attempting to resolve "
				 "PDC for %s using DNS\n", name));
			query = ads_dns_query_string_pdc(ctx, name);
			break;

		case 0x1c:
			DEBUG(5,("resolve_ads: Attempting to resolve "
				 "DCs for %s using DNS\n", name));
			query = ads_dns_query_string_dcs(ctx, name);
			break;
		case KDC_NAME_TYPE:
			DEBUG(5,("resolve_ads: Attempting to resolve "
				 "KDCs for %s using DNS\n", name));
			query = ads_dns_query_string_kdcs(ctx, name);
			break;
		default:
			status = NT_STATUS_INVALID_PARAMETER;
			break;
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (query == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	DBG_DEBUG("SRV query for %s\n", query);

	status = ads_dns_query_srv(
		ctx,
		lp_get_async_dns_timeout(),
		sitename,
		query,
		&dcs,
		&numdcs);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (numdcs == 0) {
		*return_addrs = NULL;
		*return_count = 0;
		TALLOC_FREE(dcs);
		return NT_STATUS_OK;
	}

	/* First count the sizes of each array. */
	for(i = 0; i < numdcs; i++) {
		if (dcs[i].ss_s == NULL) {
			/*
			 * Nothing received or timeout in A/AAAA reqs
			 */
			continue;
		}

		if (num_srv_addrs + dcs[i].num_ips < num_srv_addrs) {
			/* Wrap check. */
			TALLOC_FREE(dcs);
			return NT_STATUS_INVALID_PARAMETER;
		}
		/* Add in the number of addresses we got. */
		num_srv_addrs += dcs[i].num_ips;
	}

	/* Allocate the list of IP addresses we already have. */
	srv_addrs = talloc_zero_array(ctx,
				struct sockaddr_storage,
				num_srv_addrs);
	if (srv_addrs == NULL) {
		TALLOC_FREE(dcs);
		return NT_STATUS_NO_MEMORY;
	}

	num_srv_addrs = 0;
	for(i = 0; i < numdcs; i++) {
		/* Copy all the IP addresses from the SRV response */
		size_t j;
		for (j = 0; j < dcs[i].num_ips; j++) {
			char addr[INET6_ADDRSTRLEN];

			srv_addrs[num_srv_addrs] = dcs[i].ss_s[j];
			if (is_zero_addr(&srv_addrs[num_srv_addrs])) {
				continue;
			}

			DBG_DEBUG("SRV lookup %s got IP[%zu] %s\n",
				name,
				j,
				print_sockaddr(addr,
					sizeof(addr),
					&srv_addrs[num_srv_addrs]));

			num_srv_addrs++;
		}
	}

	TALLOC_FREE(dcs);

	*return_addrs = srv_addrs;
	*return_count = num_srv_addrs;
	return NT_STATUS_OK;
}

static const char **filter_out_nbt_lookup(TALLOC_CTX *mem_ctx,
					  const char **resolve_order)
{
	size_t i, len, result_idx;
	const char **result;

	len = 0;
	while (resolve_order[len] != NULL) {
		len += 1;
	}

	result = talloc_array(mem_ctx, const char *, len+1);
	if (result == NULL) {
		return NULL;
	}

	result_idx = 0;

	for (i=0; i<len; i++) {
		const char *tok = resolve_order[i];

		if (strequal(tok, "lmhosts") || strequal(tok, "wins") ||
		    strequal(tok, "bcast")) {
			continue;
		}
		result[result_idx++] = tok;
	}
	result[result_idx] = NULL;

	return result;
}

/*******************************************************************
 Samba interface to resolve a name into an IP address.
 Use this function if the string is either an IP address, DNS
 or host name or NetBIOS name. This uses the name switch in the
 smb.conf to determine the order of name resolution.

 Added support for ip addr/port to support ADS ldap servers.
 the only place we currently care about the port is in the
 resolve_hosts() when looking up DC's via SRV RR entries in DNS
**********************************************************************/

NTSTATUS internal_resolve_name(TALLOC_CTX *ctx,
				const char *name,
			        int name_type,
				const char *sitename,
				struct samba_sockaddr **return_salist,
				size_t *return_count,
				const char **resolve_order)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	size_t i;
	size_t nc_count = 0;
	size_t ret_count = 0;
	bool ok;
	struct sockaddr_storage *ss_list = NULL;
	struct samba_sockaddr *sa_list = NULL;
	TALLOC_CTX *frame = talloc_stackframe();

	DBG_DEBUG("looking up %s#%x (sitename %s)\n",
		name, name_type, sitename ? sitename : "(null)");

	if (is_ipaddress(name)) {
		struct sockaddr_storage ss;

		/* if it's in the form of an IP address then get the lib to interpret it */
		ok = interpret_string_addr(&ss, name, AI_NUMERICHOST);
		if (!ok) {
			DBG_WARNING("interpret_string_addr failed on %s\n",
				name);
			TALLOC_FREE(frame);
			return NT_STATUS_INVALID_PARAMETER;
		}
		if (is_zero_addr(&ss)) {
			TALLOC_FREE(frame);
			return NT_STATUS_UNSUCCESSFUL;
		}

		status = sockaddr_array_to_samba_sockaddr_array(frame,
							&sa_list,
							&ret_count,
							&ss,
							1);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}

		*return_salist = talloc_move(ctx, &sa_list);
		*return_count = 1;
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	/* Check name cache */

	ok = namecache_fetch(frame,
				name,
				name_type,
				&sa_list,
				&nc_count);
	if (ok) {
		/*
		 * remove_duplicate_addrs2() has the
		 * side effect of removing zero addresses,
		 * so use it here.
		 */
		nc_count = remove_duplicate_addrs2(sa_list, nc_count);
		if (nc_count == 0) {
			TALLOC_FREE(sa_list);
			TALLOC_FREE(frame);
			return NT_STATUS_UNSUCCESSFUL;
		}
		*return_count = nc_count;
		*return_salist = talloc_move(ctx, &sa_list);
		TALLOC_FREE(frame);
		return NT_STATUS_OK;
	}

	/* set the name resolution order */

	if (resolve_order && strcmp(resolve_order[0], "NULL") == 0) {
		DBG_DEBUG("all lookups disabled\n");
		TALLOC_FREE(frame);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!resolve_order || !resolve_order[0]) {
		static const char *host_order[] = { "host", NULL };
		resolve_order = host_order;
	}

	if ((strlen(name) > MAX_NETBIOSNAME_LEN - 1) ||
	    (strchr(name, '.') != NULL)) {
		/*
		 * Don't do NBT lookup, the name would not fit anyway
		 */
		resolve_order = filter_out_nbt_lookup(frame, resolve_order);
		if (resolve_order == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* iterate through the name resolution backends */

	for (i=0; resolve_order[i]; i++) {
		const char *tok = resolve_order[i];

		if ((strequal(tok, "host") || strequal(tok, "hosts"))) {
			status = resolve_hosts(talloc_tos(),
					       name,
					       name_type,
					       &ss_list,
					       &ret_count);
			if (!NT_STATUS_IS_OK(status)) {
				continue;
			}
			goto done;
		}

		if (strequal(tok, "kdc")) {
			/* deal with KDC_NAME_TYPE names here.
			 * This will result in a SRV record lookup */
			status = resolve_ads(talloc_tos(),
					     name,
					     KDC_NAME_TYPE,
					     sitename,
					     &ss_list,
					     &ret_count);
			if (!NT_STATUS_IS_OK(status)) {
				continue;
			}
			/* Ensure we don't namecache
			 * this with the KDC port. */
			name_type = KDC_NAME_TYPE;
			goto done;
		}

		if (strequal(tok, "ads")) {
			/* deal with 0x1c and 0x1b names here.
			 * This will result in a SRV record lookup */
			status = resolve_ads(talloc_tos(),
					     name,
					     name_type,
					     sitename,
					     &ss_list,
					     &ret_count);
			if (!NT_STATUS_IS_OK(status)) {
				continue;
			}
			goto done;
		}

		if (strequal(tok, "lmhosts")) {
			status = resolve_lmhosts_file_as_sockaddr(
				talloc_tos(),
				get_dyn_LMHOSTSFILE(),
				name,
				name_type,
				&ss_list,
				&ret_count);
			if (!NT_STATUS_IS_OK(status)) {
				continue;
			}
			goto done;
		}

		if (strequal(tok, "wins")) {
			/* don't resolve 1D via WINS */
			if (name_type == 0x1D) {
				continue;
			}
			status = resolve_wins(talloc_tos(),
					      name,
					      name_type,
					      &ss_list,
					      &ret_count);
			if (!NT_STATUS_IS_OK(status)) {
				continue;
			}
			goto done;
		}

		if (strequal(tok, "bcast")) {
			status = name_resolve_bcast(
						talloc_tos(),
						name,
						name_type,
						&ss_list,
						&ret_count);
			if (!NT_STATUS_IS_OK(status)) {
				continue;
			}
			goto done;
		}

		DBG_ERR("unknown name switch type %s\n", tok);
	}

	/* All of the resolve_* functions above have returned false. */

	TALLOC_FREE(frame);
	*return_count = 0;

	return status;

  done:

	status = sockaddr_array_to_samba_sockaddr_array(frame,
							&sa_list,
							&ret_count,
							ss_list,
							ret_count);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	/* Remove duplicate entries.  Some queries, notably #1c (domain
	controllers) return the PDC in iplist[0] and then all domain
	controllers including the PDC in iplist[1..n].  Iterating over
	the iplist when the PDC is down will cause two sets of timeouts. */

	ret_count = remove_duplicate_addrs2(sa_list, ret_count);

	/* Save in name cache */
	if ( DEBUGLEVEL >= 100 ) {
		for (i = 0; i < ret_count && DEBUGLEVEL == 100; i++) {
			char addr[INET6_ADDRSTRLEN];
			print_sockaddr(addr, sizeof(addr),
					&sa_list[i].u.ss);
			DEBUG(100, ("Storing name %s of type %d (%s:0)\n",
					name,
					name_type,
					addr));
		}
	}

	if (ret_count) {
		namecache_store(name,
				name_type,
				ret_count,
				sa_list);
	}

	/* Display some debugging info */

	if ( DEBUGLEVEL >= 10 ) {
		DBG_DEBUG("returning %zu addresses: ",
				ret_count);

		for (i = 0; i < ret_count; i++) {
			char addr[INET6_ADDRSTRLEN];
			print_sockaddr(addr, sizeof(addr),
					&sa_list[i].u.ss);
			DEBUGADD(10, ("%s ", addr));
		}
		DEBUG(10, ("\n"));
	}

	*return_count = ret_count;
	*return_salist = talloc_move(ctx, &sa_list);

	TALLOC_FREE(frame);
	return status;
}

/********************************************************
 Internal interface to resolve a name into one IP address.
 Use this function if the string is either an IP address, DNS
 or host name or NetBIOS name. This uses the name switch in the
 smb.conf to determine the order of name resolution.
*********************************************************/

bool resolve_name(const char *name,
		struct sockaddr_storage *return_ss,
		int name_type,
		bool prefer_ipv4)
{
	struct samba_sockaddr *sa_list = NULL;
	char *sitename = NULL;
	size_t count = 0;
	NTSTATUS status;
	TALLOC_CTX *frame = NULL;

	if (is_ipaddress(name)) {
		return interpret_string_addr(return_ss, name, AI_NUMERICHOST);
	}

	frame = talloc_stackframe();

	sitename = sitename_fetch(frame, lp_realm()); /* wild guess */

	status = internal_resolve_name(frame,
					name,
					name_type,
					sitename,
					&sa_list,
					&count,
					lp_name_resolve_order());
	if (NT_STATUS_IS_OK(status)) {
		size_t i;

		if (prefer_ipv4) {
			for (i=0; i<count; i++) {
				if (!is_broadcast_addr(&sa_list[i].u.sa) &&
						(sa_list[i].u.ss.ss_family == AF_INET)) {
					*return_ss = sa_list[i].u.ss;
					TALLOC_FREE(sa_list);
					TALLOC_FREE(frame);
					return True;
				}
			}
		}

		/* only return valid addresses for TCP connections */
		for (i=0; i<count; i++) {
			if (!is_broadcast_addr(&sa_list[i].u.sa)) {
				*return_ss = sa_list[i].u.ss;
				TALLOC_FREE(sa_list);
				TALLOC_FREE(frame);
				return True;
			}
		}
	}

	TALLOC_FREE(sa_list);
	TALLOC_FREE(frame);
	return False;
}

/********************************************************
 Internal interface to resolve a name into a list of IP addresses.
 Use this function if the string is either an IP address, DNS
 or host name or NetBIOS name. This uses the name switch in the
 smb.conf to determine the order of name resolution.
*********************************************************/

NTSTATUS resolve_name_list(TALLOC_CTX *ctx,
		const char *name,
		int name_type,
		struct sockaddr_storage **return_ss_arr,
		unsigned int *p_num_entries)
{
	struct samba_sockaddr *sa_list = NULL;
	char *sitename = NULL;
	size_t count = 0;
	size_t i;
	unsigned int num_entries = 0;
	struct sockaddr_storage *result_arr = NULL;
	NTSTATUS status;

	if (is_ipaddress(name)) {
		result_arr = talloc(ctx, struct sockaddr_storage);
		if (result_arr == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		if (!interpret_string_addr(result_arr, name, AI_NUMERICHOST)) {
			TALLOC_FREE(result_arr);
			return NT_STATUS_BAD_NETWORK_NAME;
		}
		*p_num_entries = 1;
		*return_ss_arr = result_arr;
		return NT_STATUS_OK;
	}

	sitename = sitename_fetch(ctx, lp_realm()); /* wild guess */

	status = internal_resolve_name(ctx,
					name,
					name_type,
					sitename,
					&sa_list,
					&count,
					lp_name_resolve_order());
	TALLOC_FREE(sitename);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* only return valid addresses for TCP connections */
	for (i=0, num_entries = 0; i<count; i++) {
		if (!is_zero_addr(&sa_list[i].u.ss) &&
		    !is_broadcast_addr(&sa_list[i].u.sa)) {
			num_entries++;
		}
	}
	if (num_entries == 0) {
		status = NT_STATUS_BAD_NETWORK_NAME;
		goto done;
	}

	result_arr = talloc_array(ctx,
				struct sockaddr_storage,
				num_entries);
	if (result_arr == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0, num_entries = 0; i<count; i++) {
		if (!is_zero_addr(&sa_list[i].u.ss) &&
		    !is_broadcast_addr(&sa_list[i].u.sa)) {
			result_arr[num_entries++] = sa_list[i].u.ss;
		}
	}

	if (num_entries == 0) {
		TALLOC_FREE(result_arr);
		status = NT_STATUS_BAD_NETWORK_NAME;
		goto done;
	}

	status = NT_STATUS_OK;
	*p_num_entries = num_entries;
	*return_ss_arr = result_arr;
done:
	TALLOC_FREE(sa_list);
	return status;
}

/********************************************************
 Find the IP address of the master browser or DMB for a workgroup.
*********************************************************/

bool find_master_ip(const char *group, struct sockaddr_storage *master_ss)
{
	struct samba_sockaddr *sa_list = NULL;
	size_t count = 0;
	NTSTATUS status;

	if (lp_disable_netbios()) {
		DEBUG(5,("find_master_ip(%s): netbios is disabled\n", group));
		return false;
	}

	status = internal_resolve_name(talloc_tos(),
					group,
					0x1D,
					NULL,
					&sa_list,
					&count,
					lp_name_resolve_order());
	if (NT_STATUS_IS_OK(status)) {
		*master_ss = sa_list[0].u.ss;
		TALLOC_FREE(sa_list);
		return true;
	}

	TALLOC_FREE(sa_list);

	status = internal_resolve_name(talloc_tos(),
					group,
					0x1B,
					NULL,
					&sa_list,
					&count,
					lp_name_resolve_order());
	if (NT_STATUS_IS_OK(status)) {
		*master_ss = sa_list[0].u.ss;
		TALLOC_FREE(sa_list);
		return true;
	}

	TALLOC_FREE(sa_list);
	return false;
}

/********************************************************
 Get the IP address list of the primary domain controller
 for a domain.
*********************************************************/

bool get_pdc_ip(const char *domain, struct sockaddr_storage *pss)
{
	struct samba_sockaddr *sa_list = NULL;
	size_t count = 0;
	NTSTATUS status = NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	static const char *ads_order[] = { "ads", NULL };
	/* Look up #1B name */

	if (lp_security() == SEC_ADS) {
		status = internal_resolve_name(talloc_tos(),
						domain,
						0x1b,
						NULL,
						&sa_list,
						&count,
						ads_order);
	}

	if (!NT_STATUS_IS_OK(status) || count == 0) {
		TALLOC_FREE(sa_list);
		status = internal_resolve_name(talloc_tos(),
						domain,
						0x1b,
						NULL,
						&sa_list,
						&count,
						lp_name_resolve_order());
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(sa_list);
			return false;
		}
	}

	/* if we get more than 1 IP back we have to assume it is a
	   multi-homed PDC and not a mess up */

	if ( count > 1 ) {
		DBG_INFO("PDC has %zu IP addresses!\n", count);
		sort_sa_list(sa_list, count);
	}

	*pss = sa_list[0].u.ss;
	TALLOC_FREE(sa_list);
	return true;
}

/* Private enum type for lookups. */

enum dc_lookup_type { DC_NORMAL_LOOKUP, DC_ADS_ONLY, DC_KDC_ONLY };

/********************************************************
 Get the IP address list of the domain controllers for
 a domain.
*********************************************************/

static NTSTATUS get_dc_list(TALLOC_CTX *ctx,
			const char *domain,
			const char *sitename,
			struct samba_sockaddr **sa_list_ret,
			size_t *ret_count,
			enum dc_lookup_type lookup_type,
			bool *ordered)
{
	const char **resolve_order = NULL;
	char *saf_servername = NULL;
	char *pserver = NULL;
	const char *p;
	char *name;
	size_t num_addresses = 0;
	size_t local_count = 0;
	size_t i;
	struct samba_sockaddr *auto_sa_list = NULL;
	struct samba_sockaddr *return_salist = NULL;
	bool done_auto_lookup = false;
	size_t auto_count = 0;
	NTSTATUS status;
	TALLOC_CTX *frame = talloc_stackframe();
	int auto_name_type = 0x1C;

	*ordered = False;

	/* if we are restricted to solely using DNS for looking
	   up a domain controller, make sure that host lookups
	   are enabled for the 'name resolve order'.  If host lookups
	   are disabled and ads_only is True, then set the string to
	   NULL. */

	resolve_order = lp_name_resolve_order();
	if (!resolve_order) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}
	if (lookup_type == DC_ADS_ONLY)  {
		if (str_list_check_ci(resolve_order, "host")) {
			static const char *ads_order[] = { "ads", NULL };
			resolve_order = ads_order;

			/* DNS SRV lookups used by the ads resolver
			   are already sorted by priority and weight */
			*ordered = true;
		} else {
			/* this is quite bizarre! */
			static const char *null_order[] = { "NULL", NULL };
                        resolve_order = null_order;
		}
	} else if (lookup_type == DC_KDC_ONLY) {
		static const char *kdc_order[] = { "kdc", NULL };
		/* DNS SRV lookups used by the ads/kdc resolver
		   are already sorted by priority and weight */
		*ordered = true;
		resolve_order = kdc_order;
		auto_name_type = KDC_NAME_TYPE;
	}

	/* fetch the server we have affinity for.  Add the
	   'password server' list to a search for our domain controllers */

	saf_servername = saf_fetch(frame, domain);

	if (strequal(domain, lp_workgroup()) || strequal(domain, lp_realm())) {
		pserver = talloc_asprintf(frame, "%s, %s",
			saf_servername ? saf_servername : "",
			lp_password_server());
	} else {
		pserver = talloc_asprintf(frame, "%s, *",
			saf_servername ? saf_servername : "");
	}

	TALLOC_FREE(saf_servername);
	if (!pserver) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	DEBUG(3,("get_dc_list: preferred server list: \"%s\"\n", pserver ));

	/*
	 * if '*' appears in the "password server" list then add
	 * an auto lookup to the list of manually configured
	 * DC's.  If any DC is listed by name, then the list should be
	 * considered to be ordered
	 */

	p = pserver;
	while (next_token_talloc(frame, &p, &name, LIST_SEP)) {
		if (!done_auto_lookup && strequal(name, "*")) {
			done_auto_lookup = true;

			status = internal_resolve_name(frame,
							domain,
							auto_name_type,
							sitename,
							&auto_sa_list,
							&auto_count,
							resolve_order);
			if (!NT_STATUS_IS_OK(status)) {
				continue;
			}
			/* Wrap check. */
			if (num_addresses + auto_count < num_addresses) {
				TALLOC_FREE(auto_sa_list);
				status = NT_STATUS_INVALID_PARAMETER;
				goto out;
			}
			num_addresses += auto_count;
			DBG_DEBUG("Adding %zu DC's from auto lookup\n",
						auto_count);
		} else  {
			/* Wrap check. */
			if (num_addresses + 1 < num_addresses) {
				TALLOC_FREE(auto_sa_list);
				status = NT_STATUS_INVALID_PARAMETER;
				goto out;
			}
			num_addresses++;
		}
	}

	/* if we have no addresses and haven't done the auto lookup, then
	   just return the list of DC's.  Or maybe we just failed. */

	if (num_addresses == 0) {
		struct samba_sockaddr *dc_salist = NULL;
		size_t dc_count = 0;

		if (done_auto_lookup) {
			DEBUG(4,("get_dc_list: no servers found\n"));
			status = NT_STATUS_NO_LOGON_SERVERS;
			goto out;
		}
		/* talloc off frame, only move to ctx on success. */
		status = internal_resolve_name(frame,
						domain,
						auto_name_type,
						sitename,
						&dc_salist,
						&dc_count,
						resolve_order);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
		return_salist = dc_salist;
		local_count = dc_count;
		goto out;
	}

	return_salist = talloc_zero_array(frame,
					struct samba_sockaddr,
					num_addresses);
	if (return_salist == NULL) {
		DEBUG(3,("get_dc_list: malloc fail !\n"));
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	p = pserver;
	local_count = 0;

	/* fill in the return list now with real IP's */

	while ((local_count<num_addresses) &&
			next_token_talloc(frame, &p, &name, LIST_SEP)) {
		struct samba_sockaddr name_sa = {0};

		/* copy any addresses from the auto lookup */

		if (strequal(name, "*")) {
			size_t j;
			for (j=0; j<auto_count; j++) {
				char addr[INET6_ADDRSTRLEN];
				print_sockaddr(addr,
						sizeof(addr),
						&auto_sa_list[j].u.ss);
				/* Check for and don't copy any
				 * known bad DC IP's. */
				if(!NT_STATUS_IS_OK(check_negative_conn_cache(
						domain,
						addr))) {
					DEBUG(5,("get_dc_list: "
						"negative entry %s removed "
						"from DC list\n",
						addr));
					continue;
				}
				return_salist[local_count] = auto_sa_list[j];
				local_count++;
			}
			continue;
		}

		/* explicit lookup; resolve_name() will
		 * handle names & IP addresses */
		if (resolve_name(name, &name_sa.u.ss, 0x20, true)) {
			char addr[INET6_ADDRSTRLEN];
			bool ok;

			/*
			 * Ensure we set sa_socklen correctly.
			 * Doesn't matter now, but eventually we
			 * will remove ip_service and return samba_sockaddr
			 * arrays directly.
			 */
			ok = sockaddr_storage_to_samba_sockaddr(
					&name_sa,
					&name_sa.u.ss);
			if (!ok) {
				status = NT_STATUS_INVALID_ADDRESS;
				goto out;
			}

			print_sockaddr(addr,
					sizeof(addr),
					&name_sa.u.ss);

			/* Check for and don't copy any known bad DC IP's. */
			if( !NT_STATUS_IS_OK(check_negative_conn_cache(domain,
							addr)) ) {
				DEBUG(5,("get_dc_list: negative entry %s "
					"removed from DC list\n",
					name ));
				continue;
			}

			return_salist[local_count] = name_sa;
			local_count++;
			*ordered = true;
		}
	}

	/* need to remove duplicates in the list if we have any
	   explicit password servers */

	local_count = remove_duplicate_addrs2(return_salist, local_count );

	/* For DC's we always prioritize IPv4 due to W2K3 not
	 * supporting LDAP, KRB5 or CLDAP over IPv6. */

	if (local_count && return_salist != NULL) {
		prioritize_ipv4_list(return_salist, local_count);
	}

	if ( DEBUGLEVEL >= 4 ) {
		DEBUG(4,("get_dc_list: returning %zu ip addresses "
				"in an %sordered list\n",
				local_count,
				*ordered ? "":"un"));
		DEBUG(4,("get_dc_list: "));
		for ( i=0; i<local_count; i++ ) {
			char addr[INET6_ADDRSTRLEN];
			print_sockaddr(addr,
					sizeof(addr),
					&return_salist[i].u.ss);
			DEBUGADD(4,("%s ", addr));
		}
		DEBUGADD(4,("\n"));
	}

	status = (local_count != 0 ? NT_STATUS_OK : NT_STATUS_NO_LOGON_SERVERS);

  out:

	if (NT_STATUS_IS_OK(status)) {
		*sa_list_ret = talloc_move(ctx, &return_salist);
		*ret_count = local_count;
	}
	TALLOC_FREE(return_salist);
	TALLOC_FREE(auto_sa_list);
	TALLOC_FREE(frame);
	return status;
}

/*********************************************************************
 Small wrapper function to get the DC list and sort it if necessary.
 Returns a samba_sockaddr array.
*********************************************************************/

NTSTATUS get_sorted_dc_list(TALLOC_CTX *ctx,
				const char *domain,
				const char *sitename,
				struct samba_sockaddr **sa_list_ret,
				size_t *ret_count,
				bool ads_only)
{
	bool ordered = false;
	NTSTATUS status;
	enum dc_lookup_type lookup_type = DC_NORMAL_LOOKUP;
	struct samba_sockaddr *sa_list = NULL;
	size_t count = 0;

	DBG_INFO("attempting lookup for name %s (sitename %s)\n",
		domain,
		sitename ? sitename : "NULL");

	if (ads_only) {
		lookup_type = DC_ADS_ONLY;
	}

	status = get_dc_list(ctx,
			domain,
			sitename,
			&sa_list,
			&count,
			lookup_type,
			&ordered);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_LOGON_SERVERS)
			&& sitename) {
		DBG_WARNING("No server for domain '%s' available"
			    " in site '%s', fallback to all servers\n",
			    domain,
			    sitename);
		status = get_dc_list(ctx,
				domain,
				NULL,
				&sa_list,
				&count,
				lookup_type,
				&ordered);
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* only sort if we don't already have an ordered list */
	if (!ordered) {
		sort_sa_list(sa_list, count);
	}

	*ret_count = count;
	*sa_list_ret = sa_list;
	return status;
}

/*********************************************************************
 Get the KDC list - re-use all the logic in get_dc_list.
 Returns a samba_sockaddr array.
*********************************************************************/

NTSTATUS get_kdc_list(TALLOC_CTX *ctx,
			const char *realm,
			const char *sitename,
			struct samba_sockaddr **sa_list_ret,
			size_t *ret_count)
{
	size_t count = 0;
	struct samba_sockaddr *sa_list = NULL;
	bool ordered = false;
	NTSTATUS status;

	status = get_dc_list(ctx,
			realm,
			sitename,
			&sa_list,
			&count,
			DC_KDC_ONLY,
			&ordered);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* only sort if we don't already have an ordered list */
	if (!ordered ) {
		sort_sa_list(sa_list, count);
	}

	*ret_count = count;
	*sa_list_ret = sa_list;
	return status;
}
