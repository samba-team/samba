/*
   Unix SMB/CIFS implementation.

   async getaddrinfo()/dns_lookup() name resolution module

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Stefan Metzmacher 2008
   Copyright (C) Matthieu Patou 2011

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

/*
  this module uses a fork() per getaddrinfo() or dns_looup() call.
  At first that might seem crazy, but it is actually very fast,
  and solves many of the tricky problems of keeping a child
  hanging around in a librar (like what happens when the parent forks).
  We use a talloc destructor to ensure that the child is cleaned up
  when we have finished with this name resolution.
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/network.h"
#include "system/filesys.h"
#include "lib/socket/socket.h"
#include "libcli/composite/composite.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "libcli/resolve/resolve.h"
#include "lib/util/util_net.h"
#include "lib/addns/dnsquery.h"
#include "lib/addns/dns.h"
#include <arpa/nameser.h>
#include <resolv.h>

struct dns_ex_state {
	bool do_fallback;
	uint32_t flags;
	uint16_t port;
	struct nbt_name name;
	struct socket_address **addrs;
	char **names;
	pid_t child;
	int child_fd;
	struct tevent_fd *fde;
	struct tevent_context *event_ctx;
};

/*
  kill off a wayward child if needed. This allows us to stop an async
  name resolution without leaving a potentially blocking call running
  in a child
*/
static int dns_ex_destructor(struct dns_ex_state *state)
{
	int status;

	kill(state->child, SIGTERM);
	if (waitpid(state->child, &status, WNOHANG) == 0) {
		kill(state->child, SIGKILL);
		waitpid(state->child, &status, 0);
	}

	return 0;
}

struct dns_records_container {
	char **list;
	uint32_t count;
};

static int reply_to_addrs(TALLOC_CTX *mem_ctx, uint32_t *a_num,
			  char ***cur_addrs, uint32_t total,
			  struct dns_request *reply, int port)
{
	char addrstr[INET6_ADDRSTRLEN];
	struct dns_rrec *rr;
	char **addrs;
	uint32_t i;
	const char *addr;

	/* at most we over-allocate here, but not by much */
	addrs = talloc_realloc(mem_ctx, *cur_addrs, char *,
				total + reply->num_answers);
	if (!addrs) {
		return 0;
	}
	*cur_addrs = addrs;

	for (i = 0; i < reply->num_answers; i++) {
		rr = reply->answers[i];

		/* we are only interested in the IN class */
		if (rr->r_class != DNS_CLASS_IN) {
			continue;
		}

		if (rr->type == QTYPE_NS) {
			/*
			 * After the record for NS will come the A or AAAA
			 * record of the NS.
			 */
			break;
		}

		/* verify we actually have a record here */
		if (!rr->data) {
			continue;
		}

		/* we are only interested in A and AAAA records */
		switch (rr->type) {
		case QTYPE_A:
			addr = inet_ntop(AF_INET,
					 (struct in_addr *)rr->data,
					 addrstr, sizeof(addrstr));
			if (addr == NULL) {
				continue;
			}
			break;
		case QTYPE_AAAA:
#ifdef HAVE_IPV6
			addr = inet_ntop(AF_INET6,
					 (struct in6_addr *)rr->data,
					 addrstr, sizeof(addrstr));
#else
			addr = NULL;
#endif
			if (addr == NULL) {
				continue;
			}
			break;
		default:
			continue;
		}

		addrs[total] = talloc_asprintf(addrs, "%s@%u/%s",
						addrstr, port,
						rr->name->pLabelList->label);
		if (addrs[total]) {
			total++;
			if (rr->type == QTYPE_A) {
				(*a_num)++;
			}
		}
	}

	return total;
}

static DNS_ERROR dns_lookup(TALLOC_CTX *mem_ctx, const char* name,
			    uint16_t q_type, struct dns_request **reply)
{
	int len, rlen;
	uint8_t *answer;
	bool loop;
	struct dns_buffer buf;
	DNS_ERROR err;

	/* give space for a good sized answer by default */
	answer = NULL;
	len = 1500;
	do {
		answer = talloc_realloc(mem_ctx, answer, uint8_t, len);
		if (!answer) {
			return ERROR_DNS_NO_MEMORY;
		}
		rlen = res_search(name, DNS_CLASS_IN, q_type, answer, len);
		if (rlen == -1) {
			if (len >= 65535) {
				return ERROR_DNS_SOCKET_ERROR;
			}
			/* retry once with max packet size */
			len = 65535;
			loop = true;
		} else if (rlen > len) {
			len = rlen;
			loop = true;
		} else {
			loop = false;
		}
	} while(loop);

	buf.data = answer;
	buf.size = rlen;
	buf.offset = 0;
	buf.error = ERROR_DNS_SUCCESS;

	err = dns_unmarshall_request(mem_ctx, &buf, reply);

	TALLOC_FREE(answer);
	return err;
}

static struct dns_records_container get_a_aaaa_records(TALLOC_CTX *mem_ctx,
							const char* name,
							int port)
{
	struct dns_request *reply;
	struct dns_records_container ret;
	char **addrs = NULL;
	uint32_t a_num, total;
	uint16_t qtype;
	TALLOC_CTX *tmp_ctx;
	DNS_ERROR err;

	memset(&ret, 0, sizeof(struct dns_records_container));

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return ret;
	}

	qtype = QTYPE_AAAA;

	/* this is the blocking call we are going to lots of trouble
	   to avoid them in the parent */
	err = dns_lookup(tmp_ctx, name, qtype, &reply);
	if (!ERR_DNS_IS_OK(err)) {
		qtype = QTYPE_A;
		err = dns_lookup(tmp_ctx, name, qtype, &reply);
		if (!ERR_DNS_IS_OK(err)) {
			goto done;
		}
	}

	a_num = total = 0;
	total = reply_to_addrs(tmp_ctx, &a_num, &addrs, total, reply, port);

	if (qtype == QTYPE_AAAA && a_num == 0) {
		/*
		* DNS server didn't returned A when asked for AAAA records.
		* Most of the server do it, let's ask for A specificaly.
		*/
		err = dns_lookup(tmp_ctx, name, QTYPE_A, &reply);
		if (!ERR_DNS_IS_OK(err)) {
			goto done;
		}

		total = reply_to_addrs(tmp_ctx, &a_num, &addrs, total,
					reply, port);

	}

	if (total) {
		talloc_steal(mem_ctx, addrs);
		ret.count = total;
		ret.list = addrs;
	}

done:
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static struct dns_records_container get_srv_records(TALLOC_CTX *mem_ctx,
							const char* name)
{
	struct dns_records_container ret;
	char **addrs = NULL;
	struct dns_rr_srv *dclist;
	NTSTATUS status;
	uint32_t total;
	unsigned i;
	int count;

	memset(&ret, 0, sizeof(struct dns_records_container));
	/* this is the blocking call we are going to lots of trouble
	   to avoid them in the parent */
	status = ads_dns_lookup_srv(mem_ctx, NULL, name, &dclist, &count);
	if (!NT_STATUS_IS_OK(status)) {
		return ret;
	}
	total = 0;
	if (count == 0) {
		return ret;
	}

	/* Loop over all returned records and pick the records */
	for (i = 0; i < count; i++) {
		struct dns_records_container c;
		const char* tmp_str;

		tmp_str = dclist[i].hostname;
		if (strchr(tmp_str, '.') && tmp_str[strlen(tmp_str)-1] != '.') {
			/* we are asking for a fully qualified name, but the
			name doesn't end in a '.'. We need to prevent the
			DNS library trying the search domains configured in
			resolv.conf */
			tmp_str = talloc_asprintf(mem_ctx, "%s.", tmp_str);
		}

		c = get_a_aaaa_records(mem_ctx, tmp_str, dclist[i].port);
		total += c.count;
		if (addrs == NULL) {
			addrs = c.list;
		} else {
			unsigned j;

			addrs = talloc_realloc(mem_ctx, addrs, char*, total);
			for (j=0; j < c.count; j++) {
				addrs[total - j - 1] = talloc_steal(addrs, c.list[j]);
			}
		}
	}

	if (total) {
		ret.count = total;
		ret.list = addrs;
	}

	return ret;
}
/*
  the blocking child
*/
static void run_child_dns_lookup(struct dns_ex_state *state, int fd)
{
	bool first;
	bool do_srv = (state->flags & RESOLVE_NAME_FLAG_DNS_SRV);
	struct dns_records_container c;
	char* addrs = NULL;
	unsigned int i;

	if (strchr(state->name.name, '.') && state->name.name[strlen(state->name.name)-1] != '.') {
		/* we are asking for a fully qualified name, but the
		   name doesn't end in a '.'. We need to prevent the
		   DNS library trying the search domains configured in
		   resolv.conf */
		state->name.name = talloc_strdup_append(discard_const_p(char, state->name.name),
							".");
	}


	if (do_srv) {
		c = get_srv_records(state, state->name.name);
	} else {
		c = get_a_aaaa_records(state, state->name.name, state->port);
	}

	/* This line in critical - if we return without writing to the
	 * pipe, this is the signal that the name did not exist */
	if (c.count == 0) {
		goto done;
	}

	addrs = talloc_strdup(state, "");
	if (!addrs) {
		goto done;
	}
	first = true;

	for (i=0; i < c.count; i++) {
		addrs = talloc_asprintf_append_buffer(addrs, "%s%s",
							first?"":",",
							c.list[i]);
		first = false;
	}

	if (addrs) {
		DEBUG(11, ("Addrs = %s\n", addrs));
		write(fd, addrs, talloc_get_size(addrs));
	}

done:
	close(fd);
}

/*
  the blocking child
*/
static void run_child_getaddrinfo(struct dns_ex_state *state, int fd)
{
	int ret;
	struct addrinfo hints;
	struct addrinfo *res;
	struct addrinfo *res_list = NULL;
	char *addrs;
	bool first;

	ZERO_STRUCT(hints);
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;

	ret = getaddrinfo(state->name.name, "0", &hints, &res_list);
	/* try to fallback in case of error */
	if (state->do_fallback) {
		switch (ret) {
#ifdef EAI_NODATA
		case EAI_NODATA:
#endif
		case EAI_FAIL:
			/* Linux returns EAI_NODATA on non-RFC1034-compliant names. FreeBSD returns EAI_FAIL */
		case EAI_NONAME:
			/* getaddrinfo() doesn't handle CNAME or non-RFC1034 compatible records */
			run_child_dns_lookup(state, fd);
			return;
		default:
			break;
		}
	}
	if (ret != 0) {
		goto done;
	}

	addrs = talloc_strdup(state, "");
	if (!addrs) {
		goto done;
	}
	first = true;
	for (res = res_list; res; res = res->ai_next) {
		char addrstr[INET6_ADDRSTRLEN];
		if (!print_sockaddr_len(addrstr, sizeof(addrstr), (struct sockaddr *)res->ai_addr, res->ai_addrlen)) {
			continue;
		}
		addrs = talloc_asprintf_append_buffer(addrs, "%s%s@%u/%s",
						      first?"":",",
						      addrstr,
						      state->port,
						      state->name.name);
		if (!addrs) {
			goto done;
		}
		first = false;
	}

	if (addrs) {
		write(fd, addrs, talloc_get_size(addrs));
	}
done:
	if (res_list) {
		freeaddrinfo(res_list);
	}
	close(fd);
}

/*
  handle a read event on the pipe
*/
static void pipe_handler(struct tevent_context *ev, struct tevent_fd *fde, 
			 uint16_t flags, void *private_data)
{
	struct composite_context *c = talloc_get_type(private_data, struct composite_context);
	struct dns_ex_state *state = talloc_get_type(c->private_data,
				     struct dns_ex_state);
	char *address;
	uint32_t num_addrs, i;
	char **addrs;
	int ret;
	int status;
	int value = 0;

	/* if we get any event from the child then we know that we
	   won't need to kill it off */
	talloc_set_destructor(state, NULL);

	if (ioctl(state->child_fd, FIONREAD, &value) != 0) {
		value = 8192;
	}

	address = talloc_array(state, char, value+1);
	if (address) {
		/* yes, we don't care about EAGAIN or other niceities
		   here. They just can't happen with this parent/child
		   relationship, and even if they did then giving an error is
		   the right thing to do */
		ret = read(state->child_fd, address, value);
	} else {
		ret = -1;
	}
	if (waitpid(state->child, &status, WNOHANG) == 0) {
		kill(state->child, SIGKILL);
		waitpid(state->child, &status, 0);
	}

	if (ret <= 0) {
		/* The check for ret == 0 here is important, if the
		 * name does not exist, then no bytes are written to
		 * the pipe */
		DEBUG(3,("dns child failed to find name '%s' of type %s\n",
			 state->name.name, (state->flags & RESOLVE_NAME_FLAG_DNS_SRV)?"SRV":"A"));
		composite_error(c, NT_STATUS_OBJECT_NAME_NOT_FOUND);
		return;
	}

	/* enusre the address looks good */
	address[ret] = 0;

	addrs = str_list_make(state, address, ",");
	if (composite_nomem(addrs, c)) return;

	num_addrs = str_list_length((const char * const *)addrs);

	state->addrs = talloc_array(state, struct socket_address *,
				    num_addrs+1);
	if (composite_nomem(state->addrs, c)) return;

	state->names = talloc_array(state, char *, num_addrs+1);
	if (composite_nomem(state->names, c)) return;

	for (i=0; i < num_addrs; i++) {
		uint32_t port = 0;
		char *p = strrchr(addrs[i], '@');
		char *n;

		if (!p) {
			composite_error(c, NT_STATUS_OBJECT_NAME_NOT_FOUND);
			return;
		}

		*p = '\0';
		p++;

		n = strrchr(p, '/');
		if (!n) {
			composite_error(c, NT_STATUS_OBJECT_NAME_NOT_FOUND);
			return;
		}

		*n = '\0';
		n++;

		if (strcmp(addrs[i], "0.0.0.0") == 0) {
			composite_error(c, NT_STATUS_OBJECT_NAME_NOT_FOUND);
			return;
		}
		port = strtoul(p, NULL, 10);
		if (port > UINT16_MAX) {
			composite_error(c, NT_STATUS_OBJECT_NAME_NOT_FOUND);
			return;
		}
		state->addrs[i] = socket_address_from_strings(state->addrs,
							      "ip",
							      addrs[i],
							      port);
		if (composite_nomem(state->addrs[i], c)) return;

		state->names[i] = talloc_strdup(state->names, n);
		if (composite_nomem(state->names[i], c)) return;
	}
	state->addrs[i] = NULL;
	state->names[i] = NULL;

	composite_done(c);
}

/*
  getaddrinfo() or dns_lookup() name resolution method - async send
 */
struct composite_context *resolve_name_dns_ex_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *event_ctx,
						   void *privdata,
						   uint32_t flags,
						   uint16_t port,
						   struct nbt_name *name,
						   bool do_fallback)
{
	struct composite_context *c;
	struct dns_ex_state *state;
	int fd[2] = { -1, -1 };
	int ret;

	c = composite_create(mem_ctx, event_ctx);
	if (c == NULL) return NULL;

	if (flags & RESOLVE_NAME_FLAG_FORCE_NBT) {
		composite_error(c, NT_STATUS_OBJECT_NAME_NOT_FOUND);
		return c;
	}

	state = talloc_zero(c, struct dns_ex_state);
	if (composite_nomem(state, c)) return c;
	c->private_data = state;

	c->status = nbt_name_dup(state, name, &state->name);
	if (!composite_is_ok(c)) return c;

	/* setup a pipe to chat to our child */
	ret = pipe(fd);
	if (ret == -1) {
		composite_error(c, map_nt_error_from_unix_common(errno));
		return c;
	}

	state->do_fallback = do_fallback;
	state->flags = flags;
	state->port = port;

	state->child_fd = fd[0];
	state->event_ctx = c->event_ctx;

	/* we need to put the child in our event context so
	   we know when the dns_lookup() has finished */
	state->fde = tevent_add_fd(c->event_ctx, c, state->child_fd, TEVENT_FD_READ,
				  pipe_handler, c);
	if (composite_nomem(state->fde, c)) {
		close(fd[0]);
		close(fd[1]);
		return c;
	}
	tevent_fd_set_auto_close(state->fde);

	state->child = fork();
	if (state->child == (pid_t)-1) {
		composite_error(c, map_nt_error_from_unix_common(errno));
		return c;
	}

	if (state->child == 0) {
		close(fd[0]);
		if (state->flags & RESOLVE_NAME_FLAG_FORCE_DNS) {
			run_child_dns_lookup(state, fd[1]);
		} else {
			run_child_getaddrinfo(state, fd[1]);
		}
		_exit(0);
	}
	close(fd[1]);

	/* cleanup wayward children */
	talloc_set_destructor(state, dns_ex_destructor);

	return c;
}

/*
  getaddrinfo() or dns_lookup() name resolution method - recv side
*/
NTSTATUS resolve_name_dns_ex_recv(struct composite_context *c, 
				  TALLOC_CTX *mem_ctx,
				  struct socket_address ***addrs,
				  char ***names)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct dns_ex_state *state = talloc_get_type(c->private_data,
					     struct dns_ex_state);
		*addrs = talloc_steal(mem_ctx, state->addrs);
		if (names) {
			*names = talloc_steal(mem_ctx, state->names);
		}
	}

	talloc_free(c);
	return status;
}
