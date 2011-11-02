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

#ifdef class
#undef class
#endif

#include "heimdal/lib/roken/resolve.h"

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

static uint32_t count_dns_rr(struct rk_resource_record *head, unsigned record_type)
{
	uint32_t count = 0;
	struct rk_resource_record *rr;

	for (rr=head; rr; rr=rr->next) {

		/* we are only interested in the IN class */
		if (rr->class != rk_ns_c_in) {
			continue;
		}

		/* we are only interested by requested record */
		if (rr->type != record_type) {
			continue;
		}

		switch(record_type) {
			case rk_ns_t_srv:

				/* verify we actually have a SRV record here */
				if (!rr->u.srv) {
					continue;
				}

				/* Verify we got a port */
				if (rr->u.srv->port == 0) {
					continue;
				}
				count++;
				break;
			case rk_ns_t_a:
			case rk_ns_t_aaaa:
				/* verify we actually have a record here */
				if (!rr->u.data) {
					continue;
				}
				count++;
				break;
			default:
				count++;
				break;
		}
	}

	return count;
}

struct dns_records_container {
	char **list;
	uint32_t count;
};

static char* rr_to_string(TALLOC_CTX *mem_ctx,
					struct rk_resource_record *rr,
					uint16_t port)
{
	char addrstr[INET6_ADDRSTRLEN];
	char *addr;

	switch (rr->type) {
		case rk_ns_t_a:
			if (inet_ntop(AF_INET, rr->u.a,
				      addrstr, sizeof(addrstr)) == NULL) {
				return NULL;
			}
			break;
#ifdef HAVE_IPV6
		case rk_ns_t_aaaa:
			if (inet_ntop(AF_INET6, (struct in6_addr *)rr->u.data,
				      addrstr, sizeof(addrstr)) == NULL) {
				return NULL;
			}
			break;
#endif
		default:
			return NULL;
	}

	addr = talloc_asprintf(mem_ctx, "%s@%u/%s", addrstr,
					 port, rr->domain);

	return addr;
}

static struct dns_records_container get_a_aaaa_records(TALLOC_CTX *mem_ctx,
							const char* name,
							int port)
{
	struct rk_dns_reply *reply, *reply2, *rep, *tmp[3];
	struct rk_resource_record *rr;
	struct dns_records_container ret;
	char **addrs = NULL;
	uint32_t count, count2, total;
	uint32_t i;

	memset(&ret, 0, sizeof(struct dns_records_container));
	/* this is the blocking call we are going to lots of trouble
	   to avoid them in the parent */
	reply = rk_dns_lookup(name, "AAAA");

	count = count2 = 0;

	if (reply) {

		count = count_dns_rr(reply->head, rk_ns_t_aaaa);
		count2 = count_dns_rr(reply->head, rk_ns_t_a);

		if (!count2) {
			/*
			* DNS server didn't returned A when asked for AAAA records.
			* Most of the server do it, let's ask for A specificaly.
			*/
			reply2 = rk_dns_lookup(name, "A");

			if (!reply2) {
				return ret;
			}

			count2 = count_dns_rr(reply2->head, rk_ns_t_a);
		} else {
			reply2 = NULL;
		}
	} else {

		reply = rk_dns_lookup(name, "A");
		if (!reply) {
			return ret;
		}

		reply2 = NULL;
		count = count_dns_rr(reply->head, rk_ns_t_a);
	}
	count += count2;

	if (count == 0) {
		goto done;
	}

	addrs = talloc_zero_array(mem_ctx, char*, count);
	total = 0;

	tmp[0] = reply;
	tmp[1] = reply2;
	tmp[2] = NULL;

	/* Loop over all returned records and pick the records */
	for (i=0; tmp[i] != NULL; i++) {
		rep = tmp[i];
		for (rr=rep->head; rr; rr=rr->next) {
			/* we are only interested in the IN class */
			if (rr->class != rk_ns_c_in) {
				continue;
			}

			/* we are only interested in A and AAAA records */
			if (rr->type != rk_ns_t_a && rr->type != rk_ns_t_aaaa) {
				continue;
			}

			/* verify we actually have a record here */
			if (!rr->u.data) {
				continue;
			}
			rr_to_string(mem_ctx, rr, port);
			addrs[total] = rr_to_string(mem_ctx, rr, port);
			if (addrs[total]) {
				total++;
			}
		}
	}
	if (total) {
		ret.count = total;
		ret.list = addrs;
	}

done:
	if (reply != NULL)
		rk_dns_free_data(reply);

	if (reply2 != NULL)
		rk_dns_free_data(reply2);

	return ret;
}

static struct dns_records_container get_srv_records(TALLOC_CTX *mem_ctx,
							const char* name)
{
	struct rk_dns_reply *reply;
	struct rk_resource_record *rr;
	struct dns_records_container ret;
	char **addrs = NULL;
	uint32_t count, total;

	memset(&ret, 0, sizeof(struct dns_records_container));
	/* this is the blocking call we are going to lots of trouble
	   to avoid them in the parent */
	reply = rk_dns_lookup(name, "SRV");

	if (!reply) {
		return ret;
	}

	rk_dns_srv_order(reply);
	count = count_dns_rr(reply->head, rk_ns_t_srv);

	total = 0;
	if (count == 0) {
		goto done;
	}

	/* Loop over all returned records and pick the records */
	for (rr=reply->head; rr; rr=rr->next) {
		struct dns_records_container c;
		char* tmp_str;
		/* we are only interested in the IN class */
		if (rr->class != rk_ns_c_in) {
			continue;
		}

		/* we are only interested in SRV records */
		if (rr->type != rk_ns_t_srv) {
			continue;
		}

		/* verify we actually have a srv record here */
		if (!rr->u.srv) {
			continue;
		}

		/* Verify we got a port */
		if (rr->u.srv->port == 0) {
			continue;
		}

		tmp_str = rr->u.srv->target;
		if (strchr(tmp_str, '.') && tmp_str[strlen(tmp_str)-1] != '.') {
			/* we are asking for a fully qualified name, but the
			name doesn't end in a '.'. We need to prevent the
			DNS library trying the search domains configured in
			resolv.conf */
			tmp_str = talloc_asprintf(mem_ctx, "%s.", tmp_str);
		}

		c = get_a_aaaa_records(mem_ctx, tmp_str, rr->u.srv->port);
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


done:
	if (reply != NULL)
		rk_dns_free_data(reply);

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
		case EAI_NONAME:
			/* getaddrinfo() doesn't handle CNAME records */
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
