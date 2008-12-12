/*
   Unix SMB/CIFS implementation.

   async getaddrinfo()/dns_lookup() name resolution module

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Stefan Metzmacher 2008

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
#include "heimdal/lib/roken/resolve.h"

struct dns_ex_state {
	bool do_getaddrinfo;
	bool do_fallback;
	bool do_srv;
	struct nbt_name name;
	struct socket_address **addrs;
	pid_t child;
	int child_fd;
	struct fd_event *fde;
	struct event_context *event_ctx;
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
	close(state->child_fd);
	if (waitpid(state->child, &status, WNOHANG) == 0) {
		kill(state->child, SIGKILL);
		waitpid(state->child, &status, 0);
	}

	return 0;
}

/*
  the blocking child
*/
static void run_child_dns_lookup(struct dns_ex_state *state, int fd)
{
	struct dns_reply *reply;
	struct resource_record *rr;
	uint32_t count = 0;
	uint32_t srv_valid = 0;
	struct resource_record **srv_rr;
	uint32_t addrs_valid = 0;
	struct resource_record **addrs_rr;
	char *addrs;
	bool first;
	uint32_t i;

	/* this is the blocking call we are going to lots of trouble
	   to avoid in the parent */
	reply = dns_lookup(state->name.name, state->do_srv?"SRV":"A");
	if (!reply) {
		goto done;
	}

	if (state->do_srv) {
		dns_srv_order(reply);
	}

	/* Loop over all returned records and pick the "srv" records */
	for (rr=reply->head; rr; rr=rr->next) {
		/* we are only interested in the IN class */
		if (rr->class != C_IN) {
			continue;
		}

		if (state->do_srv) {
			/* we are only interested in SRV records */
			if (rr->type != T_SRV) {
				continue;
			}

			/* verify we actually have a SRV record here */
			if (!rr->u.srv) {
				continue;
			}

			/* Verify we got a port */
			if (rr->u.srv->port == 0) {
				continue;
			}
		} else {
			/* we are only interested in A records */
			/* TODO: add AAAA support */
			if (rr->type != T_A) {
				continue;
			}

			/* verify we actually have a A record here */
			if (!rr->u.a) {
				continue;
			}
		}
		count++;
	}

	if (count == 0) {
		goto done;
	}

	srv_rr = talloc_zero_array(state,
				   struct resource_record *,
				   count);
	if (!srv_rr) {
		goto done;
	}

	addrs_rr = talloc_zero_array(state,
				     struct resource_record *,
				     count);
	if (!addrs_rr) {
		goto done;
	}

	/* Loop over all returned records and pick the records */
	for (rr=reply->head;rr;rr=rr->next) {
		/* we are only interested in the IN class */
		if (rr->class != C_IN) {
			continue;
		}

		if (state->do_srv) {
			/* we are only interested in SRV records */
			if (rr->type != T_SRV) {
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

			srv_rr[srv_valid] = rr;
			srv_valid++;
		} else {
			/* we are only interested in A records */
			/* TODO: add AAAA support */
			if (rr->type != T_A) {
				continue;
			}

			/* verify we actually have a A record here */
			if (!rr->u.a) {
				continue;
			}

			addrs_rr[addrs_valid] = rr;
			addrs_valid++;
		}
	}

	for (i=0; i < srv_valid; i++) {
		for (rr=reply->head;rr;rr=rr->next) {

			if (rr->class != C_IN) {
				continue;
			}

			/* we are only interested in SRV records */
			if (rr->type != T_A) {
				continue;
			}

			/* verify we actually have a srv record here */
			if (strcmp(&srv_rr[i]->u.srv->target[0], rr->domain) != 0) {
				continue;
			}

			addrs_rr[i] = rr;
			addrs_valid++;
			break;
		}
	}

	if (addrs_valid == 0) {
		goto done;
	}

	addrs = talloc_strdup(state, "");
	if (!addrs) {
		goto done;
	}
	first = true;
	for (i=0; i < count; i++) {
		if (!addrs_rr[i]) {
			continue;
		}
		addrs = talloc_asprintf_append_buffer(addrs, "%s%s:%u",
						      first?"":",",
						      inet_ntoa(*addrs_rr[i]->u.a),
						      srv_rr[i]?srv_rr[i]->u.srv->port:0);
		if (!addrs) {
			goto done;
		}
		first = false;
	}

	if (addrs) {
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
	hints.ai_family = AF_INET;/* TODO: add AF_INET6 support */
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;

	ret = getaddrinfo(state->name.name, "0", &hints, &res_list);
	if (ret == EAI_NODATA && state->do_fallback) {
		/* getaddrinfo() doesn't handle CNAME records */
		run_child_dns_lookup(state, fd);
		return;
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
		struct sockaddr_in *in;

		if (res->ai_family != AF_INET) {
			continue;
		}
		in = (struct sockaddr_in *)res->ai_addr;

		addrs = talloc_asprintf_append_buffer(addrs, "%s%s:%u",
						      first?"":",",
						      inet_ntoa(in->sin_addr),
						      0);
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
static void pipe_handler(struct event_context *ev, struct fd_event *fde, 
			 uint16_t flags, void *private_data)
{
	struct composite_context *c = talloc_get_type(private_data, struct composite_context);
	struct dns_ex_state *state = talloc_get_type(c->private_data,
				     struct dns_ex_state);
	char address[2048];
	uint32_t num_addrs, i;
	char **addrs;
	int ret;
	int status;

	/* if we get any event from the child then we know that we
	   won't need to kill it off */
	talloc_set_destructor(state, NULL);

	/* yes, we don't care about EAGAIN or other niceities
	   here. They just can't happen with this parent/child
	   relationship, and even if they did then giving an error is
	   the right thing to do */
	ret = read(state->child_fd, address, sizeof(address)-1);
	close(state->child_fd);
	if (waitpid(state->child, &status, WNOHANG) == 0) {
		kill(state->child, SIGKILL);
		waitpid(state->child, &status, 0);
	}

	if (ret <= 0) {
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

	for (i=0; i < num_addrs; i++) {
		uint32_t port = 0;
		char *p = strrchr(addrs[i], ':');

		if (!p) {
			composite_error(c, NT_STATUS_OBJECT_NAME_NOT_FOUND);
			return;
		}

		*p = '\0';
		p++;

		if (strcmp(addrs[i], "0.0.0.0") == 0 ||
		    inet_addr(addrs[i]) == INADDR_NONE) {
			composite_error(c, NT_STATUS_OBJECT_NAME_NOT_FOUND);
			return;
		}
		port = strtoul(p, NULL, 10);
		if (port > UINT16_MAX) {
			port = 0;
		}
		state->addrs[i] = socket_address_from_strings(state->addrs,
							      "ipv4",
							      addrs[i],
							      port);
		if (composite_nomem(state->addrs[i], c)) return;
	}
	state->addrs[i] = NULL;

	composite_done(c);
}

/*
  getaddrinfo() or dns_lookup() name resolution method - async send
 */
struct composite_context *resolve_name_dns_ex_send(TALLOC_CTX *mem_ctx,
						   struct event_context *event_ctx,
						   void *privdata,
						   struct nbt_name *name,
						   bool do_getaddrinfo,
						   bool do_fallback,
						   bool do_srv)
{
	struct composite_context *c;
	struct dns_ex_state *state;
	int fd[2] = { -1, -1 };
	int ret;

	c = composite_create(mem_ctx, event_ctx);
	if (c == NULL) return NULL;

	if (composite_nomem(c->event_ctx, c)) return c;

	state = talloc_zero(c, struct dns_ex_state);
	if (composite_nomem(state, c)) return c;
	c->private_data = state;

	c->status = nbt_name_dup(state, name, &state->name);
	if (!composite_is_ok(c)) return c;

	/* setup a pipe to chat to our child */
	ret = pipe(fd);
	if (ret == -1) {
		composite_error(c, map_nt_error_from_unix(errno));
		return c;
	}

	state->do_getaddrinfo = do_getaddrinfo;
	state->do_fallback = do_fallback;
	state->do_srv = do_srv;

	state->child_fd = fd[0];
	state->event_ctx = c->event_ctx;

	/* we need to put the child in our event context so
	   we know when the dns_lookup() has finished */
	state->fde = event_add_fd(c->event_ctx, c, state->child_fd, EVENT_FD_READ, 
				  pipe_handler, c);
	if (composite_nomem(state->fde, c)) {
		close(fd[0]);
		close(fd[1]);
		return c;
	}

	state->child = fork();
	if (state->child == (pid_t)-1) {
		composite_error(c, map_nt_error_from_unix(errno));
		return c;
	}

	if (state->child == 0) {
		close(fd[0]);
		if (state->do_getaddrinfo) {
			run_child_getaddrinfo(state, fd[1]);
		} else {
			run_child_dns_lookup(state, fd[1]);
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
				  struct socket_address ***addrs)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct dns_ex_state *state = talloc_get_type(c->private_data,
					     struct dns_ex_state);
		*addrs = talloc_steal(mem_ctx, state->addrs);
	}

	talloc_free(c);
	return status;
}
