/* 
   Unix SMB/CIFS implementation.

   Winbind child daemons

   Copyright (C) Andrew Tridgell 2002
   Copyright (C) Volker Lendecke 2004,2005

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
 * We fork a child per domain to be able to act non-blocking in the main
 * winbind daemon. A domain controller thousands of miles away being being
 * slow replying with a 10.000 user list should not hold up netlogon calls
 * that can be handled locally.
 */

#include "includes.h"
#include "winbindd.h"
#include "rpc_client/rpc_client.h"
#include "nsswitch/wb_reqtrans.h"
#include "secrets.h"
#include "../lib/util/select.h"
#include "../libcli/security/security.h"
#include "system/select.h"
#include "messages.h"
#include "../lib/util/tevent_unix.h"
#include "lib/param/loadparm.h"
#include "lib/util/sys_rw.h"
#include "lib/util/sys_rw_data.h"
#include "passdb.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

extern bool override_logfile;

static void forall_domain_children(bool (*fn)(struct winbindd_child *c,
					      void *private_data),
				   void *private_data)
{
	struct winbindd_domain *d;

	for (d = domain_list(); d != NULL; d = d->next) {
		int i;

		for (i = 0; i < lp_winbind_max_domain_connections(); i++) {
			struct winbindd_child *c = &d->children[i];
			bool ok;

			if (c->pid == 0) {
				continue;
			}

			ok = fn(c, private_data);
			if (!ok) {
				return;
			}
		}
	}
}

static void forall_children(bool (*fn)(struct winbindd_child *c,
				       void *private_data),
			    void *private_data)
{
	struct winbindd_child *c;
	bool ok;

	c = idmap_child();
	if (c->pid != 0) {
		ok = fn(c, private_data);
		if (!ok) {
			return;
		}
	}

	c = locator_child();
	if (c->pid != 0) {
		ok = fn(c, private_data);
		if (!ok) {
			return;
		}
	}

	forall_domain_children(fn, private_data);
}

/* Read some data from a client connection */

static NTSTATUS child_read_request(int sock, struct winbindd_request *wreq)
{
	NTSTATUS status;

	status = read_data_ntstatus(sock, (char *)wreq, sizeof(*wreq));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("child_read_request: read_data failed: %s\n",
			  nt_errstr(status)));
		return status;
	}

	if (wreq->extra_len == 0) {
		wreq->extra_data.data = NULL;
		return NT_STATUS_OK;
	}

	DEBUG(10, ("Need to read %d extra bytes\n", (int)wreq->extra_len));

	wreq->extra_data.data = SMB_MALLOC_ARRAY(char, wreq->extra_len + 1);
	if (wreq->extra_data.data == NULL) {
		DEBUG(0, ("malloc failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/* Ensure null termination */
	wreq->extra_data.data[wreq->extra_len] = '\0';

	status = read_data_ntstatus(sock, wreq->extra_data.data,
				    wreq->extra_len);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Could not read extra data: %s\n",
			  nt_errstr(status)));
	}
	return status;
}

static NTSTATUS child_write_response(int sock, struct winbindd_response *wrsp)
{
	struct iovec iov[2];
	int iov_count;

	iov[0].iov_base = (void *)wrsp;
	iov[0].iov_len = sizeof(struct winbindd_response);
	iov_count = 1;

	if (wrsp->length > sizeof(struct winbindd_response)) {
		iov[1].iov_base = (void *)wrsp->extra_data.data;
		iov[1].iov_len = wrsp->length-iov[0].iov_len;
		iov_count = 2;
	}

	DEBUG(10, ("Writing %d bytes to parent\n", (int)wrsp->length));

	if (write_data_iov(sock, iov, iov_count) != wrsp->length) {
		DEBUG(0, ("Could not write result\n"));
		return NT_STATUS_INVALID_HANDLE;
	}

	return NT_STATUS_OK;
}

/*
 * Do winbind child async request. This is not simply wb_simple_trans. We have
 * to do the queueing ourselves because while a request is queued, the child
 * might have crashed, and we have to re-fork it in the _trigger function.
 */

struct wb_child_request_state {
	struct tevent_context *ev;
	struct tevent_req *queue_subreq;
	struct tevent_req *subreq;
	struct winbindd_child *child;
	struct winbindd_request *request;
	struct winbindd_response *response;
};

static bool fork_domain_child(struct winbindd_child *child);

static void wb_child_request_waited(struct tevent_req *subreq);
static void wb_child_request_done(struct tevent_req *subreq);
static void wb_child_request_orphaned(struct tevent_req *subreq);

static void wb_child_request_cleanup(struct tevent_req *req,
				     enum tevent_req_state req_state);

struct tevent_req *wb_child_request_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct winbindd_child *child,
					 struct winbindd_request *request)
{
	struct tevent_req *req;
	struct wb_child_request_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_child_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->child = child;

	/*
	 * We have to make a copy of "request", because our caller
	 * might drop us via talloc_free().
	 *
	 * The talloc_move() magic in wb_child_request_cleanup() keeps
	 * all the requests, but if we are sitting deep within
	 * writev_send() down to the client, we have given it the
	 * pointer to "request". As our caller lost interest, it will
	 * just free "request", while writev_send still references it.
	 */

	state->request = talloc_memdup(state, request, sizeof(*request));
	if (tevent_req_nomem(state->request, req)) {
		return tevent_req_post(req, ev);
	}

	if (request->extra_data.data != NULL) {
		state->request->extra_data.data = talloc_memdup(
			state->request,
			request->extra_data.data,
			request->extra_len);
		if (tevent_req_nomem(state->request->extra_data.data, req)) {
			return tevent_req_post(req, ev);
		}
	}

	subreq = tevent_queue_wait_send(state, ev, child->queue);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, wb_child_request_waited, req);
	state->queue_subreq = subreq;

	tevent_req_set_cleanup_fn(req, wb_child_request_cleanup);

	return req;
}

static void wb_child_request_waited(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_child_request_state *state = tevent_req_data(
		req, struct wb_child_request_state);
	bool ok;

	ok = tevent_queue_wait_recv(subreq);
	if (!ok) {
		tevent_req_oom(req);
		return;
	}
	/*
	 * We need to keep state->queue_subreq
	 * in order to block the queue.
	 */
	subreq = NULL;

	if ((state->child->sock == -1) && (!fork_domain_child(state->child))) {
		tevent_req_error(req, errno);
		return;
	}

	tevent_fd_set_flags(state->child->monitor_fde, 0);

	subreq = wb_simple_trans_send(state, global_event_context(), NULL,
				      state->child->sock, state->request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	state->subreq = subreq;
	tevent_req_set_callback(subreq, wb_child_request_done, req);
	tevent_req_set_endtime(req, state->ev, timeval_current_ofs(300, 0));
}

static void wb_child_request_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_child_request_state *state = tevent_req_data(
		req, struct wb_child_request_state);
	int ret, err;

	ret = wb_simple_trans_recv(subreq, state, &state->response, &err);
	/* Freeing the subrequest is deferred until the cleanup function,
	 * which has to know whether a subrequest exists, and consequently
	 * decide whether to shut down the pipe to the child process.
	 */
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

static void wb_child_request_orphaned(struct tevent_req *subreq)
{
	struct winbindd_child *child =
		(struct winbindd_child *)tevent_req_callback_data_void(subreq);

	DBG_WARNING("cleanup orphaned subreq[%p]\n", subreq);
	TALLOC_FREE(subreq);

	if (child->domain != NULL) {
		/*
		 * If the child is attached to a domain,
		 * we need to make sure the domain queue
		 * can move forward, after the orphaned
		 * request is done.
		 */
		tevent_queue_start(child->domain->queue);
	}
}

int wb_child_request_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  struct winbindd_response **presponse, int *err)
{
	struct wb_child_request_state *state = tevent_req_data(
		req, struct wb_child_request_state);

	if (tevent_req_is_unix_error(req, err)) {
		return -1;
	}
	*presponse = talloc_move(mem_ctx, &state->response);
	return 0;
}

static void wb_child_request_cleanup(struct tevent_req *req,
				     enum tevent_req_state req_state)
{
	struct wb_child_request_state *state =
	    tevent_req_data(req, struct wb_child_request_state);

	if (state->subreq == NULL) {
		/* nothing to cleanup */
		return;
	}

	if (req_state == TEVENT_REQ_RECEIVED) {
		struct tevent_req *subreq = NULL;

		/*
		 * Our caller gave up, but we need to keep
		 * the low level request (wb_simple_trans)
		 * in order to maintain the parent child protocol.
		 *
		 * We also need to keep the child queue blocked
		 * until we got the response from the child.
		 */

		subreq = talloc_move(state->child->queue, &state->subreq);
		talloc_move(subreq, &state->queue_subreq);
		talloc_move(subreq, &state->request);
		tevent_req_set_callback(subreq,
					wb_child_request_orphaned,
					state->child);

		DBG_WARNING("keep orphaned subreq[%p]\n", subreq);
		return;
	}

	TALLOC_FREE(state->subreq);
	TALLOC_FREE(state->queue_subreq);

	tevent_fd_set_flags(state->child->monitor_fde, TEVENT_FD_READ);

	if (state->child->domain != NULL) {
		/*
		 * If the child is attached to a domain,
		 * we need to make sure the domain queue
		 * can move forward, after the request
		 * is done.
		 */
		tevent_queue_start(state->child->domain->queue);
	}

	if (req_state == TEVENT_REQ_DONE) {
		/* transmitted request and got response */
		return;
	}

	/*
	 * Failed to transmit and receive response, or request
	 * cancelled while being serviced.
	 * The basic parent/child communication broke, close
	 * our socket
	 */
	TALLOC_FREE(state->child->monitor_fde);
	close(state->child->sock);
	state->child->sock = -1;
}

static void child_socket_readable(struct tevent_context *ev,
				  struct tevent_fd *fde,
				  uint16_t flags,
				  void *private_data)
{
	struct winbindd_child *child = private_data;

	if ((flags & TEVENT_FD_READ) == 0) {
		return;
	}

	TALLOC_FREE(child->monitor_fde);

	/*
	 * We're only active when there is no outstanding child
	 * request. Arriving here means the child closed its socket,
	 * it died. Do the same here.
	 */

	SMB_ASSERT(child->sock != -1);

	close(child->sock);
	child->sock = -1;
}

static struct winbindd_child *choose_domain_child(struct winbindd_domain *domain)
{
	struct winbindd_child *shortest = &domain->children[0];
	struct winbindd_child *current;
	int i;

	for (i=0; i<lp_winbind_max_domain_connections(); i++) {
		size_t shortest_len, current_len;

		current = &domain->children[i];
		current_len = tevent_queue_length(current->queue);

		if (current_len == 0) {
			/* idle child */
			return current;
		}

		shortest_len = tevent_queue_length(shortest->queue);

		if (current_len < shortest_len) {
			shortest = current;
		}
	}

	return shortest;
}

struct dcerpc_binding_handle *dom_child_handle(struct winbindd_domain *domain)
{
	return domain->binding_handle;
}

struct wb_domain_request_state {
	struct tevent_context *ev;
	struct tevent_queue_entry *queue_entry;
	struct winbindd_domain *domain;
	struct winbindd_child *child;
	struct winbindd_request *request;
	struct winbindd_request *init_req;
	struct winbindd_response *response;
	struct tevent_req *pending_subreq;
};

static void wb_domain_request_cleanup(struct tevent_req *req,
				      enum tevent_req_state req_state)
{
	struct wb_domain_request_state *state = tevent_req_data(
		req, struct wb_domain_request_state);

	/*
	 * If we're completely done or got a failure.
	 * we should remove ourself from the domain queue,
	 * after removing the child subreq from the child queue
	 * and give the next one in the queue the chance
	 * to check for an idle child.
	 */
	TALLOC_FREE(state->pending_subreq);
	TALLOC_FREE(state->queue_entry);
	tevent_queue_start(state->domain->queue);
}

static void wb_domain_request_trigger(struct tevent_req *req,
				      void *private_data);
static void wb_domain_request_gotdc(struct tevent_req *subreq);
static void wb_domain_request_initialized(struct tevent_req *subreq);
static void wb_domain_request_done(struct tevent_req *subreq);

struct tevent_req *wb_domain_request_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct winbindd_domain *domain,
					  struct winbindd_request *request)
{
	struct tevent_req *req;
	struct wb_domain_request_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct wb_domain_request_state);
	if (req == NULL) {
		return NULL;
	}

	state->domain = domain;
	state->ev = ev;
	state->request = request;

	tevent_req_set_cleanup_fn(req, wb_domain_request_cleanup);

	state->queue_entry = tevent_queue_add_entry(
			domain->queue, state->ev, req,
			wb_domain_request_trigger, NULL);
	if (tevent_req_nomem(state->queue_entry, req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void wb_domain_request_trigger(struct tevent_req *req,
				      void *private_data)
{
	struct wb_domain_request_state *state = tevent_req_data(
		req, struct wb_domain_request_state);
	struct winbindd_domain *domain = state->domain;
	struct tevent_req *subreq = NULL;
	size_t shortest_queue_length;

	state->child = choose_domain_child(domain);
	shortest_queue_length = tevent_queue_length(state->child->queue);
	if (shortest_queue_length > 0) {
		/*
		 * All children are busy, we need to stop
		 * the queue and untrigger our own queue
		 * entry. Once a pending request
		 * is done it calls tevent_queue_start
		 * and we get retriggered.
		 */
		state->child = NULL;
		tevent_queue_stop(state->domain->queue);
		tevent_queue_entry_untrigger(state->queue_entry);
		return;
	}

	if (domain->initialized) {
		subreq = wb_child_request_send(state, state->ev, state->child,
					       state->request);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_domain_request_done, req);
		state->pending_subreq = subreq;

		/*
		 * Once the domain is initialized and
		 * once we placed our real request into the child queue,
		 * we can remove ourself from the domain queue
		 * and give the next one in the queue the chance
		 * to check for an idle child.
		 */
		TALLOC_FREE(state->queue_entry);
		return;
	}

	state->init_req = talloc_zero(state, struct winbindd_request);
	if (tevent_req_nomem(state->init_req, req)) {
		return;
	}

	if (IS_DC || domain->primary || domain->internal) {
		/* The primary domain has to find the DC name itself */
		state->init_req->cmd = WINBINDD_INIT_CONNECTION;
		fstrcpy(state->init_req->domain_name, domain->name);
		state->init_req->data.init_conn.is_primary = domain->primary;
		fstrcpy(state->init_req->data.init_conn.dcname, "");

		subreq = wb_child_request_send(state, state->ev, state->child,
					       state->init_req);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, wb_domain_request_initialized,
					req);
		state->pending_subreq = subreq;
		return;
	}

	/*
	 * This is *not* the primary domain,
	 * let's ask our DC about a DC name.
	 *
	 * We prefer getting a dns name in dc_unc,
	 * which is indicated by DS_RETURN_DNS_NAME.
	 * For NT4 domains we still get the netbios name.
	 */
	subreq = wb_dsgetdcname_send(state, state->ev,
				     state->domain->name,
				     NULL, /* domain_guid */
				     NULL, /* site_name */
				     DS_RETURN_DNS_NAME); /* flags */
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_domain_request_gotdc, req);
	state->pending_subreq = subreq;
	return;
}

static void wb_domain_request_gotdc(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_domain_request_state *state = tevent_req_data(
		req, struct wb_domain_request_state);
	struct netr_DsRGetDCNameInfo *dcinfo = NULL;
	NTSTATUS status;
	const char *dcname = NULL;

	state->pending_subreq = NULL;

	status = wb_dsgetdcname_recv(subreq, state, &dcinfo);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	dcname = dcinfo->dc_unc;
	while (dcname != NULL && *dcname == '\\') {
		dcname++;
	}
	state->init_req->cmd = WINBINDD_INIT_CONNECTION;
	fstrcpy(state->init_req->domain_name, state->domain->name);
	state->init_req->data.init_conn.is_primary = False;
	fstrcpy(state->init_req->data.init_conn.dcname,
		dcname);

	TALLOC_FREE(dcinfo);

	subreq = wb_child_request_send(state, state->ev, state->child,
				       state->init_req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_domain_request_initialized, req);
	state->pending_subreq = subreq;
}

static void wb_domain_request_initialized(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_domain_request_state *state = tevent_req_data(
		req, struct wb_domain_request_state);
	struct winbindd_response *response;
	int ret, err;

	state->pending_subreq = NULL;

	ret = wb_child_request_recv(subreq, talloc_tos(), &response, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}

	if (!string_to_sid(&state->domain->sid,
			   response->data.domain_info.sid)) {
		DEBUG(1,("init_child_recv: Could not convert sid %s "
			"from string\n", response->data.domain_info.sid));
		tevent_req_error(req, EINVAL);
		return;
	}

	talloc_free(state->domain->name);
	state->domain->name = talloc_strdup(state->domain,
					    response->data.domain_info.name);
	if (state->domain->name == NULL) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	if (response->data.domain_info.alt_name[0] != '\0') {
		talloc_free(state->domain->alt_name);

		state->domain->alt_name = talloc_strdup(state->domain,
				response->data.domain_info.alt_name);
		if (state->domain->alt_name == NULL) {
			tevent_req_error(req, ENOMEM);
			return;
		}
	}

	state->domain->native_mode = response->data.domain_info.native_mode;
	state->domain->active_directory =
		response->data.domain_info.active_directory;
	state->domain->initialized = true;

	TALLOC_FREE(response);

	subreq = wb_child_request_send(state, state->ev, state->child,
				       state->request);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_domain_request_done, req);
	state->pending_subreq = subreq;

	/*
	 * Once the domain is initialized and
	 * once we placed our real request into the child queue,
	 * we can remove ourself from the domain queue
	 * and give the next one in the queue the chance
	 * to check for an idle child.
	 */
	TALLOC_FREE(state->queue_entry);
}

static void wb_domain_request_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_domain_request_state *state = tevent_req_data(
		req, struct wb_domain_request_state);
	int ret, err;

	state->pending_subreq = NULL;

	ret = wb_child_request_recv(subreq, talloc_tos(), &state->response,
				    &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

int wb_domain_request_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			   struct winbindd_response **presponse, int *err)
{
	struct wb_domain_request_state *state = tevent_req_data(
		req, struct wb_domain_request_state);

	if (tevent_req_is_unix_error(req, err)) {
		return -1;
	}
	*presponse = talloc_move(mem_ctx, &state->response);
	return 0;
}

static void child_process_request(struct winbindd_child *child,
				  struct winbindd_cli_state *state)
{
	struct winbindd_domain *domain = child->domain;
	const struct winbindd_child_dispatch_table *table = child->table;

	/* Free response data - we may be interrupted and receive another
	   command before being able to send this data off. */

	state->response->result = WINBINDD_ERROR;
	state->response->length = sizeof(struct winbindd_response);

	/* as all requests in the child are sync, we can use talloc_tos() */
	state->mem_ctx = talloc_tos();

	/* Process command */

	for (; table->name; table++) {
		if (state->request->cmd == table->struct_cmd) {
			DEBUG(10,("child_process_request: request fn %s\n",
				  table->name));
			state->response->result = table->struct_fn(domain, state);
			return;
		}
	}

	DEBUG(1, ("child_process_request: unknown request fn number %d\n",
		  (int)state->request->cmd));
	state->response->result = WINBINDD_ERROR;
}

void setup_child(struct winbindd_domain *domain, struct winbindd_child *child,
		 const struct winbindd_child_dispatch_table *table,
		 const char *logprefix,
		 const char *logname)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	if (logprefix && logname) {
		char *logbase = NULL;

		if (*lp_logfile(talloc_tos(), lp_sub)) {
			char *end = NULL;

			if (asprintf(&logbase, "%s", lp_logfile(talloc_tos(), lp_sub)) < 0) {
				smb_panic("Internal error: asprintf failed");
			}

			if ((end = strrchr_m(logbase, '/'))) {
				*end = '\0';
			}
		} else {
			if (asprintf(&logbase, "%s", get_dyn_LOGFILEBASE()) < 0) {
				smb_panic("Internal error: asprintf failed");
			}
		}

		if (asprintf(&child->logfilename, "%s/%s-%s",
			     logbase, logprefix, logname) < 0) {
			SAFE_FREE(logbase);
			smb_panic("Internal error: asprintf failed");
		}

		SAFE_FREE(logbase);
	} else {
		smb_panic("Internal error: logprefix == NULL && "
			  "logname == NULL");
	}

	child->pid = 0;
	child->sock = -1;
	child->domain = domain;
	child->table = table;
	child->queue = tevent_queue_create(NULL, "winbind_child");
	SMB_ASSERT(child->queue != NULL);
	if (domain == NULL) {
		child->binding_handle = wbint_binding_handle(NULL, NULL, child);
		SMB_ASSERT(child->binding_handle != NULL);
	}
}

struct winbind_child_died_state {
	pid_t pid;
	struct winbindd_child *child;
};

static bool winbind_child_died_fn(struct winbindd_child *child,
				  void *private_data)
{
	struct winbind_child_died_state *state = private_data;

	if (child->pid == state->pid) {
		state->child = child;
		return false;
	}
	return true;
}

void winbind_child_died(pid_t pid)
{
	struct winbind_child_died_state state = { .pid = pid };

	forall_children(winbind_child_died_fn, &state);

	if (state.child == NULL) {
		DEBUG(5, ("Already reaped child %u died\n", (unsigned int)pid));
		return;
	}

	state.child->pid = 0;
}

/* Ensure any negative cache entries with the netbios or realm names are removed. */

void winbindd_flush_negative_conn_cache(struct winbindd_domain *domain)
{
	flush_negative_conn_cache_for_domain(domain->name);
	if (domain->alt_name != NULL) {
		flush_negative_conn_cache_for_domain(domain->alt_name);
	}
}

/* 
 * Parent winbindd process sets its own debug level first and then
 * sends a message to all the winbindd children to adjust their debug
 * level to that of parents.
 */

struct winbind_msg_relay_state {
	struct messaging_context *msg_ctx;
	uint32_t msg_type;
	DATA_BLOB *data;
};

static bool winbind_msg_relay_fn(struct winbindd_child *child,
				 void *private_data)
{
	struct winbind_msg_relay_state *state = private_data;

	DBG_DEBUG("sending message to pid %u.\n",
		  (unsigned int)child->pid);

	messaging_send(state->msg_ctx, pid_to_procid(child->pid),
		       state->msg_type, state->data);
	return true;
}

void winbind_msg_debug(struct messaging_context *msg_ctx,
 			 void *private_data,
			 uint32_t msg_type,
			 struct server_id server_id,
			 DATA_BLOB *data)
{
	struct winbind_msg_relay_state state = {
		.msg_ctx = msg_ctx, .msg_type = msg_type, .data = data
	};

	DEBUG(10,("winbind_msg_debug: got debug message.\n"));

	debug_message(msg_ctx, private_data, MSG_DEBUG, server_id, data);

	forall_children(winbind_msg_relay_fn, &state);
}

void winbind_disconnect_dc_parent(struct messaging_context *msg_ctx,
				  void *private_data,
				  uint32_t msg_type,
				  struct server_id server_id,
				  DATA_BLOB *data)
{
	struct winbind_msg_relay_state state = {
		.msg_ctx = msg_ctx, .msg_type = msg_type, .data = data
	};

	DBG_DEBUG("Got disconnect_dc message\n");

	forall_children(winbind_msg_relay_fn, &state);
}

static void winbindd_msg_reload_services_child(struct messaging_context *msg,
					       void *private_data,
					       uint32_t msg_type,
					       struct server_id server_id,
					       DATA_BLOB *data)
{
	DBG_DEBUG("Got reload-config message\n");
	winbindd_reload_services_file((const char *)private_data);
}

/* React on 'smbcontrol winbindd reload-config' in the same way as on SIGHUP*/
void winbindd_msg_reload_services_parent(struct messaging_context *msg,
					 void *private_data,
					 uint32_t msg_type,
					 struct server_id server_id,
					 DATA_BLOB *data)
{
	struct winbind_msg_relay_state state = {
		.msg_ctx = msg,
		.msg_type = msg_type,
		.data = data,
	};

	DBG_DEBUG("Got reload-config message\n");

        /* Flush various caches */
	winbindd_flush_caches();

	winbindd_reload_services_file((const char *)private_data);

	forall_children(winbind_msg_relay_fn, &state);
}

/* Set our domains as offline and forward the offline message to our children. */

struct winbind_msg_on_offline_state {
	struct messaging_context *msg_ctx;
	uint32_t msg_type;
};

static bool winbind_msg_on_offline_fn(struct winbindd_child *child,
				      void *private_data)
{
	struct winbind_msg_on_offline_state *state = private_data;

	if (child->domain->internal) {
		return true;
	}

	/*
	 * Each winbindd child should only process requests for one
	 * domain - make sure we only set it online / offline for that
	 * domain.
	 */
	DBG_DEBUG("sending message to pid %u for domain %s.\n",
		  (unsigned int)child->pid, child->domain->name);

	messaging_send_buf(state->msg_ctx,
			   pid_to_procid(child->pid),
			   state->msg_type,
			   (const uint8_t *)child->domain->name,
			   strlen(child->domain->name)+1);

	return true;
}

void winbind_msg_offline(struct messaging_context *msg_ctx,
			 void *private_data,
			 uint32_t msg_type,
			 struct server_id server_id,
			 DATA_BLOB *data)
{
	struct winbind_msg_on_offline_state state = {
		.msg_ctx = msg_ctx,
		.msg_type = MSG_WINBIND_OFFLINE,
	};
	struct winbindd_domain *domain;

	DEBUG(10,("winbind_msg_offline: got offline message.\n"));

	if (!lp_winbind_offline_logon()) {
		DEBUG(10,("winbind_msg_offline: rejecting offline message.\n"));
		return;
	}

	/* Set our global state as offline. */
	if (!set_global_winbindd_state_offline()) {
		DEBUG(10,("winbind_msg_offline: offline request failed.\n"));
		return;
	}

	/* Set all our domains as offline. */
	for (domain = domain_list(); domain; domain = domain->next) {
		if (domain->internal) {
			continue;
		}
		DEBUG(5,("winbind_msg_offline: marking %s offline.\n", domain->name));
		set_domain_offline(domain);
	}

	forall_domain_children(winbind_msg_on_offline_fn, &state);
}

/* Set our domains as online and forward the online message to our children. */

void winbind_msg_online(struct messaging_context *msg_ctx,
			void *private_data,
			uint32_t msg_type,
			struct server_id server_id,
			DATA_BLOB *data)
{
	struct winbind_msg_on_offline_state state = {
		.msg_ctx = msg_ctx,
		.msg_type = MSG_WINBIND_ONLINE,
	};
	struct winbindd_domain *domain;

	DEBUG(10,("winbind_msg_online: got online message.\n"));

	if (!lp_winbind_offline_logon()) {
		DEBUG(10,("winbind_msg_online: rejecting online message.\n"));
		return;
	}

	/* Set our global state as online. */
	set_global_winbindd_state_online();

	smb_nscd_flush_user_cache();
	smb_nscd_flush_group_cache();

	/* Set all our domains as online. */
	for (domain = domain_list(); domain; domain = domain->next) {
		if (domain->internal) {
			continue;
		}
		DEBUG(5,("winbind_msg_online: requesting %s to go online.\n", domain->name));

		winbindd_flush_negative_conn_cache(domain);
		set_domain_online_request(domain);

		/* Send an online message to the idmap child when our
		   primary domain comes back online */

		if ( domain->primary ) {
			pid_t idmap_pid = idmap_child_pid();

			if (idmap_pid != 0) {
				messaging_send_buf(msg_ctx,
						   pid_to_procid(idmap_pid),
						   MSG_WINBIND_ONLINE,
						   (const uint8_t *)domain->name,
						   strlen(domain->name)+1);
			}
		}
	}

	forall_domain_children(winbind_msg_on_offline_fn, &state);
}

static const char *collect_onlinestatus(TALLOC_CTX *mem_ctx)
{
	struct winbindd_domain *domain;
	char *buf = NULL;

	if ((buf = talloc_asprintf(mem_ctx, "global:%s ", 
				   get_global_winbindd_state_offline() ? 
				   "Offline":"Online")) == NULL) {
		return NULL;
	}

	for (domain = domain_list(); domain; domain = domain->next) {
		if ((buf = talloc_asprintf_append_buffer(buf, "%s:%s ", 
						  domain->name, 
						  domain->online ?
						  "Online":"Offline")) == NULL) {
			return NULL;
		}
	}

	buf = talloc_asprintf_append_buffer(buf, "\n");

	DEBUG(5,("collect_onlinestatus: %s", buf));

	return buf;
}

void winbind_msg_onlinestatus(struct messaging_context *msg_ctx,
			      void *private_data,
			      uint32_t msg_type,
			      struct server_id server_id,
			      DATA_BLOB *data)
{
	TALLOC_CTX *mem_ctx;
	const char *message;

	DEBUG(5,("winbind_msg_onlinestatus received.\n"));

	mem_ctx = talloc_init("winbind_msg_onlinestatus");
	if (mem_ctx == NULL) {
		return;
	}

	message = collect_onlinestatus(mem_ctx);
	if (message == NULL) {
		talloc_destroy(mem_ctx);
		return;
	}

	messaging_send_buf(msg_ctx, server_id, MSG_WINBIND_ONLINESTATUS,
			   (const uint8_t *)message, strlen(message) + 1);

	talloc_destroy(mem_ctx);
}

void winbind_msg_dump_domain_list(struct messaging_context *msg_ctx,
				  void *private_data,
				  uint32_t msg_type,
				  struct server_id server_id,
				  DATA_BLOB *data)
{
	TALLOC_CTX *mem_ctx;
	const char *message = NULL;
	const char *domain = NULL;
	char *s = NULL;
	NTSTATUS status;
	struct winbindd_domain *dom = NULL;

	DEBUG(5,("winbind_msg_dump_domain_list received.\n"));

	mem_ctx = talloc_init("winbind_msg_dump_domain_list");
	if (!mem_ctx) {
		return;
	}

	if (data->length > 0) {
		domain = (const char *)data->data;
	}

	if (domain) {

		DEBUG(5,("winbind_msg_dump_domain_list for domain: %s\n",
			domain));

		message = NDR_PRINT_STRUCT_STRING(mem_ctx, winbindd_domain,
						  find_domain_from_name_noinit(domain));
		if (!message) {
			talloc_destroy(mem_ctx);
			return;
		}

		messaging_send_buf(msg_ctx, server_id,
				   MSG_WINBIND_DUMP_DOMAIN_LIST,
				   (const uint8_t *)message, strlen(message) + 1);

		talloc_destroy(mem_ctx);

		return;
	}

	DEBUG(5,("winbind_msg_dump_domain_list all domains\n"));

	for (dom = domain_list(); dom; dom=dom->next) {
		message = NDR_PRINT_STRUCT_STRING(mem_ctx, winbindd_domain, dom);
		if (!message) {
			talloc_destroy(mem_ctx);
			return;
		}

		s = talloc_asprintf_append(s, "%s\n", message);
		if (!s) {
			talloc_destroy(mem_ctx);
			return;
		}
	}

	status = messaging_send_buf(msg_ctx, server_id,
				    MSG_WINBIND_DUMP_DOMAIN_LIST,
				    (uint8_t *)s, strlen(s) + 1);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("failed to send message: %s\n",
		nt_errstr(status)));
	}

	talloc_destroy(mem_ctx);
}

static void account_lockout_policy_handler(struct tevent_context *ctx,
					   struct tevent_timer *te,
					   struct timeval now,
					   void *private_data)
{
	struct winbindd_child *child =
		(struct winbindd_child *)private_data;
	TALLOC_CTX *mem_ctx = NULL;
	struct samr_DomInfo12 lockout_policy;
	NTSTATUS result;

	DEBUG(10,("account_lockout_policy_handler called\n"));

	TALLOC_FREE(child->lockout_policy_event);

	if ( !winbindd_can_contact_domain( child->domain ) ) {
		DEBUG(10,("account_lockout_policy_handler: Removing myself since I "
			  "do not have an incoming trust to domain %s\n", 
			  child->domain->name));

		return;		
	}

	mem_ctx = talloc_init("account_lockout_policy_handler ctx");
	if (!mem_ctx) {
		result = NT_STATUS_NO_MEMORY;
	} else {
		result = wb_cache_lockout_policy(child->domain, mem_ctx,
						 &lockout_policy);
	}
	TALLOC_FREE(mem_ctx);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10,("account_lockout_policy_handler: lockout_policy failed error %s\n",
			 nt_errstr(result)));
	}

	child->lockout_policy_event = tevent_add_timer(global_event_context(), NULL,
						      timeval_current_ofs(3600, 0),
						      account_lockout_policy_handler,
						      child);
}

static time_t get_machine_password_timeout(void)
{
	/* until we have gpo support use lp setting */
	return lp_machine_password_timeout();
}

static bool calculate_next_machine_pwd_change(const char *domain,
					      struct timeval *t)
{
	time_t pass_last_set_time;
	time_t timeout;
	time_t next_change;
	struct timeval tv;
	char *pw;

	pw = secrets_fetch_machine_password(domain,
					    &pass_last_set_time,
					    NULL);

	if (pw == NULL) {
		DEBUG(0,("cannot fetch own machine password ????"));
		return false;
	}

	SAFE_FREE(pw);

	timeout = get_machine_password_timeout();
	if (timeout == 0) {
		DEBUG(10,("machine password never expires\n"));
		return false;
	}

	tv.tv_sec = pass_last_set_time;
	DEBUG(10, ("password last changed %s\n",
		   timeval_string(talloc_tos(), &tv, false)));
	tv.tv_sec += timeout;
	DEBUGADD(10, ("password valid until %s\n",
		      timeval_string(talloc_tos(), &tv, false)));

	if (time(NULL) < (pass_last_set_time + timeout)) {
		next_change = pass_last_set_time + timeout;
		DEBUG(10,("machine password still valid until: %s\n",
			http_timestring(talloc_tos(), next_change)));
		*t = timeval_set(next_change, 0);

		if (lp_clustering()) {
			uint8_t randbuf;
			/*
			 * When having a cluster, we have several
			 * winbinds racing for the password change. In
			 * the machine_password_change_handler()
			 * function we check if someone else was
			 * faster when the event triggers. We add a
			 * 255-second random delay here, so that we
			 * don't run to change the password at the
			 * exact same moment.
			 */
			generate_random_buffer(&randbuf, sizeof(randbuf));
			DEBUG(10, ("adding %d seconds randomness\n",
				   (int)randbuf));
			t->tv_sec += randbuf;
		}
		return true;
	}

	DEBUG(10,("machine password expired, needs immediate change\n"));

	*t = timeval_zero();

	return true;
}

static void machine_password_change_handler(struct tevent_context *ctx,
					    struct tevent_timer *te,
					    struct timeval now,
					    void *private_data)
{
	struct messaging_context *msg_ctx = global_messaging_context();
	struct winbindd_child *child =
		(struct winbindd_child *)private_data;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_cli_context *netlogon_creds_ctx = NULL;
	NTSTATUS result;
	struct timeval next_change;

	DEBUG(10,("machine_password_change_handler called\n"));

	TALLOC_FREE(child->machine_password_change_event);

	if (!calculate_next_machine_pwd_change(child->domain->name,
					       &next_change)) {
		DEBUG(10, ("calculate_next_machine_pwd_change failed\n"));
		return;
	}

	DEBUG(10, ("calculate_next_machine_pwd_change returned %s\n",
		   timeval_string(talloc_tos(), &next_change, false)));

	if (!timeval_expired(&next_change)) {
		DEBUG(10, ("Someone else has already changed the pw\n"));
		goto done;
	}

	if (!winbindd_can_contact_domain(child->domain)) {
		DEBUG(10,("machine_password_change_handler: Removing myself since I "
			  "do not have an incoming trust to domain %s\n",
			  child->domain->name));
		return;
	}

	result = cm_connect_netlogon_secure(child->domain,
					    &netlogon_pipe,
					    &netlogon_creds_ctx);
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10,("machine_password_change_handler: "
			"failed to connect netlogon pipe: %s\n",
			 nt_errstr(result)));
		return;
	}

	result = trust_pw_change(netlogon_creds_ctx,
				 msg_ctx,
				 netlogon_pipe->binding_handle,
				 child->domain->name,
				 child->domain->dcname,
				 false); /* force */

	DEBUG(10, ("machine_password_change_handler: "
		   "trust_pw_change returned %s\n",
		   nt_errstr(result)));

	if (NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED) ) {
		DEBUG(3,("machine_password_change_handler: password set returned "
			 "ACCESS_DENIED.  Maybe the trust account "
			 "password was changed and we didn't know it. "
			 "Killing connections to domain %s\n",
			 child->domain->name));
		invalidate_cm_connection(child->domain);
	}

	if (!calculate_next_machine_pwd_change(child->domain->name,
					       &next_change)) {
		DEBUG(10, ("calculate_next_machine_pwd_change failed\n"));
		return;
	}

	DEBUG(10, ("calculate_next_machine_pwd_change returned %s\n",
		   timeval_string(talloc_tos(), &next_change, false)));

	if (!NT_STATUS_IS_OK(result)) {
		struct timeval tmp;
		/*
		 * In case of failure, give the DC a minute to recover
		 */
		tmp = timeval_current_ofs(60, 0);
		next_change = timeval_max(&next_change, &tmp);
	}

done:
	child->machine_password_change_event = tevent_add_timer(global_event_context(), NULL,
							      next_change,
							      machine_password_change_handler,
							      child);
}

/* Deal with a request to go offline. */

static void child_msg_offline(struct messaging_context *msg,
			      void *private_data,
			      uint32_t msg_type,
			      struct server_id server_id,
			      DATA_BLOB *data)
{
	struct winbindd_domain *domain;
	struct winbindd_domain *primary_domain = NULL;
	const char *domainname = (const char *)data->data;

	if (data->data == NULL || data->length == 0) {
		return;
	}

	DEBUG(5,("child_msg_offline received for domain %s.\n", domainname));

	if (!lp_winbind_offline_logon()) {
		DEBUG(10,("child_msg_offline: rejecting offline message.\n"));
		return;
	}

	primary_domain = find_our_domain();

	/* Mark the requested domain offline. */

	for (domain = domain_list(); domain; domain = domain->next) {
		if (domain->internal) {
			continue;
		}
		if (strequal(domain->name, domainname)) {
			DEBUG(5,("child_msg_offline: marking %s offline.\n", domain->name));
			set_domain_offline(domain);
			/* we are in the trusted domain, set the primary domain 
			 * offline too */
			if (domain != primary_domain) {
				set_domain_offline(primary_domain);
			}
		}
	}
}

/* Deal with a request to go online. */

static void child_msg_online(struct messaging_context *msg,
			     void *private_data,
			     uint32_t msg_type,
			     struct server_id server_id,
			     DATA_BLOB *data)
{
	struct winbindd_domain *domain;
	struct winbindd_domain *primary_domain = NULL;
	const char *domainname = (const char *)data->data;

	if (data->data == NULL || data->length == 0) {
		return;
	}

	DEBUG(5,("child_msg_online received for domain %s.\n", domainname));

	if (!lp_winbind_offline_logon()) {
		DEBUG(10,("child_msg_online: rejecting online message.\n"));
		return;
	}

	primary_domain = find_our_domain();

	/* Set our global state as online. */
	set_global_winbindd_state_online();

	/* Try and mark everything online - delete any negative cache entries
	   to force a reconnect now. */

	for (domain = domain_list(); domain; domain = domain->next) {
		if (domain->internal) {
			continue;
		}
		if (strequal(domain->name, domainname)) {
			DEBUG(5,("child_msg_online: requesting %s to go online.\n", domain->name));
			winbindd_flush_negative_conn_cache(domain);
			set_domain_online_request(domain);

			/* we can be in trusted domain, which will contact primary domain
			 * we have to bring primary domain online in trusted domain process
			 * see, winbindd_dual_pam_auth() --> winbindd_dual_pam_auth_samlogon()
			 * --> contact_domain = find_our_domain()
			 * */
			if (domain != primary_domain) {
				winbindd_flush_negative_conn_cache(primary_domain);
				set_domain_online_request(primary_domain);
			}
		}
	}
}

struct winbindd_reinit_after_fork_state {
	const struct winbindd_child *myself;
};

static bool winbindd_reinit_after_fork_fn(struct winbindd_child *child,
					  void *private_data)
{
	struct winbindd_reinit_after_fork_state *state = private_data;

	if (child == state->myself) {
		return true;
	}

	/* Destroy all possible events in child list. */
	TALLOC_FREE(child->lockout_policy_event);
	TALLOC_FREE(child->machine_password_change_event);

	/*
	 * Children should never be able to send each other messages,
	 * all messages must go through the parent.
	 */
	child->pid = (pid_t)0;

	/*
	 * Close service sockets to all other children
	 */
	if (child->sock != -1) {
		close(child->sock);
		child->sock = -1;
	}

	return true;
}

NTSTATUS winbindd_reinit_after_fork(const struct winbindd_child *myself,
				    const char *logfilename)
{
	struct winbindd_reinit_after_fork_state state = { .myself = myself };
	struct winbindd_domain *domain;
	NTSTATUS status;

	status = reinit_after_fork(
		global_messaging_context(),
		global_event_context(),
		true, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("reinit_after_fork() failed\n"));
		return status;
	}
	initialize_password_db(true, global_event_context());

	close_conns_after_fork();

	if (!override_logfile && logfilename) {
		lp_set_logfile(logfilename);
		reopen_logs();
	}

	if (!winbindd_setup_sig_term_handler(false))
		return NT_STATUS_NO_MEMORY;
	if (!winbindd_setup_sig_hup_handler(override_logfile ? NULL :
					    logfilename))
		return NT_STATUS_NO_MEMORY;

	/* Stop zombies in children */
	CatchChild();

	/* Don't handle the same messages as our parent. */
	messaging_deregister(global_messaging_context(),
			     MSG_SMB_CONF_UPDATED, NULL);
	messaging_deregister(global_messaging_context(),
			     MSG_SHUTDOWN, NULL);
	messaging_deregister(global_messaging_context(),
			     MSG_WINBIND_OFFLINE, NULL);
	messaging_deregister(global_messaging_context(),
			     MSG_WINBIND_ONLINE, NULL);
	messaging_deregister(global_messaging_context(),
			     MSG_WINBIND_ONLINESTATUS, NULL);
	messaging_deregister(global_messaging_context(),
			     MSG_WINBIND_DUMP_DOMAIN_LIST, NULL);
	messaging_deregister(global_messaging_context(),
			     MSG_DEBUG, NULL);

	messaging_deregister(global_messaging_context(),
			     MSG_WINBIND_DOMAIN_OFFLINE, NULL);
	messaging_deregister(global_messaging_context(),
			     MSG_WINBIND_DOMAIN_ONLINE, NULL);

	/* We have destroyed all events in the winbindd_event_context
	 * in reinit_after_fork(), so clean out all possible pending
	 * event pointers. */

	/* Deal with check_online_events. */

	for (domain = domain_list(); domain; domain = domain->next) {
		TALLOC_FREE(domain->check_online_event);
	}

	/* Ensure we're not handling a credential cache event inherited
	 * from our parent. */

	ccache_remove_all_after_fork();

	forall_children(winbindd_reinit_after_fork_fn, &state);

	return NT_STATUS_OK;
}

/*
 * In a child there will be only one domain, reference that here.
 */
static struct winbindd_domain *child_domain;

struct winbindd_domain *wb_child_domain(void)
{
	return child_domain;
}

struct child_handler_state {
	struct winbindd_child *child;
	struct winbindd_cli_state cli;
};

static void child_handler(struct tevent_context *ev, struct tevent_fd *fde,
			  uint16_t flags, void *private_data)
{
	struct child_handler_state *state =
		(struct child_handler_state *)private_data;
	NTSTATUS status;

	/* fetch a request from the main daemon */
	status = child_read_request(state->cli.sock, state->cli.request);

	if (!NT_STATUS_IS_OK(status)) {
		/* we lost contact with our parent */
		_exit(0);
	}

	DEBUG(4,("child daemon request %d\n",
		 (int)state->cli.request->cmd));

	ZERO_STRUCTP(state->cli.response);
	state->cli.request->null_term = '\0';
	state->cli.mem_ctx = talloc_tos();
	child_process_request(state->child, &state->cli);

	DEBUG(4, ("Finished processing child request %d\n",
		  (int)state->cli.request->cmd));

	SAFE_FREE(state->cli.request->extra_data.data);

	status = child_write_response(state->cli.sock, state->cli.response);
	if (!NT_STATUS_IS_OK(status)) {
		exit(1);
	}
}

static bool fork_domain_child(struct winbindd_child *child)
{
	int fdpair[2];
	struct child_handler_state state;
	struct winbindd_request request;
	struct winbindd_response response;
	struct winbindd_domain *primary_domain = NULL;
	NTSTATUS status;
	ssize_t nwritten;
	struct tevent_fd *fde;

	if (child->domain) {
		DEBUG(10, ("fork_domain_child called for domain '%s'\n",
			   child->domain->name));
	} else {
		DEBUG(10, ("fork_domain_child called without domain.\n"));
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fdpair) != 0) {
		DEBUG(0, ("Could not open child pipe: %s\n",
			  strerror(errno)));
		return False;
	}

	ZERO_STRUCT(state);
	state.child = child;
	state.cli.pid = getpid();
	state.cli.request = &request;
	state.cli.response = &response;

	child->pid = fork();

	if (child->pid == -1) {
		DEBUG(0, ("Could not fork: %s\n", strerror(errno)));
		close(fdpair[0]);
		close(fdpair[1]);
		return False;
	}

	if (child->pid != 0) {
		/* Parent */
		ssize_t nread;

		close(fdpair[0]);

		nread = sys_read(fdpair[1], &status, sizeof(status));
		if (nread != sizeof(status)) {
			DEBUG(1, ("fork_domain_child: Could not read child status: "
				  "nread=%d, error=%s\n", (int)nread,
				  strerror(errno)));
			close(fdpair[1]);
			return false;
		}
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("fork_domain_child: Child status is %s\n",
				  nt_errstr(status)));
			close(fdpair[1]);
			return false;
		}

		child->monitor_fde = tevent_add_fd(global_event_context(),
						   global_event_context(),
						   fdpair[1],
						   TEVENT_FD_READ,
						   child_socket_readable,
						   child);
		if (child->monitor_fde == NULL) {
			DBG_WARNING("tevent_add_fd failed\n");
			close(fdpair[1]);
			return false;
		}

		child->sock = fdpair[1];
		set_blocking(child->sock, false);
		return True;
	}

	/* Child */
	child_domain = child->domain;

	DEBUG(10, ("Child process %d\n", (int)getpid()));

	state.cli.sock = fdpair[0];
	close(fdpair[1]);

	status = winbindd_reinit_after_fork(child, child->logfilename);

	nwritten = sys_write(state.cli.sock, &status, sizeof(status));
	if (nwritten != sizeof(status)) {
		DEBUG(1, ("fork_domain_child: Could not write status: "
			  "nwritten=%d, error=%s\n", (int)nwritten,
			  strerror(errno)));
		_exit(0);
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("winbindd_reinit_after_fork failed: %s\n",
			  nt_errstr(status)));
		_exit(0);
	}

	if (child_domain != NULL) {
		setproctitle("domain child [%s]", child_domain->name);
	} else if (child == idmap_child()) {
		setproctitle("idmap child");
	}

	/* Handle online/offline messages. */
	messaging_register(global_messaging_context(), NULL,
			   MSG_WINBIND_OFFLINE, child_msg_offline);
	messaging_register(global_messaging_context(), NULL,
			   MSG_WINBIND_ONLINE, child_msg_online);
	messaging_register(global_messaging_context(), NULL,
			   MSG_DEBUG, debug_message);
	messaging_register(global_messaging_context(), NULL,
			   MSG_WINBIND_IP_DROPPED,
			   winbind_msg_ip_dropped);
	messaging_register(global_messaging_context(), NULL,
			   MSG_WINBIND_DISCONNECT_DC,
			   winbind_msg_disconnect_dc);
	messaging_register(global_messaging_context(),
			   override_logfile ? NULL : child->logfilename,
			   MSG_SMB_CONF_UPDATED,
			   winbindd_msg_reload_services_child);

	primary_domain = find_our_domain();

	if (primary_domain == NULL) {
		smb_panic("no primary domain found");
	}

	/* It doesn't matter if we allow cache login,
	 * try to bring domain online after fork. */
	if ( child->domain ) {
		child->domain->startup = True;
		child->domain->startup_time = time_mono(NULL);
		/* we can be in primary domain or in trusted domain
		 * If we are in trusted domain, set the primary domain
		 * in start-up mode */
		if (!(child->domain->internal)) {
			set_domain_online_request(child->domain);
			if (!(child->domain->primary)) {
				primary_domain->startup = True;
				primary_domain->startup_time = time_mono(NULL);
				set_domain_online_request(primary_domain);
			}
		}
	}

	/*
	 * We are in idmap child, make sure that we set the
	 * check_online_event to bring primary domain online.
	 */
	if (child == idmap_child()) {
		set_domain_online_request(primary_domain);
	}

	/* We might be in the idmap child...*/
	if (child->domain && !(child->domain->internal) &&
	    lp_winbind_offline_logon()) {

		set_domain_online_request(child->domain);

		if (primary_domain && (primary_domain != child->domain)) {
			/* We need to talk to the primary
			 * domain as well as the trusted
			 * domain inside a trusted domain
			 * child.
			 * See the code in :
			 * set_dc_type_and_flags_trustinfo()
			 * for details.
			 */
			set_domain_online_request(primary_domain);
		}

		child->lockout_policy_event = tevent_add_timer(
			global_event_context(), NULL, timeval_zero(),
			account_lockout_policy_handler,
			child);
	}

	if (child->domain && child->domain->primary &&
	    !USE_KERBEROS_KEYTAB &&
	    lp_server_role() == ROLE_DOMAIN_MEMBER) {

		struct timeval next_change;

		if (calculate_next_machine_pwd_change(child->domain->name,
						       &next_change)) {
			child->machine_password_change_event = tevent_add_timer(
				global_event_context(), NULL, next_change,
				machine_password_change_handler,
				child);
		}
	}

	fde = tevent_add_fd(global_event_context(), NULL, state.cli.sock,
			    TEVENT_FD_READ, child_handler, &state);
	if (fde == NULL) {
		DEBUG(1, ("tevent_add_fd failed\n"));
		_exit(1);
	}

	while (1) {

		int ret;
		TALLOC_CTX *frame = talloc_stackframe();

		ret = tevent_loop_once(global_event_context());
		if (ret != 0) {
			DEBUG(1, ("tevent_loop_once failed: %s\n",
				  strerror(errno)));
			_exit(1);
		}

		if (child->domain && child->domain->startup &&
				(time_mono(NULL) > child->domain->startup_time + 30)) {
			/* No longer in "startup" mode. */
			DEBUG(10,("fork_domain_child: domain %s no longer in 'startup' mode.\n",
				child->domain->name ));
			child->domain->startup = False;
		}

		TALLOC_FREE(frame);
	}
}

void winbind_msg_ip_dropped_parent(struct messaging_context *msg_ctx,
				   void *private_data,
				   uint32_t msg_type,
				   struct server_id server_id,
				   DATA_BLOB *data)
{
	struct winbind_msg_relay_state state = {
		.msg_ctx = msg_ctx,
		.msg_type = msg_type,
		.data = data,
	};

	winbind_msg_ip_dropped(msg_ctx, private_data, msg_type,
			       server_id, data);

	forall_children(winbind_msg_relay_fn, &state);
}
