/*
   event script handling

   Copyright (C) Andrew Tridgell  2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"
#include "system/wait.h"
#include "system/dir.h"
#include "system/locale.h"
#include "system/time.h"
#include "system/dir.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"

#include "ctdb_private.h"

#include "common/rb_tree.h"
#include "common/common.h"
#include "common/logging.h"
#include "common/reqid.h"
#include "common/sock_io.h"
#include "common/path.h"

#include "protocol/protocol_util.h"
#include "event/event_protocol_api.h"

/*
 * Setting up event daemon
 */

struct eventd_context {
	struct tevent_context *ev;
	const char *path;
	const char *socket;

	/* server state */
	pid_t eventd_pid;
	struct tevent_fd *eventd_fde;

	/* client state */
	struct reqid_context *idr;
	struct sock_queue *queue;
	struct eventd_client_state *calls;
};

static bool eventd_context_init(TALLOC_CTX *mem_ctx,
				struct ctdb_context *ctdb,
				struct eventd_context **out)
{
	struct eventd_context *ectx;
	const char *eventd = CTDB_HELPER_BINDIR "/ctdb-eventd";
	const char *value;
	int ret;

	ectx = talloc_zero(mem_ctx, struct eventd_context);
	if (ectx == NULL) {
		return false;
	}

	ectx->ev = ctdb->ev;

	value = getenv("CTDB_EVENTD");
	if (value != NULL) {
		eventd = value;
	}

	ectx->path = talloc_strdup(ectx, eventd);
	if (ectx->path == NULL) {
		talloc_free(ectx);
		return false;
	}

	ectx->socket = path_socket(ectx, "eventd");
	if (ectx->socket == NULL) {
		talloc_free(ectx);
		return false;
	}

	ret = reqid_init(ectx, 1, &ectx->idr);
	if (ret != 0) {
		talloc_free(ectx);
		return false;
	}

	ectx->eventd_pid = -1;

	*out = ectx;
	return true;
}

struct eventd_startup_state {
	bool done;
	int ret;
	int fd;
};

static void eventd_startup_timeout_handler(struct tevent_context *ev,
					   struct tevent_timer *te,
					   struct timeval t,
					   void *private_data)
{
	struct eventd_startup_state *state =
		(struct eventd_startup_state *) private_data;

	state->done = true;
	state->ret = ETIMEDOUT;
}

static void eventd_startup_handler(struct tevent_context *ev,
				   struct tevent_fd *fde, uint16_t flags,
				   void *private_data)
{
	struct eventd_startup_state *state =
		(struct eventd_startup_state *)private_data;
	unsigned int data;
	ssize_t num_read;

	num_read = sys_read(state->fd, &data, sizeof(data));
	if (num_read == sizeof(data)) {
		if (data == 0) {
			state->ret = 0;
		} else {
			state->ret = EIO;
		}
	} else if (num_read == 0) {
		state->ret = EPIPE;
	} else if (num_read == -1) {
		state->ret = errno;
	} else {
		state->ret = EINVAL;
	}

	state->done = true;
}


static int wait_for_daemon_startup(struct tevent_context *ev,
				   int fd)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_timer *timer;
	struct tevent_fd *fde;
	struct eventd_startup_state state = {
		.done = false,
		.ret = 0,
		.fd = fd,
	};

	mem_ctx = talloc_new(ev);
	if (mem_ctx == NULL) {
		return ENOMEM;
	}

	timer = tevent_add_timer(ev,
				 mem_ctx,
				 tevent_timeval_current_ofs(10, 0),
				 eventd_startup_timeout_handler,
				 &state);
	if (timer == NULL) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	fde = tevent_add_fd(ev,
			    mem_ctx,
			    fd,
			    TEVENT_FD_READ,
			    eventd_startup_handler,
			    &state);
	if (fde == NULL) {
		talloc_free(mem_ctx);
		return ENOMEM;
	}

	while (! state.done) {
		tevent_loop_once(ev);
	}

	talloc_free(mem_ctx);

	return state.ret;
}


/*
 * Start and stop event daemon
 */

static bool eventd_client_connect(struct eventd_context *ectx);
static void eventd_dead_handler(struct tevent_context *ev,
				struct tevent_fd *fde, uint16_t flags,
				void *private_data);

int ctdb_start_eventd(struct ctdb_context *ctdb)
{
	struct eventd_context *ectx;
	const char **argv;
	int fd[2];
	pid_t pid;
	int ret;
	bool status;

	if (ctdb->ectx == NULL) {
		status = eventd_context_init(ctdb, ctdb, &ctdb->ectx);
		if (! status) {
			DEBUG(DEBUG_ERR,
			      ("Failed to initialize eventd context\n"));
			return -1;
		}
	}

	ectx = ctdb->ectx;

	if (! sock_clean(ectx->socket)) {
		return -1;
	}

	ret = pipe(fd);
	if (ret != 0) {
		return -1;
	}

	argv = talloc_array(ectx, const char *, 6);
	if (argv == NULL) {
		close(fd[0]);
		close(fd[1]);
		return -1;
	}

	argv[0] = ectx->path;
	argv[1] = "-P";
	argv[2] = talloc_asprintf(argv, "%d", ctdb->ctdbd_pid);
	argv[3] = "-S";
	argv[4] = talloc_asprintf(argv, "%d", fd[1]);
	argv[5] = NULL;

	if (argv[2] == NULL || argv[4] == NULL) {
		close(fd[0]);
		close(fd[1]);
		talloc_free(argv);
		return -1;
	}

	D_NOTICE("Starting event daemon %s %s %s %s %s\n",
		 argv[0],
		 argv[1],
		 argv[2],
		 argv[3],
		 argv[4]);

	pid = ctdb_fork(ctdb);
	if (pid == -1) {
		close(fd[0]);
		close(fd[1]);
		talloc_free(argv);
		return -1;
	}

	if (pid == 0) {
		close(fd[0]);
		ret = execv(argv[0], discard_const(argv));
		if (ret == -1) {
			_exit(errno);
		}
		_exit(0);
	}

	talloc_free(argv);
	close(fd[1]);

	ret = wait_for_daemon_startup(ctdb->ev, fd[0]);
	if (ret != 0) {
		ctdb_kill(ctdb, pid, SIGKILL);
		close(fd[0]);
		D_ERR("Failed to initialize event daemon (%d)\n", ret);
		return -1;
	}

	ectx->eventd_fde = tevent_add_fd(ctdb->ev, ectx, fd[0],
					 TEVENT_FD_READ,
					 eventd_dead_handler, ectx);
	if (ectx->eventd_fde == NULL) {
		ctdb_kill(ctdb, pid, SIGKILL);
		close(fd[0]);
		return -1;
	}

	tevent_fd_set_auto_close(ectx->eventd_fde);
	ectx->eventd_pid = pid;

	status = eventd_client_connect(ectx);
	if (! status) {
		DEBUG(DEBUG_ERR, ("Failed to connect to event daemon\n"));
		ctdb_stop_eventd(ctdb);
		return -1;
	}

	return 0;
}

static void eventd_dead_handler(struct tevent_context *ev,
				struct tevent_fd *fde, uint16_t flags,
				void *private_data)
{
	D_ERR("Eventd went away - exiting\n");
	exit(1);
}

void ctdb_stop_eventd(struct ctdb_context *ctdb)
{
	struct eventd_context *ectx = ctdb->ectx;

	if (ectx == NULL) {
		return;
	}

	TALLOC_FREE(ectx->eventd_fde);
	if (ectx->eventd_pid != -1) {
		kill(ectx->eventd_pid, SIGTERM);
		ectx->eventd_pid = -1;
	}
	TALLOC_FREE(ctdb->ectx);
}

/*
 * Connect to event daemon
 */

struct eventd_client_state {
	struct eventd_client_state *prev, *next;

	struct eventd_context *ectx;
	void (*callback)(struct ctdb_event_reply *reply, void *private_data);
	void *private_data;

	uint32_t reqid;
	uint8_t *buf;
	size_t buflen;
};

static void eventd_client_read(uint8_t *buf, size_t buflen,
			       void *private_data);
static int eventd_client_state_destructor(struct eventd_client_state *state);

static bool eventd_client_connect(struct eventd_context *ectx)
{
	int fd;

	if (ectx->queue != NULL) {
		return true;
	}

	fd = sock_connect(ectx->socket);
	if (fd == -1) {
		return false;
	}

	ectx->queue = sock_queue_setup(ectx, ectx->ev, fd,
				       eventd_client_read, ectx);
	if (ectx->queue == NULL) {
		close(fd);
		return false;
	}

	return true;
}

static int eventd_client_write(struct eventd_context *ectx,
			       TALLOC_CTX *mem_ctx,
			       struct ctdb_event_request *request,
			       void (*callback)(struct ctdb_event_reply *reply,
						void *private_data),
			       void *private_data)
{
	struct ctdb_event_header header = { 0 };
	struct eventd_client_state *state;
	int ret;

	if (! eventd_client_connect(ectx)) {
		return -1;
	}

	state = talloc_zero(mem_ctx, struct eventd_client_state);
	if (state == NULL) {
		return -1;
	}

	state->ectx = ectx;
	state->callback = callback;
	state->private_data = private_data;

	state->reqid = reqid_new(ectx->idr, state);
	if (state->reqid == REQID_INVALID) {
		talloc_free(state);
		return -1;
	}

	talloc_set_destructor(state, eventd_client_state_destructor);

	header.reqid = state->reqid;

	state->buflen = ctdb_event_request_len(&header, request);
	state->buf = talloc_size(state, state->buflen);
	if (state->buf == NULL) {
		talloc_free(state);
		return -1;
	}

	ret = ctdb_event_request_push(&header,
				      request,
				      state->buf,
				      &state->buflen);
	if (ret != 0) {
		talloc_free(state);
		return -1;
	}

	ret = sock_queue_write(ectx->queue, state->buf, state->buflen);
	if (ret != 0) {
		talloc_free(state);
		return -1;
	}

	DLIST_ADD(ectx->calls, state);

	return 0;
}

static int eventd_client_state_destructor(struct eventd_client_state *state)
{
	struct eventd_context *ectx = state->ectx;

	reqid_remove(ectx->idr, state->reqid);
	DLIST_REMOVE(ectx->calls, state);
	return 0;
}

static void eventd_client_read(uint8_t *buf, size_t buflen,
			       void *private_data)
{
	struct eventd_context *ectx = talloc_get_type_abort(
		private_data, struct eventd_context);
	struct eventd_client_state *state;
	struct ctdb_event_header header;
	struct ctdb_event_reply *reply;
	int ret;

	if (buf == NULL) {
		/* connection lost */
		TALLOC_FREE(ectx->queue);
		return;
	}

	ret = ctdb_event_reply_pull(buf, buflen, &header, ectx, &reply);
	if (ret != 0) {
		D_ERR("Invalid packet received, ret=%d\n", ret);
		return;
	}

	if (buflen != header.length) {
		D_ERR("Packet size mismatch %zu != %"PRIu32"\n",
		      buflen, header.length);
		talloc_free(reply);
		return;
	}

	state = reqid_find(ectx->idr, header.reqid,
			   struct eventd_client_state);
	if (state == NULL) {
		talloc_free(reply);
		return;
	}

	if (state->reqid != header.reqid) {
		talloc_free(reply);
		return;
	}

	state = talloc_steal(reply, state);
	state->callback(reply, state->private_data);
	talloc_free(reply);
}

/*
 * Run an event
 */

struct eventd_client_run_state {
	struct eventd_context *ectx;
	void (*callback)(int result, void *private_data);
	void *private_data;
};

static void eventd_client_run_done(struct ctdb_event_reply *reply,
				   void *private_data);

static int eventd_client_run(struct eventd_context *ectx,
			     TALLOC_CTX *mem_ctx,
			     void (*callback)(int result,
					      void *private_data),
			     void *private_data,
			     enum ctdb_event event,
			     const char *arg_str,
			     uint32_t timeout)
{
	struct eventd_client_run_state *state;
	struct ctdb_event_request request;
	struct ctdb_event_request_run rdata;
	int ret;

	state = talloc_zero(mem_ctx, struct eventd_client_run_state);
	if (state == NULL) {
		return -1;
	}

	state->ectx = ectx;
	state->callback = callback;
	state->private_data = private_data;

	rdata.component = "legacy";
	rdata.event = ctdb_event_to_string(event);
	rdata.args = arg_str;
	rdata.timeout = timeout;
	rdata.flags = 0;

	request.cmd = CTDB_EVENT_CMD_RUN;
	request.data.run = &rdata;

	ret = eventd_client_write(ectx, state, &request,
				  eventd_client_run_done, state);
	if (ret != 0) {
		talloc_free(state);
		return ret;
	}

	return 0;
}

static void eventd_client_run_done(struct ctdb_event_reply *reply,
				   void *private_data)
{
	struct eventd_client_run_state *state = talloc_get_type_abort(
		private_data, struct eventd_client_run_state);

	state = talloc_steal(state->ectx, state);
	state->callback(reply->result, state->private_data);
	talloc_free(state);
}

/*
 * CTDB event script functions
 */

int ctdb_event_script_run(struct ctdb_context *ctdb,
			  TALLOC_CTX *mem_ctx,
			  void (*callback)(struct ctdb_context *ctdb,
					   int result, void *private_data),
			  void *private_data,
			  enum ctdb_event event,
			  const char *fmt, va_list ap)
			  PRINTF_ATTRIBUTE(6,0);

struct ctdb_event_script_run_state {
	struct ctdb_context *ctdb;
	void (*callback)(struct ctdb_context *ctdb, int result,
			 void *private_data);
	void *private_data;
	enum ctdb_event event;
};

static bool event_allowed_during_recovery(enum ctdb_event event);
static void ctdb_event_script_run_done(int result, void *private_data);
static bool check_options(enum ctdb_event call, const char *options);

int ctdb_event_script_run(struct ctdb_context *ctdb,
			  TALLOC_CTX *mem_ctx,
			  void (*callback)(struct ctdb_context *ctdb,
					   int result, void *private_data),
			  void *private_data,
			  enum ctdb_event event,
			  const char *fmt, va_list ap)
{
	struct ctdb_event_script_run_state *state;
	char *arg_str;
	int ret;

	if ( (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) &&
	     (! event_allowed_during_recovery(event)) ) {
		DEBUG(DEBUG_ERR,
		      ("Refusing to run event '%s' while in recovery\n",
		       ctdb_eventscript_call_names[event]));
		return -1;
	}

	state = talloc_zero(mem_ctx, struct ctdb_event_script_run_state);
	if (state == NULL) {
		return -1;
	}

	state->ctdb = ctdb;
	state->callback = callback;
	state->private_data = private_data;
	state->event = event;

	if (fmt != NULL) {
		arg_str = talloc_vasprintf(state, fmt, ap);
		if (arg_str == NULL) {
			talloc_free(state);
			return -1;
		}
	} else {
		arg_str = NULL;
	}

	if (! check_options(event, arg_str)) {
		DEBUG(DEBUG_ERR,
		      ("Bad event script arguments '%s' for '%s'\n",
		       arg_str, ctdb_eventscript_call_names[event]));
		talloc_free(arg_str);
		return -1;
	}

	ret = eventd_client_run(ctdb->ectx, state,
				ctdb_event_script_run_done, state,
				event, arg_str, ctdb->tunable.script_timeout);
	if (ret != 0) {
		talloc_free(state);
		return ret;
	}

	DEBUG(DEBUG_INFO,
	      (__location__ " Running event %s with arguments %s\n",
	       ctdb_eventscript_call_names[event], arg_str));

	talloc_free(arg_str);
	return 0;
}

static void ctdb_event_script_run_done(int result, void *private_data)
{
	struct ctdb_event_script_run_state *state = talloc_get_type_abort(
		private_data, struct ctdb_event_script_run_state);

	if (result == ETIMEDOUT) {
		switch (state->event) {
		case CTDB_EVENT_START_RECOVERY:
		case CTDB_EVENT_RECOVERED:
		case CTDB_EVENT_TAKE_IP:
		case CTDB_EVENT_RELEASE_IP:
			DEBUG(DEBUG_ERR,
			      ("Ignoring hung script for %s event\n",
			       ctdb_eventscript_call_names[state->event]));
			result = 0;
			break;

		default:
			break;
		}
	}

	state = talloc_steal(state->ctdb, state);
	state->callback(state->ctdb, result, state->private_data);
	talloc_free(state);
}


static unsigned int count_words(const char *options)
{
	unsigned int words = 0;

	if (options == NULL) {
		return 0;
	}

	options += strspn(options, " \t");
	while (*options) {
		words++;
		options += strcspn(options, " \t");
		options += strspn(options, " \t");
	}
	return words;
}

static bool check_options(enum ctdb_event call, const char *options)
{
	switch (call) {
	/* These all take no arguments. */
	case CTDB_EVENT_INIT:
	case CTDB_EVENT_SETUP:
	case CTDB_EVENT_STARTUP:
	case CTDB_EVENT_START_RECOVERY:
	case CTDB_EVENT_RECOVERED:
	case CTDB_EVENT_MONITOR:
	case CTDB_EVENT_SHUTDOWN:
	case CTDB_EVENT_IPREALLOCATED:
		return count_words(options) == 0;

	case CTDB_EVENT_TAKE_IP: /* interface, IP address, netmask bits. */
	case CTDB_EVENT_RELEASE_IP:
		return count_words(options) == 3;

	case CTDB_EVENT_UPDATE_IP: /* old interface, new interface, IP address, netmask bits. */
		return count_words(options) == 4;

	default:
		DEBUG(DEBUG_ERR,(__location__ "Unknown ctdb_event %u\n", call));
		return false;
	}
}

/* only specific events are allowed while in recovery */
static bool event_allowed_during_recovery(enum ctdb_event event)
{
	const enum ctdb_event allowed_events[] = {
		CTDB_EVENT_INIT,
		CTDB_EVENT_SETUP,
		CTDB_EVENT_START_RECOVERY,
		CTDB_EVENT_SHUTDOWN,
		CTDB_EVENT_RELEASE_IP,
		CTDB_EVENT_IPREALLOCATED,
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(allowed_events); i++) {
		if (event == allowed_events[i]) {
			return true;
		}
	}

	return false;
}

/*
  run the event script in the background, calling the callback when
  finished.  If mem_ctx is freed, callback will never be called.
 */
int ctdb_event_script_callback(struct ctdb_context *ctdb,
			       TALLOC_CTX *mem_ctx,
			       void (*callback)(struct ctdb_context *, int, void *),
			       void *private_data,
			       enum ctdb_event call,
			       const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = ctdb_event_script_run(ctdb, mem_ctx, callback, private_data,
				    call, fmt, ap);
	va_end(ap);

	return ret;
}


struct ctdb_event_script_args_state {
	bool done;
	int status;
};

static void ctdb_event_script_args_done(struct ctdb_context *ctdb,
					int status, void *private_data)
{
	struct ctdb_event_script_args_state *s =
		(struct ctdb_event_script_args_state *)private_data;

	s->done = true;
	s->status = status;
}

/*
  run the event script, waiting for it to complete. Used when the caller
  doesn't want to continue till the event script has finished.
 */
int ctdb_event_script_args(struct ctdb_context *ctdb, enum ctdb_event call,
			   const char *fmt, ...)
{
	va_list ap;
	int ret;
	struct ctdb_event_script_args_state state = {
		.status = -1,
		.done = false,
	};

	va_start(ap, fmt);
	ret = ctdb_event_script_run(ctdb, ctdb,
				    ctdb_event_script_args_done, &state,
				    call, fmt, ap);
	va_end(ap);
	if (ret != 0) {
		return ret;
	}

	while (! state.done) {
		tevent_loop_once(ctdb->ev);
	}

	if (state.status == ETIMEDOUT) {
		/* Don't ban self if CTDB is starting up or shutting down */
		if (call != CTDB_EVENT_INIT && call != CTDB_EVENT_SHUTDOWN) {
			DEBUG(DEBUG_ERR,
			      (__location__ " eventscript for '%s' timed out."
			       " Immediately banning ourself for %d seconds\n",
			       ctdb_eventscript_call_names[call],
			       ctdb->tunable.recovery_ban_period));
			ctdb_ban_self(ctdb);
		}
	}

	return state.status;
}

int ctdb_event_script(struct ctdb_context *ctdb, enum ctdb_event call)
{
	/* GCC complains about empty format string, so use %s and "". */
	return ctdb_event_script_args(ctdb, call, NULL);
}
