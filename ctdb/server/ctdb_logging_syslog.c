/*
   ctdb logging code - syslog backend

   Copyright (C) Andrew Tridgell  2008
   Copyright (C) Ronnie Sahlberg  2009

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

#include "includes.h"
#include "../include/ctdb_client.h"
#include "../include/ctdb_private.h"
#include "system/syslog.h"

struct syslog_message {
	uint32_t level;
	uint32_t len;
	char message[1];
};


struct ctdb_syslog_state {
	int syslog_fd;
	int fd[2];
};

static int syslogd_is_started = 0;

static int ctdb_debug_to_syslog_level(int dbglevel)
{
	int level;

	switch (dbglevel) {
	case DEBUG_ERR:
		level = LOG_ERR;
		break;
	case DEBUG_WARNING:
		level = LOG_WARNING;
		break;
	case DEBUG_NOTICE:
		level = LOG_NOTICE;
		break;
	case DEBUG_INFO:
		level = LOG_INFO;
		break;
	default:
		level = LOG_DEBUG;
		break;
	}

	return level;
}

/* called when child is finished
 * this is for the syslog daemon, we can not use DEBUG here
 */
static void ctdb_syslog_handler(struct event_context *ev, struct fd_event *fde,
				      uint16_t flags, void *p)
{
	struct ctdb_syslog_state *state = talloc_get_type(p, struct ctdb_syslog_state);

	int count;
	char str[65536];
	struct syslog_message *msg;

	if (state == NULL) {
		return;
	}

	count = recv(state->syslog_fd, str, sizeof(str), 0);
	if (count < sizeof(struct syslog_message)) {
		return;
	}
	msg = (struct syslog_message *)str;
	if (msg->len >= (sizeof(str) - offsetof(struct syslog_message, message))) {
		msg->len = (sizeof(str)-1) - offsetof(struct syslog_message, message);
	}
	msg->message[msg->len] = '\0';

	syslog(msg->level, "%s", msg->message);
}


/* called when the pipe from the main daemon has closed
 * this is for the syslog daemon, we can not use DEBUG here
 */
static void ctdb_syslog_terminate_handler(struct event_context *ev, struct fd_event *fde,
				      uint16_t flags, void *p)
{
	syslog(LOG_ERR, "Shutting down SYSLOG daemon with pid:%d", (int)getpid());
	_exit(0);
}



/*
 * this is for the syslog daemon, we can not use DEBUG here
 */
int start_syslog_daemon(struct ctdb_context *ctdb)
{
	struct sockaddr_in syslog_sin;
	struct ctdb_syslog_state *state;
	struct tevent_fd *fde;
	int startup_fd[2];
	int ret = -1;

	state = talloc(ctdb, struct ctdb_syslog_state);
	CTDB_NO_MEMORY(ctdb, state);

	if (pipe(state->fd) != 0) {
		printf("Failed to create syslog pipe\n");
		talloc_free(state);
		return -1;
	}

	if (pipe(startup_fd) != 0) {
		printf("Failed to create syslog startup pipe\n");
		close(state->fd[0]);
		close(state->fd[1]);
		talloc_free(state);
		return -1;
	}

	ctdb->syslogd_pid = ctdb_fork(ctdb);
	if (ctdb->syslogd_pid == (pid_t)-1) {
		printf("Failed to create syslog child process\n");
		close(state->fd[0]);
		close(state->fd[1]);
		close(startup_fd[0]);
		close(startup_fd[1]);
		talloc_free(state);
		return -1;
	}

	if (ctdb->syslogd_pid != 0) {
		ssize_t n;
		int dummy;

		DEBUG(DEBUG_ERR,("Starting SYSLOG child process with pid:%d\n", (int)ctdb->syslogd_pid));

		close(state->fd[1]);
		set_close_on_exec(state->fd[0]);

		close(startup_fd[1]);
		n = sys_read(startup_fd[0], &dummy, sizeof(dummy));
		close(startup_fd[0]);
		if (n < sizeof(dummy)) {
			return -1;
		}

		syslogd_is_started = 1;
		return 0;
	}

	debug_extra = talloc_asprintf(NULL, "syslogd:");
	talloc_free(ctdb->ev);
	ctdb->ev = event_context_init(NULL);

	syslog(LOG_ERR, "Starting SYSLOG daemon with pid:%d", (int)getpid());
	ctdb_set_process_name("ctdb_syslogd");

	close(state->fd[0]);
	close(startup_fd[0]);
	set_close_on_exec(state->fd[1]);
	set_close_on_exec(startup_fd[1]);
	fde = event_add_fd(ctdb->ev, state, state->fd[1], EVENT_FD_READ,
		     ctdb_syslog_terminate_handler, state);
	tevent_fd_set_auto_close(fde);

	state->syslog_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (state->syslog_fd == -1) {
		printf("Failed to create syslog socket\n");
		close(startup_fd[1]);
		return ret;
	}

	set_close_on_exec(state->syslog_fd);

	syslog_sin.sin_family = AF_INET;
	syslog_sin.sin_port   = htons(CTDB_PORT);
	syslog_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(state->syslog_fd, (struct sockaddr *)&syslog_sin,
		 sizeof(syslog_sin)) == -1)
	{
		printf("syslog daemon failed to bind to socket. errno:%d(%s)\n", errno, strerror(errno));
		close(startup_fd[1]);
		_exit(10);
	}


	fde = event_add_fd(ctdb->ev, state, state->syslog_fd, EVENT_FD_READ,
		     ctdb_syslog_handler, state);
	tevent_fd_set_auto_close(fde);

	/* Tell parent that we're up */
	ret = 0;
	sys_write(startup_fd[1], &ret, sizeof(ret));
	close(startup_fd[1]);

	event_loop_wait(ctdb->ev);

	/* this should not happen */
	_exit(10);
}

/*
  syslog logging function
 */
static void ctdb_log_to_syslog(void *private_ptr, int dbglevel, const char *s)
{
	struct syslog_message *msg;
	int len;
	int syslog_fd;
	struct sockaddr_in syslog_sin;

	len = offsetof(struct syslog_message, message) + strlen(debug_extra) + strlen(s) + 1;
	msg = malloc(len);
	if (msg == NULL) {
		return;
	}
	msg->level = ctdb_debug_to_syslog_level(dbglevel);
	msg->len   = strlen(debug_extra) + strlen(s);
	strcpy(msg->message, debug_extra);
	strcat(msg->message, s);

	if (syslogd_is_started == 0) {
		syslog(msg->level, "%s", msg->message);
	} else {
		syslog_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (syslog_fd == -1) {
			printf("Failed to create syslog socket\n");
			free(msg);
			return;
		}

		syslog_sin.sin_family = AF_INET;
		syslog_sin.sin_port   = htons(CTDB_PORT);
		syslog_sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		(void) sendto(syslog_fd, msg, len, 0,
			      (struct sockaddr *)&syslog_sin,
			      sizeof(syslog_sin));
		/* no point in checking here since we cant log an error */

		close(syslog_fd);
	}

	free(msg);
}

int ctdb_log_setup_syslog(void)
{
	debug_set_callback(NULL, ctdb_log_to_syslog);
	return 0;
}
