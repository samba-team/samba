/*
   ctdb logging code - syslog backend

   Copyright (C) Andrew Tridgell  2008
   Copyright (C) Martin Schwenke  2014

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
#include "system/network.h"
#include "system/syslog.h"

#include "lib/util/debug.h"
#include "lib/util/blocking.h"
#include "lib/util/time_basic.h"
#include "lib/util/samba_util.h" /* get_myname */

#include "ctdb_private.h"

#include "common/logging.h"

/* Linux and FreeBSD define this appropriately - try good old /dev/log
 * for anything that doesn't... */
#ifndef _PATH_LOG
#define _PATH_LOG "/dev/log"
#endif

#define CTDB_LOG_SYSLOG_PREFIX "syslog"
#define CTDB_SYSLOG_FACILITY LOG_USER

struct ctdb_syslog_sock_state {
	int fd;
	const char *app_name;
	const char *hostname;
	int (*format)(int dbglevel, struct ctdb_syslog_sock_state *state,
		      const char *str, char *buf, int bsize);
};

/**********************************************************************/

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

/**********************************************************************/

/* Format messages as per RFC3164. */

/* It appears that some syslog daemon implementations do not allow a
 * hostname when messages are sent via a Unix domain socket, so omit
 * it.  Similarly, syslogd on FreeBSD does not understand the hostname
 * part of the header, even when logging via UDP.  Note that most
 * implementations will log messages against "localhost" when logging
 * via UDP.  A timestamp could be sent but rsyslogd on Linux limits
 * the timestamp logged to the precision that was received on
 * /dev/log.  It seems sane to send degenerate RFC3164 messages
 * without a header at all, so that the daemon will generate high
 * resolution timestamps if configured. */
static int format_rfc3164(int dbglevel, struct ctdb_syslog_sock_state *state,
			  const char *str, char *buf, int bsize)
{
	int pri;
	int len;

	pri = CTDB_SYSLOG_FACILITY | ctdb_debug_to_syslog_level(dbglevel);
	len = snprintf(buf, bsize, "<%d>%s[%u]: %s%s",
		       pri, state->app_name, getpid(), debug_extra, str);
	len = MIN(len, bsize - 1);

	return len;
}

/* Format messages as per RFC5424
 *
 * <165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1
 *         myproc 8710 - - %% It's time to make the do-nuts.
 */
static int format_rfc5424(int dbglevel, struct ctdb_syslog_sock_state *state,
			  const char *str, char *buf, int bsize)
{
	int pri;
	struct timeval tv;
	struct timeval_buf tvbuf;
	int len, s;

	/* Header */
	pri = CTDB_SYSLOG_FACILITY | ctdb_debug_to_syslog_level(dbglevel);
	GetTimeOfDay(&tv);
	len = snprintf(buf, bsize,
		       "<%d>1 %s %s %s %u - - ",
		       pri, timeval_str_buf(&tv, true, true, &tvbuf),
		       state->hostname, state->app_name, getpid());
	/* A truncated header is not useful... */
	if (len >= bsize) {
		return -1;
	}

	/* Message */
	s = snprintf(&buf[len], bsize - len, "%s %s", debug_extra, str);
	len = MIN(len + s, bsize - 1);

	return len;
}

/**********************************************************************/

/* Non-blocking logging */

static void ctdb_log_to_syslog_sock(void *private_ptr,
				    int dbglevel, const char *str)
{
	struct ctdb_syslog_sock_state *state = talloc_get_type(
		private_ptr, struct ctdb_syslog_sock_state);

	/* RFC3164 says: The total length of the packet MUST be 1024
	   bytes or less. */
	char buf[1024];
	int n;

	n = state->format(dbglevel, state, str, buf, sizeof(buf));
	if (n == -1) {
		fprintf(stderr, "Failed to format syslog message %s\n", str);
		return;
	}

	/* Could extend this to count failures, which probably
	 * indicate dropped messages due to EAGAIN or EWOULDBLOCK */
	(void)send(state->fd, buf, n, 0);
}

static int
ctdb_syslog_sock_state_destructor(struct ctdb_syslog_sock_state *state)
{
	if (state->fd != -1) {
		close(state->fd);
		state->fd = -1;
	}
	return 0;
}

static struct ctdb_syslog_sock_state *
ctdb_log_setup_syslog_common(TALLOC_CTX *mem_ctx,
			     const char *app_name)
{
	struct ctdb_syslog_sock_state *state;

	state = talloc_zero(mem_ctx, struct ctdb_syslog_sock_state);
	if (state == NULL) {
		return NULL;
	}
	state->fd = -1;
	state->app_name = app_name;
	talloc_set_destructor(state, ctdb_syslog_sock_state_destructor);

	return state;
}

static int ctdb_log_setup_syslog_un(TALLOC_CTX *mem_ctx,
				    const char *app_name)
{
	struct ctdb_syslog_sock_state *state;
	struct sockaddr_un dest;
	int ret;

	state = ctdb_log_setup_syslog_common(mem_ctx, app_name);
	if (state == NULL) {
		return ENOMEM;
	}

	state->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (state->fd == -1) {
		int save_errno = errno;
		talloc_free(state);
		return save_errno;
	}

	dest.sun_family = AF_UNIX;
	strncpy(dest.sun_path, _PATH_LOG, sizeof(dest.sun_path)-1);
	ret = connect(state->fd,
		      (struct sockaddr *)&dest, sizeof(dest));
	if (ret == -1) {
		int save_errno = errno;
		talloc_free(state);
		return save_errno;
	}
	set_blocking(state->fd, false);

	state->hostname = NULL; /* Make this explicit */
	state->format = format_rfc3164;

	debug_set_callback(state, ctdb_log_to_syslog_sock);

	return 0;
}

static int ctdb_log_setup_syslog_udp(TALLOC_CTX *mem_ctx,
				     const char *app_name,
				     bool rfc5424)
{
	struct ctdb_syslog_sock_state *state;
	struct sockaddr_in dest;
	int ret;

	state = ctdb_log_setup_syslog_common(mem_ctx, app_name);
	if (state == NULL) {
		return ENOMEM;
	}

	state->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (state->fd == -1) {
		int save_errno = errno;
		talloc_free(state);
		return save_errno;
	}

	dest.sin_family = AF_INET;
	dest.sin_port   = htons(514);
	dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	ret = connect(state->fd,
		      (struct sockaddr *)&dest, sizeof(dest));
	if (ret == -1) {
		int save_errno = errno;
		talloc_free(state);
		return save_errno;
	}

	state->hostname = get_myname(state);
	if (state->hostname == NULL) {
		/* Use a fallback instead of failing initialisation */
		state->hostname = "localhost";
	}
	if (rfc5424) {
		state->format = format_rfc5424;
	} else {
		state->format = format_rfc3164;
	}

	debug_set_callback(state, ctdb_log_to_syslog_sock);

	return 0;
}

/**********************************************************************/

static void ctdb_log_to_syslog(void *private_ptr, int dbglevel, const char *s)
{
	syslog(ctdb_debug_to_syslog_level(dbglevel),
	       "%s%s", debug_extra, s);
}

static int ctdb_log_setup_syslog(TALLOC_CTX *mem_ctx,
				 const char *logging,
				 const char *app_name)
{
	size_t l = strlen(CTDB_LOG_SYSLOG_PREFIX);

	if (logging[l] != '\0') {
		/* Handle non-blocking extensions here */
		const char *method;

		if (logging[l] != ':') {
			return EINVAL;
		}
		method = &logging[0] + l + 1;
		if (strcmp(method, "nonblocking") == 0) {
			ctdb_log_setup_syslog_un(mem_ctx, app_name);
			return 0;
		}
		if (strcmp(method, "udp") == 0) {
			ctdb_log_setup_syslog_udp(mem_ctx, app_name, false);
			return 0;
		}
		if (strcmp(method, "udp-rfc5424") == 0) {
			ctdb_log_setup_syslog_udp(mem_ctx, app_name, true);
			return 0;
		}

		return EINVAL;
	}

	debug_set_callback(NULL, ctdb_log_to_syslog);
	return 0;
}

void ctdb_log_init_syslog(void)
{
	ctdb_log_register_backend(CTDB_LOG_SYSLOG_PREFIX,
				  ctdb_log_setup_syslog);
}
