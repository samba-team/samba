/*
   logging wrapper for libctdb

   Copyright (C) Ronnie Sahlberg 2010

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
#include <sys/time.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>
#include <ctdb.h>
#include <string.h>
#include <tdb.h>
#include "libctdb_private.h"

int ctdb_log_level = LOG_WARNING;

void ctdb_do_debug(struct ctdb_connection *ctdb,
		   int severity, const char *format, ...)
{
        va_list ap;

        va_start(ap, format);
	ctdb->log(ctdb->log_priv, severity, format, ap);
        va_end(ap);
}

/* Attach tdb logging to our ctdb logging. */
void ctdb_tdb_log_bridge(struct tdb_context *tdb,
			 enum tdb_debug_level level,
			 const char *format, ...)
{
	va_list ap;
	int sev;
	struct ctdb_connection *ctdb = tdb_get_logging_private(tdb);
	char *newformat;

	switch (level) {
	case TDB_DEBUG_FATAL:
		sev = LOG_CRIT;
		break;
	case TDB_DEBUG_ERROR:
		sev = LOG_ERR;
		break;
	case TDB_DEBUG_WARNING:
		sev = LOG_WARNING;
		break;
	case TDB_DEBUG_TRACE:
		sev = LOG_DEBUG;
		break;
	default:
		sev = LOG_CRIT;
	}

	if (sev > ctdb_log_level) {
		return;
	}

	newformat = malloc(sizeof("TDB error: ") + strlen(format));
	if (!newformat) {
		DEBUG(ctdb, LOG_ERR,
		      "memory allocation failure reporting tdb error %s",
		      format);
		return;
	}

	/* Prepend TDB error: and remove \n */
	strcpy(newformat, "TDB error: ");
	strcat(newformat, format);
	if (newformat[strlen(newformat)-1] == '\n')
		newformat[strlen(newformat)-1] = '\0';

	va_start(ap, format);
	ctdb->log(ctdb->log_priv, sev, newformat, ap);
	va_end(ap);
	free(newformat);
}

/* Convenient log helper. */
void ctdb_log_file(FILE *outf, int priority, const char *format, va_list ap)
{
	fprintf(outf, "%s:",
		priority == LOG_EMERG ? "EMERG" :
		priority == LOG_ALERT ? "ALERT" :
		priority == LOG_CRIT ? "CRIT" :
		priority == LOG_ERR ? "ERR" :
		priority == LOG_WARNING ? "WARNING" :
		priority == LOG_NOTICE ? "NOTICE" :
		priority == LOG_INFO ? "INFO" :
		priority == LOG_DEBUG ? "DEBUG" :
		"Unknown Error Level");

	vfprintf(outf, format, ap);
	if (priority == LOG_ERR) {
		fprintf(outf, " (%s)", strerror(errno));
	}
	fprintf(outf, "\n");
}
