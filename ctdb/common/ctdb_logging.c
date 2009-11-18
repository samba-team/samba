/* 
   ctdb logging code

   Copyright (C) Ronnie Sahlberg 2009

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
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "../include/ctdb_private.h"
#include "../include/ctdb.h"

struct ctdb_log_entry {
	int32_t level;
	struct timeval t;
	char *message;
};

#define MAX_LOG_ENTRIES 500000
static int first_entry;
static int last_entry;

static struct ctdb_log_entry log_entries[MAX_LOG_ENTRIES];

/*
 * this function logs all messages for all levels to a ringbuffer
 */
static void log_ringbuffer_v(const char *format, va_list ap)
{
	int ret;
	char *s = NULL;

	if (log_entries[last_entry].message != NULL) {
		free(log_entries[last_entry].message);
		log_entries[last_entry].message = NULL;
	}

	ret = vasprintf(&s, format, ap);
	if (ret == -1) {
		return;
	}

	log_entries[last_entry].level = this_log_level;
	log_entries[last_entry].t = timeval_current();
	log_entries[last_entry].message = s;

	last_entry++;
	if (last_entry >= MAX_LOG_ENTRIES) {
		last_entry = 0;
	}
	if (first_entry == last_entry) {
		first_entry++;
	}
	if (first_entry >= MAX_LOG_ENTRIES) {
		first_entry = 0;
	}
}

void log_ringbuffer(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_ringbuffer_v(format, ap);
	va_end(ap);
}



static void ctdb_collect_log(struct ctdb_context *ctdb, struct ctdb_get_log_addr *log_addr)
{
	char *buf = talloc_size(NULL, 0);
	struct ctdb_log_entry_wire *log_entry;
	uint32_t old_size, len;
	TDB_DATA data;

	DEBUG(DEBUG_INFO,("Marshalling log entries\n"));
	while (first_entry != last_entry) {
		int slen = strlen(log_entries[first_entry].message);

		if (log_entries[first_entry].level > log_addr->level) {
			first_entry++;
			if (first_entry >= MAX_LOG_ENTRIES) {
				first_entry = 0;
			}
			continue;
		}

		len = offsetof(struct ctdb_log_entry_wire, message) + slen + 1;
		/* pad it to uint42 */
		len = (len+3)&0xfffffffc;

		old_size = talloc_get_size(buf);
		buf = talloc_realloc_size(NULL, buf, old_size + len);

		log_entry = (struct ctdb_log_entry_wire *)&buf[old_size];
		log_entry->level       = log_entries[first_entry].level;
		log_entry->t           = log_entries[first_entry].t;
		log_entry->message_len = slen;
		memcpy(log_entry->message, log_entries[first_entry].message, slen);
		log_entry->message[slen] = 0;

		first_entry++;
		if (first_entry >= MAX_LOG_ENTRIES) {
			first_entry = 0;
		}
	}

	data.dptr  = (uint8_t *)buf;
	data.dsize = talloc_get_size(buf);
	DEBUG(DEBUG_INFO,("Marshalling log entries into a blob of %d bytes\n", (int)data.dsize));

	DEBUG(DEBUG_INFO,("Send log to %d:%d\n", (int)log_addr->pnn, (int)log_addr->srvid));
	ctdb_send_message(ctdb, log_addr->pnn, log_addr->srvid, data);
}

int32_t ctdb_control_get_log(struct ctdb_context *ctdb, TDB_DATA addr)
{
	struct ctdb_get_log_addr *log_addr = (struct ctdb_get_log_addr *)addr.dptr;
	pid_t child;

	/* spawn a child process to marshall the huge log blob and send it back
	   to the ctdb tool using a MESSAGE
	*/
	child = fork();
	if (child == (pid_t)-1) {
		DEBUG(DEBUG_ERR,("Failed to fork a log collector child\n"));
		return -1;
	}

	if (child == 0) {
		if (switch_from_server_to_client(ctdb) != 0) {
			DEBUG(DEBUG_CRIT, (__location__ "ERROR: failed to switch log collector child into client mode.\n"));
			_exit(1);
		}
		ctdb_collect_log(ctdb, log_addr);
		_exit(0);
	}

	return 0;
}


int32_t ctdb_control_clear_log(struct ctdb_context *ctdb)
{
	first_entry = 0;
	last_entry  = 0;

	return 0;
}

