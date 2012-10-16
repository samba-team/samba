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
#include "lib/tdb/include/tdb.h"
#include "system/time.h"
#include "../include/ctdb_private.h"
#include "../include/ctdb_client.h"

int log_ringbuf_size;

#define MAX_LOG_SIZE 128

static int first_entry;
static int last_entry;

struct ctdb_log_entry {
	int32_t level;
	struct timeval t;
	char message[MAX_LOG_SIZE];
};


static struct ctdb_log_entry *log_entries;

/*
 * this function logs all messages for all levels to a ringbuffer
 */
static void log_ringbuffer_v(const char *format, va_list ap)
{
	int ret;

	if (log_entries == NULL && log_ringbuf_size != 0) {
		/* Hope this works. We cant log anything if it doesnt anyway */
		log_entries = malloc(sizeof(struct ctdb_log_entry) * log_ringbuf_size);
	}
	if (log_entries == NULL) {
		return;
	}

	log_entries[last_entry].message[0] = '\0';

	ret = vsnprintf(&log_entries[last_entry].message[0], MAX_LOG_SIZE, format, ap);
	if (ret == -1) {
		return;
	}

	log_entries[last_entry].level = this_log_level;
	log_entries[last_entry].t = timeval_current();

	last_entry++;
	if (last_entry >= log_ringbuf_size) {
		last_entry = 0;
	}
	if (first_entry == last_entry) {
		first_entry++;
	}
	if (first_entry >= log_ringbuf_size) {
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



void ctdb_collect_log(struct ctdb_context *ctdb, struct ctdb_get_log_addr *log_addr)
{
	TDB_DATA data;
	FILE *f;
	long fsize;
	int tmp_entry;
	int count = 0;
	DEBUG(DEBUG_ERR,("Marshalling log entries  first:%d last:%d\n", first_entry, last_entry));

	/* dump to a file, then send the file as a blob */
	f = tmpfile();
	if (f == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Unable to open tmpfile - %s\n", strerror(errno)));
		return;
	}

	tmp_entry = first_entry;
	while (tmp_entry != last_entry) {
		struct tm *tm;
		char tbuf[100];

		if (log_entries == NULL) {
			break;
		}

		if (log_entries[tmp_entry].level > log_addr->level) {
			tmp_entry++;
			if (tmp_entry >= log_ringbuf_size) {
				tmp_entry = 0;
			}
		 	continue;
		}

		tm = localtime(&log_entries[tmp_entry].t.tv_sec);
		strftime(tbuf, sizeof(tbuf)-1,"%Y/%m/%d %H:%M:%S", tm);

		if (log_entries[tmp_entry].message) {
			count += fprintf(f, "%s:%s %s", tbuf, get_debug_by_level(log_entries[tmp_entry].level), log_entries[tmp_entry].message);
		}

		tmp_entry++;
		if (tmp_entry >= log_ringbuf_size) {
			tmp_entry = 0;
		}
	}

	fsize = ftell(f);
	rewind(f);
	data.dptr = talloc_size(NULL, fsize);
	CTDB_NO_MEMORY_VOID(ctdb, data.dptr);
	data.dsize = fread(data.dptr, 1, fsize, f);
	fclose(f);

	DEBUG(DEBUG_ERR,("Marshalling log entries into a blob of %d bytes\n", (int)data.dsize));

	DEBUG(DEBUG_ERR,("Send log to %d:%d\n", (int)log_addr->pnn, (int)log_addr->srvid));
	ctdb_client_send_message(ctdb, log_addr->pnn, log_addr->srvid, data);

	talloc_free(data.dptr);
}

int32_t ctdb_control_get_log(struct ctdb_context *ctdb, TDB_DATA addr)
{
	struct ctdb_get_log_addr *log_addr = (struct ctdb_get_log_addr *)addr.dptr;
	pid_t child;

	/* spawn a child process to marshall the huge log blob and send it back
	   to the ctdb tool using a MESSAGE
	*/
	child = ctdb_fork(ctdb);
	if (child == (pid_t)-1) {
		DEBUG(DEBUG_ERR,("Failed to fork a log collector child\n"));
		return -1;
	}

	if (child == 0) {
		if (switch_from_server_to_client(ctdb, "log-collector") != 0) {
			DEBUG(DEBUG_CRIT, (__location__ "ERROR: failed to switch log collector child into client mode.\n"));
			_exit(1);
		}
		ctdb_collect_log(ctdb, log_addr);
		_exit(0);
	}

	return 0;
}

void ctdb_clear_log(struct ctdb_context *ctdb)
{
	first_entry = 0;
	last_entry  = 0;
}

int32_t ctdb_control_clear_log(struct ctdb_context *ctdb)
{
	ctdb_clear_log(ctdb);

	return 0;
}
