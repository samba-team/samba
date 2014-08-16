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
#include "tdb.h"
#include "system/time.h"
#include "../include/ctdb_private.h"
#include "../include/ctdb_client.h"

int LogLevel = DEBUG_NOTICE;
int this_log_level = 0;
const char *debug_extra = "";

int log_ringbuf_size;

#define MAX_LOG_SIZE 128

static int first_entry = 0;
static int ringbuf_count = 0;

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
	int next_entry;

	if (log_entries == NULL && log_ringbuf_size != 0) {
		/* Hope this works. We cant log anything if it doesnt anyway */
		log_entries = malloc(sizeof(struct ctdb_log_entry) * log_ringbuf_size);
	}
	if (log_entries == NULL) {
		return;
	}

	next_entry = (first_entry + ringbuf_count) % log_ringbuf_size;

	if (ringbuf_count > 0 && first_entry == next_entry) {
		first_entry = (first_entry + 1) % log_ringbuf_size;
	}

	log_entries[next_entry].message[0] = '\0';

	ret = vsnprintf(&log_entries[next_entry].message[0], MAX_LOG_SIZE, format, ap);
	if (ret == -1) {
		return;
	}
	/* Log messages longer than MAX_LOG_SIZE are truncated to MAX_LOG_SIZE-1
	 * bytes.  In that case, add a newline.
	 */
	if (ret >= MAX_LOG_SIZE) {
		log_entries[next_entry].message[MAX_LOG_SIZE-2] = '\n';
	}

	log_entries[next_entry].level = this_log_level;
	log_entries[next_entry].t = timeval_current();

	if (ringbuf_count < log_ringbuf_size) {
		ringbuf_count++;
	}
}

void log_ringbuffer(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_ringbuffer_v(format, ap);
	va_end(ap);
}

void ctdb_log_ringbuffer_free(void)
{
	if (log_entries != NULL) {
		free(log_entries);
		log_entries = NULL;
	}
	log_ringbuf_size = 0;
}

TDB_DATA ctdb_log_ringbuffer_collect_log(TALLOC_CTX *mem_ctx,
					 enum debug_level max_level)
{
	TDB_DATA data;
	FILE *f;
	long fsize;
	int tmp_entry;
	struct tm *tm;
	char tbuf[100];
	int i;

	DEBUG(DEBUG_ERR,("Marshalling %d log entries\n", ringbuf_count));

	/* dump to a file, then send the file as a blob */
	f = tmpfile();
	if (f == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Unable to open tmpfile - %s\n",
				 strerror(errno)));
		return tdb_null;
	}

	for (i=0; i<ringbuf_count; i++) {
		tmp_entry = (first_entry + i) % log_ringbuf_size;

		if (log_entries[tmp_entry].level > max_level) {
		 	continue;
		}

		tm = localtime(&log_entries[tmp_entry].t.tv_sec);
		strftime(tbuf, sizeof(tbuf)-1,"%Y/%m/%d %H:%M:%S", tm);

		if (log_entries[tmp_entry].message[0] != '\0') {
			fprintf(f, "%s:%s %s", tbuf,
				get_debug_by_level(log_entries[tmp_entry].level),
				log_entries[tmp_entry].message);
		}
	}

	fsize = ftell(f);
	if (fsize < 0) {
		fclose(f);
		DEBUG(DEBUG_ERR, ("Cannot get file size for log entries\n"));
		return tdb_null;
	}
	rewind(f);
	data.dptr = talloc_size(NULL, fsize);
	if (data.dptr == NULL) {
		fclose(f);
		DEBUG(DEBUG_ERR, (__location__ " Memory allocation error\n"));
		return tdb_null;
	}
	data.dsize = fread(data.dptr, 1, fsize, f);
	fclose(f);

	DEBUG(DEBUG_ERR,("Marshalling log entries into a blob of %d bytes\n", (int)data.dsize));

	return data;
}

void ctdb_clear_log(struct ctdb_context *ctdb)
{
	first_entry = 0;
	ringbuf_count  = 0;
}

int32_t ctdb_control_clear_log(struct ctdb_context *ctdb)
{
	ctdb_clear_log(ctdb);

	return 0;
}

struct debug_levels debug_levels[] = {
	{DEBUG_EMERG,	"EMERG"},
	{DEBUG_ALERT,	"ALERT"},
	{DEBUG_CRIT,	"CRIT"},
	{DEBUG_ERR,	"ERR"},
	{DEBUG_WARNING,	"WARNING"},
	{DEBUG_NOTICE,	"NOTICE"},
	{DEBUG_INFO,	"INFO"},
	{DEBUG_DEBUG,	"DEBUG"},
	{0, NULL}
};

const char *get_debug_by_level(int32_t level)
{
	int i;

	for (i=0; debug_levels[i].description != NULL; i++) {
		if (debug_levels[i].level == level) {
			return debug_levels[i].description;
		}
	}
	return "Unknown";
}

int32_t get_debug_by_desc(const char *desc)
{
	int i;

	for (i=0; debug_levels[i].description != NULL; i++) {
		if (!strcasecmp(debug_levels[i].description, desc)) {
			return debug_levels[i].level;
		}
	}

	return DEBUG_ERR;
}
