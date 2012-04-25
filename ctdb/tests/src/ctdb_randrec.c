/* 
   create a lot of random records, both current records and deleted records

   Copyright (C) Andrew Tridgell  2008
	Ronnie sahlberg 2007

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
#include "system/filesys.h"
#include "popt.h"
#include "cmdline.h"
#include "ctdb_private.h"

#include <sys/time.h>
#include <time.h>

static struct timeval tp1,tp2;

static void start_timer(void)
{
	gettimeofday(&tp1,NULL);
}

static double end_timer(void)
{
	gettimeofday(&tp2,NULL);
	return (tp2.tv_sec + (tp2.tv_usec*1.0e-6)) - 
		(tp1.tv_sec + (tp1.tv_usec*1.0e-6));
}

static int num_records = 10;
static int delete_pct = 75;
static int base_rec;

static void store_records(struct ctdb_context *ctdb, struct event_context *ev)
{
	TDB_DATA key, data;
	struct ctdb_db_context *ctdb_db;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	int ret;
	struct ctdb_record_handle *h;
	uint32_t i=0;
	
	ctdb_db = ctdb_db_handle(ctdb, "test.tdb");

	srandom(time(NULL) ^ getpid());

	start_timer();

	printf("working with %d records\n", num_records);
	while (1) {
		unsigned r = random() % num_records;
		key.dptr = (uint8_t *)&r;
		key.dsize = sizeof(r); 

		h = ctdb_fetch_lock(ctdb_db, tmp_ctx, key, &data);
		if (h == NULL) {
			printf("Failed to fetch record '%s' on node %d\n", 
			       (const char *)key.dptr, ctdb_get_pnn(ctdb));
			talloc_free(tmp_ctx);
			return;
		}

		if (random() % 100 < delete_pct) {
			data.dptr = NULL;
			data.dsize = 0;
		} else {
			data.dptr = talloc_zero_size(h, data.dsize + sizeof(r));
			data.dsize += sizeof(r);
		}

		ret = ctdb_record_store(h, data);
		if (ret != 0) {
			printf("Failed to store record\n");
		}

		if (data.dptr == NULL && data.dsize == 0) {
			struct ctdb_control_schedule_for_deletion *dd;
			TDB_DATA indata;
			int32_t status;

			indata.dsize = offsetof(struct ctdb_control_schedule_for_deletion, key) + key.dsize;
			indata.dptr = talloc_zero_array(ctdb, uint8_t, indata.dsize);
			if (indata.dptr == NULL) {
				printf("out of memory\n");
				exit(1);
			}
			dd = (struct ctdb_control_schedule_for_deletion *)(void *)indata.dptr;
			dd->db_id = ctdb_db->db_id;
			dd->hdr = *ctdb_header_from_record_handle(h);
			dd->keylen = key.dsize;
			memcpy(dd->key, key.dptr, key.dsize);

			ret = ctdb_control(ctdb,
					   CTDB_CURRENT_NODE,
					   ctdb_db->db_id,
					   CTDB_CONTROL_SCHEDULE_FOR_DELETION,
					   0, /* flags */
					   indata,
					   NULL, /* mem_ctx */
					   NULL, /* outdata */
					   &status,
					   NULL, /* timeout : NULL == wait forever */
					   NULL); /* error message */

			talloc_free(indata.dptr);

			if (ret != 0 || status != 0) {
				DEBUG(DEBUG_ERR, (__location__ " Error sending "
						  "SCHEDULE_FOR_DELETION "
						  "control.\n"));
			}
		}

		talloc_free(h);

		if (i % 1000 == 0) {
			printf("%7.0f recs/second   %u total\r", 1000.0 / end_timer(), i);
			fflush(stdout);
			start_timer();
		}
		i++;
	}

	talloc_free(tmp_ctx);
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
		{ "num-records", 'r', POPT_ARG_INT, &num_records, 0, "num_records", "integer" },
		{ "base-rec", 'b', POPT_ARG_INT, &base_rec, 0, "base_rec", "integer" },
		{ "delete-pct", 'p', POPT_ARG_INT, &delete_pct, 0, "delete_pct", "integer" },
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	poptContext pc;
	struct event_context *ev;

	pc = poptGetContext(argv[0], argc, argv, popt_options, POPT_CONTEXT_KEEP_FIRST);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "Invalid option %s: %s\n", 
				poptBadOption(pc, 0), poptStrerror(opt));
			exit(1);
		}
	}

	/* setup the remaining options for the main program to use */
	extra_argv = poptGetArgs(pc);
	if (extra_argv) {
		extra_argv++;
		while (extra_argv[extra_argc]) extra_argc++;
	}

	ev = event_context_init(NULL);

	ctdb = ctdb_cmdline_client(ev, timeval_current_ofs(3, 0));

	if (ctdb == NULL) {
		printf("failed to connect to daemon\n");
		exit(1);
	}

	/* attach to a specific database */
	ctdb_db = ctdb_attach(ctdb, timeval_current_ofs(2, 0), "test.tdb",
			      false, 0);
	if (!ctdb_db) {
		printf("ctdb_attach failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	store_records(ctdb, ev);

	return 0;
}
