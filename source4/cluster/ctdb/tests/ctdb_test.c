/* 
   ctdb test harness

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "popt.h"
#include "cmdline.h"

enum my_functions {FUNC_SORT=1, FUNC_FETCH=2};

static int int_compare(int *i1, int *i2)
{
	return *i1 - *i2;
}

/*
  add an integer into a record in sorted order
*/
static int sort_func(struct ctdb_call_info *call)
{
	if (call->call_data == NULL ||
	    call->call_data->dsize != sizeof(int)) {
		return CTDB_ERR_INVALID;
	}
	call->new_data = talloc(call, TDB_DATA);
	if (call->new_data == NULL) {
		return CTDB_ERR_NOMEM;
	}
	call->new_data->dptr = talloc_size(call, 
					   call->record_data.dsize + 
					   call->call_data->dsize);
	if (call->new_data->dptr == NULL) {
		return CTDB_ERR_NOMEM;
	}
	call->new_data->dsize = call->record_data.dsize + call->call_data->dsize;
	memcpy(call->new_data->dptr,
	       call->record_data.dptr, call->record_data.dsize);
	memcpy(call->new_data->dptr+call->record_data.dsize,
	       call->call_data->dptr, call->call_data->dsize);

	qsort(call->new_data->dptr, call->new_data->dsize / sizeof(int),
	      sizeof(int), (comparison_fn_t)int_compare);

	return 0;
}

/*
  ctdb call function to fetch a record
*/
static int fetch_func(struct ctdb_call_info *call)
{
	call->reply_data = &call->record_data;
	return 0;
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
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	int i, ret;
	poptContext pc;
	struct event_context *ev;
	struct ctdb_call call;

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

	/* initialise ctdb */
	ctdb = ctdb_cmdline_init(ev);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
		exit(1);
	}

	/* attach to a specific database */
	ctdb_db = ctdb_attach(ctdb, "test.tdb", TDB_DEFAULT, O_RDWR|O_CREAT|O_TRUNC, 0666);
	if (!ctdb_db) {
		printf("ctdb_attach failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* setup a ctdb call function */
	ret = ctdb_set_call(ctdb_db, sort_func,  FUNC_SORT);
	ret = ctdb_set_call(ctdb_db, fetch_func, FUNC_FETCH);

	/* start the protocol running */
	ret = ctdb_start(ctdb);

	ctdb_connect_wait(ctdb);

	ZERO_STRUCT(call);
	call.key.dptr = discard_const("test");
	call.key.dsize = strlen("test")+1;

	/* add some random data */
	for (i=0;i<10;i++) {
		int v = random() % 1000;

		call.call_id = FUNC_SORT;
		call.call_data.dptr = (uint8_t *)&v;
		call.call_data.dsize = sizeof(v);

		ret = ctdb_call(ctdb_db, &call);
		if (ret == -1) {
			printf("ctdb_call FUNC_SORT failed - %s\n", ctdb_errstr(ctdb));
			exit(1);
		}
	}

	/* fetch the record */
	call.call_id = FUNC_FETCH;
	call.call_data.dptr = NULL;
	call.call_data.dsize = 0;

	ret = ctdb_call(ctdb_db, &call);
	if (ret == -1) {
		printf("ctdb_call FUNC_FETCH failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	for (i=0;i<call.reply_data.dsize/sizeof(int);i++) {
		printf("%3d\n", ((int *)call.reply_data.dptr)[i]);
	}
	talloc_free(call.reply_data.dptr);

	/* go into a wait loop to allow other nodes to complete */
	ctdb_shutdown(ctdb);

	return 0;
}
