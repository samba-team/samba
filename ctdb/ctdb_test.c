/* 
   ctdb test harness

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "replace.h"
#include "system/filesys.h"
#include "tdb.h"
#include "talloc.h"
#include "ctdb.h"
#include "popt.h"

enum my_functions {FUNC_SORT=1, FUNC_FETCH=2};

static int int_compare(int *i1, int *i2)
{
	return *i1 - *i2;
}

/*
  add an integer into a record in sorted order
*/
static int sort_func(struct ctdb_call *call)
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
	memcpy(call->new_data->dptr+call->record_data.dsize,
	       call->call_data->dptr, call->call_data->dsize);
	qsort(call->new_data->dptr, call->new_data->dsize / sizeof(int),
	      sizeof(int), (comparison_fn_t)int_compare);
	return 0;
}

/*
  ctdb call function to fetch a record
*/
static int fetch_func(struct ctdb_call *call)
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
	const char *nlist = NULL;
	const char *myaddress = NULL;

	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		{ "nlist", 0, POPT_ARG_STRING, &nlist, 0, "node list file", "filename" },
		{ "listen", 0, POPT_ARG_STRING, &myaddress, 0, "address to listen on", "address" },
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	int i, ret;
	TDB_DATA key, data;
	poptContext pc;

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

	if (nlist == NULL || myaddress == NULL) {
		printf("You must provide a node list with --nlist and an address with --listen\n");
		exit(1);
	}

	/* initialise ctdb */
	ctdb = ctdb_init(NULL);
	if (ctdb == NULL) {
		printf("Failed to init ctdb\n");
		exit(1);
	}

	/* tell ctdb what address to listen on */
	ret = ctdb_set_address(ctdb, myaddress);
	if (ret == -1) {
		printf("ctdb_set_address failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* tell ctdb what nodes are available */
	ret = ctdb_set_nlist(ctdb, nlist);
	if (ret == -1) {
		printf("ctdb_set_nlist failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* setup a ctdb call function */
	ret = ctdb_set_call(ctdb, sort_func,  FUNC_SORT);
	ret = ctdb_set_call(ctdb, fetch_func, FUNC_FETCH);

	/* attach to a specific database */
	ret = ctdb_attach(ctdb, "test.tdb", TDB_DEFAULT, O_RDWR|O_CREAT|O_TRUNC, 0666);
	if (ret == -1) {
		printf("ctdb_attach failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	/* start the protocol running */
	ret = ctdb_start(ctdb);
       
	key.dptr = "test";
	key.dsize = strlen("test")+1;

	/* add some random data */
	for (i=0;i<100;i++) {
		int v = random();
		data.dptr = (uint8_t *)&v;
		data.dsize = sizeof(v);
		ret = ctdb_call(ctdb, key, FUNC_SORT, &data, NULL);
		if (ret == -1) {
			printf("ctdb_call FUNC_SORT failed - %s\n", ctdb_errstr(ctdb));
			exit(1);
		}
	}

	/* fetch the record */
	ret = ctdb_call(ctdb, key, FUNC_FETCH, NULL, &data);
	if (ret == -1) {
		printf("ctdb_call FUNC_FETCH failed - %s\n", ctdb_errstr(ctdb));
		exit(1);
	}

	for (i=0;i<data.dsize/sizeof(int);i++) {
		printf("%3d\n", ((int *)data.dptr)[i]);
	}
	
	/* shut it down */
	talloc_free(ctdb);
	return 0;
}
