/* 
   ctdb status tool

   Copyright (C) Andrew Tridgell  2007

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

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "popt.h"
#include "cmdline.h"
#include "../include/ctdb_private.h"
#include "db_wrap.h"


/*
  show usage message
 */
static void usage(void)
{
	printf("Usage: ctdb_dump <path>\n");
	exit(1);
}

static int traverse_fn(struct tdb_context *tdb, TDB_DATA key, TDB_DATA data, void *p)
{
	int *num_nodes = (int *)p;
	struct id {
		dev_t dev;
		ino_t inode;
	} *id;
	struct ctdb_ltdb_header *h = (struct ctdb_ltdb_header *)data.dptr;
	char *keystr;
	id = (struct id *)key.dptr;
	if (key.dsize == sizeof(*id)) {
		keystr = talloc_asprintf(NULL, "%llu:%llu", 
					 (uint64_t)id->dev, (uint64_t)id->inode);
	} else {
		keystr = hex_encode(NULL, key.dptr, key.dsize);
	}
	printf("  rec %s lmaster=%u dmaster=%u %c\n", 
	       keystr, 
	       ctdb_hash(&key) % (*num_nodes),
	       h->dmaster,
		);
	talloc_free(keystr);
	return 0;
}

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int i, extra_argc = 0;
	poptContext pc;
	struct tdb_wrap *db;

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

	if (extra_argc < 1) {
		usage();
	}

	for (i=0;i<extra_argc;i++) {
		db = tdb_wrap_open(NULL, extra_argv[i], 0, TDB_DEFAULT, O_RDONLY, 0);
		if (db == NULL) {
			printf("Failed to open %s - %s\n", 
			       extra_argv[i], strerror(errno));
			exit(1);
		}

		printf("db %s\n", extra_argv[i]);
		tdb_traverse(db->tdb, traverse_fn, &extra_argc);
		
		talloc_free(db);
	}

	return 0;
}
