/* 
   simple rb vs dlist benchmark

   Copyright (C) Ronnie Sahlberg 2007

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
#include "lib/util/dlinklist.h"
#include "system/filesys.h"
#include "popt.h"
#include "cmdline.h"

#include <sys/time.h>
#include <time.h>
#include "common/rb_tree.h"

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


static int num_records = 1000;


struct list_node {
	struct list_node *prev, *next;
};

/*
  main program
*/
int main(int argc, const char *argv[])
{
	struct poptOption popt_options[] = {
		POPT_AUTOHELP
		POPT_CTDB_CMDLINE
		{ "num-records", 'r', POPT_ARG_INT, &num_records, 0, "num_records", "integer" },
		POPT_TABLEEND
	};
	int opt;
	const char **extra_argv;
	int extra_argc = 0;
	int ret;
	poptContext pc;
	struct event_context *ev;
	double elapsed;
	int i;
	trbt_tree_t *tree;
	struct list_node *list, *list_new, *list_head=NULL;

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


	printf("testing tree insert for %d records\n", num_records);
	tree = trbt_create(NULL);
	start_timer();
	for (i=0;i<num_records;i++) {
		trbt_insert32(tree, i, NULL);
	}
	elapsed=end_timer();
	printf("%f seconds\n",(float)elapsed);


	printf("testing dlist (worst case) add to tail for %d records\n", num_records);
	list_new=talloc(NULL, struct list_node);
	DLIST_ADD(list_head, list_new);
	start_timer();
	for (i=0;i<num_records;i++) {
		for(list=list_head;list->next;list=list->next) {
			/* the events code does a timeval_compare */
			timeval_compare(&tp1, &tp2);
		}

		list_new=talloc(NULL, struct list_node);
		DLIST_ADD_AFTER(list_head, list_new, list);
	}
	elapsed=end_timer();
	printf("%f seconds\n",(float)elapsed);

	return 0;
}
