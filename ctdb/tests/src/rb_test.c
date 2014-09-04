/* 
   simple rb test tool

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

int num_records=5;

static void *callback(void *p, void *d)
{
	uint32_t *data = (uint32_t *)d;

	if (d==NULL) {
		data = (uint32_t *)p;
	}

	(*data)++;

	return data;
}

static void *random_add(void *p, void *d)
{
	return p;
}

static int traverse(void *p, void *d)
{
	uint32_t *data = (uint32_t *)d;

	printf("traverse data:%d\n",*data);
	return 0;
}

static int random_traverse(void *p, void *d)
{
	printf("%s   ",(char *)d);
	return 0;
}

static uint32_t calc_checksum = 0;	
static int traverse_checksum(void *p, void *d)
{
	int i,j,k;

	sscanf(d, "%d.%d.%d", &i, &j, &k);
	calc_checksum += i*100+j*10+k;
	return 0;
}

static int count_traverse(void *p, void *d)
{
	int *count = p;
	(*count)++;
	return 0;
}

static int count_traverse_abort(void *p, void *d)
{
	int *count = p;
	(*count)++;
	return -1;
}

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
	int opt, traverse_count;
	const char **extra_argv;
	int extra_argc = 0;
	poptContext pc;
	int i,j,k;
	trbt_tree_t *tree;
	uint32_t *data;
	uint32_t key[3];
	uint32_t key1[3] = {0,10,20};
	uint32_t key2[3] = {0,10,21};
	uint32_t key3[3] = {0,11,20};
	uint32_t key4[3] = {2,10,20};
	TALLOC_CTX *memctx;
	uint32_t **u32array;
	uint32_t checksum;

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

	printf("testing trbt_insert32_callback for %d records\n", num_records);
	memctx   = talloc_new(NULL);
	u32array = talloc_array(memctx, uint32_t *, num_records);
	tree = trbt_create(memctx, 0);
	for (i=0; i<num_records; i++) {
		u32array[i]  = talloc(u32array, uint32_t);
		*u32array[i] = 0;
		trbt_insert32_callback(tree, i, callback, u32array[i]);
	}
	for (i=3; i<num_records; i++) {
		trbt_insert32_callback(tree, i, callback, NULL);
	}

	printf("first 3 keys should have data==1\n");
	printf("the rest of the keys should have data==2\n");
	for (i=0; i<num_records; i++) {
		data = trbt_lookup32(tree, i);
		printf("key:%d data:%d\n", i, *data);
	}
//	talloc_report_full(tree, stdout);
//	talloc_report_full(memctx, stdout);
//	print_tree(tree);

	printf("deleting key 2\n");
	talloc_free(u32array[2]);
//	talloc_report_full(tree, stdout);
//	talloc_report_full(memctx, stdout);
//	print_tree(tree);

	printf("deleting key 1\n");
	talloc_free(u32array[1]);
//	talloc_report_full(tree, stdout);
//	talloc_report_full(memctx, stdout);
//	print_tree(tree);

	printf("freeing tree\n");
	talloc_report_full(memctx, stdout);
	talloc_free(memctx);


	printf("testing trbt_insertarray32_callback\n");
	memctx   = talloc_new(NULL);
	tree = trbt_create(memctx, 0);
	u32array = talloc_array(memctx, uint32_t *, 4);
	for (i=0;i<4;i++) {
		u32array[i]  = talloc(u32array, uint32_t);
		*u32array[i] = 0;
	}
	trbt_insertarray32_callback(tree, 3, key1, callback, u32array[0]);
	trbt_insertarray32_callback(tree, 3, key1, callback, u32array[0]);
	trbt_insertarray32_callback(tree, 3, key2, callback, u32array[1]);
	trbt_insertarray32_callback(tree, 3, key3, callback, u32array[2]);
	trbt_insertarray32_callback(tree, 3, key2, callback, u32array[1]);
	trbt_insertarray32_callback(tree, 3, key1, callback, u32array[0]);

	data = trbt_lookuparray32(tree, 3, key1);
	printf("key1 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key2);
	printf("key2 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key3);
	printf("key3 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key4);
	printf("key4 dataptr:%p == %d\n",data,data?*data:-1);
	trbt_traversearray32(tree, 3, traverse, NULL);

	printf("\ndeleting key4\n");
	talloc_free(trbt_lookuparray32(tree, 3, key4));
	data = trbt_lookuparray32(tree, 3, key1);
	printf("key1 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key2);
	printf("key2 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key3);
	printf("key3 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key4);
	printf("key4 dataptr:%p == %d\n",data,data?*data:-1);
	trbt_traversearray32(tree, 3, traverse, NULL);

	printf("\ndeleting key2\n");
	talloc_free(trbt_lookuparray32(tree, 3, key2));
	data = trbt_lookuparray32(tree, 3, key1);
	printf("key1 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key2);
	printf("key2 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key3);
	printf("key3 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key4);
	printf("key4 dataptr:%p == %d\n",data,data?*data:-1);
	trbt_traversearray32(tree, 3, traverse, NULL);
	
	printf("\ndeleting key3\n");
	talloc_free(trbt_lookuparray32(tree, 3, key3));
	data = trbt_lookuparray32(tree, 3, key1);
	printf("key1 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key2);
	printf("key2 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key3);
	printf("key3 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key4);
	printf("key4 dataptr:%p == %d\n",data,data?*data:-1);
	trbt_traversearray32(tree, 3, traverse, NULL);
	
	printf("\ndeleting key1\n");
	talloc_free(trbt_lookuparray32(tree, 3, key1));
	data = trbt_lookuparray32(tree, 3, key1);
	printf("key1 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key2);
	printf("key2 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key3);
	printf("key3 dataptr:%p == %d\n",data,data?*data:-1);
	data = trbt_lookuparray32(tree, 3, key4);
	printf("key4 dataptr:%p == %d\n",data,data?*data:-1);
	trbt_traversearray32(tree, 3, traverse, NULL);

	talloc_free(tree);
	talloc_free(memctx);
	

	printf("\nrun random insert and delete for 60 seconds\n");
	memctx   = talloc_new(NULL);
	tree = trbt_create(memctx, 0);
	i=0;
	start_timer();
	checksum = 0;
	/* add and delete nodes from a 3 level tree fro 60 seconds.
	   each time a node is added or deleted, traverse the tree and
	   compute a checksum over the data stored in the tree and compare this
	   with a checksum we keep which contains what the checksum should be
	 */
	while(end_timer() < 60.0){
		char *str;

		i++;
		key[0]=random()%10;
		key[1]=random()%10;
		key[2]=random()%10;
		if (random()%2) {
			if (trbt_lookuparray32(tree, 3, key) == NULL) {
				/* this node does not yet exist, add it to the
				   tree and update the checksum
				 */
				str=talloc_asprintf(memctx, "%d.%d.%d", key[0],key[1],key[2]);
				trbt_insertarray32_callback(tree, 3, key, random_add, str);
				checksum += key[0]*100+key[1]*10+key[2];
			}
		} else {
			if ((str=trbt_lookuparray32(tree, 3, key)) != NULL) {
				/* this node does exist in  the tree, delete 
				   it and update the checksum accordingly
				 */
				talloc_free(str);
				checksum -= key[0]*100+key[1]*10+key[2];
			}
		}
		/* traverse all nodes in the tree and calculate the checksum
		   it better match the one we keep track of in
		   'checksum'
		*/
		calc_checksum = 0;
		trbt_traversearray32(tree, 3, traverse_checksum, NULL);
		if(checksum != calc_checksum) {
			printf("Wrong checksum  %d!=%d\n",checksum, calc_checksum);
			exit(10);
		}

		if(i%1000==999)printf(".");fflush(stdout);
	}
	printf("\niterations passed:%d\n", i);
	trbt_traversearray32(tree, 3, random_traverse, NULL);
	printf("\n");
	printf("first node: %s\n", (char *)trbt_findfirstarray32(tree, 3));

	traverse_count = 0;
	trbt_traversearray32(tree, 3, count_traverse, &traverse_count);
	printf("\n");
	printf("number of entries in traverse %d\n", traverse_count);

	traverse_count = 0;
	trbt_traversearray32(tree, 3, count_traverse_abort, &traverse_count);
	printf("\n");
	printf("number of entries in aborted traverse %d\n", traverse_count);
	if (traverse_count != 1) {
		printf("Failed to abort the traverse. Should have been aborted after 1 element but did iterate over %d elements\n", traverse_count);
		exit(10);
	}
	printf("\ndeleting all entries\n");
	for(i=0;i<10;i++){
	for(j=0;j<10;j++){
	for(k=0;k<10;k++){
		key[0]=i;
		key[1]=j;
		key[2]=k;
		talloc_free(trbt_lookuparray32(tree, 3, key));
	}
	}
	}
	trbt_traversearray32(tree, 3, random_traverse, NULL);
	printf("\n");
	talloc_report_full(tree, stdout);

	return 0;
}
