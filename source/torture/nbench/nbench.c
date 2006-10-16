/* 
   Unix SMB/CIFS implementation.
   SMB torture tester - NBENCH test
   Copyright (C) Andrew Tridgell 1997-2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "libcli/libcli.h"
#include "torture/ui.h"
#include "torture/util.h"
#include "torture/torture.h"
#include "system/filesys.h"
#include "pstring.h"

#include "torture/nbench/proto.h"

int nbench_line_count = 0;
static int timelimit = 600;
static int warmup;
static const char *loadfile;

#define ival(s) strtol(s, NULL, 0)

/* run a test that simulates an approximate netbench client load */
static BOOL run_netbench(struct torture_context *tctx, struct smbcli_state *cli, int client)
{
	extern int torture_nprocs;
	int i;
	pstring line;
	char *cname;
	FILE *f;
	const char **params;
	BOOL correct = True;

	if (torture_nprocs == 1) {
		if (!torture_setup_dir(cli, "\\clients")) {
			return False;
		}
	}

	nb_setup(cli, client);

	asprintf(&cname, "client%d", client+1);

	f = fopen(loadfile, "r");

	if (!f) {
		perror(loadfile);
		return False;
	}

again:
	while (fgets(line, sizeof(line)-1, f)) {
		NTSTATUS status;

		nbench_line_count++;

		line[strlen(line)-1] = 0;

		all_string_sub(line,"client1", cname, sizeof(line));
		
		params = str_list_make_shell(NULL, line, " ");
		i = str_list_length(params);

		if (i < 2 || params[0][0] == '#') continue;

		if (!strncmp(params[0],"SMB", 3)) {
			printf("ERROR: You are using a dbench 1 load file\n");
			exit(1);
		}

		if (strncmp(params[i-1], "NT_STATUS_", 10) != 0) {
			printf("Badly formed status at line %d\n", nbench_line_count);
			talloc_free(params);
			continue;
		}

		status = nt_status_string_to_code(params[i-1]);

		DEBUG(9,("run_netbench(%d): %s %s\n", client, params[0], params[1]));

		if (!strcmp(params[0],"NTCreateX")) {
			nb_createx(params[1], ival(params[2]), ival(params[3]), 
				   ival(params[4]), status);
		} else if (!strcmp(params[0],"Close")) {
			nb_close(ival(params[1]), status);
		} else if (!strcmp(params[0],"Rename")) {
			nb_rename(params[1], params[2], status);
		} else if (!strcmp(params[0],"Unlink")) {
			nb_unlink(params[1], ival(params[2]), status);
		} else if (!strcmp(params[0],"Deltree")) {
			nb_deltree(params[1]);
		} else if (!strcmp(params[0],"Rmdir")) {
			nb_rmdir(params[1], status);
		} else if (!strcmp(params[0],"Mkdir")) {
			nb_mkdir(params[1], status);
		} else if (!strcmp(params[0],"QUERY_PATH_INFORMATION")) {
			nb_qpathinfo(params[1], ival(params[2]), status);
		} else if (!strcmp(params[0],"QUERY_FILE_INFORMATION")) {
			nb_qfileinfo(ival(params[1]), ival(params[2]), status);
		} else if (!strcmp(params[0],"QUERY_FS_INFORMATION")) {
			nb_qfsinfo(ival(params[1]), status);
		} else if (!strcmp(params[0],"SET_FILE_INFORMATION")) {
			nb_sfileinfo(ival(params[1]), ival(params[2]), status);
		} else if (!strcmp(params[0],"FIND_FIRST")) {
			nb_findfirst(params[1], ival(params[2]), 
				     ival(params[3]), ival(params[4]), status);
		} else if (!strcmp(params[0],"WriteX")) {
			nb_writex(ival(params[1]), 
				  ival(params[2]), ival(params[3]), ival(params[4]),
				  status);
		} else if (!strcmp(params[0],"Write")) {
			nb_write(ival(params[1]), 
				 ival(params[2]), ival(params[3]), ival(params[4]),
				 status);
		} else if (!strcmp(params[0],"LockX")) {
			nb_lockx(ival(params[1]), 
				 ival(params[2]), ival(params[3]), status);
		} else if (!strcmp(params[0],"UnlockX")) {
			nb_unlockx(ival(params[1]), 
				 ival(params[2]), ival(params[3]), status);
		} else if (!strcmp(params[0],"ReadX")) {
			nb_readx(ival(params[1]), 
				 ival(params[2]), ival(params[3]), ival(params[4]),
				 status);
		} else if (!strcmp(params[0],"Flush")) {
			nb_flush(ival(params[1]), status);
		} else if (!strcmp(params[0],"Sleep")) {
			nb_sleep(ival(params[1]), status);
		} else {
			printf("[%d] Unknown operation %s\n", nbench_line_count, params[0]);
		}

		talloc_free(params);
		
		if (nb_tick()) goto done;
	}

	rewind(f);
	goto again;

done:
	fclose(f);

	if (torture_nprocs == 1) {
		smbcli_deltree(cli->tree, "\\clients");
	}
	if (!torture_close_connection(cli)) {
		correct = False;
	}
	
	return correct;
}


/* run a test that simulates an approximate netbench client load */
BOOL torture_nbench(struct torture_context *torture)
{
	BOOL correct = True;
	extern int torture_nprocs;
	struct smbcli_state *cli;
	const char *p;

	p = lp_parm_string(-1, "torture", "timelimit");
	if (p && *p) {
		timelimit = atoi(p);
	}

	warmup = timelimit / 20;

	loadfile =  lp_parm_string(-1, "torture", "loadfile");
	if (!loadfile || !*loadfile) {
		loadfile = "client.txt";
	}

	if (torture_nprocs > 1) {
		if (!torture_open_connection(&cli, 0)) {
			return False;
		}

		if (!torture_setup_dir(cli, "\\clients")) {
			return False;
		}
	}

	nbio_shmem(torture_nprocs, timelimit, warmup);

	printf("Running for %d seconds with load '%s' and warmup %d secs\n", 
	       timelimit, loadfile, warmup);

	/* we need to reset SIGCHLD here as the name resolution
	   library may have changed it. We rely on correct signals
	   from childs in the main torture code which reaps
	   children. This is why smbtorture BENCH-NBENCH was sometimes
	   failing */
	signal(SIGCHLD, SIG_DFL);


	signal(SIGALRM, nb_alarm);
	alarm(1);
	torture_create_procs(torture, run_netbench, &correct);
	alarm(0);

	if (torture_nprocs > 1) {
		smbcli_deltree(cli->tree, "\\clients");
	}

	printf("\nThroughput %g MB/sec\n", nbio_result());
	return correct;
}

NTSTATUS torture_nbench_init(void)
{
	struct torture_suite *suite = torture_suite_create(
										talloc_autofree_context(),
										"BENCH");

	torture_suite_add_simple_test(suite, "NBENCH", torture_nbench);

	suite->description = talloc_strdup(suite, 
								"Benchmarks");

	torture_register_suite(suite);
	return NT_STATUS_OK;
}
