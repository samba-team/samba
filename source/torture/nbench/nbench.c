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

int nbench_line_count = 0;
static int timelimit = 600;
static int warmup;
static const char *loadfile;

#define ival(s) strtol(s, NULL, 0)

/* run a test that simulates an approximate netbench client load */
static BOOL run_netbench(struct smbcli_state *cli, int client)
{
	int i;
	pstring line;
	char *cname;
	FILE *f;
	fstring params[20];
	const char *p;
	BOOL correct = True;

	nb_setup(cli, client, warmup);

	asprintf(&cname, "client%d", client+1);

	f = fopen(loadfile, "r");

	if (!f) {
		perror(loadfile);
		return False;
	}

again:
	while (fgets(line, sizeof(line)-1, f)) {
		NTSTATUS status;
		double t = end_timer();

		if (warmup && t >= warmup) {
			warmup = 0;
			nb_warmup_done();
			start_timer();
		}

		if (end_timer() >= timelimit) {
			goto done;
		}

		nbench_line_count++;

		line[strlen(line)-1] = 0;

		all_string_sub(line,"client1", cname, sizeof(line));
		
		p = line;
		for (i=0; 
		     i<19 && next_token(&p, params[i], " ", sizeof(fstring));
		     i++) ;

		params[i][0] = 0;

		if (i < 2 || params[0][0] == '#') continue;

		if (!strncmp(params[0],"SMB", 3)) {
			printf("ERROR: You are using a dbench 1 load file\n");
			exit(1);
		}

		if (strncmp(params[i-1], "NT_STATUS_", 10) != 0) {
			printf("Badly formed status at line %d\n", nbench_line_count);
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
		} else {
			printf("[%d] Unknown operation %s\n", nbench_line_count, params[0]);
		}
	}

	rewind(f);
	goto again;

done:
	fclose(f);
	nb_cleanup(cname);

	if (!torture_close_connection(cli)) {
		correct = False;
	}
	
	return correct;
}


/* run a test that simulates an approximate netbench client load */
BOOL torture_nbench(int dummy)
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

	if (!torture_open_connection(&cli)) {
		return False;
	}

	nb_setup(cli, -1, warmup);
	nb_deltree("\\clients");

	nbio_shmem(torture_nprocs);

	printf("Running for %d seconds with load '%s' and warmup %d secs\n", 
	       timelimit, loadfile, warmup);

	signal(SIGALRM, SIGNAL_CAST nb_alarm);
	alarm(1);
	torture_create_procs(run_netbench, &correct);
	alarm(0);

	printf("\nThroughput %g MB/sec\n", 
	       1.0e-6 * nbio_total() / timelimit);
	return correct;
}
