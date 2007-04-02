/* 
   Unix SMB/CIFS implementation.
   randomised byte range lock tester
   Copyright (C) Andrew Tridgell 1999
   
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
#include "system/filesys.h"
#include "system/time.h"
#include "pstring.h"
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "libcli/libcli.h"

static int numops = 1000;
static BOOL showall;
static BOOL analyze;
static BOOL hide_unlock_fails;
static BOOL use_oplocks;
static uint_t lock_range = 100;
static uint_t lock_base = 0;
static uint_t min_length = 0;
static BOOL exact_error_codes;
static BOOL zero_zero;

#define FILENAME "\\locktest.dat"

#define READ_PCT 50
#define LOCK_PCT 45
#define UNLOCK_PCT 70
#define RANGE_MULTIPLE 1
#define NSERVERS 2
#define NCONNECTIONS 2
#define NFILES 2
#define LOCK_TIMEOUT 0

static struct cli_credentials *servers[NSERVERS];

enum lock_op {OP_LOCK, OP_UNLOCK, OP_REOPEN};

struct record {
	enum lock_op lock_op;
	enum brl_type lock_type;
	char conn, f;
	uint64_t start, len;
	char needed;
	uint16_t pid;
};

#define PRESETS 0

#if PRESETS
static struct record preset[] = {
{OP_LOCK, WRITE_LOCK, 0, 0, 2, 0, 1},
{OP_LOCK, WRITE_LOCK, 0, 0, 0, 0, 1},
{OP_LOCK, WRITE_LOCK, 0, 0, 3, 0, 1},
{OP_UNLOCK, 0       , 0, 0, 2, 0, 1},
{OP_REOPEN, 0, 0, 0, 0, 0, 1},

{OP_LOCK, READ_LOCK, 0, 0, 2, 0, 1},
{OP_LOCK, READ_LOCK, 0, 0, 1, 1, 1},
{OP_LOCK, WRITE_LOCK, 0, 0, 0, 0, 1},
{OP_REOPEN, 0, 0, 0, 0, 0, 1},

{OP_LOCK, READ_LOCK, 0, 0, 2, 0, 1},
{OP_LOCK, WRITE_LOCK, 0, 0, 3, 1, 1},
{OP_LOCK, WRITE_LOCK, 0, 0, 0, 0, 1},
{OP_REOPEN, 0, 0, 0, 0, 0, 1},

{OP_LOCK, READ_LOCK, 0, 0, 2, 0, 1},
{OP_LOCK, WRITE_LOCK, 0, 0, 1, 1, 1},
{OP_LOCK, WRITE_LOCK, 0, 0, 0, 0, 1},
{OP_REOPEN, 0, 0, 0, 0, 0, 1},

{OP_LOCK, WRITE_LOCK, 0, 0, 2, 0, 1},
{OP_LOCK, READ_LOCK, 0, 0, 1, 1, 1},
{OP_LOCK, WRITE_LOCK, 0, 0, 0, 0, 1},
{OP_REOPEN, 0, 0, 0, 0, 0, 1},

{OP_LOCK, WRITE_LOCK, 0, 0, 2, 0, 1},
{OP_LOCK, READ_LOCK, 0, 0, 3, 1, 1},
{OP_LOCK, WRITE_LOCK, 0, 0, 0, 0, 1},
{OP_REOPEN, 0, 0, 0, 0, 0, 1},

};
#endif

static struct record *recorded;

/***************************************************** 
return a connection to a server
*******************************************************/
static struct smbcli_state *connect_one(char *share, int snum, int conn)
{
	struct smbcli_state *c;
	fstring server, myname;
	NTSTATUS status;
	int retries = 10;

	printf("connect_one(%s, %d, %d)\n", share, snum, conn);

	fstrcpy(server,share+2);
	share = strchr_m(server,'\\');
	if (!share) return NULL;
	*share = 0;
	share++;

	if (snum == 0) {
		char **unc_list = NULL;
		int num_unc_names;
		const char *p;
		p = lp_parm_string(-1, "torture", "unclist");
		if (p) {
			char *h, *s;
			unc_list = file_lines_load(p, &num_unc_names, NULL);
			if (!unc_list || num_unc_names <= 0) {
				printf("Failed to load unc names list from '%s'\n", p);
				exit(1);
			}

			if (!smbcli_parse_unc(unc_list[conn % num_unc_names],
					      NULL, &h, &s)) {
				printf("Failed to parse UNC name %s\n",
				       unc_list[conn % num_unc_names]);
				exit(1);
			}
			fstrcpy(server, h);
			fstrcpy(share, s);
		}
	}


	slprintf(myname,sizeof(myname), "lock-%u-%u", getpid(), snum);
	cli_credentials_set_workstation(servers[snum], myname, CRED_SPECIFIED);

	do {
		printf("\\\\%s\\%s\n", server, share);
		status = smbcli_full_connection(NULL, &c, 
						server, 
						share, NULL,
						servers[snum], NULL);
		if (!NT_STATUS_IS_OK(status)) {
			sleep(2);
		}
	} while (!NT_STATUS_IS_OK(status) && retries--);

	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	return c;
}


static void reconnect(struct smbcli_state *cli[NSERVERS][NCONNECTIONS], int fnum[NSERVERS][NCONNECTIONS][NFILES],
		      char *share[NSERVERS])
{
	int server, conn, f;

	for (server=0;server<NSERVERS;server++)
	for (conn=0;conn<NCONNECTIONS;conn++) {
		if (cli[server][conn]) {
			for (f=0;f<NFILES;f++) {
				if (fnum[server][conn][f] != -1) {
					smbcli_close(cli[server][conn]->tree, fnum[server][conn][f]);
					fnum[server][conn][f] = -1;
				}
			}
			talloc_free(cli[server][conn]);
		}
		cli[server][conn] = connect_one(share[server], server, conn);
		if (!cli[server][conn]) {
			DEBUG(0,("Failed to connect to %s\n", share[server]));
			exit(1);
		}
	}
}



static BOOL test_one(struct smbcli_state *cli[NSERVERS][NCONNECTIONS], 
		     int fnum[NSERVERS][NCONNECTIONS][NFILES],
		     struct record *rec)
{
	uint_t conn = rec->conn;
	uint_t f = rec->f;
	uint64_t start = rec->start;
	uint64_t len = rec->len;
	enum brl_type op = rec->lock_type;
	int server;
	BOOL ret[NSERVERS];
	NTSTATUS status[NSERVERS];

	switch (rec->lock_op) {
	case OP_LOCK:
		/* set a lock */
		for (server=0;server<NSERVERS;server++) {
			NTSTATUS res;
			struct smbcli_tree *tree=cli[server][conn]->tree;
			int fn=fnum[server][conn][f];

			if (!(tree->session->transport->negotiate.capabilities & CAP_LARGE_FILES)) {
				res=smbcli_lock(tree, fn, start, len, LOCK_TIMEOUT, rec->lock_op);
			} else {
				union smb_lock parms;
				int ltype;
				struct smb_lock_entry lock[1];

				parms.lockx.level = RAW_LOCK_LOCKX;
				parms.lockx.in.file.fnum = fn;
	
				ltype = (rec->lock_op == READ_LOCK? 1 : 0);
				ltype |= LOCKING_ANDX_LARGE_FILES;
				parms.lockx.in.mode = ltype;
				parms.lockx.in.timeout = LOCK_TIMEOUT;
				parms.lockx.in.ulock_cnt = 0;
				parms.lockx.in.lock_cnt = 1;
				lock[0].pid = rec->pid;
				lock[0].offset = start;
				lock[0].count = len;
				parms.lockx.in.locks = &lock[0];

				res = smb_raw_lock(tree, &parms);
			}

			ret[server] = NT_STATUS_IS_OK(res); 
			status[server] = smbcli_nt_error(cli[server][conn]->tree);
			if (!exact_error_codes && 
			    NT_STATUS_EQUAL(status[server], 
					    NT_STATUS_FILE_LOCK_CONFLICT)) {
				status[server] = NT_STATUS_LOCK_NOT_GRANTED;
			}
		}
		if (showall || !NT_STATUS_EQUAL(status[0],status[1])) {
			printf("lock   conn=%u f=%u range=%.0f(%.0f) op=%s -> %s:%s\n",
			       conn, f, 
			       (double)start, (double)len,
			       op==READ_LOCK?"READ_LOCK":"WRITE_LOCK",
			       nt_errstr(status[0]), nt_errstr(status[1]));
		}
		if (!NT_STATUS_EQUAL(status[0],status[1])) return False;
		break;
		
	case OP_UNLOCK:
		/* unset a lock */
		for (server=0;server<NSERVERS;server++) {
			NTSTATUS res;
			struct smbcli_tree *tree=cli[server][conn]->tree;
			int fn=fnum[server][conn][f];


			if (!(tree->session->transport->negotiate.capabilities & CAP_LARGE_FILES)) {
				res=smbcli_unlock(tree, fn, start, len);
			} else {
				union smb_lock parms;
				struct smb_lock_entry lock[1];

				parms.lockx.level = RAW_LOCK_LOCKX;
				parms.lockx.in.file.fnum = fn;
				parms.lockx.in.mode = LOCKING_ANDX_LARGE_FILES;
				parms.lockx.in.timeout = 0;
				parms.lockx.in.ulock_cnt = 1;
				parms.lockx.in.lock_cnt = 0;
				lock[0].pid = rec->pid;
				lock[0].count = len;
				lock[0].offset = start;
				parms.lockx.in.locks = &lock[0];

				res = smb_raw_lock(tree, &parms);
			}

			ret[server] = NT_STATUS_IS_OK(res);
			status[server] = smbcli_nt_error(cli[server][conn]->tree);
		}
		if (showall || 
		    (!hide_unlock_fails && !NT_STATUS_EQUAL(status[0],status[1]))) {
			printf("unlock conn=%u f=%u range=%.0f(%.0f)       -> %s:%s\n",
			       conn, f, 
			       (double)start, (double)len,
			       nt_errstr(status[0]), nt_errstr(status[1]));
		}
		if (!hide_unlock_fails && !NT_STATUS_EQUAL(status[0],status[1])) 
			return False;
		break;

	case OP_REOPEN:
		/* reopen the file */
		for (server=0;server<NSERVERS;server++) {
			smbcli_close(cli[server][conn]->tree, fnum[server][conn][f]);
			fnum[server][conn][f] = -1;
		}
		for (server=0;server<NSERVERS;server++) {
			fnum[server][conn][f] = smbcli_open(cli[server][conn]->tree, FILENAME,
							 O_RDWR|O_CREAT,
							 DENY_NONE);
			if (fnum[server][conn][f] == -1) {
				printf("failed to reopen on share%d\n", server);
				return False;
			}
		}
		if (showall) {
			printf("reopen conn=%u f=%u\n",
			       conn, f);
		}
		break;
	}

	return True;
}

static void close_files(struct smbcli_state *cli[NSERVERS][NCONNECTIONS], 
			int fnum[NSERVERS][NCONNECTIONS][NFILES])
{
	int server, conn, f; 

	for (server=0;server<NSERVERS;server++)
	for (conn=0;conn<NCONNECTIONS;conn++)
	for (f=0;f<NFILES;f++) {
		if (fnum[server][conn][f] != -1) {
			smbcli_close(cli[server][conn]->tree, fnum[server][conn][f]);
			fnum[server][conn][f] = -1;
		}
	}
	for (server=0;server<NSERVERS;server++) {
		smbcli_unlink(cli[server][0]->tree, FILENAME);
	}
}

static void open_files(struct smbcli_state *cli[NSERVERS][NCONNECTIONS], 
		       int fnum[NSERVERS][NCONNECTIONS][NFILES])
{
	int server, conn, f; 

	for (server=0;server<NSERVERS;server++)
	for (conn=0;conn<NCONNECTIONS;conn++)
	for (f=0;f<NFILES;f++) {
		fnum[server][conn][f] = smbcli_open(cli[server][conn]->tree, FILENAME,
						 O_RDWR|O_CREAT,
						 DENY_NONE);
		if (fnum[server][conn][f] == -1) {
			fprintf(stderr,"Failed to open fnum[%u][%u][%u]\n",
				server, conn, f);
			exit(1);
		}
	}
}


static int retest(struct smbcli_state *cli[NSERVERS][NCONNECTIONS], 
		   int fnum[NSERVERS][NCONNECTIONS][NFILES],
		   int n)
{
	int i;
	printf("testing %u ...\n", n);
	for (i=0; i<n; i++) {
		if (i && i % 100 == 0) {
			printf("%u\n", i);
		}

		if (recorded[i].needed &&
		    !test_one(cli, fnum, &recorded[i])) return i;
	}
	return n;
}


/* each server has two connections open to it. Each connection has two file
   descriptors open on the file - 8 file descriptors in total 

   we then do random locking ops in tamdem on the 4 fnums from each
   server and ensure that the results match
 */
static void test_locks(char *share[NSERVERS])
{
	struct smbcli_state *cli[NSERVERS][NCONNECTIONS];
	int fnum[NSERVERS][NCONNECTIONS][NFILES];
	int n, i, n1, skip, r1, r2; 

	ZERO_STRUCT(fnum);
	ZERO_STRUCT(cli);

	recorded = malloc_array_p(struct record, numops);

	for (n=0; n<numops; n++) {
#if PRESETS
		if (n < sizeof(preset) / sizeof(preset[0])) {
			recorded[n] = preset[n];
		} else {
#endif
			recorded[n].conn = random() % NCONNECTIONS;
			recorded[n].f = random() % NFILES;
			recorded[n].start = lock_base + ((uint_t)random() % (lock_range-1));
			recorded[n].len =  min_length +
				random() % (lock_range-(recorded[n].start-lock_base));
			recorded[n].start *= RANGE_MULTIPLE;
			recorded[n].len *= RANGE_MULTIPLE;
			recorded[n].pid = random()%3;
			if (recorded[n].pid == 2) {
				recorded[n].pid = 0xFFFF; /* see if its magic */
			}
			r1 = random() % 100;
			r2 = random() % 100;
			if (r1 < READ_PCT) {
				recorded[n].lock_type = READ_LOCK;
			} else {
				recorded[n].lock_type = WRITE_LOCK;
			}
			if (r2 < LOCK_PCT) {
				recorded[n].lock_op = OP_LOCK;
			} else if (r2 < UNLOCK_PCT) {
				recorded[n].lock_op = OP_UNLOCK;
			} else {
				recorded[n].lock_op = OP_REOPEN;
			}
			recorded[n].needed = True;
			if (!zero_zero && recorded[n].start==0 && recorded[n].len==0) {
				recorded[n].len = 1;
			}
#if PRESETS
		}
#endif
	}

	reconnect(cli, fnum, share);
	open_files(cli, fnum);
	n = retest(cli, fnum, numops);

	if (n == numops || !analyze) return;
	n++;

	skip = n/2;

	while (1) {
		n1 = n;

		close_files(cli, fnum);
		reconnect(cli, fnum, share);
		open_files(cli, fnum);

		for (i=0;i<n-skip;i+=skip) {
			int m, j;
			printf("excluding %d-%d\n", i, i+skip-1);
			for (j=i;j<i+skip;j++) {
				recorded[j].needed = False;
			}

			close_files(cli, fnum);
			open_files(cli, fnum);

			m = retest(cli, fnum, n);
			if (m == n) {
				for (j=i;j<i+skip;j++) {
					recorded[j].needed = True;
				}
			} else {
				if (i+(skip-1) < m) {
					memmove(&recorded[i], &recorded[i+skip],
						(m-(i+skip-1))*sizeof(recorded[0]));
				}
				n = m-(skip-1);
				i--;
			}
		}

		if (skip > 1) {
			skip = skip/2;
			printf("skip=%d\n", skip);
			continue;
		}

		if (n1 == n) break;
	}

	close_files(cli, fnum);
	reconnect(cli, fnum, share);
	open_files(cli, fnum);
	showall = True;
	n1 = retest(cli, fnum, n);
	if (n1 != n-1) {
		printf("ERROR - inconsistent result (%u %u)\n", n1, n);
	}
	close_files(cli, fnum);

	for (i=0;i<n;i++) {
		printf("{%d, %d, %u, %u, %.0f, %.0f, %u},\n",
		       recorded[i].lock_op,
		       recorded[i].lock_type,
		       recorded[i].conn,
		       recorded[i].f,
		       (double)recorded[i].start,
		       (double)recorded[i].len,
		       recorded[i].needed);
	}	
}



static void usage(void)
{
	printf(
"Usage:\n\
  locktest //server1/share1 //server2/share2 [options..]\n\
  options:\n\
        -U user%%pass        (may be specified twice)\n\
        -s seed\n\
        -o numops\n\
        -u          hide unlock fails\n\
        -a          (show all ops)\n\
        -A          analyse for minimal ops\n\
        -O          use oplocks\n\
        -E          enable exact error code checking\n\
        -Z          enable the zero/zero lock\n\
        -R range    set lock range\n\
        -B base     set lock base\n\
        -M min      set min lock length\n\
        -l filename unclist file\n\
");
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	char *share[NSERVERS];
	int opt;
	int seed, server;
	int username_count=0;

	setlinebuf(stdout);

	setup_logging("locktest", DEBUG_STDOUT);

	if (argc < 3 || argv[1][0] == '-') {
		usage();
		exit(1);
	}

	setup_logging(argv[0], DEBUG_STDOUT);

	for (server=0;server<NSERVERS;server++) {
		share[server] = argv[1+server];
		all_string_sub(share[server],"/","\\",0);
	}

	argc -= NSERVERS;
	argv += NSERVERS;

	lp_load();

	servers[0] = cli_credentials_init(talloc_autofree_context());
	servers[1] = cli_credentials_init(talloc_autofree_context());
	cli_credentials_guess(servers[0]);
	cli_credentials_guess(servers[1]);

	seed = time(NULL);

	while ((opt = getopt(argc, argv, "U:s:ho:aAW:OR:B:M:EZW:l:")) != EOF) {
		switch (opt) {
		case 'U':
			if (username_count == 2) {
				usage();
				exit(1);
			}
			cli_credentials_parse_string(servers[username_count], 
						     optarg, CRED_SPECIFIED);
			username_count++;
			break;
		case 'R':
			lock_range = strtol(optarg, NULL, 0);
			break;
		case 'B':
			lock_base = strtol(optarg, NULL, 0);
			break;
		case 'M':
			min_length = strtol(optarg, NULL, 0);
			break;
		case 's':
			seed = atoi(optarg);
			break;
		case 'u':
			hide_unlock_fails = True;
			break;
		case 'o':
			numops = atoi(optarg);
			break;
		case 'O':
			use_oplocks = True;
			break;
		case 'a':
			showall = True;
			break;
		case 'A':
			analyze = True;
			break;
		case 'Z':
			zero_zero = True;
			break;
		case 'E':
			exact_error_codes = True;
			break;
		case 'l':
			lp_set_cmdline("torture:unclist", optarg);
			break;
		case 'W':
			lp_set_cmdline("workgroup", optarg);
			break;
		case 'h':
			usage();
			exit(1);
		default:
			printf("Unknown option %c (%d)\n", (char)opt, opt);
			exit(1);
		}
	}

	if (username_count == 0) {
		usage();
		return -1;
	}
	if (username_count == 1) {
		servers[1] = servers[0];
	}

	gensec_init();

	argc -= optind;
	argv += optind;

	DEBUG(0,("seed=%u base=%d range=%d min_length=%d\n", 
		 seed, lock_base, lock_range, min_length));
	srandom(seed);

	test_locks(share);

	return(0);
}

