/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   mask_match tester
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

#define NO_SYSLOG

#include "includes.h"

static fstring password;
static fstring username;
static fstring workgroup;
static int got_pass;
static int numops = 1000;
static BOOL showall;
static BOOL analyze;

#define FILENAME "locktest.dat"
#define LOCKRANGE 100
#define LOCKBASE 0

/*
#define LOCKBASE (0x40000000 - 50)
*/

#define READ_PCT 50
#define LOCK_PCT 25
#define UNLOCK_PCT 65
#define RANGE_MULTIPLE 1
#define NCONNECTIONS 2
#define NFILES 2
#define LOCK_TIMEOUT 0

#define NASTY_POSIX_LOCK_HACK 1


struct record {
	char r1, r2;
	char conn, f;
	unsigned start, len;
	char needed;
};

static struct record preset[] = {
{36,  5, 0, 0, 0,  8, 1},
{ 2,  6, 0, 1, 0,  1, 1},
{53, 92, 0, 0, 0,  0, 1},
{99, 11, 0, 0, 7,  1, 1},
};

static struct record *recorded;

static void print_brl(SMB_DEV_T dev, SMB_INO_T ino, int pid, 
		      enum brl_type lock_type,
		      br_off start, br_off size)
{
#if NASTY_POSIX_LOCK_HACK
	{
		pstring cmd;
		static SMB_INO_T lastino;

		if (lastino != ino) {
			slprintf(cmd, sizeof(cmd), 
				 "egrep POSIX.*%u /proc/locks", (int)ino);
			system(cmd);
		}
		lastino = ino;
	}
#endif

	printf("%6d   %05x:%05x    %s  %.0f:%.0f(%.0f)\n", 
	       (int)pid, (int)dev, (int)ino, 
	       lock_type==READ_LOCK?"R":"W",
	       (double)start, (double)start+size-1,(double)size);

}

/***************************************************** 
return a connection to a server
*******************************************************/
struct cli_state *connect_one(char *share)
{
	struct cli_state *c;
	struct nmb_name called, calling;
	char *server_n;
	fstring server;
	struct in_addr ip;
	extern struct in_addr ipzero;
	fstring myname;
	static int count;

	fstrcpy(server,share+2);
	share = strchr(server,'\\');
	if (!share) return NULL;
	*share = 0;
	share++;

	server_n = server;
	
	ip = ipzero;

	slprintf(myname,sizeof(myname), "lock-%u-%u", getpid(), count++);

	make_nmb_name(&calling, myname, 0x0);
	make_nmb_name(&called , server, 0x20);

 again:
	ip = ipzero;

	/* have to open a new connection */
	if (!(c=cli_initialise(NULL)) || (cli_set_port(c, 139) == 0) ||
	    !cli_connect(c, server_n, &ip)) {
		DEBUG(0,("Connection to %s failed\n", server_n));
		return NULL;
	}

	if (!cli_session_request(c, &calling, &called)) {
		DEBUG(0,("session request to %s failed\n", called.name));
		cli_shutdown(c);
		if (strcmp(called.name, "*SMBSERVER")) {
			make_nmb_name(&called , "*SMBSERVER", 0x20);
			goto again;
		}
		return NULL;
	}

	DEBUG(4,(" session request ok\n"));

	if (!cli_negprot(c)) {
		DEBUG(0,("protocol negotiation failed\n"));
		cli_shutdown(c);
		return NULL;
	}

	if (!got_pass) {
		char *pass = getpass("Password: ");
		if (pass) {
			pstrcpy(password, pass);
		}
	}

	if (!cli_session_setup(c, username, 
			       password, strlen(password),
			       password, strlen(password),
			       workgroup)) {
		DEBUG(0,("session setup failed: %s\n", cli_errstr(c)));
		return NULL;
	}

	/*
	 * These next two lines are needed to emulate
	 * old client behaviour for people who have
	 * scripts based on client output.
	 * QUESTION ? Do we want to have a 'client compatibility
	 * mode to turn these on/off ? JRA.
	 */

	if (*c->server_domain || *c->server_os || *c->server_type)
		DEBUG(1,("Domain=[%s] OS=[%s] Server=[%s]\n",
			c->server_domain,c->server_os,c->server_type));
	
	DEBUG(4,(" session setup ok\n"));

	if (!cli_send_tconX(c, share, "?????",
			    password, strlen(password)+1)) {
		DEBUG(0,("tree connect failed: %s\n", cli_errstr(c)));
		cli_shutdown(c);
		return NULL;
	}

	DEBUG(4,(" tconx ok\n"));

	return c;
}


static void reconnect(struct cli_state *cli[2][2], int fnum[2][2][2],
		      char *share1, char *share2)
{
	int server, conn, f;
	char *share[2];
	share[0] = share1;
	share[1] = share2;

	for (server=0;server<2;server++)
	for (conn=0;conn<NCONNECTIONS;conn++) {
		if (cli[server][conn]) {
			for (f=0;f<NFILES;f++) {
				cli_close(cli[server][conn], fnum[server][conn][f]);
			}
			cli_ulogoff(cli[server][conn]);
			cli_shutdown(cli[server][conn]);
			free(cli[server][conn]);
			cli[server][conn] = NULL;
		}
		cli[server][conn] = connect_one(share[server]);
		if (!cli[server][conn]) {
			DEBUG(0,("Failed to connect to %s\n", share[server]));
			exit(1);
		}
	}
}



static BOOL test_one(struct cli_state *cli[2][2], 
		     int fnum[2][2][2],
		     struct record *rec)
{
	unsigned conn = rec->conn;
	unsigned f = rec->f;
	unsigned start = rec->start;
	unsigned len = rec->len;
	unsigned r1 = rec->r1;
	unsigned r2 = rec->r2;
	unsigned op;
	BOOL ret1, ret2;

	if (r1 < READ_PCT) {
		op = READ_LOCK; 
	} else {
		op = WRITE_LOCK; 
	}

	if (r2 < LOCK_PCT) {
		/* set a lock */
		ret1 = cli_lock(cli[0][conn], 
				fnum[0][conn][f],
				start, len, LOCK_TIMEOUT, op);
		ret2 = cli_lock(cli[1][conn], 
				fnum[1][conn][f],
				start, len, LOCK_TIMEOUT, op);
		if (showall || ret1 != ret2) {
			printf("lock   conn=%u f=%u range=%u:%u(%u) op=%s -> %u:%u\n",
			       conn, f, 
			       start, start+len-1, len,
			       op==READ_LOCK?"READ_LOCK":"WRITE_LOCK",
			       ret1, ret2);
		}
		if (showall) brl_forall(print_brl);
		if (ret1 != ret2) return False;
	} else if (r2 < LOCK_PCT+UNLOCK_PCT) {
		/* unset a lock */
		ret1 = cli_unlock(cli[0][conn], 
				  fnum[0][conn][f],
				  start, len);
		ret2 = cli_unlock(cli[1][conn], 
				  fnum[1][conn][f],
				  start, len);
		if (showall || ret1 != ret2) {
			printf("unlock conn=%u f=%u range=%u:%u(%u)       -> %u:%u\n",
			       conn, f, 
			       start, start+len-1, len,
			       ret1, ret2);
		}
		if (showall) brl_forall(print_brl);
		if (ret1 != ret2) return False;
	} else {
		/* reopen the file */
		cli_close(cli[0][conn], fnum[0][conn][f]);
		cli_close(cli[1][conn], fnum[1][conn][f]);
		fnum[0][conn][f] = cli_open(cli[0][conn], FILENAME,
					    O_RDWR|O_CREAT,
					    DENY_NONE);
		fnum[1][conn][f] = cli_open(cli[1][conn], FILENAME,
					    O_RDWR|O_CREAT,
					    DENY_NONE);
		if (fnum[0][conn][f] == -1) {
			printf("failed to reopen on share1\n");
			return False;
		}
		if (fnum[1][conn][f] == -1) {
			printf("failed to reopen on share2\n");
			return False;
		}
		if (showall) {
			printf("reopen conn=%u f=%u\n",
			       conn, f);
			brl_forall(print_brl);
		}
	}
	return True;
}

static void close_files(struct cli_state *cli[2][2], 
			int fnum[2][2][2])
{
	int server, conn, f; 

	for (server=0;server<2;server++)
	for (conn=0;conn<NCONNECTIONS;conn++)
	for (f=0;f<NFILES;f++) {
		if (fnum[server][conn][f] != -1) {
			cli_close(cli[server][conn], fnum[server][conn][f]);
			fnum[server][conn][f] = -1;
		}
	}
	cli_unlink(cli[0][0], FILENAME);
	cli_unlink(cli[1][0], FILENAME);
}

static void open_files(struct cli_state *cli[2][2], 
		       int fnum[2][2][2])
{
	int server, conn, f; 

	for (server=0;server<2;server++)
	for (conn=0;conn<NCONNECTIONS;conn++)
	for (f=0;f<NFILES;f++) {
		fnum[server][conn][f] = cli_open(cli[server][conn], FILENAME,
						 O_RDWR|O_CREAT,
						 DENY_NONE);
		if (fnum[server][conn][f] == -1) {
			fprintf(stderr,"Failed to open fnum[%u][%u][%u]\n",
				server, conn, f);
			exit(1);
		}
	}
}


static int retest(struct cli_state *cli[2][2], 
		   int fnum[2][2][2],
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
static void test_locks(char *share1, char *share2)
{
	struct cli_state *cli[2][2];
	int fnum[2][2][2];
	int n, i, n1; 

	ZERO_STRUCT(fnum);
	ZERO_STRUCT(cli);

	recorded = (struct record *)malloc(sizeof(*recorded) * numops);

	for (n=0; n<numops; n++) {
		if (n < sizeof(preset) / sizeof(preset[0])) {
			recorded[n] = preset[n];
		} else {
			recorded[n].conn = random() % NCONNECTIONS;
			recorded[n].f = random() % NFILES;
			recorded[n].start = LOCKBASE + ((unsigned)random() % (LOCKRANGE-1));
			recorded[n].len = 1 + 
				random() % (LOCKRANGE-(recorded[n].start-LOCKBASE));
			recorded[n].start *= RANGE_MULTIPLE;
			recorded[n].len *= RANGE_MULTIPLE;
			recorded[n].r1 = random() % 100;
			recorded[n].r2 = random() % 100;
			recorded[n].needed = True;
		}
	}

	reconnect(cli, fnum, share1, share2);
	open_files(cli, fnum);
	n = retest(cli, fnum, numops);

	if (n == numops || !analyze) return;
	n++;

	while (1) {
		n1 = n;

		close_files(cli, fnum);
		reconnect(cli, fnum, share1, share2);
		open_files(cli, fnum);

		for (i=0;i<n-1;i++) {
			int m;
			recorded[i].needed = False;

			close_files(cli, fnum);
			open_files(cli, fnum);

			m = retest(cli, fnum, n);
			if (m == n) {
				recorded[i].needed = True;
			} else {
				if (i < m) {
					memmove(&recorded[i], &recorded[i+1],
						(m-i)*sizeof(recorded[0]));
				}
				n = m;
				i--;
			}
		}

		if (n1 == n) break;
	}

	close_files(cli, fnum);
	reconnect(cli, fnum, share1, share2);
	open_files(cli, fnum);
	showall = True;
	n1 = retest(cli, fnum, n);
	if (n1 != n-1) {
		printf("ERROR - inconsistent result (%u %u)\n", n1, n);
	}
	close_files(cli, fnum);

	for (i=0;i<n;i++) {
		printf("{%u, %u, %u, %u, %u, %u, %u},\n",
		       recorded[i].r1,
		       recorded[i].r2,
		       recorded[i].conn,
		       recorded[i].f,
		       recorded[i].start,
		       recorded[i].len,
		       recorded[i].needed);
	}	
}



static void usage(void)
{
	printf(
"Usage:\n\
  locktest //server1/share1 //server2/share2 [options..]\n\
  options:\n\
        -U user%%pass\n\
        -s seed\n\
        -o numops\n\
        -a          (show all ops)\n\
");
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	char *share1, *share2;
	extern char *optarg;
	extern int optind;
	extern FILE *dbf;
	int opt;
	char *p;
	int seed;
	static pstring servicesf = CONFIGFILE;

	setlinebuf(stdout);

	dbf = stderr;

	if (argv[1][0] == '-' || argc < 3) {
		usage();
		exit(1);
	}

	share1 = argv[1];
	share2 = argv[2];

	all_string_sub(share1,"/","\\",0);
	all_string_sub(share2,"/","\\",0);

	setup_logging(argv[0],True);

	argc -= 2;
	argv += 2;

	TimeInit();
	charset_initialise();

	lp_load(servicesf,True,False,False);
	load_interfaces();

	if (getenv("USER")) {
		pstrcpy(username,getenv("USER"));
	}

	seed = time(NULL);

	while ((opt = getopt(argc, argv, "U:s:ho:aA")) != EOF) {
		switch (opt) {
		case 'U':
			pstrcpy(username,optarg);
			p = strchr(username,'%');
			if (p) {
				*p = 0;
				pstrcpy(password, p+1);
				got_pass = 1;
			}
			break;
		case 's':
			seed = atoi(optarg);
			break;
		case 'o':
			numops = atoi(optarg);
			break;
		case 'a':
			showall = True;
			break;
		case 'A':
			analyze = True;
			break;
		case 'h':
			usage();
			exit(1);
		default:
			printf("Unknown option %c (%d)\n", (char)opt, opt);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	DEBUG(0,("seed=%u\n", seed));
	srandom(seed);

	locking_init(1);
	test_locks(share1, share2);

	return(0);
}
