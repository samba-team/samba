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

#define FILENAME "locktest.dat"
#define LOCKRANGE 100

#define READ_PCT 50
#define LOCK_PCT 45
#define UNLOCK_PCT 45

struct preset {
	int r1, r2;
	int conn, f;
	int start, len;
	int rw;
} preset[] = {
{86, 37, 0, 1,  0, 3, WRITE_LOCK},
{46, 21, 0, 1,  1, 1, READ_LOCK},
{51, 35, 0, 0, 10, 1, WRITE_LOCK},
{69, 97, 0, 1,  0, 0, 0},
{35, 27, 1, 1,  0, 3, READ_LOCK},
	};

/* each server has two connections open to it. Each connection has two file
   descriptors open on the file - 8 file descriptors in total 

   we then do random locking ops in tamdem on the 4 fnums from each
   server and ensure that the results match
 */
static void test_locks(struct cli_state *cli[2][2])
{
	int fnum[2][2][2];
	int server, conn, f, n; 

	cli_unlink(cli[0][0], FILENAME);
	cli_unlink(cli[1][0], FILENAME);

	for (server=0;server<2;server++)
	for (conn=0;conn<2;conn++)
	for (f=0;f<2;f++) {
		fnum[server][conn][f] = cli_open(cli[server][conn], FILENAME,
						 O_RDWR|O_CREAT,
						 DENY_NONE);
		if (fnum[server][conn][f] == -1) {
			fprintf(stderr,"Failed to open fnum[%d][%d][%d]\n",
				server, conn, f);
			return;
		}
	}

	for (n=0; n<numops; n++) {
		int start, len, op, r1, r2;
		BOOL ret1, ret2;

		if (n < sizeof(preset) / sizeof(preset[0])) {
			conn = preset[n].conn;
			f = preset[n].f;
			start = preset[n].start;
			len = preset[n].len;
			r1 = preset[n].r1;
			r2 = preset[n].r2;
		} else {
			conn = random() % 2;
			f = random() % 2;
			start = random() % (LOCKRANGE-1);
			len = 1 + random() % (LOCKRANGE-start);

			r1 = random() % 100;
			r2 = random() % 100;
		}

		if (r1 < READ_PCT) {
			op = READ_LOCK; 
		} else {
			op = WRITE_LOCK; 
		}


		if (r2 < LOCK_PCT) {
			/* set a lock */
			ret1 = cli_lock(cli[0][conn], 
					fnum[0][conn][f],
					start, len, 0, op);
			ret2 = cli_lock(cli[1][conn], 
					fnum[1][conn][f],
					start, len, 0, op);
			if (showall || ret1 != ret2) {
				printf("%5d r1=%d r2=%d lock   conn=%d f=%d %d:%d op=%s -> %d:%d\n",
				       n, r1, r2, conn, f, start, len, op==READ_LOCK?"READ_LOCK":"WRITE_LOCK",
				       ret1, ret2);
			}
			if (ret1 != ret2) return;
		} else if (r2 < LOCK_PCT+UNLOCK_PCT) {
			/* unset a lock */
			/* set a lock */
			ret1 = cli_unlock(cli[0][conn], 
					  fnum[0][conn][f],
					  start, len);
			ret2 = cli_unlock(cli[1][conn], 
					  fnum[1][conn][f],
					  start, len);
			if (showall || ret1 != ret2) {
				printf("%5d r1=%d r2=%d unlock conn=%d f=%d %d:%d       -> %d:%d\n",
				       n, r1, r2, conn, f, start, len,
				       ret1, ret2);
			}
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
				return;
			}
			if (fnum[1][conn][f] == -1) {
				printf("failed to reopen on share2\n");
				return;
			}
			if (showall) {
				printf("%5d r1=%d r2=%d reopen conn=%d f=%d\n",
				       n, r1, r2, conn, f);
			}
		}
		if (n % 100 == 0) {
			printf("%d\n", n);
		}
	}
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

	fstrcpy(server,share+2);
	share = strchr(server,'\\');
	if (!share) return NULL;
	*share = 0;
	share++;

	server_n = server;
	
	ip = ipzero;

	make_nmb_name(&calling, "locktest", 0x0);
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
	struct cli_state *cli[2][2];
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

	while ((opt = getopt(argc, argv, "U:s:ho:a")) != EOF) {
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

	DEBUG(0,("seed=%d\n", seed));
	srandom(seed);

	cli[0][0] = connect_one(share1);
	cli[0][1] = connect_one(share1);
	if (!cli[0][0] || !cli[0][1]) {
		DEBUG(0,("Failed to connect to %s\n", share1));
		exit(1);
	}

	cli[1][0] = connect_one(share2);
	cli[1][1] = connect_one(share2);
	if (!cli[1][0] || !cli[1][1]) {
		DEBUG(0,("Failed to connect to %s\n", share2));
		exit(1);
	}

	test_locks(cli);

	return(0);
}
