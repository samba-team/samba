/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   
   Copyright (C) Andrew Tridgell 2000
   
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
static int got_pass;


/* print a ascii version of a security descriptor on a FILE handle */
static void sec_desc_print(FILE *f, SEC_DESC *sd)
{
	fstring sidstr;
	int i;

	/* Print owner and group sid */

	if (sd->owner_sid) {
		sid_to_string(sidstr, sd->owner_sid);
	} else {
		fstrcpy(sidstr, "");
	}

	printf("%s\n", sidstr);

	if (sd->grp_sid) {
		sid_to_string(sidstr, sd->grp_sid);
	} else {
		fstrcpy(sidstr, "");
	}

	fprintf(f, "%s\n", sidstr);

	/* Print aces */

	if (!sd->dacl) {
		return;
	}

	for (i = 0; i < sd->dacl->num_aces; i++) {
		SEC_ACE *ace = &sd->dacl->ace[i];
		fstring sidstr;

		sid_to_string(sidstr, &ace->sid);

		fprintf(f, "%d %d 0x%08x %s\n", ace->type, ace->flags,
			ace->info.mask, sidstr);
	}
}




/***************************************************** 
dump the acls for a file
*******************************************************/
static void cacl_dump(struct cli_state *cli, char *filename)
{
	int fnum;
	SEC_DESC *sd;

	fnum = cli_open(cli, filename, O_RDONLY, 0);
	if (fnum == -1) {
		printf("Failed to open %s\n", filename);
		return;
	}

	sd = cli_query_secdesc(cli, fnum);

	if (!sd) {
		printf("ERROR: secdesc query failed\n");
		return;
	}

	sec_desc_print(stdout, sd);

	free_sec_desc(&sd);

	cli_close(cli, fnum);
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
	extern pstring global_myname;

	fstrcpy(server,share+2);
	share = strchr(server,'\\');
	if (!share) return NULL;
	*share = 0;
	share++;

	server_n = server;
	
	ip = ipzero;

	make_nmb_name(&calling, global_myname, 0x0);
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
			       lp_workgroup())) {
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
  smbcacls //server1/share1 filename\n\n");
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	char *share;
	char *filename;
	extern char *optarg;
	extern int optind;
	extern FILE *dbf;
	int opt;
	char *p;
	int seed;
	static pstring servicesf = CONFIGFILE;
	struct cli_state *cli;

	setlinebuf(stdout);

	dbf = stderr;

	if (argc < 4 || argv[1][0] == '-') {
		usage();
		exit(1);
	}

	setup_logging(argv[0],True);

	share = argv[1];
	filename = argv[2];
	all_string_sub(share,"/","\\",0);

	argc -= 2;
	argv += 2;

	TimeInit();
	charset_initialise();

	lp_load(servicesf,True,False,False);
	codepage_initialise(lp_client_code_page());
	load_interfaces();

	if (getenv("USER")) {
		pstrcpy(username,getenv("USER"));
	}

	seed = time(NULL);

	while ((opt = getopt(argc, argv, "U:h")) != EOF) {
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

	cli = connect_one(share);
	if (!cli) exit(1);

	cacl_dump(cli, filename);

	return(0);
}
