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

extern int DEBUGLEVEL;
static fstring password;
static fstring username;
static int got_pass;

static BOOL showall = False;
static BOOL old_list = False;
static char *maskchars = "<>\"?*abc.";
static char *filechars = "abcdefghijklm.";

static BOOL reg_match_one(char *pattern, char *file)
{
	if (strcmp(file,"..") == 0) file = ".";
	if (strcmp(pattern,".") == 0) return False;

	/* oh what a weird world this is */
	if (old_list && strcmp(pattern, "*.*") == 0) return True;

	return ms_fnmatch(pattern, file)==0;
}

static char *reg_test(char *pattern, char *file, char *short_name)
{
	static fstring ret;
	fstrcpy(ret, "---");

	pattern = 1+strrchr(pattern,'\\');
	file = 1+strrchr(file,'\\');

	if (reg_match_one(pattern, ".")) ret[0] = '+';
	if (reg_match_one(pattern, "..")) ret[1] = '+';
	if (reg_match_one(pattern, file) || 
	    (*short_name && reg_match_one(pattern, short_name))) ret[2] = '+';
	return ret;
}


/***************************************************** 
return a connection to a server
*******************************************************/
struct cli_state *connect_one(char *share)
{
	struct cli_state *c;
	struct nmb_name called, calling;
	char *server_n;
	char *server;
	struct in_addr ip;
	extern struct in_addr ipzero;

	server = share+2;
	share = strchr(server,'\\');
	if (!share) return NULL;
	*share = 0;
	share++;

	server_n = server;
	
	ip = ipzero;

	make_nmb_name(&calling, "masktest", 0x0);
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

static char *resultp;
static file_info *finfo;

void listfn(file_info *f, const char *s)
{
	if (strcmp(f->name,".") == 0) {
		resultp[0] = '+';
	} else if (strcmp(f->name,"..") == 0) {
		resultp[1] = '+';		
	} else {
		resultp[2] = '+';
	}
	finfo = f;
}

static void get_short_name(struct cli_state *cli, 
			   char *name, fstring short_name)
{
	cli_list(cli, name, aHIDDEN | aDIR, listfn);
	if (finfo) {
		fstrcpy(short_name, finfo->short_name);
		strlower(short_name);
	}
}

static void testpair(struct cli_state *cli, char *mask, char *file)
{
	int fnum;
	fstring res1;
	char *res2;
	static int count;
	fstring short_name;

	count++;

	fstrcpy(res1, "---");

	fnum = cli_open(cli, file, O_CREAT|O_TRUNC|O_RDWR, 0);
	if (fnum == -1) {
		DEBUG(0,("Can't create %s\n", file));
		return;
	}
	cli_close(cli, fnum);

	resultp = res1;
	fstrcpy(short_name, "");
	finfo = NULL;
	if (old_list) {
		cli_list_old(cli, mask, aHIDDEN | aDIR, listfn);
	} else {
		get_short_name(cli, file, short_name);
		finfo = NULL;
		fstrcpy(res1, "---");
		cli_list(cli, mask, aHIDDEN | aDIR, listfn);
	}

	res2 = reg_test(mask, file, short_name);

	if (showall || strcmp(res1, res2)) {
		DEBUG(0,("%s %s %d mask=[%s] file=[%s] mfile=[%s]\n",
			 res1, res2, count, mask, file, short_name));
	}

	cli_unlink(cli, file);

	if (count % 100 == 0) DEBUG(0,("%d\n", count));
}

static void test_mask(int argc, char *argv[], 
		      struct cli_state *cli)
{
	pstring mask, file;
	int l1, l2, i, l;
	int mc_len = strlen(maskchars);
	int fc_len = strlen(filechars);

	cli_mkdir(cli, "\\masktest");

	cli_unlink(cli, "\\masktest\\*");

	if (argc >= 2) {
		while (argc >= 2) {
			pstrcpy(mask,"\\masktest\\");
			pstrcpy(file,"\\masktest\\");
			pstrcat(mask, argv[0]);
			pstrcat(file, argv[1]);
			testpair(cli, mask, file);
			argv += 2;
			argc -= 2;
		}
		goto finished;
	}

	while (1) {
		l1 = 1 + random() % 20;
		l2 = 1 + random() % 20;
		pstrcpy(mask,"\\masktest\\");
		pstrcpy(file,"\\masktest\\");
		l = strlen(mask);
		for (i=0;i<l1;i++) {
			mask[i+l] = maskchars[random() % mc_len];
		}
		mask[l+l1] = 0;

		for (i=0;i<l2;i++) {
			file[i+l] = filechars[random() % fc_len];
		}
		file[l+l2] = 0;

		if (strcmp(file+l,".") == 0 || 
		    strcmp(file+l,"..") == 0 ||
		    strcmp(mask+l,"..") == 0) continue;

		testpair(cli, mask, file);
	}

 finished:
	cli_rmdir(cli, "\\masktest");
}


static void usage(void)
{
	printf(
"Usage:\n\
  masktest //server/share [options..]\n\
  options:\n\
        -W workgroup\n\
        -U user%%pass\n\
        -s seed\n\
        -f filechars (default %s)\n\
        -m maskchars (default %s)\n\
        -a                             show all tests\n\
\n\
  This program tests wildcard matching between two servers. It generates\n\
  random pairs of filenames/masks and tests that they match in the same\n\
  way on the servers and internally\n\
", 
  filechars, maskchars);
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	char *share;
	struct cli_state *cli;	
	extern char *optarg;
	extern int optind;
	extern FILE *dbf;
	int opt;
	char *p;
	int seed;
	static pstring servicesf = CONFIGFILE;

	setlinebuf(stdout);

	dbf = stderr;

	if (argv[1][0] == '-' || argc < 2) {
		usage();
		exit(1);
	}

	share = argv[1];

	all_string_sub(share,"/","\\",0);

	setup_logging(argv[0],True);

	argc -= 1;
	argv += 1;

	TimeInit();
	charset_initialise();
	codepage_initialise(lp_client_code_page());

	lp_load(servicesf,True,False,False);
	load_interfaces();

	if (getenv("USER")) {
		pstrcpy(username,getenv("USER"));
	}

	seed = time(NULL);

	while ((opt = getopt(argc, argv, "U:s:hm:f:aoW:")) != EOF) {
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
		case 'h':
			usage();
			exit(1);
		case 'm':
			maskchars = optarg;
			break;
		case 'f':
			filechars = optarg;
			break;
		case 'a':
			showall = 1;
			break;
		case 'o':
			old_list = True;
			break;
		default:
			printf("Unknown option %c (%d)\n", (char)opt, opt);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;


	cli = connect_one(share);
	if (!cli) {
		DEBUG(0,("Failed to connect to %s\n", share));
		exit(1);
	}

	/* need to init seed after connect as clientgen uses random numbers */
	DEBUG(0,("seed=%d\n", seed));
	srandom(seed);

	test_mask(argc, argv, cli);

	return(0);
}
