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

	printf("REVISION:%x TYPE:%x\n", sd->revision, sd->type);

	/* Print owner and group sid */

	if (sd->owner_sid) {
		sid_to_string(sidstr, sd->owner_sid);
	} else {
		fstrcpy(sidstr, "");
	}

	printf("OWNER:%s\n", sidstr);

	if (sd->grp_sid) {
		sid_to_string(sidstr, sd->grp_sid);
	} else {
		fstrcpy(sidstr, "");
	}

	fprintf(f, "GROUP:%s\n", sidstr);

	/* Print aces */
	for (i = 0; sd->dacl && i < sd->dacl->num_aces; i++) {
		SEC_ACE *ace = &sd->dacl->ace[i];
		fstring sidstr;

		sid_to_string(sidstr, &ace->sid);

		fprintf(f, "DACL:%x:%x:%08x:%s\n", ace->type, ace->flags,
			ace->info.mask, sidstr);
	}

	for (i = 0; sd->sacl && i < sd->sacl->num_aces; i++) {
		SEC_ACE *ace = &sd->sacl->ace[i];
		fstring sidstr;

		sid_to_string(sidstr, &ace->sid);

		fprintf(f, "SACL:%x:%x:%08x:%s\n", ace->type, ace->flags,
			ace->info.mask, sidstr);
	}
}


/* add an ACE to a list of ACEs in a SEC_ACL */
static BOOL add_acl(SEC_ACL **acl, SEC_ACE *ace)
{
	if (! *acl) {
		*acl = (SEC_ACL *)calloc(1, sizeof(*acl));
		if (! *acl) return False;
		(*acl)->revision = 3;
	}

	(*acl)->ace = Realloc((*acl)->ace,(1+((*acl)->num_aces))*sizeof(SEC_ACE));
	if (!(*acl)->ace) return False;
	memcpy(&((*acl)->ace[(*acl)->num_aces]), ace, sizeof(SEC_ACE));
	(*acl)->num_aces++;
	return True;
}

/* parse a ascii version of a security descriptor */
static SEC_DESC *sec_desc_parse(char *str)
{
	char *p = str;
	fstring tok;
	SEC_DESC *sd, *ret;
	int sd_size;

	sd = (SEC_DESC *)calloc(1, sizeof(SEC_DESC));
	if (!sd) return NULL;

	while (next_token(&p, tok, " \t,\r\n", sizeof(tok))) {

		if (strncmp(tok,"REVISION:", 9) == 0) {
			sd->revision = strtol(tok+9, NULL, 16);
		}

		if (strncmp(tok,"TYPE:", 5) == 0) {
			sd->type = strtol(tok+5, NULL, 16);
		}

		if (strncmp(tok,"OWNER:", 6) == 0) {
			sd->owner_sid = (DOM_SID *)calloc(1, sizeof(DOM_SID));
			if (!sd->owner_sid ||
			    !string_to_sid(sd->owner_sid, tok+6)) {
				printf("Failed to parse owner sid\n");
				return NULL;
			}
		}

		if (strncmp(tok,"GROUP:", 6) == 0) {
			sd->grp_sid = (DOM_SID *)calloc(1, sizeof(DOM_SID));
			if (!sd->grp_sid ||
			    !string_to_sid(sd->grp_sid, tok+6)) {
				printf("Failed to parse group sid\n");
				return NULL;
			}
		}

		if (strncmp(tok,"DACL:", 5) == 0) {
			fstring s;
			unsigned atype, aflags, amask;
			SEC_ACE ace;
			ZERO_STRUCT(ace);
			if (sscanf(tok+5, "%x:%x:%08x:%s", 
				   &atype, &aflags, &amask,s) != 4 ||
			    !string_to_sid(&ace.sid, s)) {
				printf("Failed to parse DACL\n");
				return NULL;
			}
			ace.type = atype;
			ace.flags = aflags;
			ace.info.mask = amask;
			add_acl(&sd->dacl, &ace);
		}

		if (strncmp(tok,"SACL:", 5) == 0) {
			fstring s;
			unsigned atype, aflags, amask;
			SEC_ACE ace;
			ZERO_STRUCT(ace);
			if (sscanf(tok+5, "%x:%x:%08x:%s", 
				   &atype, &aflags, &amask,s) != 4 ||
			    !string_to_sid(&ace.sid, s)) {
				printf("Failed to parse SACL\n");
				return NULL;
			}
			ace.type = atype;
			ace.flags = aflags;
			ace.info.mask = amask;
			add_acl(&sd->sacl, &ace);
		}
	}

	ret = make_sec_desc(sd->revision, sd->type, sd->owner_sid, sd->grp_sid, 
			    sd->sacl, sd->dacl, &sd_size);

	free_sec_desc(&sd);

	return ret;
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
set the ACLs on a file given an ascii description
*******************************************************/
static void cacl_set(struct cli_state *cli, char *filename, char *set_acl)
{
	int fnum;
	SEC_DESC *sd;

	sd = sec_desc_parse(set_acl);
	if (!sd) {
		printf("Failed to parse security descriptor\n");
		return;
	}

	fnum = cli_open(cli, filename, O_RDONLY, 0);
	if (fnum == -1) {
		printf("Failed to open %s\n", filename);
		return;
	}

	/* sec_desc_print(stdout, sd); */

	if (!cli_set_secdesc(cli, fnum, sd)) {
		printf("ERROR: secdesc set failed\n");
		return;
	}

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
	char *set_acl = NULL;

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

	while ((opt = getopt(argc, argv, "U:hs:")) != EOF) {
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
			set_acl = optarg;
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

	if (set_acl) {
		cacl_set(cli, filename, set_acl);
	} else {
		cacl_dump(cli, filename);
	}

	return(0);
}
