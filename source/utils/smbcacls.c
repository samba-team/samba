/* 
   Unix SMB/Netbios implementation.
   ACL get/set utility
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

/* numeric is set when the user wants numeric SIDs and ACEs rather
   than going via LSA calls to resolve them */
static int numeric;

/* convert a SID to a string, either numeric or username/group */
static void SidToString(fstring str, DOM_SID *sid)
{
	if (numeric) {
		sid_to_string(str, sid);
	} else {
		printf("need to add LSA lookups\n");
		sid_to_string(str, sid);
	}
}

/* convert a string to a SID, either numeric or username/group */
static BOOL StringToSid(DOM_SID *sid, fstring str)
{
	if (strncmp(str,"S-", 2) == 0) {
		return string_to_sid(sid, str);
	} else {
		printf("need to add LSA lookups\n");
		return False;
	}
}


/* print an ACE on a FILE, using either numeric or ascii representation */
static void print_ace(FILE *f, SEC_ACE *ace)
{
	fstring sidstr;
	char *perm;

	SidToString(sidstr, &ace->sid);

	fprintf(f, "%s:", sidstr);

	if (numeric) {
		fprintf(f, "%x/%x/%08x\n", 
			ace->type, ace->flags, ace->info.mask);
		return;
	}

	/* this interpretation is almost certainly wrong, Tim, please
	   have a look at these */
	if (ace->info.mask == 0x001f01ff) {
		perm = "F";
	} else if (ace->info.mask == 0x001301bf) {
		perm = "C";
	} else if (ace->info.mask == 0x001200a9) {
		perm = "R";
	} else if (ace->info.mask == 0x00000000) {
		perm = "N";
	} else {
		perm = "?";
	}

	fprintf(f,"%s\n", perm);
}


/* parse an ACE in the same format as print_ace() */
static BOOL parse_ace(SEC_ACE *ace, char *str)
{
	char *p;
	unsigned atype, aflags, amask;
	ZERO_STRUCTP(ace);
	p = strchr(str,':');
	if (!p) return False;
	*p = 0;
	if (sscanf(p+1, "%x/%x/%08x", 
		   &atype, &aflags, &amask) != 3 ||
	    !StringToSid(&ace->sid, str)) {
		return False;
	}
	ace->type = atype;
	ace->flags = aflags;
	ace->info.mask = amask;
	return True;
}



/* add an ACE to a list of ACEs in a SEC_ACL */
static BOOL add_ace(SEC_ACL **acl, SEC_ACE *ace)
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
	SEC_DESC *ret;
	int sd_size;
	DOM_SID *grp_sid=NULL, *owner_sid=NULL;
	SEC_ACL *dacl=NULL, *sacl=NULL;
	int revision=1;
	int type=0x8004;

	while (next_token(&p, tok, " \t,\r\n", sizeof(tok))) {

		if (strncmp(tok,"REVISION:", 9) == 0) {
			revision = strtol(tok+9, NULL, 16);
		}

		if (strncmp(tok,"TYPE:", 5) == 0) {
			type = strtol(tok+5, NULL, 16);
		}

		if (strncmp(tok,"OWNER:", 6) == 0) {
			owner_sid = (DOM_SID *)calloc(1, sizeof(DOM_SID));
			if (!owner_sid ||
			    !StringToSid(owner_sid, tok+6)) {
				printf("Failed to parse owner sid\n");
				return NULL;
			}
		}

		if (strncmp(tok,"GROUP:", 6) == 0) {
			grp_sid = (DOM_SID *)calloc(1, sizeof(DOM_SID));
			if (!grp_sid ||
			    !StringToSid(grp_sid, tok+6)) {
				printf("Failed to parse group sid\n");
				return NULL;
			}
		}

		if (strncmp(tok,"DACL:", 5) == 0) {
			SEC_ACE ace;
			if (!parse_ace(&ace, tok+5) || 
			    !add_ace(&dacl, &ace)) {
				printf("Failed to parse DACL\n");
				return NULL;
			}
		}

		if (strncmp(tok,"SACL:", 5) == 0) {
			SEC_ACE ace;
			if (!parse_ace(&ace, tok+5) || 
			    !add_ace(&sacl, &ace)) {
				printf("Failed to parse SACL\n");
				return NULL;
			}
		}
	}

	ret = make_sec_desc(revision, type, owner_sid, grp_sid, 
			    sacl, dacl, &sd_size);

	free_sec_acl(&sacl);
	free_sec_acl(&dacl);
	if (grp_sid) free(grp_sid);
	if (owner_sid) free(owner_sid);

	return ret;
}


/* print a ascii version of a security descriptor on a FILE handle */
static void sec_desc_print(FILE *f, SEC_DESC *sd)
{
	fstring sidstr;
	int i;

	printf("REVISION:%x TYPE:%x\n", sd->revision, sd->type);

	/* Print owner and group sid */

	if (sd->owner_sid) {
		SidToString(sidstr, sd->owner_sid);
	} else {
		fstrcpy(sidstr, "");
	}

	printf("OWNER:%s\n", sidstr);

	if (sd->grp_sid) {
		SidToString(sidstr, sd->grp_sid);
	} else {
		fstrcpy(sidstr, "");
	}

	fprintf(f, "GROUP:%s\n", sidstr);

	/* Print aces */
	for (i = 0; sd->dacl && i < sd->dacl->num_aces; i++) {
		SEC_ACE *ace = &sd->dacl->ace[i];
		fprintf(f, "DACL:");
		print_ace(f, ace);
	}

	for (i = 0; sd->sacl && i < sd->sacl->num_aces; i++) {
		SEC_ACE *ace = &sd->sacl->ace[i];
		fstring sidstr;

		SidToString(sidstr, &ace->sid);

		fprintf(f, "SACL:%s:%x:%x:%08x\n", sidstr, 
			ace->type, ace->flags,
			ace->info.mask);
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

	while ((opt = getopt(argc, argv, "U:nhS:")) != EOF) {
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

		case 'S':
			set_acl = optarg;
			break;

		case 'n':
			numeric = 1;
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
