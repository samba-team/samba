/* 
   Unix SMB/Netbios implementation.
   ACL get/set utility
   Version 3.0
   
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Tim Potter      2000
   
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

static fstring password;
static fstring username;
static fstring server;
static int got_pass;
static int test_args;

/* numeric is set when the user wants numeric SIDs and ACEs rather
   than going via LSA calls to resolve them */
static int numeric;

enum acl_mode {ACL_SET, ACL_DELETE, ACL_MODIFY, ACL_ADD};

struct perm_value {
	char *perm;
	uint32 mask;
};

/* These values discovered by inspection */

static struct perm_value special_values[] = {
	{ "R", 0x00120089 },
	{ "W", 0x00120116 },
	{ "X", 0x001200a0 },
	{ "D", 0x00010000 },
	{ "P", 0x00040000 },
	{ "O", 0x00080000 },
	{ NULL, 0 },
};

static struct perm_value standard_values[] = {
	{ "READ",   0x001200a9 },
	{ "CHANGE", 0x001301bf },
	{ "FULL",   0x001f01ff },
	{ NULL, 0 },
};

struct cli_state lsa_cli;
POLICY_HND pol;
struct ntuser_creds creds;
BOOL got_policy_hnd;

/* Open cli connection and policy handle */

static BOOL open_policy_hnd(void)
{
	creds.pwd.null_pwd = 1;

	/* Initialise cli LSA connection */

	if (!lsa_cli.initialised && 
	    !cli_lsa_initialise(&lsa_cli, server, &creds)) {
		return False;
	}

	/* Open policy handle */

	if (!got_policy_hnd) {
		if (cli_lsa_open_policy(&lsa_cli, True, 
					SEC_RIGHTS_MAXIMUM_ALLOWED, &pol)
		    != NT_STATUS_NOPROBLEMO) {
			return False;
		}

		got_policy_hnd = True;
	}
	
	return True;
}

/* convert a SID to a string, either numeric or username/group */
static void SidToString(fstring str, DOM_SID *sid)
{
	char **names = NULL;
	uint32 *types = NULL;
	int num_names;

	sid_to_string(str, sid);

	if (numeric) return;

	/* Ask LSA to convert the sid to a name */

	if (open_policy_hnd() &&
	    cli_lsa_lookup_sids(&lsa_cli, &pol, 1, sid, &names, &types, 
				&num_names) == NT_STATUS_NOPROBLEMO) {

		/* Converted OK */

		fstrcpy(str, names[0]);

		safe_free(names[0]);
		safe_free(names);
		safe_free(types);
	}
}

/* convert a string to a SID, either numeric or username/group */
static BOOL StringToSid(DOM_SID *sid, fstring str)
{
	uint32 *types = NULL;
	DOM_SID *sids = NULL;
	int num_sids;
	BOOL result = False;
	
	/* Short cut */

	if (strncmp(str, "S-", 2) == 0) {
		result = string_to_sid(sid, str);
		goto done;
	}

	if (open_policy_hnd() &&
	    cli_lsa_lookup_names(&lsa_cli, &pol, 1, &str, &sids, &types, 
				 &num_sids) == NT_STATUS_NOPROBLEMO) {
		result = string_to_sid(sid, str);
		goto done;
	}

	sid_copy(sid, &sids[0]);

	safe_free(sids);
	safe_free(types);

 done:
	return result;
}


/* print an ACE on a FILE, using either numeric or ascii representation */
static void print_ace(FILE *f, SEC_ACE *ace)
{
	struct perm_value *v;
	fstring sidstr;
	int do_print = 0;
	uint32 got_mask;

	SidToString(sidstr, &ace->sid);

	fprintf(f, "%s:", sidstr);

	if (numeric) {
		fprintf(f, "%d/%d/0x%08x\n", 
			ace->type, ace->flags, ace->info.mask);
		return;
	}

	/* Ace type */

	if (ace->type == SEC_ACE_TYPE_ACCESS_ALLOWED) {
		fprintf(f, "ALLOWED");
	} else if (ace->type == SEC_ACE_TYPE_ACCESS_DENIED) {
		fprintf(f, "DENIED");
	} else {
		fprintf(f, "%d", ace->type);
	}

	/* Not sure what flags can be set in a file ACL */

	fprintf(f, "/%d/", ace->flags);

	/* Standard permissions */

	for (v = standard_values; v->perm; v++) {
		if (ace->info.mask == v->mask) {
			fprintf(f, "%s\n", v->perm);
			return;
		}
	}

	/* Special permissions.  Print out a hex value if we have
	   leftover bits in the mask. */

	got_mask = ace->info.mask;

 again:
	for (v = special_values; v->perm; v++) {
		if ((ace->info.mask & v->mask) == v->mask) {
			if (do_print) {
				fprintf(f, "%s", v->perm);
			}
			got_mask &= ~v->mask;
		}
	}

	if (!do_print) {
		if (got_mask != 0) {
			fprintf(f, "0x%08x", ace->info.mask);
		} else {
			do_print = 1;
			goto again;
		}
	}

	fprintf(f, "\n");
}


/* parse an ACE in the same format as print_ace() */
static BOOL parse_ace(SEC_ACE *ace, char *str)
{
	char *p;
	fstring tok;
	unsigned atype, aflags, amask;
	DOM_SID sid;
	SEC_ACCESS mask;
	struct perm_value *v;

	ZERO_STRUCTP(ace);
	p = strchr(str,':');
	if (!p) return False;
	*p = '\0';
	p++;

	/* Try to parse numeric form */

	if (sscanf(p, "%i/%i/%i", &atype, &aflags, &amask) == 3 &&
	    StringToSid(&sid, str)) {
		goto done;
	}

	/* Try to parse text form */

	if (!StringToSid(&sid, str)) {
		return False;
	}

	if (!next_token(&p, tok, "/", sizeof(fstring))) {
		return False;
	}

	if (strncmp(tok, "ALLOWED", strlen("ALLOWED")) == 0) {
		atype = SEC_ACE_TYPE_ACCESS_ALLOWED;
	} else if (strncmp(tok, "DENIED", strlen("DENIED")) == 0) {
		atype = SEC_ACE_TYPE_ACCESS_DENIED;
	} else {
		return False;
	}

	/* Only numeric form accepted for flags at present */

	if (!(next_token(NULL, tok, "/", sizeof(fstring)) &&
	      sscanf(tok, "%i", &aflags))) {
		return False;
	}

	if (!next_token(NULL, tok, "/", sizeof(fstring))) {
		return False;
	}

	if (strncmp(tok, "0x", 2) == 0) {
		if (sscanf(tok, "%i", &amask) != 1) {
			return False;
		}
		goto done;
	}

	for (v = standard_values; v->perm; v++) {
		if (strcmp(tok, v->perm) == 0) {
			amask = v->mask;
			goto done;
		}
	}

	p = tok;

	while(*p) {
		BOOL found = False;

		for (v = special_values; v->perm; v++) {
			if (v->perm[0] == *p) {
				amask |= v->mask;
				found = True;
			}
		}

		if (!found) return False;
		p++;
	}

	if (*p) {
		return False;
	}

 done:
	mask.mask = amask;
	init_sec_ace(ace, &sid, atype, mask, aflags);
	return True;
}

/* add an ACE to a list of ACEs in a SEC_ACL */
static BOOL add_ace(SEC_ACL **acl, SEC_ACE *ace)
{
	SEC_ACL *new;
	SEC_ACE *aces;
	if (! *acl) {
		(*acl) = make_sec_acl(3, 1, ace);
		return True;
	}

	aces = calloc(1+(*acl)->num_aces,sizeof(SEC_ACE));
	memcpy(aces, (*acl)->ace, (*acl)->num_aces * sizeof(SEC_ACE));
	memcpy(aces+(*acl)->num_aces, ace, sizeof(SEC_ACE));
	new = make_sec_acl((*acl)->revision,1+(*acl)->num_aces, aces);
	free_sec_acl(acl);
	free(aces);
	(*acl) = new;
	return True;
}

/* parse a ascii version of a security descriptor */
static SEC_DESC *sec_desc_parse(char *str)
{
	char *p = str;
	fstring tok;
	SEC_DESC *ret;
	unsigned sd_size;
	DOM_SID *grp_sid=NULL, *owner_sid=NULL;
	SEC_ACL *dacl=NULL;
	int revision=1;

	while (next_token(&p, tok, " \t,\r\n", sizeof(tok))) {

		if (strncmp(tok,"REVISION:", 9) == 0) {
			revision = strtol(tok+9, NULL, 16);
			continue;
		}

		if (strncmp(tok,"OWNER:", 6) == 0) {
			owner_sid = (DOM_SID *)calloc(1, sizeof(DOM_SID));
			if (!owner_sid ||
			    !StringToSid(owner_sid, tok+6)) {
				printf("Failed to parse owner sid\n");
				return NULL;
			}
			continue;
		}

		if (strncmp(tok,"GROUP:", 6) == 0) {
			grp_sid = (DOM_SID *)calloc(1, sizeof(DOM_SID));
			if (!grp_sid ||
			    !StringToSid(grp_sid, tok+6)) {
				printf("Failed to parse group sid\n");
				return NULL;
			}
			continue;
		}

		if (strncmp(tok,"ACL:", 4) == 0) {
			SEC_ACE ace;
			if (!parse_ace(&ace, tok+4) || 
			    !add_ace(&dacl, &ace)) {
				printf("Failed to parse ACL\n");
				return NULL;
			}
			continue;
		}

		printf("Failed to parse security descriptor\n");
		return NULL;
	}

	ret = make_sec_desc(revision, owner_sid, grp_sid, 
			    NULL, dacl, &sd_size);

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

	printf("REVISION:%d\n", sd->revision);

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
		fprintf(f, "ACL:");
		print_ace(f, ace);
	}

}


/***************************************************** 
dump the acls for a file
*******************************************************/
static void cacl_dump(struct cli_state *cli, char *filename)
{
	int fnum;
	SEC_DESC *sd;

	if (test_args) return;

	fnum = cli_nt_create(cli, filename, 0x20000);
	if (fnum == -1) {
		printf("Failed to open %s: %s\n", filename, cli_errstr(cli));
		return;
	}

	sd = cli_query_secdesc(cli, fnum);

	if (!sd) {
		printf("ERROR: secdesc query failed: %s\n", cli_errstr(cli));
		return;
	}

	sec_desc_print(stdout, sd);

	free_sec_desc(&sd);

	cli_close(cli, fnum);
}

/***************************************************** 
set the ACLs on a file given an ascii description
*******************************************************/
static void cacl_set(struct cli_state *cli, char *filename, 
		     char *acl, enum acl_mode mode)
{
	int fnum;
	SEC_DESC *sd, *old;
	int i, j;
	unsigned sd_size;

	sd = sec_desc_parse(acl);

	if (!sd) return;
	if (test_args) return;

	/* the desired access below is the only one I could find that works with
	   NT4, W2KP and Samba */
	fnum = cli_nt_create(cli, filename, MAXIMUM_ALLOWED_ACCESS | 0x60000);
	if (fnum == -1) {
		printf("Failed to open %s: %s\n", filename, cli_errstr(cli));
		return;
	}

	old = cli_query_secdesc(cli, fnum);

	/* the logic here is rather more complex than I would like */
	switch (mode) {
	case ACL_DELETE:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			BOOL found = False;

			for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
				if (sec_ace_equal(&sd->dacl->ace[i],
						  &old->dacl->ace[j])) {
					if (j != old->dacl->num_aces-1) {
						old->dacl->ace[j] = old->dacl->ace[j+1];
					}
					old->dacl->num_aces--;
					if (old->dacl->num_aces == 0) {
						free(old->dacl->ace);
						old->dacl->ace=NULL;
						free(old->dacl);
						old->dacl = NULL;
						old->off_dacl = 0;
					}
					found = True;
					break;
				}
			}

			if (!found) {
				fstring str;

				SidToString(str, &sd->dacl->ace[i].sid);
				printf("ACL for SID %s not found\n", str);
			}
		}
		break;

	case ACL_MODIFY:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			BOOL found = False;

			for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
				if (sid_equal(&sd->dacl->ace[i].sid,
					      &old->dacl->ace[j].sid)) {
					old->dacl->ace[j] = sd->dacl->ace[i];
					found = True;
				}
			}

			if (!found) {
				fstring str;

				SidToString(str, &sd->dacl->ace[i].sid);
				printf("ACL for SID %s not found\n", str);
			}
		}

		break;

	case ACL_ADD:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			add_ace(&old->dacl, &sd->dacl->ace[i]);
		}
		break;

	case ACL_SET:
 		free_sec_desc(&old);
 		old = sd;
		break;
	}

	if (sd != old) {
		free_sec_desc(&sd);
	}

	sd = make_sec_desc(old->revision, old->owner_sid, old->grp_sid, 
			   NULL, old->dacl, &sd_size);

	if (!cli_set_secdesc(cli, fnum, sd)) {
		printf("ERROR: secdesc set failed: %s\n", cli_errstr(cli));
		return;
	}

	free_sec_desc(&sd);
	free_sec_desc(&old);

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
"Usage: smbcacls //server1/share1 filename -U username [options]\n\
\n\
\t-D <acls>               delete an acl\n\
\t-M <acls>               modify an acl\n\
\t-A <acls>               add an acl\n\
\t-S <acls>               set acls\n\
\t-n                      don't resolve sids or masks to names\n\
\t-h                      print help\n\
\n\
The username can be of the form username%%password or\n\
workgroup\\username%%password.\n\n\
An acl is of the form ACL:<SID>:type/flags/mask\n\
You can string acls together with spaces, commas or newlines\n\
");
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
	enum acl_mode mode;
	char *acl = NULL;

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

	while ((opt = getopt(argc, argv, "U:nhS:D:A:M:t")) != EOF) {
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
			acl = optarg;
			mode = ACL_SET;
			break;

		case 'D':
			acl = optarg;
			mode = ACL_DELETE;
			break;

		case 'M':
			acl = optarg;
			mode = ACL_MODIFY;
			break;

		case 'A':
			acl = optarg;
			mode = ACL_ADD;
			break;

		case 'n':
			numeric = 1;
			break;

		case 't':
			test_args = 1;
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
	
	if (argc > 0) {
		usage();
		exit(1);
	}

	if (!test_args) {
		cli = connect_one(share);
		if (!cli) exit(1);
	}

	if (acl) {
		cacl_set(cli, filename, acl, mode);
	} else {
		cacl_dump(cli, filename);
	}

	return(0);
}
