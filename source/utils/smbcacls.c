/* 
   Unix SMB/CIFS implementation.
   ACL get/set utility
   
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Tim Potter      2000
   Copyright (C) Jeremy Allison  2000
   
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
static pstring username;
static pstring owner_username;
static fstring server;
static fstring workgroup = "";
static int got_pass;
static int test_args;
TALLOC_CTX *ctx;

#define CREATE_ACCESS_READ READ_CONTROL_ACCESS
#define CREATE_ACCESS_WRITE (WRITE_DAC_ACCESS | WRITE_OWNER_ACCESS)

/* numeric is set when the user wants numeric SIDs and ACEs rather
   than going via LSA calls to resolve them */
static int numeric;

enum acl_mode {SMB_ACL_SET, SMB_ACL_DELETE, SMB_ACL_MODIFY, SMB_ACL_ADD };
enum chown_mode {REQUEST_NONE, REQUEST_CHOWN, REQUEST_CHGRP};
enum exit_values {EXIT_OK, EXIT_FAILED, EXIT_PARSE_ERROR};

struct perm_value {
	const char *perm;
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

static BOOL cacls_open_policy_hnd(void)
{
	creds.pwd.null_pwd = 1;

	/* Initialise cli LSA connection */

	if (!lsa_cli.initialised && 
	    !cli_lsa_initialise(&lsa_cli, server, &creds)) {
		return False;
	}

	/* Open policy handle */

	if (!got_policy_hnd) {

		/* Some systems don't support SEC_RIGHTS_MAXIMUM_ALLOWED,
		   but NT sends 0x2000000 so we might as well do it too. */

		if (!NT_STATUS_IS_OK(cli_lsa_open_policy(&lsa_cli, lsa_cli.mem_ctx, True, 
					GENERIC_EXECUTE_ACCESS, &pol))) {
			return False;
		}

		got_policy_hnd = True;
	}
	
	return True;
}

/* convert a SID to a string, either numeric or username/group */
static void SidToString(fstring str, DOM_SID *sid)
{
	char **domains = NULL;
	char **names = NULL;
	uint32 *types = NULL;

	sid_to_string(str, sid);

	if (numeric) return;

        if (strcmp(str, "S-1-1-0") == 0) {

                fstrcpy(str, "everyone");
                return;

        }

	/* Ask LSA to convert the sid to a name */

	if (!cacls_open_policy_hnd() ||
	    !NT_STATUS_IS_OK(cli_lsa_lookup_sids(&lsa_cli, lsa_cli.mem_ctx,  
						 &pol, 1, sid, &domains, 
						 &names, &types)) ||
	    !domains || !domains[0] || !names || !names[0]) {
		return;
	}

	/* Converted OK */
	
	slprintf(str, sizeof(fstring) - 1, "%s%s%s",
		 domains[0], lp_winbind_separator(),
		 names[0]);
	
}

/* convert a string to a SID, either numeric or username/group */
static BOOL StringToSid(DOM_SID *sid, const char *str)
{
	uint32 *types = NULL;
	DOM_SID *sids = NULL;
	BOOL result = True;
	
	if (strncmp(str, "S-", 2) == 0) {
		return string_to_sid(sid, str);
	}

	if (!cacls_open_policy_hnd() ||
	    !NT_STATUS_IS_OK(cli_lsa_lookup_names(&lsa_cli, lsa_cli.mem_ctx, 
						  &pol, 1, &str, &sids, 
						  &types))) {
		result = False;
		goto done;
	}

	sid_copy(sid, &sids[0]);

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

	SidToString(sidstr, &ace->trustee);

	fprintf(f, "%s:", sidstr);

	if (numeric) {
		fprintf(f, "%d/%d/0x%08x", 
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
			fprintf(f, "%s", v->perm);
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
}


/* parse an ACE in the same format as print_ace() */
static BOOL parse_ace(SEC_ACE *ace, char *str)
{
	char *p;
	const char *cp;
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

	cp = p;
	if (!next_token(&cp, tok, "/", sizeof(fstring))) {
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

	if (!(next_token(&cp, tok, "/", sizeof(fstring)) &&
	      sscanf(tok, "%i", &aflags))) {
		return False;
	}

	if (!next_token(&cp, tok, "/", sizeof(fstring))) {
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
static BOOL add_ace(SEC_ACL **the_acl, SEC_ACE *ace)
{
	SEC_ACL *new;
	SEC_ACE *aces;
	if (! *the_acl) {
		(*the_acl) = make_sec_acl(ctx, 3, 1, ace);
		return True;
	}

	aces = calloc(1+(*the_acl)->num_aces,sizeof(SEC_ACE));
	memcpy(aces, (*the_acl)->ace, (*the_acl)->num_aces * sizeof(SEC_ACE));
	memcpy(aces+(*the_acl)->num_aces, ace, sizeof(SEC_ACE));
	new = make_sec_acl(ctx,(*the_acl)->revision,1+(*the_acl)->num_aces, aces);
	SAFE_FREE(aces);
	(*the_acl) = new;
	return True;
}

/* parse a ascii version of a security descriptor */
static SEC_DESC *sec_desc_parse(char *str)
{
	const char *p = str;
	fstring tok;
	SEC_DESC *ret;
	size_t sd_size;
	DOM_SID *grp_sid=NULL, *owner_sid=NULL;
	SEC_ACL *dacl=NULL;
	int revision=1;

	while (next_token(&p, tok, "\t,\r\n", sizeof(tok))) {

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
			if (!parse_ace(&ace, tok+4)) {
				printf("Failed to parse ACL %s\n", tok);
				return NULL;
			}
			if(!add_ace(&dacl, &ace)) {
				printf("Failed to add ACL %s\n", tok);
				return NULL;
			}
			continue;
		}

		printf("Failed to parse security descriptor\n");
		return NULL;
	}

	ret = make_sec_desc(ctx,revision, owner_sid, grp_sid, 
			    NULL, dacl, &sd_size);

	SAFE_FREE(grp_sid);
	SAFE_FREE(owner_sid);

	return ret;
}


/* print a ascii version of a security descriptor on a FILE handle */
static void sec_desc_print(FILE *f, SEC_DESC *sd)
{
	fstring sidstr;
	uint32 i;

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
		fprintf(f, "\n");
	}

}

/***************************************************** 
dump the acls for a file
*******************************************************/
static int cacl_dump(struct cli_state *cli, char *filename)
{
	int fnum;
	SEC_DESC *sd;

	if (test_args) return EXIT_OK;

	fnum = cli_nt_create(cli, filename, CREATE_ACCESS_READ);
	if (fnum == -1) {
		printf("Failed to open %s: %s\n", filename, cli_errstr(cli));
		return EXIT_FAILED;
	}

	sd = cli_query_secdesc(cli, fnum, ctx);

	if (!sd) {
		printf("ERROR: secdesc query failed: %s\n", cli_errstr(cli));
		return EXIT_FAILED;
	}

	sec_desc_print(stdout, sd);

	cli_close(cli, fnum);

	return EXIT_OK;
}

/***************************************************** 
Change the ownership or group ownership of a file. Just
because the NT docs say this can't be done :-). JRA.
*******************************************************/

static int owner_set(struct cli_state *cli, enum chown_mode change_mode, 
		     char *filename, char *new_username)
{
	int fnum;
	DOM_SID sid;
	SEC_DESC *sd, *old;
	size_t sd_size;

	fnum = cli_nt_create(cli, filename, CREATE_ACCESS_READ);

	if (fnum == -1) {
		printf("Failed to open %s: %s\n", filename, cli_errstr(cli));
		return EXIT_FAILED;
	}

	if (!StringToSid(&sid, new_username))
		return EXIT_PARSE_ERROR;

	old = cli_query_secdesc(cli, fnum, ctx);

	cli_close(cli, fnum);

	if (!old) {
		printf("owner_set: Failed to query old descriptor\n");
		return EXIT_FAILED;
	}

	sd = make_sec_desc(ctx,old->revision,
				(change_mode == REQUEST_CHOWN) ? &sid : old->owner_sid,
				(change_mode == REQUEST_CHGRP) ? &sid : old->grp_sid,
			   NULL, old->dacl, &sd_size);

	fnum = cli_nt_create(cli, filename, CREATE_ACCESS_WRITE);

	if (fnum == -1) {
		printf("Failed to open %s: %s\n", filename, cli_errstr(cli));
		return EXIT_FAILED;
	}

	if (!cli_set_secdesc(cli, fnum, sd)) {
		printf("ERROR: secdesc set failed: %s\n", cli_errstr(cli));
	}

	cli_close(cli, fnum);

	return EXIT_OK;
}


/* The MSDN is contradictory over the ordering of ACE entries in an ACL.
   However NT4 gives a "The information may have been modified by a
   computer running Windows NT 5.0" if denied ACEs do not appear before
   allowed ACEs. */

static int ace_compare(SEC_ACE *ace1, SEC_ACE *ace2)
{
	if (sec_ace_equal(ace1, ace2)) 
		return 0;

	if (ace1->type != ace2->type) 
		return ace2->type - ace1->type;

	if (sid_compare(&ace1->trustee, &ace2->trustee)) 
		return sid_compare(&ace1->trustee, &ace2->trustee);

	if (ace1->flags != ace2->flags) 
		return ace1->flags - ace2->flags;

	if (ace1->info.mask != ace2->info.mask) 
		return ace1->info.mask - ace2->info.mask;

	if (ace1->size != ace2->size) 
		return ace1->size - ace2->size;

	return memcmp(ace1, ace2, sizeof(SEC_ACE));
}

static void sort_acl(SEC_ACL *the_acl)
{
	uint32 i;
	if (!the_acl) return;

	qsort(the_acl->ace, the_acl->num_aces, sizeof(the_acl->ace[0]), QSORT_CAST ace_compare);

	for (i=1;i<the_acl->num_aces;) {
		if (sec_ace_equal(&the_acl->ace[i-1], &the_acl->ace[i])) {
			int j;
			for (j=i; j<the_acl->num_aces-1; j++) {
				the_acl->ace[j] = the_acl->ace[j+1];
			}
			the_acl->num_aces--;
		} else {
			i++;
		}
	}
}

/***************************************************** 
set the ACLs on a file given an ascii description
*******************************************************/
static int cacl_set(struct cli_state *cli, char *filename, 
		    char *the_acl, enum acl_mode mode)
{
	int fnum;
	SEC_DESC *sd, *old;
	uint32 i, j;
	size_t sd_size;
	int result = EXIT_OK;

	sd = sec_desc_parse(the_acl);

	if (!sd) return EXIT_PARSE_ERROR;
	if (test_args) return EXIT_OK;

	/* The desired access below is the only one I could find that works
	   with NT4, W2KP and Samba */

	fnum = cli_nt_create(cli, filename, CREATE_ACCESS_READ);

	if (fnum == -1) {
		printf("cacl_set failed to open %s: %s\n", filename, cli_errstr(cli));
		return EXIT_FAILED;
	}

	old = cli_query_secdesc(cli, fnum, ctx);

	if (!old) {
		printf("calc_set: Failed to query old descriptor\n");
		return EXIT_FAILED;
	}

	cli_close(cli, fnum);

	/* the logic here is rather more complex than I would like */
	switch (mode) {
	case SMB_ACL_DELETE:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			BOOL found = False;

			for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
				if (sec_ace_equal(&sd->dacl->ace[i],
						  &old->dacl->ace[j])) {
					uint32 k;
					for (k=j; k<old->dacl->num_aces-1;k++) {
						old->dacl->ace[k] = old->dacl->ace[k+1];
					}
					old->dacl->num_aces--;
					if (old->dacl->num_aces == 0) {
						SAFE_FREE(old->dacl->ace);
						SAFE_FREE(old->dacl);
						old->off_dacl = 0;
					}
					found = True;
					break;
				}
			}

			if (!found) {
				printf("ACL for ACE:"); 
				print_ace(stdout, &sd->dacl->ace[i]);
				printf(" not found\n");
			}
		}
		break;

	case SMB_ACL_MODIFY:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			BOOL found = False;

			for (j=0;old->dacl && j<old->dacl->num_aces;j++) {
				if (sid_equal(&sd->dacl->ace[i].trustee,
					      &old->dacl->ace[j].trustee)) {
					old->dacl->ace[j] = sd->dacl->ace[i];
					found = True;
				}
			}

			if (!found) {
				fstring str;

				SidToString(str, &sd->dacl->ace[i].trustee);
				printf("ACL for SID %s not found\n", str);
			}
		}

		break;

	case SMB_ACL_ADD:
		for (i=0;sd->dacl && i<sd->dacl->num_aces;i++) {
			add_ace(&old->dacl, &sd->dacl->ace[i]);
		}
		break;

	case SMB_ACL_SET:
 		old = sd;
		break;
	}

	/* Denied ACE entries must come before allowed ones */
	sort_acl(old->dacl);

	/* Create new security descriptor and set it */
	sd = make_sec_desc(ctx,old->revision, old->owner_sid, old->grp_sid, 
			   NULL, old->dacl, &sd_size);

	fnum = cli_nt_create(cli, filename, CREATE_ACCESS_WRITE);

	if (fnum == -1) {
		printf("cacl_set failed to open %s: %s\n", filename, cli_errstr(cli));
		return EXIT_FAILED;
	}

	if (!cli_set_secdesc(cli, fnum, sd)) {
		printf("ERROR: secdesc set failed: %s\n", cli_errstr(cli));
		result = EXIT_FAILED;
	}

	/* Clean up */

	cli_close(cli, fnum);

	return result;
}


/***************************************************** 
return a connection to a server
*******************************************************/
struct cli_state *connect_one(char *share)
{
	struct cli_state *c;
	struct nmb_name called, calling;
	struct in_addr ip;
	extern pstring global_myname;

	fstrcpy(server,share+2);
	share = strchr(server,'\\');
	if (!share) return NULL;
	*share = 0;
	share++;

	zero_ip(&ip);

	make_nmb_name(&calling, global_myname, 0x0);
	make_nmb_name(&called , server, 0x20);

 again:
	zero_ip(&ip);

	/* have to open a new connection */
	if (!(c=cli_initialise(NULL)) || !cli_connect(c, server, &ip)) {
		DEBUG(0,("Connection to %s failed\n", server));
		cli_shutdown(c);
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
			       (workgroup[0] ? workgroup : lp_workgroup()))) {
		DEBUG(0,("session setup failed: %s\n", cli_errstr(c)));
		cli_shutdown(c);
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
	printf("Usage: smbcacls //server1/share1 filename [options]\n");
	printf("Version: %s\n", VERSION);
	printf(
"\n\
\t-D <acls>               delete an acl\n\
\t-M <acls>               modify an acl\n\
\t-A <acls>               add an acl\n\
\t-S <acls>               set acls\n\
\t-C username             change ownership of a file\n\
\t-G username             change group ownership of a file\n\
\t-n                      don't resolve sids or masks to names\n\
\t-h                      print help\n\
\t-d debuglevel           set debug output level\n\
\t-U username             user to autheticate as\n\
\t-W workgroup or domain  workgroup or domain user is in\n\
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
	pstring filename;
	extern char *optarg;
	extern int optind;
	extern FILE *dbf;
	int opt;
	char *p;
	static pstring servicesf = CONFIGFILE;
	struct cli_state *cli=NULL;
	enum acl_mode mode = SMB_ACL_SET;
	char *the_acl = NULL;
	enum chown_mode change_mode = REQUEST_NONE;
	int result;

	ctx=talloc_init();

	setlinebuf(stdout);

	dbf = stderr;

	if (argc < 3 || argv[1][0] == '-') {
		usage();
		talloc_destroy(ctx);
		exit(EXIT_PARSE_ERROR);
	}

	setup_logging(argv[0],True);

	share = argv[1];
	pstrcpy(filename, argv[2]);
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

		if ((p=strchr(username,'%'))) {
			*p = 0;
			pstrcpy(password,p+1);
			got_pass = True;
			memset(strchr(getenv("USER"), '%') + 1, 'X',
			       strlen(password));
		}
	}

	while ((opt = getopt(argc, argv, "U:nhdS:D:A:M:C:G:t")) != EOF) {
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

                case 'W':
                        pstrcpy(workgroup, optarg);
                        break;

		case 'S':
			the_acl = optarg;
			mode = SMB_ACL_SET;
			break;

		case 'D':
			the_acl = optarg;
			mode = SMB_ACL_DELETE;
			break;

		case 'M':
			the_acl = optarg;
			mode = SMB_ACL_MODIFY;
			break;

		case 'A':
			the_acl = optarg;
			mode = SMB_ACL_ADD;
			break;

		case 'C':
			pstrcpy(owner_username,optarg);
			change_mode = REQUEST_CHOWN;
			break;

		case 'G':
			pstrcpy(owner_username,optarg);
			change_mode = REQUEST_CHGRP;
			break;

		case 'n':
			numeric = 1;
			break;

		case 't':
			test_args = 1;
			break;

		case 'h':
			usage();
			talloc_destroy(ctx);
			exit(EXIT_PARSE_ERROR);

		case 'd':
			DEBUGLEVEL = atoi(optarg);
			break;

		default:
			printf("Unknown option %c (%d)\n", (char)opt, opt);
			talloc_destroy(ctx);
			exit(EXIT_PARSE_ERROR);
		}
	}

	argc -= optind;
	argv += optind;
	
	if (argc > 0) {
		usage();
		talloc_destroy(ctx);
		exit(EXIT_PARSE_ERROR);
	}

	/* Make connection to server */

	if (!test_args) {
		cli = connect_one(share);
		if (!cli) {
			talloc_destroy(ctx);
			exit(EXIT_FAILED);
		}
	}

	all_string_sub(filename, "/", "\\", 0);
	if (filename[0] != '\\') {
		pstring s;
		s[0] = '\\';
		safe_strcpy(&s[1], filename, sizeof(pstring)-1);
		pstrcpy(filename, s);
	}

	/* Perform requested action */

	if (change_mode != REQUEST_NONE) {
		result = owner_set(cli, change_mode, filename, owner_username);
	} else if (the_acl) {
		result = cacl_set(cli, filename, the_acl, mode);
	} else {
		result = cacl_dump(cli, filename);
	}

	talloc_destroy(ctx);

	return result;
}
