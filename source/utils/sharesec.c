/*
 *  Unix SMB/Netbios implementation.
 *  Utility for managing share permissions
 *
 *  Copyright (C) Tim Potter                    2000
 *  Copyright (C) Jeremy Allison                2000
 *  Copyright (C) Jelmer Vernooij               2003
 *  Copyright (C) Gerald (Jerry) Carter         2005.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"

#define CREATE_ACCESS_READ READ_CONTROL_ACCESS

/* numeric is set when the user wants numeric SIDs and ACEs rather
   than going via LSA calls to resolve them */
static BOOL numeric = False;

enum acl_mode {SMB_ACL_REMOVE, SMB_ACL_MODIFY, SMB_ACL_ADD, SMB_ACL_REPLACE,  SMB_ACL_VIEW };
enum exit_values {EXIT_OK, EXIT_FAILED, EXIT_PARSE_ERROR};

struct perm_value {
	const char *perm;
	uint32 mask;
};

/* These values discovered by inspection */

static const struct perm_value special_values[] = {
	{ "R", 0x00120089 },
	{ "W", 0x00120116 },
	{ "X", 0x001200a0 },
	{ "D", 0x00010000 },
	{ "P", 0x00040000 },
	{ "O", 0x00080000 },
	{ NULL, 0 },
};

static const struct perm_value standard_values[] = {
	{ "READ",   0x001200a9 },
	{ "CHANGE", 0x001301bf },
	{ "FULL",   0x001f01ff },
	{ NULL, 0 },
};

/********************************************************************
 print an ACE on a FILE, using either numeric or ascii representation
********************************************************************/

static void print_ace(FILE *f, SEC_ACE *ace)
{
	const struct perm_value *v;
	fstring sidstr;
	int do_print = 0;
	uint32 got_mask;

	sid_to_string(sidstr, &ace->trustee);

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

/********************************************************************
 print a ascii version of a security descriptor on a FILE handle
********************************************************************/

static void sec_desc_print(FILE *f, SEC_DESC *sd)
{
	fstring sidstr;
	uint32 i;

	fprintf(f, "REVISION:%d\n", sd->revision);

	/* Print owner and group sid */

	if (sd->owner_sid) {
		sid_to_string(sidstr, sd->owner_sid);
	} else {
		fstrcpy(sidstr, "");
	}

	fprintf(f, "OWNER:%s\n", sidstr);

	if (sd->grp_sid) {
		sid_to_string(sidstr, sd->grp_sid);
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

/********************************************************************
********************************************************************/

static BOOL parse_ace( TALLOC_CTX *ctx, SEC_ACE *ace, char *entry )
{
	SEC_ACCESS sa;
	char *p = strchr_m( entry, ':' );
	DOM_SID sid;
	uint32 mask;
	
	if ( !p )
		return False;
		
	*p = '\0';
	p++;
	
	string_to_sid( &sid, entry );
	
	switch ( *p ) {
		case 'F':
		case 'f':
			mask = GENERIC_RIGHTS_FILE_ALL_ACCESS|STD_RIGHT_ALL_ACCESS;
			break;

		case 'R':
		case 'r':
			mask = GENERIC_RIGHTS_FILE_READ|GENERIC_RIGHTS_FILE_EXECUTE|\
				STANDARD_RIGHTS_READ_ACCESS|STANDARD_RIGHTS_EXECUTE_ACCESS;
			break;

		default:
			return False;
	}
	
	init_sec_access( &sa, mask );

	/* no flags on share permissions */
	init_sec_ace( ace, &sid, SEC_ACE_TYPE_ACCESS_ALLOWED, sa, 0 );
	
	return True;
}


/********************************************************************
********************************************************************/

static SEC_DESC* parse_acl_string( TALLOC_CTX *ctx, const char *szACL, size_t *sd_size )
{
	SEC_DESC *sd = NULL;
	SEC_ACE *ace;
	SEC_ACL *acl;
	int num_ace;
	const char *pacl;
	int i;
	
	if ( !szACL )
		return NULL;

	pacl = szACL;
	num_ace = count_chars( pacl, ',' ) + 1;
	
	if ( !(ace = TALLOC_ZERO_ARRAY( ctx, SEC_ACE, num_ace )) ) 
		return NULL;
	
	for ( i=0; i<num_ace; i++ ) {
		char *end_acl = strchr_m( pacl, ',' );
		fstring acl_string;

		strncpy( acl_string, pacl, MIN( PTR_DIFF( end_acl, pacl ), sizeof(fstring)-1) );
		acl_string[MIN( PTR_DIFF( end_acl, pacl ), sizeof(fstring)-1)] = '\0';
		
		if ( !parse_ace( ctx, &ace[i], acl_string ) )
			return NULL;

		pacl = end_acl;
		pacl++;
	}
	
	if ( !(acl = make_sec_acl( ctx, NT4_ACL_REVISION, num_ace, ace )) )
		return NULL;
		
	sd = make_sec_desc( ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE, 
		&global_sid_Builtin_Administrators,
		&global_sid_Builtin_Administrators,
		NULL, acl, sd_size);

	return sd;
}

/********************************************************************
  main program
********************************************************************/

int main(int argc, const char *argv[])
{
	int opt;
	enum acl_mode mode = SMB_ACL_REPLACE;
	static char *the_acl = NULL;
	fstring sharename;
	BOOL force_acl = False;
	size_t sd_size = 0;
	SEC_DESC *secdesc;
	int snum;
	poptContext pc;
	TALLOC_CTX *ctx;
	BOOL initialize_sid = False;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
#if 0
		{ "remove", 'r', POPT_ARG_STRING, NULL, 'r', "Delete an ACE", "ACL" },
		{ "modify", 'm', POPT_ARG_STRING, NULL, 'm', "Modify an acl", "ACL" },
		{ "add", 'a', POPT_ARG_STRING, NULL, 'a', "Add an ACE", "ACL" },
#endif
		{ "replace", 'R', POPT_ARG_STRING, NULL, 'R', "Set share mission ACL", "ACLS" },
		{ "view", 'v', POPT_ARG_NONE, NULL, 'v', "View current share permissions" },
		{ "machine-sid", 'M', POPT_ARG_NONE, NULL, 'M', "Initialize the machine SID" },
		{ "force", 'F', POPT_ARG_NONE, NULL, 'F', "Force storing the ACL", "ACLS" },
		POPT_COMMON_SAMBA
		{ NULL }
	};

	if ( !(ctx = talloc_init("main")) ) {
		fprintf( stderr, "Failed to initialize talloc context!\n");
		return -1;
	}

	/* set default debug level to 1 regardless of what smb.conf sets */
	setup_logging( "sharesec", True );
	DEBUGLEVEL_CLASS[DBGC_ALL] = 1;
	dbf = x_stderr;
	x_setbuf( x_stderr, NULL );

	setlinebuf(stdout);

	load_case_tables();

	lp_load( dyn_CONFIGFILE, False, False, False, True );

	pc = poptGetContext("smbcacls", argc, argv, long_options, 0);
	
	poptSetOtherOptionHelp(pc, "sharename\n");

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
#if 0
		case 'r':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_REMOVE;
			break;

		case 'm':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_MODIFY;
			break;

		case 'a':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_ADD;
			break;
#endif
		case 'R':
			the_acl = smb_xstrdup(poptGetOptArg(pc));
			mode = SMB_ACL_REPLACE;
			break;

		case 'v':
			mode = SMB_ACL_VIEW;
			break;

		case 'F':
			force_acl = True;
			break;
			
		case 'M':
			initialize_sid = True;
			break;
		}
	}
	
	/* check for initializing secrets.tdb first */
	
	if ( initialize_sid ) {
		DOM_SID *sid = get_global_sam_sid();
		
		if ( !sid ) {
			fprintf( stderr, "Failed to retrieve Machine SID!\n");
			return 3;
		}
		
		printf ("%s\n", sid_string_static( sid ) );
		return 0;
	}

	if ( mode == SMB_ACL_VIEW && force_acl ) {
		fprintf( stderr, "Invalid combination of -F and -v\n");
		return -1;
	}

	/* get the sharename */

	if(!poptPeekArg(pc)) { 
		poptPrintUsage(pc, stderr, 0);	
		return -1;
	}
	
	fstrcpy(sharename, poptGetArg(pc));
	
	snum = lp_servicenumber( sharename );
	
	if ( snum == -1 && !force_acl ) {
		fprintf( stderr, "Invalid sharename: %s\n", sharename);
		return -1;
	}
		
	switch ( mode ) {
		case SMB_ACL_VIEW:
			if (!(secdesc = get_share_security( ctx, sharename,
							    &sd_size )) ) {
				fprintf(stderr, "Unable to retrieve permissions for share [%s]\n", sharename);
				return -1;
			}
			sec_desc_print( stdout, secdesc );
			break;

		case SMB_ACL_REMOVE:
		case SMB_ACL_ADD:
		case SMB_ACL_MODIFY:
			printf( "Not implemented\n");
			break;

		case SMB_ACL_REPLACE:
			if ( !(secdesc = parse_acl_string( ctx, the_acl, &sd_size )) ) {
				fprintf( stderr, "Failed to parse acl\n");
				return -1;
			}
			
			if ( !set_share_security( lp_servicename(snum), secdesc ) ) {
				fprintf( stderr, "Failed to store acl for share [%s]\n", sharename );
				return 2;
			}
			break;
	}

	talloc_destroy(ctx);

	return 0;
}
