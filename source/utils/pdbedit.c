/* 
   Unix SMB/CIFS implementation.
   passdb editing frontend
   
   Copyright (C) Simo Sorce      2000
   Copyright (C) Andrew Bartlett 2001   
   Copyright (C) Jelmer Vernooij 2002

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

#define BIT_BACKEND	0x00000004
#define BIT_VERBOSE	0x00000008
#define BIT_SPSTYLE	0x00000010
#define BIT_RESERV_1	0x00000020
#define BIT_RESERV_2	0x00000040
#define BIT_RESERV_3	0x00000080
#define BIT_FULLNAME	0x00000100
#define BIT_HOMEDIR	0x00000200
#define BIT_HDIRDRIVE	0x00000400
#define BIT_LOGSCRIPT	0x00000800
#define BIT_PROFILE	0x00001000
#define BIT_MACHINE	0x00002000
#define BIT_RESERV_4	0x00004000
#define BIT_USER	0x00008000
#define BIT_LIST	0x00010000
#define BIT_MODIFY	0x00020000
#define BIT_CREATE	0x00040000
#define BIT_DELETE	0x00080000
#define BIT_ACCPOLICY	0x00100000
#define BIT_ACCPOLVAL	0x00200000
#define BIT_RESERV_6	0x00400000
#define BIT_RESERV_7	0x00800000
#define BIT_IMPORT	0x01000000
#define BIT_EXPORT	0x02000000

#define MASK_ALWAYS_GOOD	0x0000001F
#define MASK_USER_GOOD		0x00001F00

/*********************************************************
 Add all currently available users to another db
 ********************************************************/

static int export_database (struct pdb_context *in, struct pdb_context *out) {
	SAM_ACCOUNT *user = NULL;

	if (NT_STATUS_IS_ERR(in->pdb_setsampwent(in, 0))) {
		fprintf(stderr, "Can't sampwent!\n");
		return 1;
	}

	if (!NT_STATUS_IS_OK(pdb_init_sam(&user))) {
		fprintf(stderr, "Can't initialize new SAM_ACCOUNT!\n");
		return 1;
	}

	while (NT_STATUS_IS_OK(in->pdb_getsampwent(in, user))) {
		out->pdb_add_sam_account(out, user);
		if (!NT_STATUS_IS_OK(pdb_reset_sam(user))){
			fprintf(stderr, "Can't reset SAM_ACCOUNT!\n");
			return 1;
		}
	}

	in->pdb_endsampwent(in);

	return 0;
}

/*********************************************************
 Print info from sam structure
**********************************************************/

static int print_sam_info (SAM_ACCOUNT *sam_pwent, BOOL verbosity, BOOL smbpwdstyle)
{
	uid_t uid;
	gid_t gid;
	time_t tmp;

	/* TODO: chaeck if entry is a user or a workstation */
	if (!sam_pwent) return -1;
	
	if (verbosity) {
		printf ("Unix username:        %s\n", pdb_get_username(sam_pwent));
		printf ("NT username:          %s\n", pdb_get_nt_username(sam_pwent));
		printf ("Account Flags:        %s\n", pdb_encode_acct_ctrl(pdb_get_acct_ctrl(sam_pwent), NEW_PW_FORMAT_SPACE_PADDED_LEN));
		
		if (IS_SAM_UNIX_USER(sam_pwent)) {
			uid = pdb_get_uid(sam_pwent);
			gid = pdb_get_gid(sam_pwent);
			printf ("User ID/Group ID:     %d/%d\n", uid, gid);
		}
		printf ("User SID:             %s\n",
			sid_string_static(pdb_get_user_sid(sam_pwent)));
		printf ("Primary Group SID:    %s\n",
			sid_string_static(pdb_get_group_sid(sam_pwent)));
		printf ("Full Name:            %s\n", pdb_get_fullname(sam_pwent));
		printf ("Home Directory:       %s\n", pdb_get_homedir(sam_pwent));
		printf ("HomeDir Drive:        %s\n", pdb_get_dir_drive(sam_pwent));
		printf ("Logon Script:         %s\n", pdb_get_logon_script(sam_pwent));
		printf ("Profile Path:         %s\n", pdb_get_profile_path(sam_pwent));
		printf ("Domain:               %s\n", pdb_get_domain(sam_pwent));
		printf ("Account desc:         %s\n", pdb_get_acct_desc(sam_pwent));
		printf ("Workstations:         %s\n", pdb_get_workstations(sam_pwent));
		printf ("Munged dial:          %s\n", pdb_get_munged_dial(sam_pwent));
		
		tmp = pdb_get_logon_time(sam_pwent);
		printf ("Logon time:           %s\n", tmp ? http_timestring(tmp) : "0");
		
		tmp = pdb_get_logoff_time(sam_pwent);
		printf ("Logoff time:          %s\n", tmp ? http_timestring(tmp) : "0");
		
		tmp = pdb_get_kickoff_time(sam_pwent);
		printf ("Kickoff time:         %s\n", tmp ? http_timestring(tmp) : "0");
		
		tmp = pdb_get_pass_last_set_time(sam_pwent);
		printf ("Password last set:    %s\n", tmp ? http_timestring(tmp) : "0");
		
		tmp = pdb_get_pass_can_change_time(sam_pwent);
		printf ("Password can change:  %s\n", tmp ? http_timestring(tmp) : "0");
		
		tmp = pdb_get_pass_must_change_time(sam_pwent);
		printf ("Password must change: %s\n", tmp ? http_timestring(tmp) : "0");
		
	} else if (smbpwdstyle) {
		if (IS_SAM_UNIX_USER(sam_pwent)) {
			char lm_passwd[33];
			char nt_passwd[33];

			uid = pdb_get_uid(sam_pwent);
			pdb_sethexpwd(lm_passwd, 
				      pdb_get_lanman_passwd(sam_pwent), 
				      pdb_get_acct_ctrl(sam_pwent));
			pdb_sethexpwd(nt_passwd, 
				      pdb_get_nt_passwd(sam_pwent), 
				      pdb_get_acct_ctrl(sam_pwent));
			
			printf("%s:%d:%s:%s:%s:LCT-%08X:\n",
			       pdb_get_username(sam_pwent),
			       uid,
			       lm_passwd,
			       nt_passwd,
			       pdb_encode_acct_ctrl(pdb_get_acct_ctrl(sam_pwent),NEW_PW_FORMAT_SPACE_PADDED_LEN),
			       (uint32)pdb_get_pass_last_set_time(sam_pwent));
		} else {
			fprintf(stderr, "Can't output in smbpasswd format, no uid on this record.\n");
		}
	} else {
		if (IS_SAM_UNIX_USER(sam_pwent)) {
			printf ("%s:%d:%s\n", pdb_get_username(sam_pwent), pdb_get_uid(sam_pwent), 
				pdb_get_fullname(sam_pwent));
		} else {	
			printf ("%s:(null):%s\n", pdb_get_username(sam_pwent), pdb_get_fullname(sam_pwent));
		}
	}

	return 0;	
}

/*********************************************************
 Get an Print User Info
**********************************************************/

static int print_user_info (struct pdb_context *in, const char *username, BOOL verbosity, BOOL smbpwdstyle)
{
	SAM_ACCOUNT *sam_pwent=NULL;
	BOOL ret;
	
	if (!NT_STATUS_IS_OK(pdb_init_sam (&sam_pwent))) {
		return -1;
	}
	
	ret = NT_STATUS_IS_OK(in->pdb_getsampwnam (in, sam_pwent, username));

	if (ret==False) {
		fprintf (stderr, "Username not found!\n");
		pdb_free_sam(&sam_pwent);
		return -1;
	}
	
	ret=print_sam_info (sam_pwent, verbosity, smbpwdstyle);
	pdb_free_sam(&sam_pwent);
	
	return ret;
}
	
/*********************************************************
 List Users
**********************************************************/
static int print_users_list (struct pdb_context *in, BOOL verbosity, BOOL smbpwdstyle)
{
	SAM_ACCOUNT *sam_pwent=NULL;
	BOOL check, ret;
	
	check = NT_STATUS_IS_OK(in->pdb_setsampwent(in, False));
	if (!check) {
		return 1;
	}

	check = True;
	if (!(NT_STATUS_IS_OK(pdb_init_sam(&sam_pwent)))) return 1;

	while (check && (ret = NT_STATUS_IS_OK(in->pdb_getsampwent (in, sam_pwent)))) {
		if (verbosity)
			printf ("---------------\n");
		print_sam_info (sam_pwent, verbosity, smbpwdstyle);
		pdb_free_sam(&sam_pwent);
		check = NT_STATUS_IS_OK(pdb_init_sam(&sam_pwent));
	}
	if (check) pdb_free_sam(&sam_pwent);
	
	in->pdb_endsampwent(in);
	return 0;
}

/*********************************************************
 Set User Info
**********************************************************/

static int set_user_info (struct pdb_context *in, char *username, char *fullname, char *homedir, char *drive, char *script, char *profile)
{
	SAM_ACCOUNT *sam_pwent=NULL;
	BOOL ret;
	
	pdb_init_sam(&sam_pwent);
	
	ret = NT_STATUS_IS_OK(in->pdb_getsampwnam (in, sam_pwent, username));
	if (ret==False) {
		fprintf (stderr, "Username not found!\n");
		pdb_free_sam(&sam_pwent);
		return -1;
	}
	
	if (fullname)
		pdb_set_fullname(sam_pwent, fullname, PDB_CHANGED);
	if (homedir)
		pdb_set_homedir(sam_pwent, homedir, PDB_CHANGED);
	if (drive)
		pdb_set_dir_drive(sam_pwent,drive, PDB_CHANGED);
	if (script)
		pdb_set_logon_script(sam_pwent, script, PDB_CHANGED);
	if (profile)
		pdb_set_profile_path (sam_pwent, profile, PDB_CHANGED);
	
	if (NT_STATUS_IS_OK(in->pdb_update_sam_account (in, sam_pwent)))
		print_user_info (in, username, True, False);
	else {
		fprintf (stderr, "Unable to modify entry!\n");
		pdb_free_sam(&sam_pwent);
		return -1;
	}
	pdb_free_sam(&sam_pwent);
	return 0;
}

/*********************************************************
 Add New User
**********************************************************/
static int new_user (struct pdb_context *in, char *username, char *fullname, char *homedir, char *drive, char *script, char *profile)
{
	SAM_ACCOUNT *sam_pwent=NULL;
	struct passwd  *pwd = NULL;
	char *password1, *password2, *staticpass;
	
	ZERO_STRUCT(sam_pwent);

	if ((pwd = getpwnam_alloc(username))) {
		pdb_init_sam_pw (&sam_pwent, pwd);
		passwd_free(&pwd);
	} else {
		fprintf (stderr, "WARNING: user %s does not exist in system passwd\n", username);
		pdb_init_sam(&sam_pwent);
		if (!pdb_set_username(sam_pwent, username, PDB_CHANGED)) {
			return False;
		}
	}

	staticpass = getpass("new password:");
	password1 = strdup(staticpass);
	memset(staticpass, 0, strlen(staticpass));
	staticpass = getpass("retype new password:");
	password2 = strdup(staticpass);
	memset(staticpass, 0, strlen(staticpass));
	if (strcmp (password1, password2)) {
		fprintf (stderr, "Passwords does not match!\n");
		memset(password1, 0, strlen(password1));
		SAFE_FREE(password1);
		memset(password2, 0, strlen(password2));
		SAFE_FREE(password2);
		pdb_free_sam (&sam_pwent);
		return -1;
	}

	pdb_set_plaintext_passwd(sam_pwent, password1);
	memset(password1, 0, strlen(password1));
	SAFE_FREE(password1);
	memset(password2, 0, strlen(password2));
	SAFE_FREE(password2);

	if (fullname)
		pdb_set_fullname(sam_pwent, fullname, PDB_CHANGED);
	if (homedir)
		pdb_set_homedir (sam_pwent, homedir, PDB_CHANGED);
	if (drive)
		pdb_set_dir_drive (sam_pwent, drive, PDB_CHANGED);
	if (script)
		pdb_set_logon_script(sam_pwent, script, PDB_CHANGED);
	if (profile)
		pdb_set_profile_path (sam_pwent, profile, PDB_CHANGED);
	
	pdb_set_acct_ctrl (sam_pwent, ACB_NORMAL, PDB_CHANGED);
	
	if (NT_STATUS_IS_OK(in->pdb_add_sam_account (in, sam_pwent))) { 
		print_user_info (in, username, True, False);
	} else {
		fprintf (stderr, "Unable to add user! (does it alredy exist?)\n");
		pdb_free_sam (&sam_pwent);
		return -1;
	}
	pdb_free_sam (&sam_pwent);
	return 0;
}

/*********************************************************
 Add New Machine
**********************************************************/

static int new_machine (struct pdb_context *in, char *machinename)
{
	SAM_ACCOUNT *sam_pwent=NULL;
	char name[16];
	char *password = NULL;
	
	if (!NT_STATUS_IS_OK(pdb_init_sam (&sam_pwent))) {
		return -1;
	}

	if (machinename[strlen (machinename) -1] == '$')
		machinename[strlen (machinename) -1] = '\0';
	
	safe_strcpy (name, machinename, 16);
	safe_strcat (name, "$", 16);
	
	string_set (&password, machinename);
	strlower_m(password);
	
	pdb_set_plaintext_passwd (sam_pwent, password);

	pdb_set_username (sam_pwent, name, PDB_CHANGED);
	
	pdb_set_acct_ctrl (sam_pwent, ACB_WSTRUST, PDB_CHANGED);
	
	pdb_set_group_sid_from_rid(sam_pwent, DOMAIN_GROUP_RID_COMPUTERS, PDB_CHANGED);
	
	if (NT_STATUS_IS_OK(in->pdb_add_sam_account (in, sam_pwent))) {
		print_user_info (in, name, True, False);
	} else {
		fprintf (stderr, "Unable to add machine! (does it already exist?)\n");
		pdb_free_sam (&sam_pwent);
		return -1;
	}
	pdb_free_sam (&sam_pwent);
	return 0;
}

/*********************************************************
 Delete user entry
**********************************************************/

static int delete_user_entry (struct pdb_context *in, char *username)
{
	SAM_ACCOUNT *samaccount = NULL;

	if (!NT_STATUS_IS_OK(pdb_init_sam (&samaccount))) {
		return -1;
	}

	if (NT_STATUS_IS_ERR(in->pdb_getsampwnam(in, samaccount, username))) {
		fprintf (stderr, "user %s does not exist in the passdb\n", username);
		return -1;
	}

	return NT_STATUS_IS_OK(in->pdb_delete_sam_account (in, samaccount));
}

/*********************************************************
 Delete machine entry
**********************************************************/

static int delete_machine_entry (struct pdb_context *in, char *machinename)
{
	char name[16];
	SAM_ACCOUNT *samaccount = NULL;
	
	safe_strcpy (name, machinename, 16);
	if (name[strlen(name)] != '$')
		safe_strcat (name, "$", 16);

	if (!NT_STATUS_IS_OK(pdb_init_sam (&samaccount))) {
		return -1;
	}

	if (NT_STATUS_IS_ERR(in->pdb_getsampwnam(in, samaccount, name))) {
		fprintf (stderr, "machine %s does not exist in the passdb\n", name);
		return -1;
	}

	return NT_STATUS_IS_OK(in->pdb_delete_sam_account (in, samaccount));
}

/*********************************************************
 Start here.
**********************************************************/

int main (int argc, char **argv)
{
	static BOOL list_users = False;
	static BOOL verbose = False;
	static BOOL spstyle = False;
	static BOOL machine = False;
	static BOOL add_user = False;
	static BOOL delete_user = False;
	static BOOL modify_user = False;
	uint32	setparms, checkparms;
	int opt;
	static char *full_name = NULL;
	static char *user_name = NULL;
	static char *home_dir = NULL;
	static char *home_drive = NULL;
	static char *backend = NULL;
	static char *backend_in = NULL;
	static char *backend_out = NULL;
	static char *logon_script = NULL;
	static char *profile_path = NULL;
	static char *account_policy = NULL;
	static long int account_policy_value = 0;
	BOOL account_policy_value_set = False;

	struct pdb_context *bin;
	struct pdb_context *bout;
	struct pdb_context *bdef;
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"list",	'l', POPT_ARG_NONE, &list_users, 0, "list all users", NULL},
		{"verbose",	'v', POPT_ARG_NONE, &verbose, 0, "be verbose", NULL },
		{"smbpasswd-style",	'w',POPT_ARG_NONE, &spstyle, 0, "give output in smbpasswd style", NULL},
		{"user",	'u', POPT_ARG_STRING, &user_name, 0, "use username", "USER" },
		{"fullname",	'f', POPT_ARG_STRING, &full_name, 0, "set full name", NULL},
		{"homedir",	'h', POPT_ARG_STRING, &home_dir, 0, "set home directory", NULL},
		{"drive",	'D', POPT_ARG_STRING, &home_drive, 0, "set home drive", NULL},
		{"script",	'S', POPT_ARG_STRING, &logon_script, 0, "set logon script", NULL},
		{"profile",	'p', POPT_ARG_STRING, &profile_path, 0, "set profile path", NULL},
		{"create",	'a', POPT_ARG_NONE, &add_user, 0, "create user", NULL},
		{"modify",	'r', POPT_ARG_NONE, &modify_user, 0, "modify user", NULL},
		{"machine",	'm', POPT_ARG_NONE, &machine, 0, "account is a machine account", NULL},
		{"delete",	'x', POPT_ARG_NONE, &delete_user, 0, "delete user", NULL},
		{"backend",	'b', POPT_ARG_STRING, &backend, 0, "use different passdb backend as default backend", NULL},
		{"import",	'i', POPT_ARG_STRING, &backend_in, 0, "import user accounts from this backend", NULL},
		{"export",	'e', POPT_ARG_STRING, &backend_out, 0, "export user accounts to this backend", NULL},
		{"account-policy",	'P', POPT_ARG_STRING, &account_policy, 0,"value of an account policy (like maximum password age)",NULL},
		{"value",       'V', POPT_ARG_LONG, &account_policy_value, 'V',"set the account policy to this value", NULL},
		{ NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_debug },
		{ NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_configfile },
		{0,0,0,0}
	};
	
	setup_logging("pdbedit", True);
	
	pc = poptGetContext(NULL, argc, (const char **) argv, long_options,
			    POPT_CONTEXT_KEEP_FIRST);
	
	while((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case 'V':
			account_policy_value_set = True;
			break;
		}
	}

	poptGetArg(pc); /* Drop argv[0], the program name */

	if (user_name == NULL)
		user_name = poptGetArg(pc);

	if (!lp_load(dyn_CONFIGFILE,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", dyn_CONFIGFILE);
		exit(1);
	}

	if(lp_modules())
		smb_load_modules(lp_modules());
	
	if (!init_names())
		exit(1);

	setparms =	(backend ? BIT_BACKEND : 0) +
			(verbose ? BIT_VERBOSE : 0) +
			(spstyle ? BIT_SPSTYLE : 0) +
			(full_name ? BIT_FULLNAME : 0) +
			(home_dir ? BIT_HOMEDIR : 0) +
			(home_drive ? BIT_HDIRDRIVE : 0) +
			(logon_script ? BIT_LOGSCRIPT : 0) +
			(profile_path ? BIT_PROFILE : 0) +
			(machine ? BIT_MACHINE : 0) +
			(user_name ? BIT_USER : 0) +
			(list_users ? BIT_LIST : 0) +
			(modify_user ? BIT_MODIFY : 0) +
			(add_user ? BIT_CREATE : 0) +
			(delete_user ? BIT_DELETE : 0) +
			(account_policy ? BIT_ACCPOLICY : 0) +
			(account_policy_value_set ? BIT_ACCPOLVAL : 0) +
			(backend_in ? BIT_IMPORT : 0) +
			(backend_out ? BIT_EXPORT : 0);

	if (setparms & BIT_BACKEND) {
		if (!NT_STATUS_IS_OK(make_pdb_context_string(&bdef, backend))) {
			fprintf(stderr, "Can't initialize passdb backend.\n");
			return 1;
		}
	} else {
		if (!NT_STATUS_IS_OK(make_pdb_context_list(&bdef, lp_passdb_backend()))) {
			fprintf(stderr, "Can't initialize passdb backend.\n");
			return 1;
		}
	}
	
	/* the lowest bit options are always accepted */
	checkparms = setparms & ~MASK_ALWAYS_GOOD;

	/* account policy operations */
	if ((checkparms & BIT_ACCPOLICY) && !(checkparms & ~(BIT_ACCPOLICY + BIT_ACCPOLVAL))) {
		uint32 value;
		int field = account_policy_name_to_fieldnum(account_policy);
		if (field == 0) {
			fprintf(stderr, "No account policy by that name\n");
			exit(1);
		}
		if (!account_policy_get(field, &value)) {
			fprintf(stderr, "valid account policy, but unable to fetch value!\n");
			exit(1);
		}
		if (account_policy_value_set) {
			printf("account policy value for %s was %u\n", account_policy, value);
			if (!account_policy_set(field, account_policy_value)) {
				fprintf(stderr, "valid account policy, but unable to set value!\n");
				exit(1);
			}
			printf("account policy value for %s is now %lu\n", account_policy, account_policy_value);
			exit(0);
		} else {
			printf("account policy value for %s is %u\n", account_policy, value);
			exit(0);
		}
	}

	/* import and export operations */
	if (((checkparms & BIT_IMPORT) || (checkparms & BIT_EXPORT))
			&& !(checkparms & ~(BIT_IMPORT +BIT_EXPORT))) {
		if (backend_in) {
			if (!NT_STATUS_IS_OK(make_pdb_context_string(&bin, backend_in))) {
				fprintf(stderr, "Can't initialize passdb backend.\n");
				return 1;
			}
		} else {
			bin = bdef;
		}
		if (backend_out) {
			if (!NT_STATUS_IS_OK(make_pdb_context_string(&bout, backend_out))) {
				fprintf(stderr, "Can't initialize %s.\n", backend_out);
				return 1;
			}
		} else {
			bout = bdef;
		}
		return export_database(bin, bout);
	}

	/* if BIT_USER is defined but nothing else then threat it as -l -u for compatibility */
	/* fake up BIT_LIST if only BIT_USER is defined */
	if ((checkparms & BIT_USER) && !(checkparms & ~BIT_USER)) {
		checkparms += BIT_LIST;
	}
	
	/* modify flag is optional to maintain backwards compatibility */
	/* fake up BIT_MODIFY if BIT_USER  and at least one of MASK_USER_GOOD is defined */
	if (!((checkparms & ~MASK_USER_GOOD) & ~BIT_USER) && (checkparms & MASK_USER_GOOD)) {
		checkparms += BIT_MODIFY;
	}

	/* list users operations */
	if (checkparms & BIT_LIST) {
		if (!(checkparms & ~BIT_LIST)) {
			return print_users_list (bdef, verbose, spstyle);
		}
		if (!(checkparms & ~(BIT_USER + BIT_LIST))) {
			return print_user_info (bdef, user_name, verbose, spstyle);
		}
	}
	
	/* mask out users options */
	checkparms &= ~MASK_USER_GOOD;
	
	/* account operation */
	if ((checkparms & BIT_CREATE) || (checkparms & BIT_MODIFY) || (checkparms & BIT_DELETE)) {
		/* check use of -u option */
		if (!(checkparms & BIT_USER)) {
			fprintf (stderr, "Username not specified! (use -u option)\n");
			return -1;
		}

		/* account creation operations */
		if (!(checkparms & ~(BIT_CREATE + BIT_USER + BIT_MACHINE))) {
		       	if (checkparms & BIT_MACHINE) {
				return new_machine (bdef, user_name);
			} else {
				return new_user (bdef, user_name, full_name, home_dir, 
						 home_drive, logon_script, 
						 profile_path);
			}
		}

		/* account deletion operations */
		if (!(checkparms & ~(BIT_DELETE + BIT_USER + BIT_MACHINE))) {
		       	if (checkparms & BIT_MACHINE) {
				return delete_machine_entry (bdef, user_name);
			} else {
				return delete_user_entry (bdef, user_name);
			}
		}

		/* account modification operations */
		if (!(checkparms & ~(BIT_MODIFY + BIT_USER))) {
			return set_user_info (bdef, user_name, full_name,
					      home_dir,
					      home_drive,
					      logon_script,
					      profile_path);
		}
	}

	if (setparms >= 0x20) {
		fprintf (stderr, "Incompatible or insufficient options on command line!\n");
	}
	poptPrintHelp(pc, stderr, 0);

	return 1;
}
