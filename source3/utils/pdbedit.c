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

extern pstring global_myname;
extern BOOL AllowDebugChange;

/*********************************************************
 Add all currently available users to another db
 ********************************************************/

int export_database (struct pdb_context *in, char *db){
	struct pdb_context *context;
	SAM_ACCOUNT *user = NULL;

	if(!NT_STATUS_IS_OK(make_pdb_context_name(&context, db))){
		fprintf(stderr, "Can't initialize %s.\n", db);
		return 1;
	}

	if(!in->pdb_setsampwent(in, 0)){
		fprintf(stderr, "Can't sampwent!\n");
		return 1;
	}

	if(!NT_STATUS_IS_OK(pdb_init_sam(&user))){
		fprintf(stderr, "Can't initialize new SAM_ACCOUNT!\n");
		return 1;
	}

	while(in->pdb_getsampwent(in,user)){
		context->pdb_add_sam_account(context,user);
		if(!NT_STATUS_IS_OK(pdb_reset_sam(user))){
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
		printf ("Unix/NT username:     %s/%s\n",  pdb_get_username(sam_pwent),pdb_get_nt_username(sam_pwent));
		if (IS_SAM_UNIX_USER(sam_pwent)) {
			uid = pdb_get_uid(sam_pwent);
			gid = pdb_get_gid(sam_pwent);
			printf ("user ID/Group:        %d/%d\n", uid, gid);
		}
		printf ("user RID/GRID:        %u/%u\n", (unsigned int)pdb_get_user_rid(sam_pwent),
			(unsigned int)pdb_get_group_rid(sam_pwent));
		printf ("Full Name:            %s\n", pdb_get_fullname(sam_pwent));
		printf ("Home Directory:       %s\n", pdb_get_homedir(sam_pwent));
		printf ("HomeDir Drive:        %s\n", pdb_get_dirdrive(sam_pwent));
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

static int print_user_info (struct pdb_context *in, char *username, BOOL verbosity, BOOL smbpwdstyle)
{
	SAM_ACCOUNT *sam_pwent=NULL;
	BOOL ret;
	
	if (!NT_STATUS_IS_OK(pdb_init_sam (&sam_pwent))) {
		return -1;
	}
	
	ret = in->pdb_getsampwnam (in, sam_pwent, username);

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
	
	errno = 0; /* testing --simo */
	check = in->pdb_setsampwent(in, False);
	if (check && errno == ENOENT) {
		fprintf (stderr,"Password database not found!\n");
		exit(1);
	}

	check = True;
	if (!(NT_STATUS_IS_OK(pdb_init_sam(&sam_pwent)))) return 1;

	while (check && (ret = in->pdb_getsampwent (in, sam_pwent))) {
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
	
	ret = in->pdb_getsampwnam (in, sam_pwent, username);
	if (ret==False) {
		fprintf (stderr, "Username not found!\n");
		pdb_free_sam(&sam_pwent);
		return -1;
	}
	
	if (fullname)
		pdb_set_fullname(sam_pwent, fullname);
	if (homedir)
		pdb_set_homedir(sam_pwent, homedir, True);
	if (drive)
		pdb_set_dir_drive(sam_pwent,drive, True);
	if (script)
		pdb_set_logon_script(sam_pwent, script, True);
	if (profile)
		pdb_set_profile_path (sam_pwent, profile, True);
	
	if (in->pdb_update_sam_account (in, sam_pwent))
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
	char *password1, *password2;
	
	ZERO_STRUCT(sam_pwent);

	if ((pwd = getpwnam_alloc(username))) {
		pdb_init_sam_pw (&sam_pwent, pwd);
		passwd_free(&pwd);
	} else {
		fprintf (stderr, "WARNING: user %s does not exist in system passwd\n", username);
		pdb_init_sam(&sam_pwent);
		if (!pdb_set_username(sam_pwent, username)) {
			return False;
		}
	}

	password1 = getpass("new password:");
	password2 = getpass("retype new password:");
	if (strcmp (password1, password2)) {
		 fprintf (stderr, "Passwords does not match!\n");
		 pdb_free_sam (&sam_pwent);
		 return -1;
	}

	pdb_set_plaintext_passwd(sam_pwent, password1);

	if (fullname)
		pdb_set_fullname(sam_pwent, fullname);
	if (homedir)
		pdb_set_homedir (sam_pwent, homedir, True);
	if (drive)
		pdb_set_dir_drive (sam_pwent, drive, True);
	if (script)
		pdb_set_logon_script(sam_pwent, script, True);
	if (profile)
		pdb_set_profile_path (sam_pwent, profile, True);
	
	pdb_set_acct_ctrl (sam_pwent, ACB_NORMAL);
	
	if (in->pdb_add_sam_account (in, sam_pwent)) { 
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

	pdb_set_username (sam_pwent, name);
	
	pdb_set_acct_ctrl (sam_pwent, ACB_WSTRUST);
	
	pdb_set_group_rid(sam_pwent, DOMAIN_GROUP_RID_COMPUTERS);
	
	if (in->pdb_add_sam_account (in, sam_pwent)) {
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

	if (!in->pdb_getsampwnam(in, samaccount, username)) {
		fprintf (stderr, "user %s does not exist in the passdb\n", username);
		return -1;
	}

	return in->pdb_delete_sam_account (in, samaccount);
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

	if (!in->pdb_getsampwnam(in, samaccount, name)) {
		fprintf (stderr, "user %s does not exist in the passdb\n", name);
		return -1;
	}

	return in->pdb_delete_sam_account (in, samaccount);
}

/*********************************************************
 Start here.
**********************************************************/

int main (int argc, char **argv)
{
	static BOOL list_users = False;
	static BOOL verbose = False;
	static BOOL spstyle = False;
	static BOOL setparms = False;
	static BOOL machine = False;
	static BOOL add_user = False;
	static BOOL delete_user = False;
	static BOOL import = False;
	int opt;
	static char *full_name = NULL;
	static char *user_name = NULL;
	static char *home_dir = NULL;
	static char *home_drive = NULL;
	static char *backend_in = NULL;
	static char *backend_out = NULL;
	static char *logon_script = NULL;
	static char *profile_path = NULL;
	static int new_debuglevel = -1;

	struct pdb_context *in;
	poptContext pc;
	struct poptOption long_options[] = {
		POPT_AUTOHELP
		{"list",	'l',POPT_ARG_VAL, &list_users, 1, "list all users", NULL},
		{"verbose",	'v',POPT_ARG_VAL, &verbose, 1, "be verbose", NULL },
		{"smbpasswd-style",	'w',POPT_ARG_VAL, &spstyle, 1, "give output in smbpasswd style", NULL},
		{"user",	'u',POPT_ARG_STRING,&user_name, 0, "use username", "USER" },
		{"fullname",	'f',POPT_ARG_STRING,&full_name, 0, "set full name", NULL},
		{"homedir",	'h',POPT_ARG_STRING,&home_dir, 0, "set home directory", NULL},
		{"drive",	'd',POPT_ARG_STRING,&home_drive, 0, "set home drive", NULL},
		{"script",	's',POPT_ARG_STRING,&logon_script, 0, "set logon script", NULL},
		{"profile",	'p',POPT_ARG_STRING,&profile_path, 0, "set profile path", NULL},
		{"create",	'a',POPT_ARG_VAL,&add_user, 1, "create user", NULL},
		{"machine",	'm',POPT_ARG_VAL,&machine, 1,"account is a machine account",NULL},
		{"delete",	'x',POPT_ARG_VAL,&delete_user,1,"delete user",NULL},
		{"import",	'i',POPT_ARG_STRING,&backend_in,0,"use different passdb backend",NULL},
		{"export",	'e',POPT_ARG_STRING,&backend_out,0,"export user accounts to backend", NULL},
		{"debuglevel",'D',POPT_ARG_INT,&new_debuglevel,0,"set debuglevel",NULL},
		{0,0,0,0}
	};

	DEBUGLEVEL = 1;
	setup_logging("pdbedit", True);
	AllowDebugChange = False;

	if (!lp_load(dyn_CONFIGFILE,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", 
				dyn_CONFIGFILE);
		exit(1);
	}

	backend_in = lp_passdb_backend();

	pc = poptGetContext(NULL, argc, (const char **) argv, long_options,
						POPT_CONTEXT_KEEP_FIRST);

	while((opt = poptGetNextOpt(pc)) != -1);

	if (new_debuglevel != -1) {
		DEBUGLEVEL = new_debuglevel;
	}

	setparms = (full_name || home_dir || home_drive || logon_script || profile_path);

	if (((add_user?1:0) + (delete_user?1:0) + (list_users?1:0) + (import?1:0) + (setparms?1:0)) + (backend_out?1:0) > 1) {
		fprintf (stderr, "Incompatible options on command line!\n");
		exit(1);
	}


	if(!NT_STATUS_IS_OK(make_pdb_context_name(&in, backend_in))){
		fprintf(stderr, "Can't initialize %s.\n", backend_in);
		return 1;
	}

	if (add_user) {
		if (!user_name) {
			fprintf (stderr, "Username not specified! (use -u option)\n");
			return -1;
		}
		if (machine)
			return new_machine (in, user_name);
		else
			return new_user (in, user_name, full_name, home_dir, 
					 home_drive, logon_script, 
					 profile_path);
	}

	if (delete_user) {
		if (!user_name) {
			fprintf (stderr, "Username not specified! (use -u option)\n");
			return -1;
		}
		if (machine)
			return delete_machine_entry (in, user_name);
		else
			return delete_user_entry (in, user_name);
	}

	if (user_name) {
		if (setparms)
			return set_user_info (in, user_name, full_name,
					      home_dir,
					      home_drive,
					      logon_script,
					      profile_path);
		else
			return print_user_info (in, user_name, verbose, 
						spstyle);
	}

	if (list_users) 
		return print_users_list (in, verbose, spstyle);

	if (backend_out)
		return export_database(in, backend_out);

	poptPrintHelp(pc, stderr, 0);

	return 1;
}


