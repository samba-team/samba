/*
 * Unix SMB/Netbios implementation. Version 1.9. tdbedit module. Copyright
 * (C) Simo Sorce 2000
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

/* base uid for trust accounts is set to 60000 ! 
 * May be we should add the defines in smb.h to make it possible having 
 * different values on different platforms?
 */

#define BASE_MACHINE_UID 60000
#define MAX_MACHINE_UID 65500 /* 5500 trust acconts aren't enough? */

#include "includes.h"

extern pstring global_myname;
extern int DEBUGLEVEL;

/*
 * Next two lines needed for SunOS and don't
 * hurt anything else...
 */
extern char *optarg;
extern int optind;

/*********************************************************
 Print command usage on stderr and die.
**********************************************************/
static void usage(void)
{
	if (getuid() == 0) {
		printf("tdbedit options\n");
	} else {
		printf("You need to be root to use this tool!\n");
	}
	printf("(actually to add a user you need to use smbpasswd)\n");
	printf("options:\n");
	printf("  -l                   list usernames\n");
	printf("     -v                verbose output\n");
	printf("     -w                smbpasswd file style\n");
	printf("  -u username          print user's info\n");
	printf("     -f fullname       set Full Name\n");
	printf("     -h homedir        set home directory\n");
	printf("     -d drive          set home dir drive\n");
	printf("     -s script         set logon script\n");
	printf("     -p profile        set profile path\n");
	printf("  -a                   create new account\n");
	printf("     -m                it is a machine trust\n");
	printf("  -x                   delete this user\n");
	printf("  -i file              import account from file (smbpasswd style)\n");
	exit(1);
}
/*********************************************************
 Print info from sam structure
**********************************************************/
static int print_sam_info (SAM_ACCOUNT *sam_pwent, BOOL verbosity, BOOL smbpwdstyle)
{
	/* TODO: chaeck if entry is a user or a workstation */
	if (!sam_pwent) return -1;
	
	if (verbosity)
	{
		printf ("username:       %s\n", sam_pwent->username);
		printf ("user ID/Group:  %d/%d\n", sam_pwent->uid,
						  sam_pwent->gid);
		printf ("user RID/GRID:  %d/%d\n", sam_pwent->user_rid,
						  sam_pwent->group_rid);
		printf ("Full Name:      %s\n", sam_pwent->full_name);
		printf ("Home Directory: %s\n", sam_pwent->home_dir);
		printf ("HomeDir Drive:  %s\n", sam_pwent->dir_drive);
		printf ("Logon Script:   %s\n", sam_pwent->logon_script);
		printf ("Profile Path:   %s\n", sam_pwent->profile_path);
	}
	else if (smbpwdstyle)
	{
		char lm_passwd[33];
		char nt_passwd[33];
		pdb_sethexpwd(lm_passwd, pdb_get_lanman_passwd(sam_pwent), pdb_get_acct_ctrl(sam_pwent));
		pdb_sethexpwd(nt_passwd, pdb_get_nt_passwd(sam_pwent), pdb_get_acct_ctrl(sam_pwent));
		
		printf ("%s:%d:%s:%s:%s:LCT-%08x:\n",
			pdb_get_username(sam_pwent),
			pdb_get_uid(sam_pwent),
			lm_passwd,
			nt_passwd,
			pdb_encode_acct_ctrl(pdb_get_acct_ctrl(sam_pwent),NEW_PW_FORMAT_SPACE_PADDED_LEN),
			(uint32)pdb_get_pass_last_set_time(sam_pwent));
	}
	else
	{
		printf ("%s:%d:%s\n", sam_pwent->username, sam_pwent->uid, sam_pwent->full_name);
	}	
	
	return 0;	
}

/*********************************************************
 Get an Print User Info
**********************************************************/
static int print_user_info (char *username, BOOL verbosity, BOOL smbpwdstyle)
{
	SAM_ACCOUNT *sam_pwent=NULL;
	BOOL ret;
	
	pdb_init_sam(&sam_pwent);
	
	ret = pdb_getsampwnam (sam_pwent, username);

	if (ret==False) {
		fprintf (stderr, "Username not found!\n");
		pdb_free_sam(sam_pwent);
		return -1;
	}
	
	ret=print_sam_info (sam_pwent, verbosity, smbpwdstyle);
	pdb_free_sam(sam_pwent);
	
	return ret;
}
	
/*********************************************************
 List Users
**********************************************************/
static int print_users_list (BOOL verbosity, BOOL smbpwdstyle)
{
	SAM_ACCOUNT *sam_pwent=NULL;
	BOOL ret;
	
	pdb_init_sam(&sam_pwent);

	ret = pdb_setsampwent(False);
	if (ret && errno == ENOENT) {
		fprintf (stderr,"Password database not found!\n");
		pdb_free_sam(sam_pwent);
		exit(1);
	}

	while ((ret = pdb_getsampwent (sam_pwent)))
	{
		if (verbosity) printf ("---------------\n");
		print_sam_info (sam_pwent, verbosity, smbpwdstyle);
		pdb_reset_sam(sam_pwent);
	}
	
	pdb_endsampwent ();
	pdb_free_sam(sam_pwent);
	return 0;
}

/*********************************************************
 Set User Info
**********************************************************/
static int set_user_info (char *username, char *fullname, char *homedir, char *drive, char *script, char *profile)
{
	SAM_ACCOUNT *sam_pwent=NULL;
	BOOL ret;
	
	pdb_init_sam(&sam_pwent);
	
	ret = pdb_getsampwnam (sam_pwent, username);
	if (ret==False)
	{
		fprintf (stderr, "Username not found!\n");
		pdb_free_sam(sam_pwent);
		return -1;
	}
	
	if (fullname) pdb_set_fullname(sam_pwent, fullname);
	if (homedir) pdb_set_homedir(sam_pwent, homedir);
	if (drive) pdb_set_dir_drive(sam_pwent,drive);
	if (script) pdb_set_logon_script(sam_pwent, script);
	if (profile) pdb_set_profile_path (sam_pwent, profile);
	
	if (pdb_update_sam_account (sam_pwent, TRUE)) print_user_info (username, TRUE, FALSE);
	else
	{
		fprintf (stderr, "Unable to modify entry!\n");
		pdb_free_sam(sam_pwent);
		return -1;
	}
	pdb_free_sam(sam_pwent);
	return 0;
}

/*********************************************************
 Add New User
**********************************************************/
static int new_user (char *username, char *fullname, char *homedir, char *drive, char *script, char *profile)
{
	SAM_ACCOUNT sam_pwent;
	struct passwd  *pwd = NULL;
	uchar new_p16[16];
	uchar new_nt_p16[16];
	char *password1, *password2;
	
	ZERO_STRUCT(sam_pwent);

	if (pdb_getsampwnam (&sam_pwent, username))
	{
		fprintf (stderr, "Username already exist in database!\n");
		return -1;
	}

	if (!(pwd = sys_getpwnam(username)))
	{
		fprintf (stderr, "User %s does not exist in system passwd!\n", username);
		return -1;
	}
	
	password1 = getpass("new password:");
	password2 = getpass("retype new password:");
	if (strcmp (password1, password2))
	{
		 fprintf (stderr, "Passwords does not match!\n");
		 return -1;
	}
	nt_lm_owf_gen (password1, new_nt_p16, new_p16);
	
	pdb_set_username(&sam_pwent, username);
	if (fullname) pdb_set_fullname(&sam_pwent, fullname);
	if (homedir) pdb_set_homedir (&sam_pwent, homedir);
	if (drive) pdb_set_dir_drive (&sam_pwent, drive);
	if (script) pdb_set_logon_script(&sam_pwent, script);
	if (profile) pdb_set_profile_path (&sam_pwent, profile);
	
	/* TODO: Check uid not being in MACHINE UID range!! */
	sam_pwent.uid = pwd->pw_uid;
	sam_pwent.gid = pwd->pw_gid;
	sam_pwent.user_rid = pdb_uid_to_user_rid (pwd->pw_uid);
	sam_pwent.group_rid = pdb_gid_to_group_rid (pwd->pw_gid);
	sam_pwent.lm_pw = new_p16;
	sam_pwent.nt_pw = new_nt_p16;
	sam_pwent.acct_ctrl = ACB_NORMAL;
	
	if (pdb_add_sam_account (&sam_pwent)) print_user_info (username, TRUE, FALSE);
	else
	{
		fprintf (stderr, "Unable to add user!\n");
		return -1;
	}
	return 0;
}

/*********************************************************
 Add New Machine
**********************************************************/
static int new_machine (char *machinename)
{
	SAM_ACCOUNT sam_pwent;
	SAM_ACCOUNT sam_trust;
	uchar new_p16[16];
	uchar new_nt_p16[16];
	char name[16];
	char *password = NULL;
	uid_t uid;

	if (machinename[strlen (machinename) -1] == '$') machinename[strlen (machinename) -1] = '\0';
	
	safe_strcpy (name, machinename, 16);
	safe_strcat (name, "$", 16);
	
	string_set (&password, machinename);
	strlower(password);
	nt_lm_owf_gen (password, new_nt_p16, new_p16);
	
	pdb_set_username(&sam_pwent, name);
	
	for (uid=BASE_MACHINE_UID; uid<=MAX_MACHINE_UID; uid++)
		if (!(pdb_getsampwuid (&sam_trust, uid)))
			break;

	if (uid>MAX_MACHINE_UID) {
		fprintf (stderr, "No more free UIDs available to Machine accounts!\n");
		return -1;
	}

	sam_pwent.uid = uid;
	sam_pwent.gid = BASE_MACHINE_UID; /* TODO: set there more appropriate value!! */
	sam_pwent.user_rid = pdb_uid_to_user_rid (uid);
	sam_pwent.group_rid = pdb_gid_to_group_rid (BASE_MACHINE_UID);
	sam_pwent.lm_pw = new_p16;
	sam_pwent.nt_pw = new_nt_p16;
	sam_pwent.acct_ctrl = ACB_WSTRUST;
	
	if (pdb_add_sam_account (&sam_pwent))
		print_user_info (name, TRUE, FALSE);
	else {
		fprintf (stderr, "Unable to add machine!\n");
		return -1;
	}
	return 0;
}

/*********************************************************
 Delete user entry
**********************************************************/
static int delete_user_entry (char *username)
{
	return pdb_delete_sam_account (username);
}

/*********************************************************
 Delete machine entry
**********************************************************/
static int delete_machine_entry (char *machinename)
{
	char name[16];
	
	safe_strcpy (name, machinename, 16);
	if (name[strlen(name)] != '$')
	{
		safe_strcat (name, "$", 16);
	}
	return pdb_delete_sam_account (name);
}

/*********************************************************
 Import smbpasswd style file
**********************************************************/
static int import_users (char *filename)
{
	FILE *fp = NULL;
	SAM_ACCOUNT sam_pwent;
	SAM_ACCOUNT sam_test;
	static pstring  user_name;
	static unsigned char smbpwd[16];
	static unsigned char smbntpwd[16];
	char linebuf[256];
	size_t linebuf_len;
	unsigned char c;
	unsigned char *p;
	long uidval;
	int line = 0;
	int good = 0;

	if((fp = sys_fopen(filename, "rb")) == NULL)
	{
		fprintf (stderr, "%s\n", strerror (ferror (fp)));
		return -1;
	}
	
	while (!feof(fp))
	{
		/*Get a new line*/
		linebuf[0] = '\0';
		fgets(linebuf, 256, fp);
		if (ferror(fp))
		{
			fprintf (stderr, "%s\n", strerror (ferror (fp)));
			return -1;
		}
		if ((linebuf_len = strlen(linebuf)) == 0)
		{
			line++;
			continue;
		}
		if (linebuf[linebuf_len - 1] != '\n')
		{
			c = '\0';
			while (!ferror(fp) && !feof(fp))
			{
				c = fgetc(fp);
				if (c == '\n') break;
			}
    		}
		else linebuf[linebuf_len - 1] = '\0';
		linebuf[linebuf_len] = '\0';
		if ((linebuf[0] == 0) && feof(fp))
		{
			/*end of file!!*/
			return 0;
		}
		line++;
		if (linebuf[0] == '#' || linebuf[0] == '\0') continue;
		
		/*pdb_init_sam (&sam_pwent);*/
		sam_pwent.acct_ctrl = ACB_NORMAL;
		
		/* Get user name */
		p = (unsigned char *) strchr(linebuf, ':');
		if (p == NULL)
		{
			fprintf (stderr, "Error: malformed password entry at line %d !!\n", line);
			continue;
		}
		strncpy(user_name, linebuf, PTR_DIFF(p, linebuf));
		user_name[PTR_DIFF(p, linebuf)] = '\0';

		/* Get smb uid. */
		p++;
		if(*p == '-')
		{
			fprintf (stderr, "Error: negative uid at line %d\n", line);
			continue;
		}
		if (!isdigit(*p))
		{
			fprintf (stderr, "Error: malformed password entry at line %d (uid not number)\n", line);
			continue;
		}
		uidval = atoi((char *) p);
		while (*p && isdigit(*p)) p++;
		if (*p != ':')
		{
			fprintf (stderr, "Error: malformed password entry at line %d (no : after uid)\n", line);
			continue;
		}

		pdb_set_username(&sam_pwent, user_name);
		pdb_set_uid (&sam_pwent, uidval);
		
		/* Get passwords */
		p++;
		if (*p == '*' || *p == 'X')
		{
			/* Password deliberately invalid */
			fprintf (stderr, "Warning: entry invalidated for user %s\n", user_name);
			sam_pwent.lm_pw = NULL;
			sam_pwent.nt_pw = NULL;
			sam_pwent.acct_ctrl |= ACB_DISABLED;
		}
		else
		{
			if (linebuf_len < (PTR_DIFF(p, linebuf) + 33))
			{
				fprintf (stderr, "Error: malformed password entry at line %d (password too short)\n",line);
				continue;
			}
			if (p[32] != ':')
			{
				fprintf (stderr, "Error: malformed password entry at line %d (no terminating :)\n",line);
				continue;
			}
			if (!strncasecmp((char *) p, "NO PASSWORD", 11))
			{
				sam_pwent.lm_pw = NULL;
				sam_pwent.acct_ctrl |= ACB_PWNOTREQ;
			}
			else
			{
				if (!pdb_gethexpwd((char *)p, smbpwd))
				{
					fprintf (stderr, "Error: malformed Lanman password entry at line %d (non hex chars)\n", line);
					continue;
				}
				sam_pwent.lm_pw = smbpwd;
			}
			/* NT password */
			sam_pwent.nt_pw = NULL;
			p += 33;
			if ((linebuf_len >= (PTR_DIFF(p, linebuf) + 33)) && (p[32] == ':'))
			{
				if (*p != '*' && *p != 'X')
				{
					if (pdb_gethexpwd((char *)p,smbntpwd))
					{
						sam_pwent.nt_pw = smbntpwd;
					}
				}
				p += 33;
			}
		}

		/* Get ACCT_CTRL field if any */
		if (*p == '[')
		{
			unsigned char *end_p = (unsigned char *)strchr((char *)p, ']');
			
			sam_pwent.acct_ctrl = pdb_decode_acct_ctrl((char*)p);
			if(sam_pwent.acct_ctrl == 0) sam_pwent.acct_ctrl = ACB_NORMAL;
			
			/* Get last change time */
			if(end_p) p = end_p + 1;
			if(*p == ':')
			{
				p++;
				if(*p && (StrnCaseCmp((char *)p, "LCT-", 4)==0))
				{
					int i;
					
					p += 4;
					for(i = 0; i < 8; i++)
					{
						if(p[i] == '\0' || !isxdigit(p[i])) break;
					}
					if(i == 8)
					{
						sam_pwent.pass_last_set_time = (time_t)strtol((char *)p, NULL, 16);
					}
				}
			}
		}

		/* Test if workstation */
		else
		{
			if(sam_pwent.username[strlen(sam_pwent.username) - 1] == '$')
			{
				sam_pwent.acct_ctrl &= ~ACB_NORMAL;
				sam_pwent.acct_ctrl |= ACB_WSTRUST;
			}
		}
		if (sam_pwent.acct_ctrl & ACB_WSTRUST)
		{
			if (!(BASE_MACHINE_UID <= uidval <= MAX_MACHINE_UID))
			{
				fprintf (stderr, "Warning: Machine UID out of normal range %d-%d\n",
						 BASE_MACHINE_UID,
						 MAX_MACHINE_UID);
			}
			sam_pwent.gid = BASE_MACHINE_UID;
		}
	
		/* Test if user is valid */
		if (sam_pwent.acct_ctrl & ACB_NORMAL)
		{
			struct passwd  *pwd = NULL;

			if (pdb_getsampwnam (&sam_test,user_name))
			{
				fprintf (stderr, "Error: Username already exist in database!\n");
				continue;
			}
			if (!(pwd = sys_getpwnam(user_name)))
			{
				fprintf (stderr, "Error: User %s does not exist in system passwd!\n", user_name);
				continue;
			}
			sam_pwent.gid = pwd->pw_gid;
		}

		/* Fill in sam_pwent structure */
		sam_pwent.user_rid = pdb_uid_to_user_rid (sam_pwent.uid);
		sam_pwent.group_rid = pdb_gid_to_group_rid (sam_pwent.gid);
		/* TODO: set also full_name, home_dir, dir_drive, logon_script, profile_path, ecc...
		 * when defaults will be available (after passdb redesign)
		 * let them blank just now they are not used anyway
		 */
		 			 
		 /* Now ADD the entry */
		if (!(pdb_add_sam_account (&sam_pwent)))
		{
			fprintf (stderr, "Unable to add user entry!\n");
			continue;
		}
		printf ("%s imported!\n", user_name);
		good++;
	}
	printf ("%d lines read.\n%d entryes imported\n", line, good);
	
	return 0;
}

/*********************************************************
 Start here.
**********************************************************/
int main (int argc, char **argv)
{
	int ch;
	static pstring servicesf = CONFIGFILE;
	BOOL list_users = FALSE;
	BOOL verbose = FALSE;
	BOOL spstyle = FALSE;
	BOOL setparms = FALSE;
	BOOL machine = FALSE;
	BOOL add_user = FALSE;
	BOOL delete_user = FALSE;
	BOOL import = FALSE;
	char *user_name = NULL;
	char *full_name = NULL;
	char *home_dir = NULL;
	char *home_drive = NULL;
	char *logon_script = NULL;
	char *profile_path = NULL;
	char *smbpasswd = NULL;

	TimeInit();
	
	setup_logging("tdbedit", True);

	if (argc < 2)

	{
		usage();
		return 0;
	}
	
	if(!initialize_password_db(True)) {
		fprintf(stderr, "Can't setup password database vectors.\n");
		exit(1);
	}
	
	if (!lp_load(servicesf,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", 
			servicesf);
		exit(1);
	}
	
	while ((ch = getopt(argc, argv, "ad:f:h:i:lmp:s:u:vwx")) != EOF) {
		switch(ch) {
		case 'a':
			add_user = TRUE;
			break;
		case 'm':
			machine = TRUE;
			break;
		case 'l':
			list_users = TRUE;
			break;
		case 'v':
			verbose = TRUE;
			break;
		case 'w':
			spstyle = TRUE;
			break;
		case 'u':
			user_name = optarg;
			break;
		case 'f':
			setparms = TRUE;
			full_name = optarg;
			break;
		case 'h':
			setparms = TRUE;
			home_dir = optarg;
			break;
		case 'd':
			setparms = TRUE;
			home_drive = optarg;
			break;
		case 's':
			setparms = TRUE;
			logon_script = optarg;
			break;
		case 'p':
			setparms = TRUE;
			profile_path = optarg;
			break;
		case 'x':
			delete_user = TRUE;
			break;
		case 'i':
			import = TRUE;
			smbpasswd = optarg;
			break;
		default:
			usage();
		}
	}
	if (((add_user?1:0) + (delete_user?1:0) + (list_users?1:0) + (import?1:0) + (setparms?1:0)) > 1)
	{
		fprintf (stderr, "Incompatible options on command line!\n");
		usage();
		exit(1);
	}

	if (add_user) 
	{
		if (!user_name)
		{
			fprintf (stderr, "Username not specified! (use -u option)\n");
			return -1;
		}
		if (machine) return new_machine (user_name);
		else return new_user (user_name, full_name, home_dir, home_drive, logon_script, profile_path);
	}

	if (delete_user)
	{
		if (!user_name)
		{
			fprintf (stderr, "Username not specified! (use -u option)\n");
			return -1;
		}
		if (machine) return delete_machine_entry (user_name);
		else return delete_user_entry (user_name);
	}
	
	if (user_name) 
	{
		if (setparms) set_user_info (	user_name,
						full_name,
						home_dir,
						home_drive,
						logon_script,
						profile_path);
						
		else return print_user_info (user_name, verbose, spstyle);
		
		return 0;
	}

	
	if (list_users) 
		return print_users_list (verbose, spstyle);
	
	if (import) 
		return import_users (smbpasswd); 
	
	usage();

	return 0;
}


