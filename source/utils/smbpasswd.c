/*
 * Unix SMB/Netbios implementation. 
 * Version 1.9. 
 * smbpasswd module. 
 * Copyright (C) Jeremy Allison 1995-1998
 * Copyright (C) Tim Potter     2001
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.  */

#include "includes.h"

extern pstring global_myname;
extern BOOL AllowDebugChange;

/*
 * Next two lines needed for SunOS and don't
 * hurt anything else...
 */
extern char *optarg;
extern int optind;

/* forced running in root-mode */
static BOOL local_mode;
static BOOL joining_domain = False, got_pass = False, got_username = False;
static int local_flags = 0;
static BOOL stdin_passwd_get = False;
static fstring user_name, user_password;
static char *new_domain = NULL;
static char *new_passwd = NULL;
static char *old_passwd = NULL;
static char *remote_machine = NULL;
static pstring servicesf = CONFIGFILE;

#ifdef WITH_LDAP_SAM
static fstring ldap_secret;
#endif



/*********************************************************
 A strdup with exit
**********************************************************/

static char *strdup_x(const char *s)
{
	char *new_s = strdup(s);
	if (!new_s) {
		fprintf(stderr,"out of memory\n");
		exit(1);
	}
	return new_s;
}


/*********************************************************
 Print command usage on stderr and die.
**********************************************************/
static void usage(void)
{
	if (getuid() == 0) {
		printf("smbpasswd [options] [username] [password]\n");
	} else {
		printf("smbpasswd [options] [password]\n");
	}
	printf("options:\n");
	printf("  -c smb.conf file     Use the given path to the smb.conf file\n");
	printf("  -s                   use stdin for password prompt\n");
	printf("  -D LEVEL             debug level\n");
	printf("  -U USER              remote username\n");
	printf("  -r MACHINE           remote machine\n");

	if (getuid() == 0 || local_mode) {
		printf("  -L                   local mode\n");
		printf("  -R ORDER             name resolve order\n");
		printf("  -j DOMAIN            join domain name\n");
		printf("  -a                   add user\n");
		printf("  -x                   delete user\n");
		printf("  -d                   disable user\n");
		printf("  -e                   enable user\n");
		printf("  -n                   set no password\n");
		printf("  -m                   machine trust account\n");
#ifdef WITH_LDAP_SAM
		printf("  -w                   ldap admin password\n");
#endif
	}
	exit(1);
}

static void set_line_buffering(FILE *f)
{
	setvbuf(f, NULL, _IOLBF, 0);
}

/*******************************************************************
 Process command line options
 ******************************************************************/
static void process_options(int argc, char **argv, BOOL amroot)
{
	int ch;

	user_name[0] = '\0';

	while ((ch = getopt(argc, argv, "c:axdehmnj:r:sw:R:D:U:L")) != EOF) {
		switch(ch) {
		case 'L':
			local_mode = True;
			break;
		case 'c':
			pstrcpy(servicesf,optarg);
			break;
		case 'a':
			if (!amroot) goto bad_args;
			local_flags |= LOCAL_ADD_USER;
			break;
		case 'x':
			if (!amroot) goto bad_args;
			local_flags |= LOCAL_DELETE_USER;
			new_passwd = strdup_x("XXXXXX");
			break;
		case 'd':
			if (!amroot) goto bad_args;
			local_flags |= LOCAL_DISABLE_USER;
			new_passwd = strdup_x("XXXXXX");
			break;
		case 'e':
			if (!amroot) goto bad_args;
			local_flags |= LOCAL_ENABLE_USER;
			break;
		case 'm':
			if (!amroot) goto bad_args;
			local_flags |= LOCAL_TRUST_ACCOUNT;
			break;
		case 'n':
			if (!amroot) goto bad_args;
			local_flags |= LOCAL_SET_NO_PASSWORD;
			new_passwd = strdup_x("NO PASSWORD");
			break;
		case 'j':
			if (!amroot) goto bad_args;
			new_domain = optarg;
			strupper(new_domain);
			joining_domain = True;
			break;
		case 'r':
			remote_machine = optarg;
			break;
		case 's':
			set_line_buffering(stdin);
			set_line_buffering(stdout);
			set_line_buffering(stderr);
			stdin_passwd_get = True;
			break;
		case 'w':
			if (!amroot) goto bad_args;
#ifdef WITH_LDAP_SAM
			local_flags |= LOCAL_SET_LDAP_ADMIN_PW;
			fstrcpy(ldap_secret, optarg);
			break;
#else
			printf("-w not available unless configured --with-ldap\n");
			goto bad_args;
#endif			
		case 'R':
			if (!amroot) goto bad_args;
			lp_set_name_resolve_order(optarg);
			break;
		case 'D':
			DEBUGLEVEL = atoi(optarg);
			break;
		case 'U': {
			char *lp;

			got_username = True;
			fstrcpy(user_name, optarg);

			if ((lp = strchr(user_name, '%'))) {
				*lp = 0;
				fstrcpy(user_password, lp + 1);
				got_pass = True;
				memset(strchr(optarg, '%') + 1, 'X',
				       strlen(user_password));
			}

			break;
		}
		case 'h':
		default:
bad_args:
			usage();
		}
	}
	
	argc -= optind;
	argv += optind;

	if (joining_domain && (argc != 0))
		usage();

	switch(argc) {
	case 0:
		if (!got_username)
			fstrcpy(user_name, "");
		break;
	case 1:
		if (!amroot == 1) {
			new_passwd = argv[0];
			break;
		}
		if (got_username)
			usage();
		fstrcpy(user_name, argv[0]);
		break;
	case 2:
		if (!amroot || got_username || got_pass)
			usage();
		fstrcpy(user_name, argv[0]);
		new_passwd = strdup_x(argv[1]);
		break;
	default:
		usage();
	}

}

/* Initialise client credentials for authenticated pipe access */

void init_rpcclient_creds(struct ntuser_creds *creds, char* username,
			  char* domain, char* password)
{
	ZERO_STRUCTP(creds);
	
	if (lp_encrypted_passwords()) {
		pwd_make_lm_nt_16(&creds->pwd, password);
	} else {
		pwd_set_cleartext(&creds->pwd, password);
	}

	fstrcpy(creds->user_name, username);
	fstrcpy(creds->domain, domain);
}

/*********************************************************
Join a domain using the administrator username and password
**********************************************************/

/* Macro for checking RPC error codes to make things more readable */

#define CHECK_RPC_ERR(rpc, msg) \
        if (!NT_STATUS_IS_OK(result = rpc)) { \
                DEBUG(0, (msg ": %s\n", get_nt_error_msg(result))); \
                goto done; \
        }

#define CHECK_RPC_ERR_DEBUG(rpc, debug_args) \
        if (!NT_STATUS_IS_OK(result = rpc)) { \
                DEBUG(0, debug_args); \
                goto done; \
        }

static int join_domain_byuser(char *domain, char *remote,
			      char *username, char *password)
{
	/* libsmb variables */

	pstring pdc_name;
	struct nmb_name calling, called;
	struct ntuser_creds creds;
	struct cli_state cli;
	fstring acct_name;
	struct in_addr dest_ip;
	TALLOC_CTX *mem_ctx;

	/* rpc variables */

	POLICY_HND lsa_pol, sam_pol, domain_pol, user_pol;
	DOM_SID domain_sid;
	uint32 user_rid;

	/* Password stuff */

	char *machine_pwd;
	int plen = 0;
	uchar pwbuf[516], ntpw[16], sess_key[16];
	SAM_USERINFO_CTR ctr;
	SAM_USER_INFO_24 p24;
	SAM_USER_INFO_10 p10;

	/* Misc */

	NTSTATUS result;
	int retval = 1;

	pstrcpy(pdc_name, remote ? remote : "");

	/* Connect to remote machine */

	ZERO_STRUCT(cli);
	ZERO_STRUCT(creds);

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0, ("Could not initialise talloc context\n"));
		goto done;
	}

	if (!cli_initialise(&cli)) {
		DEBUG(0, ("Could not initialise client structure\n"));
		goto done;
	}

	init_rpcclient_creds(&creds, username, domain, password);
	cli_init_creds(&cli, &creds);

	/*
	 * If we are given a remote machine assume this is the PDC.
	 */
	
	if(remote == NULL) {
                struct in_addr *ip_list;
                int addr_count;
                if (!get_dc_list(True /* PDC only*/, domain, &ip_list, &addr_count)) {
			fprintf(stderr, "Unable to find the domain controller for domain %s.\n", domain);
			return 1;
		}
		if ((addr_count < 1) || (is_zero_ip(ip_list[0]))) {
			fprintf(stderr, "Incorrect entries returned when finding the domain controller for domain %s.\n", domain);
			return 1;
		}

		if (!lookup_dc_name(global_myname, domain, &ip_list[0], pdc_name)) {
			fprintf(stderr, "Unable to lookup the name for the domain controller for domain %s.\n", domain);
			return 1;
		}
	}

	make_nmb_name(&called, pdc_name, 0x20);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname), 0);

	if (!cli_establish_connection(&cli, pdc_name, &dest_ip, &calling, 
				      &called, "IPC$", "IPC", False, True)) {
		DEBUG(0, ("Error connecting to %s\n", pdc_name));
		goto done;
	}

	/* Fetch domain sid */

	if (!cli_nt_session_open(&cli, PIPE_LSARPC)) {
		DEBUG(0, ("Error connecting to SAM pipe\n"));
		goto done;
	}


	CHECK_RPC_ERR(cli_lsa_open_policy(&cli, mem_ctx, True,
					  SEC_RIGHTS_MAXIMUM_ALLOWED,
					  &lsa_pol),
		      "error opening lsa policy handle");

	CHECK_RPC_ERR(cli_lsa_query_info_policy(&cli, mem_ctx, &lsa_pol,
						5, domain, &domain_sid),
		      "error querying info policy");

	cli_lsa_close(&cli, mem_ctx, &lsa_pol);

	cli_nt_session_close(&cli); /* Done with this pipe */

	/* Create domain user */

	if (!cli_nt_session_open(&cli, PIPE_SAMR)) {
		DEBUG(0, ("Error connecting to SAM pipe\n"));
		goto done;
	}

	CHECK_RPC_ERR(cli_samr_connect(&cli, mem_ctx, 
				       SEC_RIGHTS_MAXIMUM_ALLOWED,
				       &sam_pol),
		      "could not connect to SAM database");

	
	CHECK_RPC_ERR(cli_samr_open_domain(&cli, mem_ctx, &sam_pol,
					   SEC_RIGHTS_MAXIMUM_ALLOWED,
					   &domain_sid, &domain_pol),
		      "could not open domain");

	/* Create domain user */

	fstrcpy(acct_name, global_myname);
	fstrcat(acct_name, "$");

	strlower(acct_name);

	{
		uint32 unknown = 0xe005000b;

		result = cli_samr_create_dom_user(&cli, mem_ctx, &domain_pol,
						  acct_name, ACB_WSTRUST,
						  unknown, &user_pol, 
						  &user_rid);
	}


	if (NT_STATUS_IS_OK(result)) {

		/* We *must* do this.... don't ask... */
	  
		CHECK_RPC_ERR_DEBUG(cli_samr_close(&cli, mem_ctx, &user_pol), ("error closing user policy"));
		result = NT_STATUS_USER_EXISTS;
	}

	if (NT_STATUS_V(result) == NT_STATUS_V(NT_STATUS_USER_EXISTS)) {
		uint32 num_rids, *name_types, *user_rids;
		uint32 flags = 0x3e8;
		char *names;
		
		/* Look up existing rid */
		
		names = (char *)&acct_name[0];

		CHECK_RPC_ERR_DEBUG(
			cli_samr_lookup_names(&cli, mem_ctx,
					      &domain_pol, flags,
					      1, &names, &num_rids,
					      &user_rids, &name_types),
			("error looking up rid for user %s: %s\n",
			 acct_name, get_nt_error_msg(result)));

		if (name_types[0] != SID_NAME_USER) {
			DEBUG(0, ("%s is not a user account\n", acct_name));
			goto done;
		}

		user_rid = user_rids[0];
		
		/* Open handle on user */

		CHECK_RPC_ERR_DEBUG(
			cli_samr_open_user(&cli, mem_ctx, &domain_pol,
					   SEC_RIGHTS_MAXIMUM_ALLOWED,
					   user_rid, &user_pol),
			("could not re-open existing user %s: %s\n",
			 acct_name, get_nt_error_msg(result)));
		
	} else if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0, ("error creating domain user: %s\n",
			  get_nt_error_msg(result)));
		goto done;
	}

	/* Create a random machine account password */

	{
		UNISTR2 upw;	/* Unicode password */

		upw.buffer = (uint16 *)talloc_zero(mem_ctx, 0xc * 
						   sizeof(uint16));

		upw.uni_str_len = 0xc;
		upw.uni_max_len = 0xc;

		machine_pwd = (char *)upw.buffer;
		plen = upw.uni_str_len * 2;
		generate_random_buffer((unsigned char *)machine_pwd, plen, True);

		encode_pw_buffer((char *)pwbuf, machine_pwd, plen, False);

		mdfour( ntpw, (unsigned char *)upw.buffer, plen);
	}

	/* Set password on machine account */

	ZERO_STRUCT(ctr);
	ZERO_STRUCT(p24);

	init_sam_user_info24(&p24, (char *)pwbuf,24);

	ctr.switch_value = 24;
	ctr.info.id24 = &p24;

	/* I don't think this is quite the right place for this
	   calculation.  It should be moved somewhere where the credentials
	   are calculated. )-: */

	mdfour(sess_key, cli.pwd.smb_nt_pwd, 16);

	CHECK_RPC_ERR(cli_samr_set_userinfo(&cli, mem_ctx, &user_pol, 24, 
					    sess_key, &ctr),
		      "error setting trust account password");

	/* Why do we have to try to (re-)set the ACB to be the same as what
	   we passed in the samr_create_dom_user() call?  When a NT
	   workstation is joined to a domain by an administrator the
	   acb_info is set to 0x80.  For a normal user with "Add
	   workstations to the domain" rights the acb_info is 0x84.  I'm
	   not sure whether it is supposed to make a difference or not.  NT
	   seems to cope with either value so don't bomb out if the set
	   userinfo2 level 0x10 fails.  -tpot */

	ZERO_STRUCT(ctr);
	ctr.switch_value = 0x10;
	ctr.info.id10 = &p10;

	init_sam_user_info10(&p10, ACB_WSTRUST);

	/* Ignoring the return value is necessary for joining a domain
	   as a normal user with "Add workstation to domain" privilege. */

	result = cli_samr_set_userinfo2(&cli, mem_ctx, &user_pol, 0x10, 
					sess_key, &ctr);

	/* Now store the secret in the secrets database */

	strupper(domain);

	if (!secrets_store_domain_sid(domain, &domain_sid) ||
	    !secrets_store_trust_account_password(domain, ntpw)) {
		DEBUG(0, ("error storing domain secrets\n"));
		goto done;
	}

	retval = 0;		/* Success! */

 done:
	/* Close down pipe - this will clean up open policy handles */

	if (cli.nt_pipe_fnum)
		cli_nt_session_close(&cli);

	/* Display success or failure */

	if (retval != 0) {
		trust_password_delete(domain);
		fprintf(stderr,"Unable to join domain %s.\n",domain);
	} else {
		printf("Joined domain %s.\n",domain);
	}
	
	return retval;
}

/*********************************************************
Join a domain. Old server manager method.
**********************************************************/

static int join_domain(char *domain, char *remote)
{
	pstring pdc_name;
	fstring trust_passwd;
	unsigned char orig_trust_passwd_hash[16];
	DOM_SID domain_sid;
	BOOL ret;

	pstrcpy(pdc_name, remote ? remote : "");
	fstrcpy(trust_passwd, global_myname);
	strlower(trust_passwd);
	E_md4hash( (uchar *)trust_passwd, orig_trust_passwd_hash);

	/* Ensure that we are not trying to join a
	   domain if we are locally set up as a domain
	   controller. */

	if(strequal(remote, global_myname)) {
		fprintf(stderr, "Cannot join domain %s as the domain controller name is our own. We cannot be a domain controller for a domain and also be a domain member.\n", domain);
		return 1;
	}

	/*
	 * Write the old machine account password.
	 */
	
	if(!secrets_store_trust_account_password(domain,  orig_trust_passwd_hash)) {              
		fprintf(stderr, "Unable to write the machine account password for \
machine %s in domain %s.\n", global_myname, domain);
		return 1;
	}
	
	/*
	 * If we are given a remote machine assume this is the PDC.
	 */
	
	if(remote == NULL) {
                struct in_addr *ip_list;
                int addr_count;
                if (!get_dc_list(True /* PDC only*/, domain, &ip_list, &addr_count)) {
			fprintf(stderr, "Unable to find the domain controller for domain %s.\n", domain);
			return 1;
		}
		if ((addr_count < 1) || (is_zero_ip(ip_list[0]))) {
			fprintf(stderr, "Incorrect entries returned when finding the domain controller for domain %s.\n", domain);
			return 1;
		}

		if (!lookup_dc_name(global_myname, domain, &ip_list[0], pdc_name)) {
			fprintf(stderr, "Unable to lookup the name for the domain controller for domain %s.\n", domain);
			return 1;
		}
	}

	if (!fetch_domain_sid( domain, pdc_name, &domain_sid) ||
		!secrets_store_domain_sid(domain, &domain_sid)) {
		fprintf(stderr,"Failed to get domain SID. Unable to join domain %s.\n",domain);
		return 1;
	}
		
	ret = change_trust_account_password( domain, pdc_name);
	
	if(!ret) {
		trust_password_delete(domain);
		fprintf(stderr,"Unable to join domain %s.\n",domain);
		return 1;
	} else {
		printf("Joined domain %s.\n",domain);
	}
	
	return 0;
}

/*************************************************************
 Utility function to prompt for passwords from stdin. Each
 password entered must end with a newline.
*************************************************************/
static char *stdin_new_passwd(void)
{
	static fstring new_passwd;
	size_t len;

	ZERO_ARRAY(new_passwd);

	/*
	 * if no error is reported from fgets() and string at least contains
	 * the newline that ends the password, then replace the newline with
	 * a null terminator.
	 */
	if ( fgets(new_passwd, sizeof(new_passwd), stdin) != NULL) {
		if ((len = strlen(new_passwd)) > 0) {
			if(new_passwd[len-1] == '\n')
				new_passwd[len - 1] = 0; 
		}
	}
	return(new_passwd);
}


/*************************************************************
 Utility function to get passwords via tty or stdin
 Used if the '-s' option is set to silently get passwords
 to enable scripting.
*************************************************************/
static char *get_pass( char *prompt, BOOL stdin_get)
{
	char *p;
	if (stdin_get) {
		p = stdin_new_passwd();
	} else {
		p = getpass(prompt);
	}
	return strdup_x(p);
}

/*************************************************************
 Utility function to prompt for new password.
*************************************************************/
static char *prompt_for_new_password(BOOL stdin_get)
{
	char *p;
	fstring new_passwd;

	ZERO_ARRAY(new_passwd);
 
	p = get_pass("New SMB password:", stdin_get);

	fstrcpy(new_passwd, p);
	safe_free(p);

	p = get_pass("Retype new SMB password:", stdin_get);

	if (strcmp(p, new_passwd)) {
		fprintf(stderr, "Mismatch - password unchanged.\n");
		ZERO_ARRAY(new_passwd);
		safe_free(p);
		return NULL;
	}

	return p;
}


/*************************************************************
 Change a password either locally or remotely.
*************************************************************/

static BOOL password_change(const char *remote_machine, char *user_name, 
			    char *old_passwd, char *new_passwd, int local_flags)
{
	BOOL ret;
	pstring err_str;
	pstring msg_str;

	if (remote_machine != NULL) {
		if (local_flags & (LOCAL_ADD_USER|LOCAL_DELETE_USER|LOCAL_DISABLE_USER|LOCAL_ENABLE_USER|
							LOCAL_TRUST_ACCOUNT|LOCAL_SET_NO_PASSWORD)) {
			/* these things can't be done remotely yet */
			return False;
		}
		ret = remote_password_change(remote_machine, user_name, 
					 old_passwd, new_passwd, err_str, sizeof(err_str));
		if(*err_str)
			fprintf(stderr, err_str);
		return ret;
	}
	
	ret = local_password_change(user_name, local_flags, new_passwd, 
				     err_str, sizeof(err_str), msg_str, sizeof(msg_str));

	if(*msg_str)
		printf(msg_str);
	if(*err_str)
		fprintf(stderr, err_str);

	return ret;
}

#ifdef WITH_LDAP_SAM
/*******************************************************************
 Store the LDAP admin password in secrets.tdb
 ******************************************************************/
static BOOL store_ldap_admin_pw (char* pw)
{
	if (!pw) 
		return False;

	if (!secrets_init())
		return False;
	
	return secrets_store_ldap_pw(lp_ldap_admin_dn(), pw);
}
#endif


/*************************************************************
 Handle password changing for root.
*************************************************************/

static int process_root(void)
{
	struct passwd  *pwd;
	int result = 0;

#ifdef WITH_LDAP_SAM
	if (local_flags & LOCAL_SET_LDAP_ADMIN_PW)
	{
		printf("Setting stored password for \"%s\" in secrets.tdb\n", 
			lp_ldap_admin_dn());
		if (!store_ldap_admin_pw(ldap_secret))
			DEBUG(0,("ERROR: Failed to store the ldap admin password!\n"));
		goto done;
	}
#endif

	/*
	 * Ensure both add/delete user are not set
	 * Ensure add/delete user and either remote machine or join domain are
	 * not both set.
	 */	
	if(((local_flags & (LOCAL_ADD_USER|LOCAL_DELETE_USER)) == (LOCAL_ADD_USER|LOCAL_DELETE_USER)) || 
	   ((local_flags & (LOCAL_ADD_USER|LOCAL_DELETE_USER)) && 
		((remote_machine != NULL) || joining_domain))) {
		usage();
	}
	
	/* Only load interfaces if we are doing network operations. */

	if (joining_domain || remote_machine) {
		load_interfaces();
	}

	/* Join a domain */

	if (joining_domain) {

		/* Are we joining by specifing an admin username and
		   password? */

		if (user_name[0]) {

			/* Get administrator password if not specified */

			if (!got_pass) {
				char *pass = getpass("Password: ");

				if (pass)
					pstrcpy(user_password, pass);
			}
				
			return join_domain_byuser(new_domain, remote_machine,
						  user_name, user_password);
		} else {

			/* Or just with the server manager? */

			return join_domain(new_domain, remote_machine);
		}
	}

	/*
	 * Deal with root - can add a user, but only locally.
	 */

	if (!user_name[0] && (pwd = sys_getpwuid(0))) {
		fstrcpy(user_name, pwd->pw_name);
	} 

	if (!user_name[0]) {
		fprintf(stderr,"You must specify a username\n");
		exit(1);
	}

	if (local_flags & LOCAL_TRUST_ACCOUNT) {
		/* add the $ automatically */
		static fstring buf;

		/*
		 * Remove any trailing '$' before we
		 * generate the initial machine password.
		 */

		if (user_name[strlen(user_name)-1] == '$') {
			user_name[strlen(user_name)-1] = 0;
		}

		if (local_flags & LOCAL_ADD_USER) {
		        safe_free(new_passwd);
			new_passwd = strdup_x(user_name);
			strlower(new_passwd);
		}

		/*
		 * Now ensure the username ends in '$' for
		 * the machine add.
		 */

		slprintf(buf, sizeof(buf)-1, "%s$", user_name);
		fstrcpy(user_name, buf);
	}

	if (remote_machine != NULL) {
		old_passwd = get_pass("Old SMB password:",stdin_passwd_get);
	}
	
	if (!new_passwd) {

		/*
		 * If we are trying to enable a user, first we need to find out
		 * if they are using a modern version of the smbpasswd file that
		 * disables a user by just writing a flag into the file. If so
		 * then we can re-enable a user without prompting for a new
		 * password. If not (ie. they have a no stored password in the
		 * smbpasswd file) then we need to prompt for a new password.
		 */

		if(local_flags & LOCAL_ENABLE_USER) {
			
			SAM_ACCOUNT *sampass = NULL;
			
			pdb_init_sam(&sampass);
			if (!pdb_getsampwnam(sampass, user_name)) {
				printf("ERROR: Unable to locate %s in passdb!\n", user_name);
				pdb_free_sam(sampass);
				result = 1;
				goto done;
			}
			if((sampass != NULL) && (pdb_get_lanman_passwd(sampass) != NULL)) {
				new_passwd = strdup_x("XXXX"); /* Don't care. */
			}
			
			pdb_free_sam(sampass);
		}

		if(!new_passwd)
			new_passwd = prompt_for_new_password(stdin_passwd_get);

		if(!new_passwd) {
			fprintf(stderr, "Unable to get new password.\n");
			exit(1);
		}
	}
	
	if (!password_change(remote_machine, user_name, old_passwd, new_passwd, local_flags)) {
		fprintf(stderr,"Failed to modify password entry for user %s\n", user_name);
		result = 1;
		goto done;
	} 

	if(!(local_flags & (LOCAL_ADD_USER|LOCAL_DISABLE_USER|LOCAL_ENABLE_USER|LOCAL_DELETE_USER|LOCAL_SET_NO_PASSWORD))) {
		SAM_ACCOUNT *sampass = NULL;
		uint16 acct_ctrl;
		
		pdb_init_sam(&sampass);
		
		if (!pdb_getsampwnam(sampass, user_name)) {
			printf("ERROR: Unable to locate %s in passdb!\n", user_name);
			pdb_free_sam(sampass);
			result = 1;
			goto done;
		}
		
		printf("Password changed for user %s.", user_name );
		acct_ctrl = pdb_get_acct_ctrl(sampass);
		if(acct_ctrl & ACB_DISABLED)
			printf(" User has disabled flag set.");
		if(acct_ctrl & ACB_PWNOTREQ)
			printf(" User has no password flag set.");
		printf("\n");
		
		pdb_free_sam(sampass);
	}

 done:
	safe_free(new_passwd);
	return result;
}


/*************************************************************
 Handle password changing for non-root.
*************************************************************/

static int process_nonroot(void)
{
	struct passwd  *pwd = NULL;
	int result = 0;

	if (!user_name[0]) {
		pwd = sys_getpwuid(getuid());
		if (pwd) {
			fstrcpy(user_name,pwd->pw_name);
		} else {
			fprintf(stderr,"you don't exist - go away\n");
			exit(1);
		}
	}
	
	/*
	 * A non-root user is always setting a password
	 * via a remote machine (even if that machine is
	 * localhost).
	 */	

	load_interfaces(); /* Delayed from main() */

	if (remote_machine == NULL) {
		remote_machine = "127.0.0.1";
	}

	if (remote_machine != NULL) {
		old_passwd = get_pass("Old SMB password:",stdin_passwd_get);
	}
	
	if (!new_passwd) {
		new_passwd = prompt_for_new_password(stdin_passwd_get);
	}
	
	if (!new_passwd) {
		fprintf(stderr, "Unable to get new password.\n");
		exit(1);
	}

	if (!password_change(remote_machine, user_name, old_passwd, new_passwd, 0)) {
		fprintf(stderr,"Failed to change password for %s\n", user_name);
		result = 1;
		goto done;
	}

	printf("Password changed for user %s\n", user_name);

 done:
	safe_free(old_passwd);
	safe_free(new_passwd);

	return result;
}



/*********************************************************
 Start here.
**********************************************************/
int main(int argc, char **argv)
{	
	BOOL amroot = getuid() == 0;

	AllowDebugChange = False;

#if defined(HAVE_SET_AUTH_PARAMETERS)
	set_auth_parameters(argc, argv);
#endif /* HAVE_SET_AUTH_PARAMETERS */

	charset_initialise();
	
	process_options(argc, argv, amroot);
	TimeInit();
	
	setup_logging("smbpasswd", True);
	
	if(!initialize_password_db(False)) {
		fprintf(stderr, "Can't setup password database vectors.\n");
		exit(1);
	}

	if (!lp_load(servicesf,True,False,False)) {
		fprintf(stderr, "Can't load %s - run testparm to debug it\n", 
			servicesf);
		exit(1);
	}

	/*
	 * Set the machine NETBIOS name if not already
	 * set from the config file. 
	 */ 
    
	if (!*global_myname) {   
		char *p;
		fstrcpy(global_myname, myhostname());
		p = strchr(global_myname, '.' );
		if (p) *p = 0;
	}           
	strupper(global_myname);

	codepage_initialise(lp_client_code_page());

	/* Check the effective uid - make sure we are not setuid */
	if ((geteuid() == (uid_t)0) && (getuid() != (uid_t)0)) {
		fprintf(stderr, "smbpasswd must *NOT* be setuid root.\n");
		exit(1);
	}

	if (local_mode || amroot) {
		secrets_init();
		return process_root();
	} 

	return process_nonroot();
}
