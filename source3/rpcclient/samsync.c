/* 
   Unix SMB/CIFS implementation.
   SAM synchronisation and replication

   Copyright (C) Tim Potter 2001,2002

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

DOM_SID domain_sid;

static void decode_domain_info(SAM_DOMAIN_INFO *a)
{
	fstring temp;
	printf("Domain Information\n");
	printf("------------------\n");

	unistr2_to_ascii(temp, &a->uni_dom_name, sizeof(temp)-1);
	printf("\tDomain              :%s\n", temp);
	printf("\tMin password len    :%d\n", a->min_pwd_len);
	printf("\tpassword history len:%d\n", a->pwd_history_len);
	printf("\tcreation time       :%s\n", http_timestring(nt_time_to_unix(&a->creation_time)));
}

static void decode_sam_group_info(SAM_GROUP_INFO *a)
{
	fstring temp;
	printf("\nDomain Group Information\n");
	printf("------------------------\n");

	unistr2_to_ascii(temp, &a->uni_grp_name, sizeof(temp)-1);
	printf("\tGroup name          :%s\n", temp);
	unistr2_to_ascii(temp, &a->uni_grp_desc, sizeof(temp)-1);
	printf("\tGroup description   :%s\n", temp);
	printf("\trid                 :%d\n", a->gid.g_rid);
	printf("\tattribute           :%d\n", a->gid.attr);
}

static void decode_sam_account_info(SAM_ACCOUNT_INFO *a)
{
	fstring temp;
	printf("\nUser Information\n");
	printf("----------------\n");

	unistr2_to_ascii(temp, &a->uni_acct_name, sizeof(temp)-1);
	printf("\tUser name          :%s\n", temp);
	printf("\tuser's rid         :%d\n", a->user_rid);
	printf("\tuser's primary gid :%d\n", a->group_rid);
	unistr2_to_ascii(temp, &a->uni_full_name, sizeof(temp)-1);
	printf("\tfull name          :%s\n", temp);
	unistr2_to_ascii(temp, &a->uni_home_dir, sizeof(temp)-1);
	printf("\thome directory     :%s\n", temp);
	unistr2_to_ascii(temp, &a->uni_dir_drive, sizeof(temp)-1);
	printf("\tdrive              :%s\n", temp);
	unistr2_to_ascii(temp, &a->uni_logon_script, sizeof(temp)-1);
	printf("\tlogon script       :%s\n", temp);
	unistr2_to_ascii(temp, &a->uni_acct_desc, sizeof(temp)-1);
	printf("\tdescription        :%s\n", temp);
	unistr2_to_ascii(temp, &a->uni_workstations, sizeof(temp)-1);
	printf("\tworkstations       :%s\n", temp);
}

static void decode_sam_grp_mem_info(SAM_GROUP_MEM_INFO *a)
{
	int i;
	printf("\nGroup members information\n");
	printf("-------------------------\n");
	printf("\tnum members        :%d\n", a->num_members);

	for (i=0; i<a->num_members; i++) {
		printf("\trid, attr:%d, %d\n", a->rids[i], a->attribs[i]);
	}
}

static void decode_sam_alias_info(SAM_ALIAS_INFO *a)
{
	fstring temp;
	printf("\nAlias Information\n");
	printf("-----------------\n");

	unistr2_to_ascii(temp, &a->uni_als_name, sizeof(temp)-1);
	printf("\tname               :%s\n", temp);
	unistr2_to_ascii(temp, &a->uni_als_desc, sizeof(temp)-1);
	printf("\tdescription        :%s\n", temp);
	printf("\trid                :%d\n", a->als_rid);
}

static void decode_sam_als_mem_info(SAM_ALIAS_MEM_INFO *a)
{
	int i;
	fstring temp;
	printf("\nAlias members Information\n");
	printf("-------------------------\n");
	printf("\tnum members        :%d\n", a->num_members);
	printf("\tnum sids           :%d\n", a->num_sids);
	for (i=0; i<a->num_sids; i++) {
		printf("\tsid                :%s\n", sid_to_string(temp, &a->sids[i].sid));
	}


}

static void decode_sam_dom_info(SAM_DELTA_DOM *a)
{
	fstring temp;
	printf("\nDomain information\n");
	printf("------------------\n");

	unistr2_to_ascii(temp, &a->domain_name, sizeof(temp)-1);
	printf("\tdomain name        :%s\n", temp);
	printf("\tsid                :%s\n", sid_to_string(temp, &a->domain_sid.sid));
}

static void decode_sam_unk0e_info(SAM_DELTA_UNK0E *a)
{
	fstring temp;
	printf("\nTrust information\n");
	printf("-----------------\n");

	unistr2_to_ascii(temp, &a->domain, sizeof(temp)-1);
	printf("\tdomain name        :%s\n", temp);
	printf("\tsid                :%s\n", sid_to_string(temp, &a->sid.sid));
	display_sec_desc(a->sec_desc);
}

static void decode_sam_privs_info(SAM_DELTA_PRIVS *a)
{
	int i;
	fstring temp;
	printf("\nSID and privileges information\n");
	printf("------------------------------\n");
	printf("\tsid                :%s\n", sid_to_string(temp, &a->sid.sid));
	display_sec_desc(a->sec_desc);
	printf("\tprivileges count   :%d\n", a->privlist_count);
	for (i=0; i<a->privlist_count; i++) {
		unistr2_to_ascii(temp, &a->uni_privslist[i], sizeof(temp)-1);
		printf("\tprivilege name     :%s\n", temp);
		printf("\tattribute          :%d\n", a->attributes[i]);
	}
}

static void decode_sam_unk12_info(SAM_DELTA_UNK12 *a)
{
	fstring temp;
	printf("\nTrusted information\n");
	printf("-------------------\n");

	unistr2_to_ascii(temp, &a->secret, sizeof(temp)-1);
	printf("\tsecret name        :%s\n", temp);
	display_sec_desc(a->sec_desc);
	
	printf("\ttime 1             :%s\n", http_timestring(nt_time_to_unix(&a->time1)));
	printf("\ttime 2             :%s\n", http_timestring(nt_time_to_unix(&a->time2)));

	display_sec_desc(a->sec_desc2);
}

static void decode_sam_stamp(SAM_DELTA_STAMP *a)
{
	printf("\nStamp information\n");
	printf("-----------------\n");
	printf("\tsequence number    :%d\n", a->seqnum);
}

static void decode_sam_deltas(uint32 num_deltas, SAM_DELTA_HDR *hdr_deltas, SAM_DELTA_CTR *deltas)
{
	int i;
        for (i = 0; i < num_deltas; i++) {
		switch (hdr_deltas[i].type) {
			case SAM_DELTA_DOMAIN_INFO: {
                		SAM_DOMAIN_INFO *a;
				a = &deltas[i].domain_info;
				decode_domain_info(a);
				break;
			}
			case SAM_DELTA_GROUP_INFO:  {
                		SAM_GROUP_INFO *a;
				a = &deltas[i].group_info;
				decode_sam_group_info(a);
				break;
			}
			case SAM_DELTA_ACCOUNT_INFO: {
                		SAM_ACCOUNT_INFO *a;
				a = &deltas[i].account_info;
				decode_sam_account_info(a);
				break;
			}
			case SAM_DELTA_GROUP_MEM: {
                		SAM_GROUP_MEM_INFO *a;
				a = &deltas[i].grp_mem_info;
				decode_sam_grp_mem_info(a);
				break;
			}
			case SAM_DELTA_ALIAS_INFO: {
                		SAM_ALIAS_INFO *a;
				a = &deltas[i].alias_info;
				decode_sam_alias_info(a);
				break;
			}
			case SAM_DELTA_ALIAS_MEM: {
                		SAM_ALIAS_MEM_INFO *a;
				a = &deltas[i].als_mem_info;
				decode_sam_als_mem_info(a);
				break;
			}
			case SAM_DELTA_POLICY_INFO: {
                		SAM_DELTA_POLICY *a;
				a = &deltas[i].dom_info;
				decode_sam_dom_info(a);
				break;
			}
			case SAM_DELTA_UNK0E_INFO: {
                		SAM_DELTA_UNK0E *a;
				a = &deltas[i].unk0e_info;
				decode_sam_unk0e_info(a);
				break;
			}
			case SAM_DELTA_PRIVS_INFO: {
                		SAM_DELTA_PRIVS *a;
				a = &deltas[i].privs_info;
				decode_sam_privs_info(a);
				break;
			}
			case SAM_DELTA_UNK12_INFO: {
                		SAM_DELTA_UNK12 *a;
				a = &deltas[i].unk12_info;
				decode_sam_unk12_info(a);
				break;
			}
			case SAM_DELTA_SAM_STAMP: {
                		SAM_DELTA_STAMP *a;
				a = &deltas[i].stamp;
				decode_sam_stamp(a);
				break;
			}
			default:
				DEBUG(0,("unknown delta type: %d\n", hdr_deltas[i].type));
				break;	
		}
	}
}

/* Convert a SAM_ACCOUNT_DELTA to a SAM_ACCOUNT. */

static void sam_account_from_delta(SAM_ACCOUNT *account,
				   SAM_ACCOUNT_INFO *delta)
{
	DOM_SID sid;
	fstring s;

	/* Username, fullname, home dir, dir drive, logon script, acct
	   desc, workstations, profile. */

	unistr2_to_ascii(s, &delta->uni_acct_name, sizeof(s) - 1);
	pdb_set_nt_username(account, s);

	/* Unix username is the same - for sainity */
	pdb_set_username(account, s);

	unistr2_to_ascii(s, &delta->uni_full_name, sizeof(s) - 1);
	pdb_set_fullname(account, s);

	unistr2_to_ascii(s, &delta->uni_home_dir, sizeof(s) - 1);
	pdb_set_homedir(account, s, True);

	unistr2_to_ascii(s, &delta->uni_dir_drive, sizeof(s) - 1);
	pdb_set_dir_drive(account, s, True);

	unistr2_to_ascii(s, &delta->uni_logon_script, sizeof(s) - 1);
	pdb_set_logon_script(account, s, True);

	unistr2_to_ascii(s, &delta->uni_acct_desc, sizeof(s) - 1);
	pdb_set_acct_desc(account, s);

	unistr2_to_ascii(s, &delta->uni_workstations, sizeof(s) - 1);
	pdb_set_workstations(account, s);

	unistr2_to_ascii(s, &delta->uni_profile, sizeof(s) - 1);
	pdb_set_profile_path(account, s, True);

	/* User and group sid */

	sid_copy(&sid, &domain_sid);
	sid_append_rid(&sid, delta->user_rid);
	pdb_set_user_sid(account, &sid);

	sid_copy(&sid, &domain_sid);
	sid_append_rid(&sid, delta->group_rid);
	pdb_set_group_sid(account, &sid);

	/* Logon and password information */

	pdb_set_logon_time(account, nt_time_to_unix(&delta->logon_time), True);
	pdb_set_logoff_time(account, nt_time_to_unix(&delta->logoff_time), 
			    True);

	pdb_set_logon_divs(account, delta->logon_divs);

	/* TODO: logon hours */
	/* TODO: bad password count */
	/* TODO: logon count */

	pdb_set_pass_last_set_time(
		account, nt_time_to_unix(&delta->pwd_last_set_time));

	/* TODO: account expiry time */

	pdb_set_acct_ctrl(account, delta->acb_info);
}

static void apply_account_info(SAM_ACCOUNT_INFO *sam_acct_delta)
{
	SAM_ACCOUNT *sam_acct;
	BOOL result;

	if (!NT_STATUS_IS_OK(pdb_init_sam(&sam_acct))) {
		return;
	}

	sam_account_from_delta(sam_acct, sam_acct_delta);
	result = pdb_add_sam_account(sam_acct);
}

/* Apply an array of deltas to the SAM database */

static void apply_deltas(uint32 num_deltas, SAM_DELTA_HDR *hdr_deltas,
			 SAM_DELTA_CTR *deltas)
{
	uint32 i;

	for (i = 0; i < num_deltas; i++) {
		switch(hdr_deltas[i].type) {
		case SAM_DELTA_ACCOUNT_INFO:
			apply_account_info(&deltas[i].account_info);
			break;
		}
	}
}

/* Synchronise sam database */

static NTSTATUS sam_sync(struct cli_state *cli, unsigned char trust_passwd[16],
                         BOOL do_smbpasswd_output, BOOL verbose)
{
        TALLOC_CTX *mem_ctx;
        SAM_DELTA_HDR *hdr_deltas_0, *hdr_deltas_2;
        SAM_DELTA_CTR *deltas_0, *deltas_2;
        uint32 num_deltas_0, num_deltas_2;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	struct pdb_context *in;
	uint32 neg_flags = 0x000001ff;

	DOM_CRED ret_creds;

        /* Initialise */

	if (!NT_STATUS_IS_OK(make_pdb_context_list(&in, lp_passdb_backend()))){
		DEBUG(0, ("Can't initialize passdb backend.\n"));
		      return result;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("talloc_init failed\n"));
		return result;
	}

	if (!cli_nt_session_open (cli, PI_NETLOGON)) {
		DEBUG(0, ("Could not initialize netlogon pipe!\n"));
		goto done;
	}

        /* Request a challenge */

        if (!NT_STATUS_IS_OK(cli_nt_setup_creds(cli, SEC_CHAN_BDC, trust_passwd, &neg_flags, 2))) {
                DEBUG(0, ("Error initialising session creds\n"));
                goto done;
        }

	/* on first call the returnAuthenticator is empty */
	memset(&ret_creds, 0, sizeof(ret_creds));

        /* Do sam synchronisation on the SAM database*/

	result = cli_netlogon_sam_sync(cli, mem_ctx, &ret_creds, 0, 0,
				       &num_deltas_0, &hdr_deltas_0, 
				       &deltas_0);
        
        if (!NT_STATUS_IS_OK(result))
		goto done;

	
        /* Update sam */

	apply_deltas(num_deltas_0, hdr_deltas_0, deltas_0);


	/* 
	 * we can't yet do several sam_sync in a raw, it's a credential problem 
	 * we must chain the credentials
	 */

#if 1
        /* Do sam synchronisation on the LSA database */

	result = cli_netlogon_sam_sync(cli, mem_ctx, &ret_creds, 2, 0, &num_deltas_2, &hdr_deltas_2, &deltas_2);
        
        if (!NT_STATUS_IS_OK(result))
		goto done;

	/* verbose mode */
	if (verbose)
		decode_sam_deltas(num_deltas_2, hdr_deltas_2, deltas_2);
#endif

        /* Produce smbpasswd output - good for migrating from NT! */

        if (do_smbpasswd_output) {
                int i;

                for (i = 0; i < num_deltas_0; i++) {
                        SAM_ACCOUNT_INFO *a;
                        fstring acct_name, hex_nt_passwd, hex_lm_passwd;
                        uchar lm_passwd[16], nt_passwd[16];

                        /* Skip non-user accounts */

                        if (hdr_deltas_0[i].type != SAM_DELTA_ACCOUNT_INFO)
                                continue;

                        a = &deltas_0[i].account_info;

                        unistr2_to_ascii(acct_name, &a->uni_acct_name,
                                         sizeof(acct_name) - 1);

                        /* Decode hashes from password hash */

                        sam_pwd_hash(a->user_rid, a->pass.buf_lm_pwd, 
                                     lm_passwd, 0);
                        sam_pwd_hash(a->user_rid, a->pass.buf_nt_pwd, 
                                     nt_passwd, 0);

                        /* Encode as strings */

                        smbpasswd_sethexpwd(hex_lm_passwd, lm_passwd,
                                            a->acb_info);
                        smbpasswd_sethexpwd(hex_nt_passwd, nt_passwd,
                                            a->acb_info);

                        /* Display user info */

                        printf("%s:%d:%s:%s:%s:LCT-0\n", acct_name,
                               a->user_rid, hex_lm_passwd, hex_nt_passwd,
                               smbpasswd_encode_acb_info(a->acb_info));
                }
                               
                goto done;
        }

 done:
	cli_nt_session_close(cli);
	talloc_destroy(mem_ctx);
        
        return result;
}

/* Replicate sam deltas */

static NTSTATUS sam_repl(struct cli_state *cli, unsigned char trust_passwde[16],
                         uint32 low_serial)
{
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

        return result;
}

/* Connect to primary domain controller */

static struct cli_state *init_connection(struct cli_state **cli,
                                         char *username, char *domain,
                                         char *password)
{
        extern pstring global_myname;
        struct in_addr pdc_ip;
        fstring dest_host;

	/* Initialise myname */

	if (!global_myname[0]) {
		char *p;

		fstrcpy(global_myname, myhostname());
		p = strchr(global_myname, '.');
		if (p)
			*p = 0;
	}

        /* Look up name of PDC controller */

        if (!get_pdc_ip(lp_workgroup(), &pdc_ip)) {
                DEBUG(0, ("Cannot find domain controller for domain %s\n",
                          lp_workgroup()));
                return NULL;
        }

        if (!lookup_dc_name(global_myname, lp_workgroup(), pdc_ip, 
			    dest_host)) {
                DEBUG(0, ("Could not lookup up PDC name for domain %s\n",
                          lp_workgroup()));
                return NULL;
        }

	if (NT_STATUS_IS_OK(cli_full_connection(cli, global_myname, dest_host,
						pdc_ip, 0,
						"IPC$", "IPC",  
						username, domain,
						password, 0))) {
		return *cli;
	}

	return NULL;
}

/* Main function */

static fstring popt_username, popt_domain, popt_password;
static BOOL popt_got_pass;

static void user_callback(poptContext con, 
			  enum poptCallbackReason reason,
			  const struct poptOption *opt,
			  const char *arg, const void *data)
{
	const char *p, *ch;

	if (!arg)
		return;

	switch(opt->val) {

		/* Check for [DOMAIN\\]username[%password]*/

	case 'U':

		p = arg;

		if ((ch = strchr(p, '\\'))) {
			fstrcpy(popt_domain, p); 
			popt_domain[ch - p] = 0;
		}

		fstrcpy(popt_username, p);

		if ((ch = strchr(p, '%'))) {
			popt_username[ch - p] = 0;
			fstrcpy(popt_password, ch + 1);
			popt_got_pass = True;
		}

		break;
		
	case 'W':
		fstrcpy(popt_domain, arg);
		break;
	}
}

/* Return domain, username and password passed in from cmd line */

void popt_common_get_auth_info(char **domain, char **username, char **password,
			       BOOL *got_pass)
{
	*domain = popt_domain;
	*username = popt_username;
	*password = popt_password;
	*got_pass = popt_got_pass;
}

struct poptOption popt_common_auth_info[] = {
	{ NULL, 0, POPT_ARG_CALLBACK, user_callback },
	{ "user", 'U', POPT_ARG_STRING, NULL, 'U', "Set username",
	  "[DOMAIN\\]username[%password]" },
	{ "domain", 'W', POPT_ARG_STRING, NULL, 'W', "Set domain name", 
	  "DOMAIN"},
	{ 0 }
};

static BOOL popt_interactive;

BOOL popt_common_is_interactive(void)
{
	return popt_interactive;
}

struct poptOption popt_common_interactive[] = {
	{ "interactive", 'i', POPT_ARG_NONE, &popt_interactive, 'i',
	  "Log to stdout" },
	{ 0 }
};

 int main(int argc, char **argv)
{
        BOOL do_sam_sync = False, do_sam_repl = False;
        struct cli_state *cli;
        NTSTATUS result;
        pstring logfile;
        BOOL do_smbpasswd_output = False;
        BOOL verbose = True, got_pass = False;
        uint32 serial = 0;
        unsigned char trust_passwd[16];
        char *username, *domain, *password;
	poptContext pc;
	char c;

	struct poptOption popt_samsync_opts[] = {
		{ "synchronise", 'S', POPT_ARG_NONE, &do_sam_sync, 'S', 
		  "Perform full SAM synchronisation" },
		{ "replicate", 'R', POPT_ARG_NONE, &do_sam_repl, 'R',
		  "Replicate SAM changes" },
		{ "serial", 0, POPT_ARG_INT, &serial, 0, "SAM serial number" },
		{ NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_debug },
		{ NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_auth_info },
		{ NULL, 0, POPT_ARG_INCLUDE_TABLE, popt_common_interactive },
		POPT_AUTOHELP
		{ 0 }
	};

	/* Read command line options */

	pc = poptGetContext("samsync", argc, (const char **)argv,
			    popt_samsync_opts, 0);

	if (argc == 1) {
		poptPrintUsage(pc, stdout, 0);
		return 1;
	}

	while ((c = poptGetNextOpt(pc)) != -1) {

		/* Argument processing error */

		if (c < -1) {
			fprintf(stderr, "samsync: %s: %s\n",
				poptBadOption(pc, POPT_BADOPTION_NOALIAS),
				poptStrerror(c));
			return 1;
		}

		/* Handle arguments */

		switch (c) {
		case 'h':
			poptPrintHelp(pc, stdout, 0);
			return 1;
		case 'u':
			poptPrintUsage(pc, stdout, 0);
			return 1;
		}
	}

	/* Bail out if any extra args were passed */

	if (poptPeekArg(pc)) {
		fprintf(stderr, "samsync: invalid argument %s\n",
			poptPeekArg(pc));
		poptPrintUsage(pc, stdout, 0);
		return 1;
	}

	poptFreeContext(pc);

	/* Setup logging */

	dbf = x_stdout;

	if (!lp_load(dyn_CONFIGFILE, True, False, False)) {
		d_fprintf(stderr, "samsync: error opening config file %s. "
			  "Error was %s\n", dyn_CONFIGFILE, strerror(errno));
		return 1;
	}

	slprintf(logfile, sizeof(logfile) - 1, "%s/log.%s", dyn_LOGFILEBASE, 
                 "samsync");

	lp_set_logfile(logfile);

        setup_logging("samsync", popt_common_is_interactive());

        if (!popt_common_is_interactive())
                reopen_logs();

	load_interfaces();

        /* Check arguments make sense */

        if (do_sam_sync && do_sam_repl) {
                DEBUG(0, ("cannot specify both -S and -R\n"));
                return 1;

        }

        if (!do_sam_sync && !do_sam_repl) {
                DEBUG(0, ("samsync: you must either --synchronise or "
			  "--replicate the SAM database\n"));
                return 1;
        }

        if (do_sam_repl && serial == 0) {
                DEBUG(0, ("samsync: must specify serial number\n"));
                return 1;
        }

	if (do_sam_sync && serial != 0) {
		DEBUG(0, ("samsync: you can't specify a serial number when "
			  "synchonising the SAM database\n"));
		return 1;
	}

        /* BDC operations require the machine account password */

        if (!secrets_init()) {
                DEBUG(0, ("samsync: unable to initialise secrets database\n"));
                return 1;
        }

	if (!secrets_fetch_trust_account_password(lp_workgroup(), 
                                                  trust_passwd, NULL)) {
		DEBUG(0, ("samsync: could not fetch trust account password\n"));
		return 1;
	}        

	/* I wish the domain sid wasn't stored in secrets.tdb */

	if (!secrets_fetch_domain_sid(lp_workgroup(), &domain_sid)) {
		DEBUG(0, ("samsync: could not retrieve domain sid\n"));
		return 1;
	}

        /* Perform sync or replication */

	popt_common_get_auth_info(&domain, &username, &password, &got_pass);

        if (!init_connection(&cli, username, domain, password))
                return 1;

        if (do_sam_sync)
                result = sam_sync(cli, trust_passwd, do_smbpasswd_output, 
				  verbose);

        if (do_sam_repl)
                result = sam_repl(cli, trust_passwd, serial);

        if (!NT_STATUS_IS_OK(result)) {
                DEBUG(0, ("%s\n", nt_errstr(result)));
                return 1;
        }

	return 0;
}
