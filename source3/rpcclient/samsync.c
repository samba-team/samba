/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Tim Potter 2001

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
			case SAM_DELTA_DOM_INFO: {
                		SAM_DELTA_DOM *a;
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

/* Synchronise sam database */

static NTSTATUS sam_sync(struct cli_state *cli, unsigned char trust_passwd[16],
                         BOOL do_smbpasswd_output, BOOL verbose)
{
        TALLOC_CTX *mem_ctx;
        SAM_DELTA_HDR *hdr_deltas_0, *hdr_deltas_1, *hdr_deltas_2;
        SAM_DELTA_CTR *deltas_0, *deltas_1, *deltas_2;
        uint32 num_deltas_0, num_deltas_1, num_deltas_2;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DOM_CRED ret_creds;
        /* Initialise */

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("talloc_init failed\n"));
		return result;
	}

	if (!cli_nt_session_open (cli, PIPE_NETLOGON)) {
		DEBUG(0, ("Could not initialize netlogon pipe!\n"));
		goto done;
	}

        /* Request a challenge */

        if (!NT_STATUS_IS_OK(new_cli_nt_setup_creds(cli, SEC_CHAN_BDC, trust_passwd))) {
                DEBUG(0, ("Error initialising session creds\n"));
                goto done;
        }

	/* on first call the returnAuthenticator is empty */
	memset(&ret_creds, 0, sizeof(ret_creds));

        /* Do sam synchronisation on the SAM database*/

	result = cli_netlogon_sam_sync(cli, mem_ctx, &ret_creds, 0, &num_deltas_0, &hdr_deltas_0, &deltas_0);
        
        if (!NT_STATUS_IS_OK(result))
		goto done;

	/* verbose mode */
	if (verbose)
		decode_sam_deltas(num_deltas_0, hdr_deltas_0, deltas_0);


	/* 
	 * we can't yet do several sam_sync in a raw, it's a credential problem 
	 * we must chain the credentials
	 */

#if 1
        /* Do sam synchronisation on the LSA database */

	result = cli_netlogon_sam_sync(cli, mem_ctx, &ret_creds, 2, &num_deltas_2, &hdr_deltas_2, &deltas_2);
        
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

        /* Update sam tdb */

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

/* Print usage information */

static void usage(void)
{
	printf("Usage: samsync [options]\n");

	printf("\t-d debuglevel         set the debuglevel\n");
	printf("\t-h                    Print this help message.\n");
	printf("\t-s configfile         specify an alternative config file\n");
	printf("\t-S                    synchronise sam database\n");
	printf("\t-R                    replicate sam deltas\n");
	printf("\t-U username           username and password\n");
        printf("\t-p                    produce smbpasswd output\n");
        printf("\t-V                    verbose output\n");
	printf("\n");
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

	if (! *username) {
		creds->pwd.null_pwd = True;
	}
}

/* Connect to primary domain controller */

static struct cli_state *init_connection(struct cli_state *cli,
                                         char *username, char *domain,
                                         char *password)
{
        struct ntuser_creds creds;
        extern pstring global_myname;
        struct in_addr *dest_ip;
        struct nmb_name calling, called;
        int count;
        fstring dest_host;

	/* Initialise cli_state information */

        ZERO_STRUCTP(cli);

	if (!cli_initialise(cli)) {
		return NULL;
	}

        init_rpcclient_creds(&creds, username, domain, password);
	cli_init_creds(cli, &creds);

        /* Look up name of PDC controller */

        if (!get_dc_list(True, lp_workgroup(), &dest_ip, &count)) {
                DEBUG(0, ("Cannot find domain controller for domain %s\n",
                          lp_workgroup()));
                return NULL;
        }

        if (!lookup_dc_name(global_myname, lp_workgroup(), dest_ip, 
			    dest_host)) {
                DEBUG(0, ("Could not lookup up PDC name for domain %s\n",
                          lp_workgroup()));
                return NULL;
        }

	get_myname((*global_myname)?NULL:global_myname);
	strupper(global_myname);

	make_nmb_name(&called, dns_to_netbios_name(dest_host), 0x20);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname), 0);

	/* Establish a SMB connection */

	if (!cli_establish_connection(cli, dest_host, dest_ip, &calling, 
				      &called, "IPC$", "IPC", False, True)) {
		return NULL;
	}
	
	return cli;
}

/* Main function */

 int main(int argc, char **argv)
{
        BOOL do_sam_sync = False, do_sam_repl = False;
        struct cli_state cli;
        NTSTATUS result;
        int opt;
        pstring logfile;
        BOOL interactive = False, do_smbpasswd_output = False;
        BOOL verbose = False;
        uint32 low_serial = 0;
        unsigned char trust_passwd[16];
        fstring username, domain, password;

        if (argc == 1) {
                usage();
                return 1;
        }

        ZERO_STRUCT(username);
        ZERO_STRUCT(domain);
        ZERO_STRUCT(password);

        /* Parse command line options */

        while((opt = getopt(argc, argv, "s:d:SR:hiU:W:pV")) != EOF) {
                switch (opt) {
                case 's':
                        pstrcpy(dyn_CONFIGFILE, optarg);
                        break;
                case 'd':
                        DEBUGLEVEL = atoi(optarg);
                        break;
                case 'S':
                        do_sam_sync = 1;
                        break;
                case 'R':
                        do_sam_repl = 1;
                        low_serial = atoi(optarg);
                        break;
                case 'i':
                        interactive = True;
                        break;
                case 'U': {
                        char *lp;

                        fstrcpy(username,optarg);
                        if ((lp=strchr_m(username,'%'))) {
                                *lp = 0;
                                fstrcpy(password,lp+1);
                                memset(strchr_m(optarg, '%') + 1, 'X',
                                       strlen(password));
			}
                        break;
                }
                case 'W':
                        pstrcpy(domain, optarg);
                        break;
                case 'p':
                        do_smbpasswd_output = True;
                        break;
                case 'V':
                        verbose = True;
                        break;
               case 'h':
                default:
                        usage();
                        exit(1);
                }
        }

        argc -= optind;

        if (argc > 0) {
                usage();
                return 1;
        }

        /* Initialise samba */

	slprintf(logfile, sizeof(logfile) - 1, "%s/log.%s", dyn_LOGFILEBASE, 
                 "samsync");
	lp_set_logfile(logfile);

        setup_logging("samsync", interactive);

        if (!interactive)
                reopen_logs();

        if (!lp_load(dyn_CONFIGFILE, True, False, False)) {
                fprintf(stderr, "Can't load %s\n", dyn_CONFIGFILE);
        }

        load_interfaces();

        /* Check arguments make sense */

        if (do_sam_sync && do_sam_repl) {
                fprintf(stderr, "cannot specify both -S and -R\n");
                return 1;

        }

        if (!do_sam_sync && !do_sam_repl) {
                fprintf(stderr, "must specify either -S or -R\n");
                return 1;
        }

        if (do_sam_repl && low_serial == 0) {
                fprintf(stderr, "serial number must be positive\n");
                return 1;
        }

        /* BDC operations require the machine account password */

        if (!secrets_init()) {
                DEBUG(0, ("Unable to initialise secrets database\n"));
                return 1;
        }

	if (!secrets_fetch_trust_account_password(lp_workgroup(), 
                                                  trust_passwd, NULL)) {
		DEBUG(0, ("could not fetch trust account password\n"));
		return 1;
	}        

        /* Perform sync or replication */

        if (!init_connection(&cli, username, domain, password))
                return 1;

        if (do_sam_sync)
                result = sam_sync(&cli, trust_passwd, do_smbpasswd_output, verbose);

        if (do_sam_repl)
                result = sam_repl(&cli, trust_passwd, low_serial);

        if (!NT_STATUS_IS_OK(result)) {
                DEBUG(0, ("%s\n", nt_errstr(result)));
                return 1;
        }

	return 0;
}
