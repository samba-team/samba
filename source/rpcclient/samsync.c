/* 
   Unix SMB/Netbios implementation.
   Version 2.2
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

/* Synchronise sam database */

static NTSTATUS sam_sync(struct cli_state *cli, unsigned char trust_passwd[16],
                         BOOL do_smbpasswd_output)
{
        TALLOC_CTX *mem_ctx;
        SAM_DELTA_HDR *hdr_deltas;
        SAM_DELTA_CTR *deltas;
        uint32 database_id = 0, num_deltas;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

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

        if (!NT_STATUS_IS_OK(new_cli_nt_setup_creds(cli, trust_passwd))) {
                DEBUG(0, ("Error initialising session creds\n"));
                goto done;
        }

        /* Do sam synchronisation */

	result = cli_netlogon_sam_sync(cli, mem_ctx, database_id,
                                       &num_deltas, &hdr_deltas, &deltas);
        
        if (!NT_STATUS_IS_OK(result)) {
		goto done;
	}

        /* Produce smbpasswd output - good for migrating from NT! */

        if (do_smbpasswd_output) {
                int i;

                for (i = 0; i < num_deltas; i++) {
                        SAM_ACCOUNT_INFO *a;
                        fstring acct_name, hex_nt_passwd, hex_lm_passwd;
                        uchar lm_passwd[16], nt_passwd[16];

                        /* Skip non-user accounts */

                        if (hdr_deltas[i].type != SAM_DELTA_ACCOUNT_INFO)
                                continue;

                        a = &deltas[i].account_info;

                        unistr2_to_unix(acct_name, &a->uni_acct_name,
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
                               smbpasswd_encode_acb_info(
                                       deltas[i].account_info.acb_info));
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
	printf("Version: %s\n", VERSION);

	printf("\t-d debuglevel         set the debuglevel\n");
	printf("\t-h                    Print this help message.\n");
	printf("\t-s configfile         specify an alternative config file\n");
	printf("\t-S                    synchronise sam database\n");
	printf("\t-R                    replicate sam deltas\n");
	printf("\t-U username           username and password\n");
        printf("\t-p                    produce smbpasswd output\n");
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

        if (!lookup_pdc_name(global_myname, lp_workgroup(), dest_ip, 
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
        pstring servicesf = CONFIGFILE;
        struct cli_state cli;
        NTSTATUS result;
        int opt;
        pstring logfile;
        BOOL interactive = False, do_smbpasswd_output = False;
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

        while((opt = getopt(argc, argv, "s:d:SR:hiU:W:p")) != EOF) {
                switch (opt) {
                case 's':
                        pstrcpy(servicesf, optarg);
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
                        if ((lp=strchr(username,'%'))) {
                                *lp = 0;
                                fstrcpy(password,lp+1);
                                memset(strchr(optarg, '%') + 1, 'X',
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

	slprintf(logfile, sizeof(logfile) - 1, "%s/log.%s", LOGFILEBASE, 
                 "samsync");
	lp_set_logfile(logfile);

        setup_logging("samsync", interactive);

        if (!interactive)
                reopen_logs();

        if (!lp_load(servicesf, True, False, False)) {
                fprintf(stderr, "Can't load %s\n", servicesf);
        }

        load_interfaces();

        TimeInit();

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
                result = sam_sync(&cli, trust_passwd, do_smbpasswd_output);

        if (do_sam_repl)
                result = sam_repl(&cli, trust_passwd, low_serial);

        if (!NT_STATUS_IS_OK(result)) {
                DEBUG(0, ("%s\n", get_nt_error_msg(result)));
                return 1;
        }

	return 0;
}
