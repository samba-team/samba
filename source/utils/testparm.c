/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Test validity of smb.conf
   Copyright (C) Karl Auer 1993, 1994-1998

   Extensively modified by Andrew Tridgell, 1995
   
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

/*
 * Testbed for loadparm.c/params.c
 *
 * This module simply loads a specified configuration file and
 * if successful, dumps it's contents to stdout. Note that the
 * operation is performed with DEBUGLEVEL at 3.
 *
 * Useful for a quick 'syntax check' of a configuration file.
 *
 */

#include "includes.h"
#include "smb.h"

extern BOOL AllowDebugChange;
extern int parsed_debuglevel_class[DBGC_LAST];

/* these live in util.c */
extern FILE *dbf;

/***********************************************
 Here we do a set of 'hard coded' checks for bad
 configuration settings.
************************************************/

static int do_global_checks(void)
{
	int ret = 0;
	SMB_STRUCT_STAT st;

	if (lp_security() == SEC_DOMAIN && !lp_encrypted_passwords()) {
		printf("ERROR: in 'security=domain' mode the 'encrypt passwords' parameter must also be set to 'true'.\n");
		ret = 1;
	}

	if (lp_wins_support() && *lp_wins_server()) {
		printf("ERROR: both 'wins support = true' and 'wins server = <server>' \
cannot be set in the smb.conf file. nmbd will abort with this setting.\n");
		ret = 1;
	}

	if (!directory_exist(lp_lockdir(), &st)) {
		printf("ERROR: lock directory %s does not exist\n",
		       lp_lockdir());
		ret = 1;
	} else if ((st.st_mode & 0777) != 0755) {
		printf("WARNING: lock directory %s should have permissions 0755 for browsing to work\n",
		       lp_lockdir());
		ret = 1;
	}

	if (!directory_exist(lp_piddir(), &st)) {
		printf("ERROR: pid directory %s does not exist\n",
		       lp_piddir());
		ret = 1;
	}

	/*
	 * Password server sanity checks.
	 */

	if((lp_security() == SEC_SERVER || lp_security() == SEC_DOMAIN) && !lp_passwordserver()) {
		pstring sec_setting;
		if(lp_security() == SEC_SERVER)
			pstrcpy(sec_setting, "server");
		else if(lp_security() == SEC_DOMAIN)
			pstrcpy(sec_setting, "domain");

		printf("ERROR: The setting 'security=%s' requires the 'password server' parameter be set \
to a valid password server.\n", sec_setting );
		ret = 1;
	}

	/*
	 * Password chat sanity checks.
	 */

	if(lp_security() == SEC_USER && lp_unix_password_sync()) {

		/*
		 * Check that we have a valid lp_passwd_program() if not using pam.
		 */

#ifdef WITH_PAM
		if (!lp_pam_password_change()) {
#endif

			if(lp_passwd_program() == NULL) {
				printf("ERROR: the 'unix password sync' parameter is set and there is no valid 'passwd program' \
parameter.\n" );
				ret = 1;
			} else {
				pstring passwd_prog;
				pstring truncated_prog;
				const char *p;

				pstrcpy( passwd_prog, lp_passwd_program());
				p = passwd_prog;
				*truncated_prog = '\0';
				next_token(&p, truncated_prog, NULL, sizeof(pstring));

				if(access(truncated_prog, F_OK) == -1) {
					printf("ERROR: the 'unix password sync' parameter is set and the 'passwd program' (%s) \
cannot be executed (error was %s).\n", truncated_prog, strerror(errno) );
					ret = 1;
				}
			}

#ifdef WITH_PAM
		}
#endif

		if(lp_passwd_chat() == NULL) {
			printf("ERROR: the 'unix password sync' parameter is set and there is no valid 'passwd chat' \
parameter.\n");
			ret = 1;
		}

		/*
		 * Check that we have a valid script and that it hasn't
		 * been written to expect the old password.
		 */

		if(lp_encrypted_passwords()) {
			if(strstr( lp_passwd_chat(), "%o")!=NULL) {
				printf("ERROR: the 'passwd chat' script [%s] expects to use the old plaintext password \
via the %%o substitution. With encrypted passwords this is not possible.\n", lp_passwd_chat() );
				ret = 1;
			}
		}
	}

	if (!lp_status(-1) && lp_max_smbd_processes()) {
		printf("ERROR: the 'max smbd processes' parameter is set and the 'status' parameter is set to 'no'.\n");
		ret = 1;
	}

	if (strlen(lp_winbind_separator()) != 1) {
		printf("ERROR: the 'winbind separator' parameter must be a single character.\n");
		ret = 1;
	}

	if (*lp_winbind_separator() == '+') {
		printf("'winbind separator = +' might cause problems with group membership.\n");
	}

	return ret;
}   

static void usage(char *pname)
{
	printf("Usage: %s [-sh] [-L servername] [configfilename] [hostname hostIP]\n", pname);
	printf("\t-s                  Suppress prompt for enter\n");
	printf("\t-x                  Print only smb.conf parameters with values that are non-default\n");
	printf("\t-h                  Print usage\n");
	printf("\t-L servername       Set %%L macro to servername\n");
	printf("\t-t encoding         Print parameters with encoding\n");
	printf("\tconfigfilename      Configuration file to test\n");
	printf("\thostname hostIP.    Hostname and Host IP address to test\n");
	printf("\t                    against \"host allow\" and \"host deny\"\n");
	printf("\n");
}


int main(int argc, char *argv[])
{
  extern char *optarg;
  extern int optind;
  extern fstring local_machine;
  pstring configfile;
  int opt;
  int s;
  BOOL show_defaults=True;
  BOOL silent_mode = False;
  int ret = 0;
  pstring term_code;

  *term_code = 0;

  TimeInit();

  setup_logging(argv[0],True);
  
  charset_initialise();

  while ((opt = getopt(argc, argv,"shL:t:x")) != EOF) {
  switch (opt) {
    case 's':
      silent_mode = True;
      break;
    case 'L':
      fstrcpy(local_machine,optarg);
      break;
    case 'h':
      usage(argv[0]);
      exit(0);
      break;
    case 't':
      pstrcpy(term_code,optarg);
      break;
    case 'x':
      show_defaults=False;
      break;
    default:
      printf("Incorrect program usage\n");
      usage(argv[0]);
      exit(1);
      break;
    }
  }

  argc += (1 - optind);

  if ((argc == 1) || (argc == 3))
    pstrcpy(configfile,CONFIGFILE);
  else if ((argc == 2) || (argc == 4))
    pstrcpy(configfile,argv[optind]);

  dbf = stdout;
  DEBUGLEVEL = 2;
  AllowDebugChange = False;

  printf("Load smb config files from %s\n",configfile);

  if (!lp_load(configfile,False,True,False)) {
      printf("Error loading services.\n");
      return(1);
  }

  printf("Loaded services file OK.\n");

  ret = do_global_checks();

  for (s=0;s<1000;s++) {
    if (VALID_SNUM(s))
      if (strlen(lp_servicename(s)) > 8) {
        printf("WARNING: You have some share names that are longer than 8 chars\n");
        printf("These may give errors while browsing or may not be accessible\nto some older clients\n");
        break;
      }
  }

  for (s=0;s<1000;s++) {
    if (VALID_SNUM(s)) {
      char *deny_list = lp_hostsdeny(s);
      char *allow_list = lp_hostsallow(s);
      if(deny_list) {
        char *hasstar = strchr(deny_list, '*');
        char *hasquery = strchr(deny_list, '?');
        if(hasstar || hasquery) {
          printf("Invalid character %c in hosts deny list %s for service %s.\n",
                 hasstar ? *hasstar : *hasquery, deny_list, lp_servicename(s) );
        }
      }

      if(allow_list) {
        char *hasstar = strchr(allow_list, '*');
        char *hasquery = strchr(allow_list, '?');
        if(hasstar || hasquery) {
          printf("Invalid character %c in hosts allow list %s for service %s.\n",
                 hasstar ? *hasstar : *hasquery, allow_list, lp_servicename(s) );
        }
      }

      if(lp_level2_oplocks(s) && !lp_oplocks(s)) {
        printf("Invalid combination of parameters for service %s. \
Level II oplocks can only be set if oplocks are also set.\n",
               lp_servicename(s) );
      }
    }
  }

  if (*term_code)
    interpret_coding_system(term_code);

  if (argc < 3) {
    if (!silent_mode) {
      printf("Press enter to see a dump of your service definitions\n");
      fflush(stdout);
      getc(stdin);
    }
    memcpy(DEBUGLEVEL_CLASS,parsed_debuglevel_class,sizeof(parsed_debuglevel_class));
    lp_dump(stdout,show_defaults, lp_numservices(), _dos_to_unix_static);
  }
  
  if (argc >= 3) {
    char *cname;
    char *caddr;
      
    if (argc == 3) {
      cname = argv[optind];
      caddr = argv[optind+1];
    } else {
      cname = argv[optind+1];
      caddr = argv[optind+2];
    }

    /* this is totally ugly, a real `quick' hack */
    for (s=0;s<1000;s++) {
      if (VALID_SNUM(s)) {		 
        if (allow_access(lp_hostsdeny(s),lp_hostsallow(s),cname,caddr)) {
          printf("Allow connection from %s (%s) to %s\n",
                 cname,caddr,lp_servicename(s));
        } else {
          printf("Deny connection from %s (%s) to %s\n",
                 cname,caddr,lp_servicename(s));
        }
      }
    }
  }
  return(ret);
}
