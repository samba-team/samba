/* 
   Unix SMB/Netbios implementation.
   Network neighbourhood browser.
   Version 3.0
   
   Copyright (C) Tim Potter      2000
   
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

static BOOL use_bcast;

struct user_auth_info {
	pstring username;
	pstring password;
	pstring workgroup;
};

/* How low can we go? */

enum tree_level {LEV_WORKGROUP, LEV_SERVER, LEV_SHARE};
enum tree_level level = LEV_SHARE;

static void usage(void)
{
	printf(
"Usage: smbtree [options]\n\
\n\
\t-d debuglevel           set debug output level\n\
\t-U username             user to autheticate as\n\
\t-W workgroup            workgroup of user to authenticate as\n\
\t-D                      list only domains (workgroups) of tree\n\
\t-S                      list domains and servers of tree\n\
\t-b                      use bcast instead of using the master browser\n\
\n\
The username can be of the form username%%password or\n\
workgroup\\username%%password.\n\n\
");
}

/* Holds a list of workgroups or servers */

struct name_list {
        struct name_list *prev, *next;
        pstring name, comment;
        uint32 server_type;
};

static struct name_list *workgroups, *servers, *shares;

static void free_name_list(struct name_list *list)
{
        while(list)
                DLIST_REMOVE(list, list);
}

static void add_name(const char *machine_name, uint32 server_type,
                     const char *comment, void *state)
{
        struct name_list **name_list = (struct name_list **)state;
        struct name_list *new_name;

        new_name = (struct name_list *)malloc(sizeof(struct name_list));

        if (!new_name)
                return;

        ZERO_STRUCTP(new_name);

        pstrcpy(new_name->name, machine_name);
        pstrcpy(new_name->comment, comment);
        new_name->server_type = server_type;

        DLIST_ADD(*name_list, new_name);
}

/* Return a cli_state pointing at the IPC$ share for the given workgroup */

static struct cli_state *get_ipc_connect(char *server,
                                         struct user_auth_info *user_info)
{
        struct nmb_name calling, called;
        extern struct in_addr ipzero;
        struct in_addr server_ip = ipzero;
        struct cli_state *cli;
        pstring myname;

        get_myname(myname);

        make_nmb_name(&called, myname, 0x0);
        make_nmb_name(&calling, server, 0x20);

        if (is_ipaddress(server))
                if (!resolve_name(server, &server_ip, 0x20))
                        return False;
                
 again:
	if (!(cli = cli_initialise(NULL))) {
                DEBUG(4, ("Unable to initialise cli structure\n"));
                goto error;
        }

        if (!cli_connect(cli, server, &server_ip)) {
                DEBUG(4, ("Unable to connect to %s\n", server));
                goto error;
        }

        if (!cli_session_request(cli, &calling, &called)) {
                cli_shutdown(cli);
                if (!strequal(called.name, "*SMBSERVER")) {
                        make_nmb_name(&called , "*SMBSERVER", 0x20);
                        goto again;
                }
                DEBUG(4, ("Session request failed to %s\n", called.name));
                goto error;
	}

        if (!cli_negprot(cli)) {
                DEBUG(4, ("Negprot failed\n"));
                goto error;
	}

	if (!cli_session_setup(cli, user_info->username, user_info->password, 
                               strlen(user_info->password),
			       user_info->password, 
                               strlen(user_info->password), server) &&
	    /* try an anonymous login if it failed */
	    !cli_session_setup(cli, "", "", 1,"", 0, server)) {
                DEBUG(4, ("Session setup failed\n"));
                goto error;
	}

	DEBUG(4,(" session setup ok\n"));

	if (!cli_send_tconX(cli, "IPC$", "?????",
			    user_info->password, 
                            strlen(user_info->password)+1)) {
                DEBUG(4, ("Tconx failed\n"));
                goto error;
	}

        return cli;

        /* Clean up after error */

 error:
        if (cli && cli->initialised)
                cli_shutdown(cli);

        SAFE_FREE(cli);
        return NULL;
}

/* Return the IP address and workgroup of a master browser on the 
   network. */

static BOOL find_master_ip_bcast(pstring workgroup, struct in_addr *server_ip)
{
	struct in_addr *ip_list;
	int i, count;

        /* Go looking for workgroups by broadcasting on the local network */ 

        if (!name_resolve_bcast(MSBROWSE, 1, &ip_list, &count)) {
                return False;
        }

	for (i = 0; i < count; i++) {
		static fstring name;

		if (!name_status_find("*", 0, 0x1d, ip_list[i], name))
			continue;

                if (!find_master_ip(name, server_ip))
			continue;

                pstrcpy(workgroup, name);

                DEBUG(4, ("found master browser %s, %s\n", 
                          name, inet_ntoa(ip_list[i])));

                return True;
	}

	return False;
}

/****************************************************************************
  display tree of smb workgroups, servers and shares
****************************************************************************/
static BOOL get_workgroups(struct user_auth_info *user_info)
{
        struct cli_state *cli;
        struct in_addr server_ip;
	pstring master_workgroup;

        /* Try to connect to a #1d name of our current workgroup.  If that
           doesn't work broadcast for a master browser and then jump off
           that workgroup. */

	pstrcpy(master_workgroup, lp_workgroup());

        if (use_bcast || !find_master_ip(lp_workgroup(), &server_ip)) {
                DEBUG(4, ("Unable to find master browser for workgroup %s\n", 
			  master_workgroup));
		if (!find_master_ip_bcast(master_workgroup, &server_ip)) {
			DEBUG(4, ("Unable to find master browser by "
				  "broadcast\n"));
			return False;
		}
        }

        if (!(cli = get_ipc_connect(inet_ntoa(server_ip), user_info)))
                return False;

        if (!cli_NetServerEnum(cli, master_workgroup, 
                               SV_TYPE_DOMAIN_ENUM, add_name, &workgroups))
                return False;

        return True;
}

/* Retrieve the list of servers for a given workgroup */

static BOOL get_servers(char *workgroup, struct user_auth_info *user_info)
{
        struct cli_state *cli;
        struct in_addr server_ip;

        /* Open an IPC$ connection to the master browser for the workgroup */

        if (!find_master_ip(workgroup, &server_ip)) {
                DEBUG(4, ("Cannot find master browser for workgroup %s\n",
                          workgroup));
                return False;
        }

        if (!(cli = get_ipc_connect(inet_ntoa(server_ip), user_info)))
                return False;

        if (!cli_NetServerEnum(cli, workgroup, SV_TYPE_ALL, add_name, 
                               &servers))
                return False;

        return True;
}

static BOOL get_shares(char *server_name, struct user_auth_info *user_info)
{
        struct cli_state *cli;

        if (!(cli = get_ipc_connect(server_name, user_info)))
                return False;

        if (!cli_RNetShareEnum(cli, add_name, &shares))
                return False;

        return True;
}

static BOOL print_tree(struct user_auth_info *user_info)
{
        struct name_list *wg, *sv, *sh;

        /* List workgroups */

        if (!get_workgroups(user_info))
                return False;

        for (wg = workgroups; wg; wg = wg->next) {

                printf("%s\n", wg->name);

                /* List servers */

                free_name_list(servers);
                servers = NULL;

                if (level == LEV_WORKGROUP || 
                    !get_servers(wg->name, user_info))
                        continue;

                for (sv = servers; sv; sv = sv->next) {

                        printf("\t\\\\%-15s\t\t%s\n", 
			       sv->name, sv->comment);

                        /* List shares */

                        free_name_list(shares);
                        shares = NULL;

                        if (level == LEV_SERVER ||
                            !get_shares(sv->name, user_info))
                                continue;

                        for (sh = shares; sh; sh = sh->next) {
                                printf("\t\t\\\\%s\\%-15s\t%s\n", 
				       sv->name, sh->name, sh->comment);
                        }
                }
        }

        return True;
}

/****************************************************************************
  main program
****************************************************************************/
 int main(int argc,char *argv[])
{
	extern char *optarg;
	extern int optind;
	int opt;
	char *p;
	struct user_auth_info user_info;
	BOOL got_pass = False;

	/* Initialise samba stuff */

	setlinebuf(stdout);

	dbf = x_stderr;

	setup_logging(argv[0],True);

	lp_load(dyn_CONFIGFILE,True,False,False);
	load_interfaces();

	if (getenv("USER")) {
		pstrcpy(user_info.username, getenv("USER"));

		if ((p=strchr(user_info.username, '%'))) {
			*p = 0;
			pstrcpy(user_info.password, p+1);
			got_pass = True;
			memset(strchr(getenv("USER"), '%') + 1, 'X',
			       strlen(user_info.password));
		}
	}

        pstrcpy(user_info.workgroup, lp_workgroup());

	/* Parse command line args */

	while ((opt = getopt(argc, argv, "U:hd:W:DSb")) != EOF) {
		switch (opt) {
		case 'U':
			pstrcpy(user_info.username,optarg);
			p = strchr(user_info.username,'%');
			if (p) {
				*p = 0;
				pstrcpy(user_info.password, p+1);
				got_pass = 1;
			}
			break;

		case 'b':
			use_bcast = True;
			break;

		case 'h':
			usage();
			exit(1);

		case 'd':
			DEBUGLEVEL = atoi(optarg);
			break;

		case 'W':
			pstrcpy(user_info.workgroup, optarg);
			break;

                case 'D':
                        level = LEV_WORKGROUP;
                        break;

                case 'S':
                        level = LEV_SERVER;
                        break;

		default:
			printf("Unknown option %c (%d)\n", (char)opt, opt);
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;
	
	if (argc > 0) {
		usage();
		exit(1);
	}

	if (!got_pass) {
		char *pass = getpass("Password: ");
		if (pass) {
			pstrcpy(user_info.password, pass);
		}
                got_pass = True;
	}

	/* Now do our stuff */

        if (!print_tree(&user_info))
                return 1;

	return 0;
}
