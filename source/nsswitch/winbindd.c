/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   Winbind daemon for ntdom nss module
   Copyright (C) Tim Potter 2000
   
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
#include "winbindd.h"
#include "sids.h"

/****************************************************************************
exit thy server
****************************************************************************/
void exit_server(char *reason)
{
	static int firsttime=1;

	if (!firsttime) exit(0);
	firsttime = 0;

	unbecome_vuser();
	DEBUG(0,("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% AARGH\n"));

	if (!reason) {   
		DEBUG(0,("====================================\n"));
	}    

	DEBUG(3,("Server exit (%s)\n", (reason ? reason : "")));
#ifdef MEM_MAN
	{
		extern FILE *dbf;
		smb_mem_write_verbose(dbf);
		dbgflush();
	}
#endif
	exit(0);
}

/* Connect to a domain controller and return domain sid */

int winbind_get_domain_sid(char *system_name, fstring domain_name,
                          DOM_SID *domain_sid)
{
    POLICY_HND lsa_handle;
    DOM_SID level3_sid, level5_sid;
    fstring level3_dom, level5_dom;
    BOOL res = True;

    /* Get SID from domain controller */

    res = res ? lsa_open_policy(system_name, &lsa_handle, False, 
                                0x02000000) : False;

    res = res ? lsa_query_info_pol(&lsa_handle, 0x03, level3_dom, 
                                   &level3_sid) : False;

    res = res ? lsa_query_info_pol(&lsa_handle, 0x05, level5_dom, 
                                   &level5_sid) : False;

    res = res ? lsa_close(&lsa_handle) : False;

    /* Return domain sid if successful */

    if (res && (domain_sid != NULL)) {
        memcpy(domain_sid, &level5_sid, sizeof(level5_sid));
        fstrcpy(domain_name, level5_dom);
    }

    return res;
}

/* Return a sid and type within a domain given a username */

int winbind_lookup_by_name(char *system_name, DOM_SID *level5_sid,
                           fstring name, DOM_SID *sid,
                           enum SID_NAME_USE *type)
{
    POLICY_HND lsa_handle;
    BOOL res = True;
    DOM_SID *sids = NULL;
    int num_sids = 0, num_names = 1;
    uint32 *types = NULL;

    if (name == NULL) {
        return 0;
    }

    res = res ? lsa_open_policy(system_name, &lsa_handle, True,
                                0x02000000) : False;
    
    res = res ? lsa_lookup_names(&lsa_handle, num_names, (char **)&name,
                                 &sids, &types, &num_sids) : False;

    res = res ? lsa_close(&lsa_handle) : False;

    /* Return rid and type if lookup successful */

    if (res) {

        if ((sid != NULL) && (sids != NULL)) {
            sid_copy(sid, &sids[0]);
        }

        if ((type != NULL) && (types != NULL)) {
            *type = types[0];
        }
    }
    
    return res;
}

/* Return a name and type within a domain given a rid */
int winbind_lookup_by_sid(char *system_name, DOM_SID *level5_sid,
                          DOM_SID *sid, char *name,
                          enum SID_NAME_USE *type)
{
    POLICY_HND lsa_handle;
    int num_sids = 1, num_names = 0;
    uint32 *types = NULL;
    char **names;
    BOOL res = True;


    res = res ? lsa_open_policy(system_name, &lsa_handle, True,
                                0x02000000) : False;

    res = res ? lsa_lookup_sids(&lsa_handle, num_sids, (DOM_SID **)&sid,
                                &names, &types, &num_names) : False;

    res = res ? lsa_close(&lsa_handle) : False;

    /* Return name and type if successful */

    if (res) {
        if ((names != NULL) && (name != NULL)) {
            fstrcpy(name, names[0]);
        }

        if ((type != NULL) && (types != NULL)) {
            *type = types[0];
        }
    }

    return res;
}

/* Lookup user information from rid */

int winbind_lookup_userinfo(char *system_name, DOM_SID *level5_sid,
                            uint32 user_rid, SAM_USERINFO_CTR *info)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res = True;

    /* Open connection to SAM pipe and SAM domain */

    res = res ? samr_connect(system_name, 0x02000000, &sam_handle) : False;

    res = res ? samr_open_domain(&sam_handle, 0x02000000, level5_sid, 
                                 &sam_dom_handle) : False;
    /* Query user info */

    res = res ? get_samr_query_userinfo(&sam_dom_handle, 0x15, user_rid,
                                        info) : False;
    /* Close up shop */

    res = res ? samr_close(&sam_dom_handle) : False;

    res = res ? samr_close(&sam_handle) : False;

    return res;
}                                   

int winbind_lookup_groupinfo(char *system_name, DOM_SID *level5_sid,
                             uint32 group_rid, GROUP_INFO_CTR *info)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res = True;

    /* Open connection to SAM pipe and SAM domain */

    res = res ? samr_connect(system_name, 0x02000000, &sam_handle) : False;

    res = res ? samr_open_domain(&sam_handle, 0x02000000, level5_sid, 
                                 &sam_dom_handle) : False;
    /* Query group info */

    res = res ? get_samr_query_groupinfo(&sam_dom_handle, 1,
                                         group_rid, info) : False;

    /* Close up shop */

    res = res ? samr_close(&sam_dom_handle) : False;

    res = res ? samr_close(&sam_handle) : False;

    return res;
}

/* Create ipc socket */

int create_winbind_socket(void)
{
    struct sockaddr_un sunaddr;
    struct stat st;
    int ret, sock;

    ret = stat(SOCKET_NAME, &st);
    if (ret == -1 && errno != ENOENT) {
        perror("stat");
        return -1;
    }

    if (ret == 0) {
        fprintf(stderr, "socket exists!\n");
        return -1;
    }

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    memset(&sunaddr, 0, sizeof(sunaddr));
    sunaddr.sun_family = AF_UNIX;
    strncpy(sunaddr.sun_path, SOCKET_NAME, sizeof(sunaddr.sun_path));
    
    if (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    
    if (chmod(SOCKET_NAME, 0700) < 0) {
        perror("chmod");
        close(sock);
      return -1;
    }
    
    if (listen(sock, 5) < 0) {
        perror("listen");
        close(sock);
        return -1;
    }
    
    /* Success! */
    
    return sock;
}

/*
 * Main function 
 */

int main(int argc, char **argv)
{
    DOM_SID domain_sid;
    fstring domain_name, sid;
    int sock;
    
    /* Initialise samba/rpc client stuff */

    lp_load(CONFIGFILE, True, False, False);
    fstrcpy(debugf, "/tmp/winbindd.log");
    setup_logging(debugf, 1);
    reopen_logs();

    charset_initialise();
    codepage_initialise(lp_client_code_page());

    /* Get the domain sid */

    if (!winbind_get_domain_sid(SERVER, domain_name, &domain_sid)) {
        DEBUG(0, ("Cannot get domain sid from %s\n", domain_name));
        return 1;
    }

    sid_to_string(sid, &domain_sid);
    DEBUG(3, ("Domain controller for domain %s has sid %s\n",
              domain_name, sid));

    sid_copy(&global_sam_sid, &domain_sid); /* ??? */
    generate_wellknown_sids(); /* ??? */

    /* Loop waiting for requests */

    if ((sock = create_winbind_socket()) == -1) {
        DEBUG(0, ("failed to create socket\n"));
        return 1;
    }

    while (1) {
        int len, sock2;
        struct sockaddr_un sunaddr;
        struct winbindd_request request;
        struct winbindd_response response;

        /* Accept connection */

        len = sizeof(sunaddr);
        sock2 = accept(sock, (struct sockaddr *)&sunaddr, &len);

        /* Read command */

        if ((len = read(sock2, &request, sizeof(request))) < 0) {
            close(sock2);
            continue;
        }

        response.result = WINBINDD_ERROR;

        /* Process command */

        switch(request.cmd) {
            
            /* User functions */

        case WINBINDD_GETPWNAM_FROM_USER: 
            DEBUG(1, ("getpwnam from user '%s'\n", request.data.username));
            winbindd_getpwnam_from_user(&domain_sid, &request, &response);
            break;

        case WINBINDD_GETPWNAM_FROM_UID:
            DEBUG(1, ("getpwnam from uid %d\n", request.data.uid));
            winbindd_getpwnam_from_uid(&domain_sid, &request, &response);
            break;

            /* Group functions */

        case WINBINDD_GETGRNAM_FROM_GROUP:
            DEBUG(1, ("getgrnam from group '%s'\n", request.data.groupname));
            winbindd_getgrnam_from_group(&domain_sid, &request, &response);
            break;

        case WINBINDD_GETGRNAM_FROM_GID:
            DEBUG(1, ("getgrnam from gid %d\n", request.data.gid));
            winbindd_getgrnam_from_gid(&domain_sid, &request, &response);
            break;

            /* Oops */

        default:
            DEBUG(0, ("oops - unknown command %d\n", request.cmd));
            break;
        }

        /* Send response */

        write(sock2, &response, sizeof(response));
        close(sock2);
    }

    return 0;
}
