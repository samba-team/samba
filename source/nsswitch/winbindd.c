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

#define SERVER "controller"

extern int DEBUGLEVEL;
extern pstring debugf;

/****************************************************************************
exit the server
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

/* Return a rid and type within a domain given a username */

int winbind_lookup_by_name(char *system_name, DOM_SID *level5_sid,
                           fstring name, uint32 *rid,
                           enum SID_NAME_USE *type)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res = True;
    uint32 num_rids, *rids = NULL, *types = NULL;
    int num_names;

    if (name == NULL) {
        return 0;
    }

    num_names = 1;

    res = res ? samr_connect(system_name, 0x02000000, &sam_handle) : False;

    res = res ? samr_open_domain(&sam_handle, 0x02000000, level5_sid,
                                 &sam_dom_handle) : False;
    
    res = res ? samr_query_lookup_names(&sam_dom_handle, 0x000003e8,
                                        num_names, (const char **)&name,
                                        &num_rids, &rids, &types) : False;

    res = res ? samr_close(&sam_dom_handle) : False;
    
    res = res ? samr_close(&sam_handle) : False;
    
    /* Return rid and type if lookup successful */

    if (res) {

        if ((rid != NULL) && (rids != NULL)) {
            *rid = rids[0];
        }

        if ((type != NULL) && (types != NULL)) {
            *type = types[0];
        }
    }
    
    return res;
}

/* Return a username and type within a domain given a rid */

static int winbind_lookup_by_rid(char *system_name, DOM_SID *level5_sid,
                                 uint32 rid, char *user_name,
                                 enum SID_NAME_USE *type)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res = True, res1 = False;

    /* Open connection to SAM pipe and SAM domain */

    res = res ? samr_connect(system_name, 0x02000000, &sam_handle) : False;

    res = res ? samr_open_domain(&sam_handle, 0x02000000, level5_sid, 
                                 &sam_dom_handle) : False;
    if (res) {
        uint32 num_rids = 1;
        int num_names = 0;
        char **names = NULL;
        uint32 *types = NULL;
        
        /* Lookup name */

        res1 = samr_query_lookup_rids(&sam_dom_handle, 0x000003e8, num_rids, 
                                      &rid, &num_names, &names, &types);

        /* Return username and type if successful */

        if (res1) {

            if ((names != NULL) && (user_name != NULL)) {
                fstrcpy(user_name, names[0]);
            }

            if ((type != NULL) && (types != NULL)) {
                *type = types[0];
            }
        }

        res = res ? samr_close(&sam_dom_handle) : False;
        res = res ? samr_close(&sam_handle) : False;
    }

    return res1;
}

/* Lookup user information from rid */

static int winbind_lookup_userinfo(char *system_name, DOM_SID *level5_sid,
                                   uint32 user_rid, SAM_USER_INFO_21 *info)
{
    POLICY_HND sam_handle, sam_dom_handle;
    SAM_USERINFO_CTR userinfo;
    BOOL res = True;

    /* Open connection to SAM pipe and SAM domain */

    res = res ? samr_connect(system_name, 0x02000000, &sam_handle) : False;

    res = res ? samr_open_domain(&sam_handle, 0x02000000, level5_sid, 
                                 &sam_dom_handle) : False;
    /* Qeury user info */

    res = res ? get_samr_query_userinfo(&sam_dom_handle, 0x15, user_rid,
                                        &userinfo) : False;

    /* Return SAM_USER_INFO_21 structure */

    if (res && (info != NULL)) {
        memcpy(info, userinfo.info.id21, sizeof(*info));
    }

    return res;
}                                   

static int winbind_lookup_groupinfo(char *system_name, DOM_SID *level5_sid,
                                    uint32 group_rid, SAM_USER_INFO_21 *info)
{
    return 0;
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

void do_getpwnam_from_user(DOM_SID *domain_sid,
                           struct winbindd_request *request,
                           struct winbindd_response *response)
{
    uint32 rid, type;
    SAM_USER_INFO_21 user_info;
    
    fprintf(stderr, "getpwname from user %s\n", request->data.username);
            
    /* Get rid and name type */
    
    if (!winbind_lookup_by_name(SERVER, domain_sid, 
                                    request->data.username, &rid, &type)) {
        fprintf(stderr, "user does not exist\n");
        return;
    }
    
    /* Get some user info */
    
    if (!winbind_lookup_userinfo(SERVER, domain_sid, rid, &user_info)) {
        fprintf(stderr, "error getting user info\n");
        return;
    }
    
    if (type == SID_NAME_USER) {
        struct winbindd_pw *pw = &response->data.pw;
        fstring temp;
        
        /* Fill in passwd field */
        
        strncpy(pw->pw_name, request->data.username, sizeof(pw->pw_name) - 1);
        strncpy(pw->pw_passwd, "x", sizeof(pw->pw_name) - 1);
        
        pw->pw_uid = 666;
        pw->pw_gid = 666;
        
        unistr2_to_ascii(temp, &user_info.uni_full_name, sizeof(temp));
        fprintf(stderr, "full name = %s\n", temp);
        strncpy(pw->pw_gecos, temp, sizeof(pw->pw_gecos) - 1);
        
        unistr2_to_ascii(temp, &user_info.uni_dir_drive, sizeof(temp));
        strncpy(pw->pw_dir, temp, sizeof(pw->pw_dir) - 1);
        
        strncpy(pw->pw_shell, "/dev/null", sizeof(pw->pw_shell) - 1);
        
        response->result = WINBINDD_OK;
        
        fprintf(stderr, "returning pw info\n");
    }
}       

void do_getpwnam_from_uid(DOM_SID *domain_sid,
                          struct winbindd_request *request,
                          struct winbindd_response *response)
{
    fprintf(stderr, "get pwnam from uid %d\n", request->data.uid);
}

void do_getgrnam_from_group(DOM_SID *domain_sid,
                            struct winbindd_request *request,
                            struct winbindd_response *response)
{
    uint32 rid, type; 

    fprintf(stderr, "getgrnam from group %s\n", request->data.groupname);

    /* Get rid and name type */

    if (!winbind_lookup_by_name(SERVER, domain_sid, request->data.groupname, 
                                &rid, &type)) {
        fprintf(stderr, "name %s does not exist\n", request->data.groupname);
        return;
    }

    /* Get group info */
    
    if (!winbind_lookup_groupinfo(SERVER, domain_sid, rid, NULL)) {
        fprintf(stderr, "error getting group info\n");
        return;
    }

    if ((type == SID_NAME_DOM_GRP) ||
        (type == SID_NAME_ALIAS)) {
        struct winbindd_gr *gr = &response->data.gr;
        fstring temp;

        /* Fill in group entry */
    }
}

void do_getgrnam_from_gid(DOM_SID *domain_sid,
                          struct winbindd_request *request,
                          struct winbindd_response *respose)
{
    fprintf(stderr, "get grnam from gid %d\n", request->data.gid);
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
    DEBUG(0, ("Domain controller for domain %s has sid %s\n",
              domain_name, sid));

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
            do_getpwnam_from_user(&domain_sid, &request, &response);
            break;

        case WINBINDD_GETPWNAM_FROM_UID:
            do_getpwnam_from_uid(&domain_sid, &request, &response);
            break;

            /* Group functions */

        case WINBINDD_GETGRNAM_FROM_GROUP:
            do_getgrnam_from_group(&domain_sid, &request, &response);
            break;

        case WINBINDD_GETGRNAM_FROM_GID:
            do_getgrnam_from_gid(&domain_sid, &request, &response);
            break;

            /* Oops */

        default:
            fprintf(stderr, "unknown command %d\n", request.cmd);
            break;

        }

        /* Send response */

        write(sock2, &response, sizeof(response));

        close(sock2);
    }

    return 0;
}
