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

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "includes.h"
#include "sids.h"

/* Connect to a domain controller and return the domain name and sid */

BOOL lookup_domain_sid(fstring domain_name, DOM_SID *domain_sid,
                       fstring domain_controller)
{
    POLICY_HND lsa_handle;
    DOM_SID level3_sid, level5_sid;
    fstring level3_dom, level5_dom;
    fstring system_name;
    BOOL res;

    if (!get_any_dc_name(domain_name, system_name)) {
        return False;
    }

    if (domain_controller != NULL) {
        fstrcpy(domain_controller, system_name);
    }

    /* Get SID from domain controller */

    res = lsa_open_policy(system_name, &lsa_handle, False, 
                          SEC_RIGHTS_MAXIMUM_ALLOWED);

    res = res ? lsa_query_info_pol(&lsa_handle, 0x03, level3_dom, 
                                   &level3_sid) : False;

    res = res ? lsa_query_info_pol(&lsa_handle, 0x05, level5_dom, 
                                   &level5_sid) : False;

    lsa_close(&lsa_handle);

    /* Return domain sid if successful */

    if (res && (domain_sid != NULL)) {
        sid_copy(domain_sid, &level5_sid);
        fstrcpy(domain_name, level5_dom);
    }

    return res;
}

/* Lookup a sid and type within a domain from a username */

BOOL winbindd_lookup_by_name(char *system_name, DOM_SID *level5_sid,
                             fstring name, DOM_SID *sid,
                             enum SID_NAME_USE *type)
{
    POLICY_HND lsa_handle;
    BOOL res;
    DOM_SID *sids = NULL;
    int num_sids = 0, num_names = 1;
    uint32 *types = NULL;

    if (name == NULL) {
        return 0;
    }

    res = lsa_open_policy(system_name, &lsa_handle, True, 
                          SEC_RIGHTS_MAXIMUM_ALLOWED);
    
    res = res ? lsa_lookup_names(&lsa_handle, num_names, (char **)&name,
                                 &sids, &types, &num_sids) : False;

    lsa_close(&lsa_handle);

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

/* Lookup a name and type within a domain from a sid */

int winbindd_lookup_by_sid(char *system_name, DOM_SID *level5_sid,
                           DOM_SID *sid, char *name,
                           enum SID_NAME_USE *type)
{
    POLICY_HND lsa_handle;
    int num_sids = 1, num_names = 0;
    uint32 *types = NULL;
    char **names;
    BOOL res;

    res = lsa_open_policy(system_name, &lsa_handle, True, 
                          SEC_RIGHTS_MAXIMUM_ALLOWED);

    res = res ? lsa_lookup_sids(&lsa_handle, num_sids, (DOM_SID **)&sid,
                                &names, &types, &num_names) : False;

    lsa_close(&lsa_handle);

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

/* Lookup user information from a rid */

int winbindd_lookup_userinfo(char *system_name, DOM_SID *level5_sid,
                             uint32 user_rid, SAM_USERINFO_CTR *user_info)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res, res1;

    /* Open connection to SAM pipe and SAM domain */

    res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                       &sam_handle);

    res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                 level5_sid, &sam_dom_handle) : False;
    /* Get user info */

    res1 = res ? get_samr_query_userinfo(&sam_dom_handle, 0x15, user_rid,
                                        user_info) : False;

    /* Close up shop */

    samr_close(&sam_dom_handle);
    samr_close(&sam_handle);

    return res && res1;
}                                   

/* Lookup group information from a rid */

int winbindd_lookup_groupinfo(char *system_name, DOM_SID *level5_sid,
                              uint32 group_rid, GROUP_INFO_CTR *info)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res;

    /* Open connection to SAM pipe and SAM domain */

    res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED, &sam_handle);

    res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                 level5_sid, &sam_dom_handle) : False;
    /* Query group info */
    
    res = res ? get_samr_query_groupinfo(&sam_dom_handle, 1,
                                         group_rid, info) : False;

    /* Close up shop */

    samr_close(&sam_dom_handle);
    samr_close(&sam_handle);

    return res;
}

/* Lookup group membership given a rid */

int winbindd_lookup_groupmem(char *system_name, DOM_SID *level5_sid,
                             uint32 group_rid, uint32 *num_names,
                             uint32 **rid_mem, char ***names,
                             uint32 **name_types)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res;

    /* Open connection to SAM pipe and SAM domain */

    res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                       &sam_handle);

    res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                 level5_sid, &sam_dom_handle) : False;
    /* Query group membership */
    
    res = res ? sam_query_groupmem(&sam_dom_handle, group_rid, num_names, 
                                   rid_mem, names, name_types) : False;

    /* Close up shop */

    samr_close(&sam_dom_handle);
    samr_close(&sam_handle);

    return res;
}

/* Lookup alias membership given a rid */

int winbindd_lookup_aliasmem(char *system_name, DOM_SID *dom_sid,
                             uint32 alias_rid, uint32 *num_names,
                             DOM_SID ***sids, char ***names,
                             uint32 **name_types)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res;

    /* Open connection to SAM pipe and SAM domain */

    res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                       &sam_handle);

    res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                 dom_sid, &sam_dom_handle) : False;

    /* Query alias membership */
    
    res = res ? sam_query_aliasmem(system_name, &sam_dom_handle, alias_rid,
                                   num_names, sids, names, name_types)
        : False;

    /* Close up shop */

    samr_close(&sam_dom_handle);
    samr_close(&sam_handle);

    return res;
}

/* Lookup alias information given a rid */

int winbindd_lookup_aliasinfo(char *system_name, DOM_SID *level5_sid,
                              uint32 alias_rid, ALIAS_INFO_CTR *info)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res;

    /* Open connection to SAM pipe and SAM domain */

    res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                       &sam_handle);

    res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                 level5_sid, &sam_dom_handle) : False;
    /* Query group info */
    
    res = res ? get_samr_query_aliasinfo(&sam_dom_handle, 1,
                                         alias_rid, info) : False;

    /* Close up shop */

    samr_close(&sam_dom_handle);
    samr_close(&sam_handle);

    return res;
}

/* Handle termination signals */

static void termination_handler(int signum)
{
    /* Clean up */

    remove_sock();
    exit(0);
}

/*
 * Main function 
 */

int main(int argc, char **argv)
{
    extern fstring global_myname;
    fstring domain_name;
    int sock, sock2;
    extern pstring debugf;
    
    /* Initialise samba/rpc client stuff */

    setup_logging("winbindd", True); /* XXX change to false for daemon log */
    slprintf(debugf, sizeof(debugf), "%s/log.winbindd", LOGFILEBASE);
    reopen_logs();

    if (!*global_myname) {
        char *p;
        fstrcpy( global_myname, myhostname() );
        p = strchr( global_myname, '.' );
        if (p) 
            *p = 0;
    }

    TimeInit();
    charset_initialise();
    generate_wellknown_sids();

    if (!lp_load(CONFIGFILE, True, False, False)) {
        fprintf(stderr, "error opening config file\n");
        exit(1);
    }

    codepage_initialise(lp_client_code_page());

    /* Setup signal handlers */

    signal (SIGINT, termination_handler);
    signal (SIGQUIT, termination_handler);
    signal (SIGTERM, termination_handler);
    signal (SIGPIPE, SIG_IGN);

    /* Get the domain sid */

    if (strcmp(lp_passwordserver(), "") == 0) {
        DEBUG(0, ("No password server specified in smb.conf!\n"));
        return 1;
    }

    fstrcpy(domain_name, lp_workgroup());

    if (!winbindd_surs_init()) {
        DEBUG(0, ("Could not initialise surs information\n"));
        return 1;
    }

//    sid_copy(&global_sam_sid, &domain_sid); /* ??? */

    /* Loop waiting for requests */

    if ((unlink(WINBINDD_SOCKET_NAME) < 0) && (errno != ENOENT)) {
        DEBUG(0, ("Unable to remove domain socket %s: %s\n",
                  WINBINDD_SOCKET_NAME, sys_errlist[errno]));
        return 1;
    }

    if ((sock = create_sock()) == -1) {
        DEBUG(0, ("failed to create socket\n"));
        return 1;
    }

    while (1) {
        int len;
        struct sockaddr_un sunaddr;
        struct winbindd_request request;
        struct winbindd_response response;

        /* Accept connection */

        len = sizeof(sunaddr);
        sock2 = accept(sock, (struct sockaddr *)&sunaddr, &len);

        /* Read command */

        if (read_sock(sock2, &request, sizeof(request)) < 0) {
            close(sock2);
            continue;
        }

        response.result = WINBINDD_ERROR;

        /* Process command */

        switch(request.cmd) {
            
            /* User functions */

        case WINBINDD_GETPWNAM_FROM_USER: 
            response.result = 
                winbindd_getpwnam_from_user(request.data.username, 
                                            &response.data.pw);
            break;
            
        case WINBINDD_GETPWNAM_FROM_UID:
            response.result = 
               winbindd_getpwnam_from_uid(request.data.uid, &response.data.pw);
            break;
            
        case WINBINDD_SETPWENT:
            response.result = winbindd_setpwent(request.pid);
            break;

        case WINBINDD_ENDPWENT:
            response.result = winbindd_endpwent(request.pid);
            break;

        case WINBINDD_GETPWENT:
            response.result = 
                winbindd_getpwent(request.pid, &response.data.pw);
            break;

            /* Group functions */

        case WINBINDD_GETGRNAM_FROM_GROUP:
            response.result = 
                winbindd_getgrnam_from_group(request.data.groupname, 
                                             &response.data.gr);
            break;

        case WINBINDD_GETGRNAM_FROM_GID:
            response.result = 
                winbindd_getgrnam_from_gid(request.data.gid, 
                                           &response.data.gr);
            break;

        case WINBINDD_SETGRENT:
            response.result = winbindd_setgrent(request.pid);
            break;

        case WINBINDD_ENDGRENT:
            response.result = winbindd_endgrent(request.pid);
            break;

        case WINBINDD_GETGRENT:
            response.result = 
                winbindd_getgrent(request.pid, &response.data.gr);
            break;

            /* Oops */

        default:
            DEBUG(0, ("oops - unknown winbindd command %d\n", request.cmd));
            break;
        }

        /* Send response */

        write_sock(sock2, &response, sizeof(response));
        close(sock2);
    }

    return 0;
}
