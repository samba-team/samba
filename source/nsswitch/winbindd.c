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
#include <sys/stat.h>
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
    
    /* Free memory */

    if (types != NULL) { free(types); }
    if (sids != NULL) { free(sids); }

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

    res = res ? lsa_lookup_sids(&lsa_handle, num_sids, &sid,
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

    /* Free memory */

    if (types != NULL) { free(types); }

    if (names != NULL) { 
        int i;

        for (i = 0; i < num_names; i++) {
            if (names[i] != NULL) {
                free(names[i]);
            }
            free(names); 
        }
    }

    return res;
}

/* Lookup user information from a rid */

int winbindd_lookup_userinfo(char *system_name, DOM_SID *dom_sid,
                             uint32 user_rid, POLICY_HND *sam_dom_handle,
                             SAM_USERINFO_CTR *user_info)
{
    POLICY_HND sam_handle, local_sam_dom_handle;
    BOOL res = True, local_handle = False;

    if (sam_dom_handle == NULL) {
        sam_dom_handle = &local_sam_dom_handle;
        local_handle = True;
    }

    /* Open connection to SAM pipe and SAM domain */

    if (local_handle) {

        res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                           &sam_handle);

        res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                     dom_sid, sam_dom_handle) : False;
    }

    /* Get user info */

    res = res ? get_samr_query_userinfo(sam_dom_handle, 0x15, 
                                        user_rid, user_info) : False;

    /* Close up shop */

    if (local_handle) {
        samr_close(sam_dom_handle);
        samr_close(&sam_handle);
    }

    return res;
}                                   

/* Lookup group information from a rid */

int winbindd_lookup_groupinfo(char *system_name, DOM_SID *dom_sid,
                              uint32 group_rid, GROUP_INFO_CTR *info)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res;

    /* Open connection to SAM pipe and SAM domain */

    res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED, &sam_handle);

    res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                 dom_sid, &sam_dom_handle) : False;
    /* Query group info */
    
    res = res ? get_samr_query_groupinfo(&sam_dom_handle, 1,
                                         group_rid, info) : False;

    /* Close up shop */

    samr_close(&sam_dom_handle);
    samr_close(&sam_handle);

    return res;
}

/* Lookup group membership given a rid */

int winbindd_lookup_groupmem(char *system_name, DOM_SID *dom_sid,
                             uint32 group_rid, POLICY_HND *sam_dom_handle,
                             uint32 *num_names, uint32 **rid_mem, 
                             char ***names, uint32 **name_types)
{
    POLICY_HND sam_handle, local_sam_dom_handle;
    BOOL res = True, local_handle = False;

    if (sam_dom_handle == NULL) {
        sam_dom_handle = &local_sam_dom_handle;
        local_handle = True;
    }

    /* Open connection to SAM pipe and SAM domain */

    if (local_handle) {

        res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                           &sam_handle);

        res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                     dom_sid, sam_dom_handle) : False;
    }
    /* Query group membership */
    
    res = res ? sam_query_groupmem(sam_dom_handle, group_rid, num_names, 
                                   rid_mem, names, name_types) : False;

    /* Close up shop */

    if (local_handle) {
        samr_close(sam_dom_handle);
        samr_close(&sam_handle);
    }

    return res;
}

/* Lookup alias membership given a rid */

int winbindd_lookup_aliasmem(char *system_name, DOM_SID *dom_sid,
                             uint32 alias_rid, POLICY_HND *sam_dom_handle,
                             uint32 *num_names, DOM_SID ***sids, 
                             char ***names, uint32 **name_types)
{
    POLICY_HND sam_handle, local_sam_dom_handle;
    BOOL res = True, local_handle = False;

    if (sam_dom_handle == NULL) {
        sam_dom_handle = &local_sam_dom_handle;
        local_handle = True;
    }

    /* Open connection to SAM pipe and SAM domain */

    if (local_handle) {

        res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                           &sam_handle);

        res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                     dom_sid, sam_dom_handle) : False;
    }

    /* Query alias membership */
    
    res = res ? sam_query_aliasmem(system_name, sam_dom_handle, alias_rid,
                                   num_names, sids, names, name_types)
        : False;

    /* Close up shop */

    if (local_handle) {
        samr_close(sam_dom_handle);
        samr_close(&sam_handle);
    }

    return res;
}

/* Lookup alias information given a rid */

int winbindd_lookup_aliasinfo(char *system_name, DOM_SID *dom_sid,
                              uint32 alias_rid, ALIAS_INFO_CTR *info)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res;

    /* Open connection to SAM pipe and SAM domain */

    res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                       &sam_handle);

    res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                 dom_sid, &sam_dom_handle) : False;
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
    /* Remove socket file */

    unlink(WINBINDD_SOCKET_DIR "/" WINBINDD_SOCKET_NAME);

    exit(0);
}

/* Create winbindd socket */

int create_sock(void)
{
    struct sockaddr_un sunaddr;
    struct stat st;
    int sock;
    mode_t old_umask;

    /* Create the socket directory or reuse the existing one */

    if ((lstat(WINBINDD_SOCKET_DIR, &st) < 0) && (errno != ENOENT)) {
        DEBUG(0, ("lstat failed on socket directory %s: %s\n",
                  WINBINDD_SOCKET_DIR, sys_errlist[errno]));
        return -1;
    }

    if (errno == ENOENT) {

        /* Create directory */

        if (mkdir(WINBINDD_SOCKET_DIR, 0755) < 0) {
            DEBUG(0, ("error creating socket directory %s: %s\n",
                      WINBINDD_SOCKET_DIR, sys_errlist[errno]));
            return -1;
        }

    } else {

        /* Check ownership and permission on existing directory */

        if (!S_ISDIR(st.st_mode)) {
            DEBUG(0, ("socket directory %s isn't a directory\n",
                      WINBINDD_SOCKET_DIR));
            return -1;
        }

        if ((st.st_uid != 0) || ((st.st_mode & 0777) != 0755)) {
            DEBUG(0, ("invalid permissions on socket directory %s\n",
                      WINBINDD_SOCKET_DIR));
            return -1;
        }
    }

    /* Create the socket file */

    old_umask = umask(0);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    memset(&sunaddr, 0, sizeof(sunaddr));
    sunaddr.sun_family = AF_UNIX;
    strncpy(sunaddr.sun_path, WINBINDD_SOCKET_DIR "/" WINBINDD_SOCKET_NAME, 
            sizeof(sunaddr.sun_path));
    
    if (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) < 0) {
        DEBUG(0, ("bind failed on winbind socket %s: %s\n",
                  WINBINDD_SOCKET_DIR "/" WINBINDD_SOCKET_NAME,
                  sys_errlist[errno]));
        close(sock);
        return -1;
    }
    
    if (listen(sock, 5) < 0) {
        DEBUG(0, ("listen failed on winbind socket %s: %s\n",
                  WINBINDD_SOCKET_DIR "/" WINBINDD_SOCKET_NAME,
                  sys_errlist[errno]));
        close(sock);
        return -1;
    }
    
    umask(old_umask);
    
    /* Success! */
    
    return sock;
}

/*
 * Main function 
 */

int main(int argc, char **argv)
{
    extern fstring global_myname;
    int sock, sock2;
    extern pstring debugf;

    /* Initialise samba/rpc client stuff */

    setup_logging("winbindd", False); /* XXX change to false for daemon log */
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
    codepage_initialise(lp_client_code_page());

    if (!lp_load(CONFIGFILE, True, False, False)) {
        fprintf(stderr, "error opening config file\n");
        exit(1);
    }

    pwdb_initialise(False);

    /* Setup signal handlers */

    signal(SIGINT, termination_handler);
    signal(SIGQUIT, termination_handler);
    signal(SIGTERM, termination_handler);
    signal(SIGPIPE, SIG_IGN);

    /* Loop waiting for requests */

    if ((sock = create_sock()) == -1) {
        DEBUG(0, ("failed to create socket\n"));
        return 1;
    }

    /* Get the domain sid */

    if (!winbindd_surs_init()) {
        DEBUG(0, ("Could not initialise surs information\n"));
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
                winbindd_getpwnam_from_user(request.data.username, NULL,
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
                winbindd_getgrnam_from_group(request.data.groupname, NULL,
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
