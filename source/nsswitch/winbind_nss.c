/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   Windows NT Domain nsswitch module
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

#include <sys/socket.h>
#include <sys/un.h>
#include <nss.h>
#include "includes.h"
#include "winbindd.h"

#define SPAMTEST 1

int connect_sock(void)
{
    int sock;
    struct sockaddr_un sunaddr;

    sunaddr.sun_family = AF_UNIX;
    strncpy(sunaddr.sun_path, SOCKET_NAME, sizeof(sunaddr.sun_path));

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) < 0) {
        return -1;
    }

    return sock;
}

/* Return (struct passwd *) given username */

enum nss_status
_nss_ntdom_getpwnam_r(const char *name,
                      struct passwd *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, len;
    
    /* Connect to agent socket */

    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Send query */

    request.cmd = WINBINDD_GETPWNAM_FROM_USER;
    strncpy(request.data.username, name, sizeof(request.data.username));

    write(sock, &request, sizeof(request));

    /* Wait for reply */

    if ((len = read(sock, &response, sizeof(response))) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    if (response.result == WINBINDD_OK) {
        struct winbindd_pw *pw = &response.data.pw;

        result->pw_name = strdup(pw->pw_name);
        result->pw_passwd = strdup(pw->pw_name);
        result->pw_uid = pw->pw_uid;
        result->pw_gid = pw->pw_gid;
        result->pw_gecos = strdup(pw->pw_gecos);
        result->pw_dir = strdup(pw->pw_dir);
        result->pw_shell = strdup(pw->pw_shell);

        return NSS_STATUS_SUCCESS;
    }

    return NSS_STATUS_NOTFOUND;
}

/* Return (struct passwd *) given uid */

enum nss_status
_nss_ntdom_getpwuid_r(uid_t uid,
                      struct passwd *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, len;

    /* Connect to agent socket */

    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Send query */

    request.cmd = WINBINDD_GETPWNAM_FROM_UID;
    request.data.uid = uid;

    write(sock, &request, sizeof(request));

    /* Wait for reply */

    if ((len = read(sock, &response, sizeof(response))) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    if (response.result == WINBINDD_OK) {
        struct winbindd_pw *pw = &response.data.pw;

        result->pw_name = strdup(pw->pw_name);
        result->pw_passwd = strdup(pw->pw_name);
        result->pw_uid = pw->pw_uid;
        result->pw_gid = pw->pw_gid;
        result->pw_gecos = strdup(pw->pw_gecos);
        result->pw_dir = strdup(pw->pw_dir);
        result->pw_shell = strdup(pw->pw_shell);

        return NSS_STATUS_SUCCESS;
    }

    return NSS_STATUS_NOTFOUND;
}

/* 
 * Functions for nss group database
 */

enum nss_status
_nss_ntdom_getgrnam_r(const char *name,
                      struct group *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, len;

    /* Connect to agent socket */

    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Send query */

    request.cmd = WINBINDD_GETGRNAM_FROM_GROUP;
    strncpy(request.data.groupname, name, sizeof(request.data.groupname));

    write(sock, &request, sizeof(request));

    /* Wait for reply */

    if ((len = read(sock, &response, sizeof(response))) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    if (response.result == WINBINDD_OK) {
        struct winbindd_gr *gr = &response.data.gr;

        result->gr_name = strdup(gr->gr_name);
        result->gr_passwd = strdup(gr->gr_passwd);
        result->gr_gid = gr->gr_gid;
        result->gr_mem = NULL; /* ??? */

        return NSS_STATUS_SUCCESS;
    }

    return NSS_STATUS_NOTFOUND;
}

enum nss_status
_nss_ntdom_getgrgid_r(gid_t gid,
                      struct group *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, len;

    /* Connect to agent socket */

    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Send query */

    request.cmd = WINBINDD_GETGRNAM_FROM_GID;
    request.data.gid = gid;

    write(sock, &request, sizeof(request));

    /* Wait for reply */

    if ((len = read(sock, &response, sizeof(response))) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    if (response.result == WINBINDD_OK) {
        struct winbindd_gr *gr = &response.data.gr;

        result->gr_name = strdup(gr->gr_name);
        result->gr_passwd = strdup(gr->gr_passwd);
        result->gr_gid = gr->gr_gid;
        result->gr_mem = NULL; /* ??? */

        return NSS_STATUS_SUCCESS;
    }

    return NSS_STATUS_NOTFOUND;
}
