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

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <nss.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "includes.h"

/* Allocate some space from the nss static buffer.  The buffer and buflen
   are the pointers passed in by the C library to the _nss_ntdom_*
   functions. */

static char *get_static(char **buffer, int *buflen, int len)
{
    char *result;

    /* Error check.  We return false if things aren't set up right, or
       there isn't enough buffer space left. */

    if ((buffer == NULL) || (buflen == NULL) || (*buflen < len)) {
        return NULL;
    }

    /* Return an index into the static buffer */

    result = *buffer;
    *buffer += len;
    *buflen -= len;

    return result;
}

/* Fill a pwent structure from a winbindd_response structure.  We use
   the static data passed to us by libc to put strings and stuff in.
   Return errno = ERANGE and NSS_STATUS_TRYAGAIN if we run out of
   memory. */

static int fill_pwent(struct passwd *result,
                      struct winbindd_response *response,
                      char **buffer, int *buflen, int *errnop)
{
    struct winbindd_pw *pw = &response->data.pw;

    /* User name */

    if ((result->pw_name = 
         get_static(buffer, buflen, strlen(pw->pw_name) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    fstrcpy(result->pw_name, pw->pw_name);

    /* Password */

    if ((result->pw_passwd = 
         get_static(buffer, buflen, strlen(pw->pw_passwd) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    fstrcpy(result->pw_passwd, pw->pw_passwd);
        
    /* [ug]id */

    result->pw_uid = pw->pw_uid;
    result->pw_gid = pw->pw_gid;

    /* GECOS */

    if ((result->pw_gecos = 
         get_static(buffer, buflen, strlen(pw->pw_gecos) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    fstrcpy(result->pw_gecos, pw->pw_gecos);

    /* Home directory */

    if ((result->pw_dir = 
         get_static(buffer, buflen, strlen(pw->pw_dir) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    fstrcpy(result->pw_dir, pw->pw_dir);

    /* Logon shell */

    if ((result->pw_shell = 
         get_static(buffer, buflen, strlen(pw->pw_shell) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    fstrcpy(result->pw_shell, pw->pw_shell);

    return NSS_STATUS_SUCCESS;
}

/* Fill a grent structure from a winbindd_response structure.  We use
   the static data passed to us by libc to put strings and stuff in.
   Return errno = ERANGE and NSS_STATUS_TRYAGAIN if we run out of
   memory. */

static int fill_grent(struct group *result, 
                      struct winbindd_response *response,
                      char **buffer, int *buflen, int *errnop)
{
    struct winbindd_gr *gr = &response->data.gr;
    char *name;
    int i;

    /* Group name */

    if ((result->gr_name =
         get_static(buffer, buflen, strlen(gr->gr_name) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    fstrcpy(result->gr_name, gr->gr_name);

    /* Password */

    if ((result->gr_passwd =
         get_static(buffer, buflen, strlen(gr->gr_passwd) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    fstrcpy(result->gr_passwd, gr->gr_passwd);

    /* gid */

    result->gr_gid = gr->gr_gid;

    /* Group membership.  Turn comma separated string into array of
       char pointers. */

    if (gr->num_gr_mem < 0) {
        gr->num_gr_mem = 0;
    }

    if ((result->gr_mem = 
         (char **)get_static(buffer, buflen, (gr->num_gr_mem + 1) * 
                             sizeof(char *))) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    if (gr->num_gr_mem == 0) {

        /* Group is empty */

        *(result->gr_mem) = NULL;
        return NSS_STATUS_SUCCESS;
    }

    /* Start looking at list */

    i = 0;

    for(name = strtok(gr->gr_mem, ","); name; name = strtok(NULL, ",")) {

        /* Allocate space for member */

        if (((result->gr_mem)[i] = 
             get_static(buffer, buflen, strlen(name) + 1)) == NULL) {

            /* Out of memory */

            *errnop = ERANGE;
            return NSS_STATUS_TRYAGAIN;
        }        

        fstrcpy((result->gr_mem)[i], name);
        i++;
    }

    /* Terminate list */

    (result->gr_mem)[gr->num_gr_mem] = NULL;
    
    return NSS_STATUS_SUCCESS;
}

/*
 * NSS user functions
 */

/* Rewind "file pointer" to start of ntdom password database */

enum nss_status
_nss_ntdom_setpwent(void)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, result;
    
    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_SETPWENT;
    request.pid = getpid();

    if ((result = write_sock(sock, &request, sizeof(request))) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_UNAVAIL;
    }

    return NSS_STATUS_SUCCESS;
}

/* Close ntdom password database "file pointer" */

enum nss_status
_nss_ntdom_endpwent(void)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock;
    
    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_ENDPWENT;
    request.pid = getpid();

    if (write_sock(sock, &request, sizeof(request)) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_UNAVAIL;
    }

    return NSS_STATUS_SUCCESS;
}

/* Fetch the next password entry from ntdom password database */

enum nss_status
_nss_ntdom_getpwent_r(struct passwd *result, char *buffer, 
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock;

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWENT;
    request.pid = getpid();

    if (write_sock(sock, &request, sizeof(request)) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_UNAVAIL;
    }

    return fill_pwent(result, &response, &buffer, &buflen, errnop);
}

/* Return passwd struct from uid */

enum nss_status
_nss_ntdom_getpwuid_r(uid_t uid, struct passwd *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock;
    enum nss_status retval;

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWNAM_FROM_UID;
    request.pid = getpid();
    request.data.uid = uid;

    if (write_sock(sock, &request, sizeof(request)) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_UNAVAIL;
    }

    retval = fill_pwent(result, &response, &buffer, &buflen, errnop);

    return retval;
}

/* Return passwd struct from username */

enum nss_status
_nss_ntdom_getpwnam_r(const char *name, struct passwd *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock;
    enum nss_status retval;
    
    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWNAM_FROM_USER;
    request.pid = getpid();
    fstrcpy(request.data.username, name);

    if (write_sock(sock, &request, sizeof(request)) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_UNAVAIL;
    }

    retval = fill_pwent(result, &response, &buffer, &buflen, errnop);

    return retval;
}

/*
 * NSS group functions
 */

/* Rewind "file pointer" to start of ntdom group database */

enum nss_status
_nss_ntdom_setgrent(void)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, result;
    
    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_SETGRENT;
    request.pid = getpid();

    if ((result = write_sock(sock, &request, sizeof(request))) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_UNAVAIL;
    }

    return NSS_STATUS_SUCCESS;
}

/* Close "file pointer" for ntdom group database */

enum nss_status
_nss_ntdom_endgrent(void)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock;
    
    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_ENDGRENT;
    request.pid = getpid();

    if (write_sock(sock, &request, sizeof(request)) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_UNAVAIL;
    }

    return NSS_STATUS_SUCCESS;
}

/* Get next entry from ntdom group database */

enum nss_status
_nss_ntdom_getgrent_r(struct group *result,
                      char *buffer, size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock;

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRENT;
    request.pid = getpid();

    if (write_sock(sock, &request, sizeof(request)) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result == WINBINDD_OK) {
        return fill_grent(result, &response, &buffer, &buflen, errnop);
    }

    return NSS_STATUS_UNAVAIL;
}

/* Return group struct from group name */

enum nss_status
_nss_ntdom_getgrnam_r(const char *name,
                      struct group *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock;

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRNAM_FROM_GROUP;
    request.pid = getpid();

    fstrcpy(request.data.groupname, name);

    if (write_sock(sock, &request, sizeof(request)) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_UNAVAIL;
    }

    return fill_grent(result, &response, &buffer, &buflen, errnop);
}

/* Return group struct from gid */

enum nss_status
_nss_ntdom_getgrgid_r(gid_t gid,
                      struct group *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock;

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRNAM_FROM_GID;
    request.pid = getpid();
    request.data.gid = gid;

    if (write_sock(sock, &request, sizeof(request)) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_UNAVAIL;
    }

    return fill_grent(result, &response, &buffer, &buflen, errnop);
}
