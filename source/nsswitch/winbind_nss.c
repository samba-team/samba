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

#define NSS_DEBUG 0

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <nss.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "includes.h"
#include "winbindd.h"

/* Allocate some space from the nss static buffer */

static char *get_static(char **buffer, int *buflen, int len)
{
    char *result;

    if ((buffer == NULL) || (buflen == NULL) || (*buflen < len)) {
        return NULL;
    }

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
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    fstrcpy(result->pw_name, pw->pw_name);

    /* Password */

    if ((result->pw_passwd = 
         get_static(buffer, buflen, strlen(pw->pw_passwd) + 1)) 
        == NULL) {
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
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    fstrcpy(result->pw_gecos, pw->pw_gecos);

    /* Home directory */

    if ((result->pw_dir = 
         get_static(buffer, buflen, strlen(pw->pw_dir) + 1)) == NULL) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    fstrcpy(result->pw_dir, pw->pw_dir);

    /* Logon shell */

    if ((result->pw_shell = 
         get_static(buffer, buflen, strlen(pw->pw_shell) + 1)) == NULL) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    fstrcpy(result->pw_shell, pw->pw_shell);

    return NSS_STATUS_SUCCESS;
}

static int fill_grent(struct group *result,
                      struct winbindd_response *response,
                      char **buffer, int *buflen, int *errnop)
{
    struct winbindd_gr *gr = &response->data.gr;
    char *tmp_mem;

    /* Group name */

    if ((result->gr_name =
         get_static(buffer, buflen, strlen(gr->gr_name) + 1)) == NULL) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    fstrcpy(result->gr_name, gr->gr_name);

    /* Password */

    if ((result->gr_passwd =
         get_static(buffer, buflen, strlen(gr->gr_passwd) + 1)) == NULL) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }
    fstrcpy(result->gr_passwd, gr->gr_passwd);

    /* gid */

    result->gr_gid = gr->gr_gid;

    /* Group membership.  Turn comma separated string into array of
       char pointers. */

    if ((result->gr_mem = 
         (char **)get_static(buffer, buflen, (gr->num_gr_mem + 1) * 
                             sizeof(char *))) == NULL) {
        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    if (gr->num_gr_mem == 0) {
        *(result->gr_mem) = NULL;
        return NSS_STATUS_SUCCESS;
    }

    if ((tmp_mem = strtok(gr->gr_mem, ",")) != NULL) {
        int i;
        
        if ((*(result->gr_mem) = 
             get_static(buffer, buflen, strlen(tmp_mem) + 1)) == NULL) {
            *errnop = ERANGE;
            return NSS_STATUS_TRYAGAIN;
        }        

        fstrcpy(*(result->gr_mem), tmp_mem);

        for (i = 1; i < gr->num_gr_mem; i++) {
            tmp_mem = strtok(NULL, ",");

            if (((result->gr_mem)[i] = 
                 get_static(buffer, buflen, strlen(tmp_mem) + 1)) == NULL) {
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
            }
            fstrcpy((result->gr_mem)[i], tmp_mem);
        }

        (result->gr_mem)[gr->num_gr_mem] = NULL;
    }
    
    return NSS_STATUS_SUCCESS;
}

/* Enumerate pwent */

enum nss_status
_nss_ntdom_setpwent(void)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, result;
    
#if NSS_DEBUG
    fprintf(stderr, "ntdom_setpwent()\n");
#endif

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_SETPWENT;

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

enum nss_status
_nss_ntdom_endpwent(void)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, nwritten;
    
#if NSS_DEBUG
    fprintf(stderr, "ntdom_endpwent()\n");
#endif

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_endpwent(): socket: %s\n", sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_ENDPWENT;

    if ((nwritten = write_sock(sock, &request, sizeof(request))) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_endpwent(): write: %s\n", sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_endpwent(): read: %s\n", sys_errlist[errno]);
#endif
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_endpwent(): winbindd returned error\n");
#endif
        return NSS_STATUS_UNAVAIL;
    }

#if NSS_DEBUG
    fprintf(stderr, "ntdom_endpwent(): ok\n");
#endif
    return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_ntdom_getpwent_r(struct passwd *result,
                      char *buffer, size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, nwritten;

#if NSS_DEBUG
    fprintf(stderr, "ntdom_getpwent()\n");
#endif

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWENT;

    if ((nwritten = write_sock(sock, &request, sizeof(request))) < 0) {
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

enum nss_status
_nss_ntdom_setgrent(void)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, result;
    
#if NSS_DEBUG
    fprintf(stderr, "ntdom_setgrent()\n");
#endif

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_setgrent(): socket: %s\n", sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_SETGRENT;

    if ((result = write_sock(sock, &request, sizeof(request))) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_setgrent(): write: %s\n", sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_setgrent(): read: %s\n", sys_errlist[errno]);
#endif
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_setgrent(): winbindd returned error\n");
#endif
        return NSS_STATUS_UNAVAIL;
    }

#if NSS_DEBUG
    fprintf(stderr, "ntdom_setgrent(): ok\n");
#endif

    return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_ntdom_endgrent(void)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, nwritten;
    
#if NSS_DEBUG
    fprintf(stderr, "ntdom_endgrent()\n");
#endif

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_endgrent(): socket: %s\n", sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_ENDGRENT;

    if ((nwritten = write_sock(sock, &request, sizeof(request))) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_endgrent(): write: %s\n", sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_endgrent(): read: %s\n", sys_errlist[errno]);
#endif
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_endgrent(): winbindd returned error\n");
#endif
        return NSS_STATUS_UNAVAIL;
    }

#if NSS_DEBUG
    fprintf(stderr, "ntdom_endgrent(): ok\n");
#endif

    return NSS_STATUS_SUCCESS;
}

enum nss_status
_nss_ntdom_getgrent_r(struct group *result,
                      char *buffer, size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, nwritten;
    enum nss_status retval;

#if NSS_DEBUG
    fprintf(stderr, "ntdom_getgrent()\n");
#endif

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getgrent(): socket: %s\n",
                sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRENT;

    if ((nwritten = write_sock(sock, &request, sizeof(request))) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getgrent(): write: %s\n",
                sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getgrent(): read %s\n",
                sys_errlist[errno]);
#endif
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getgrent(): winbindd returned error\n");
#endif
        return NSS_STATUS_UNAVAIL;
    }

    retval = fill_grent(result, &response, &buffer, &buflen, errnop);

#if NSS_DEBUG
    if (retval != NSS_STATUS_SUCCESS) {
        fprintf(stderr, "ntdom_getgrent(): fill_grent returned error\n");
    } else {
        fprintf(stderr, "ntdom_getgrent(): ok\n");
    }
#endif

    return retval;
}

/* Return (struct passwd *) given username */

enum nss_status
_nss_ntdom_getpwnam_r(const char *name,
                      struct passwd *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, nwritten;
    enum nss_status retval;
    
#if NSS_DEBUG
    fprintf(stderr, "ntdom_getpwnam(%s)\n", name);
#endif

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getpwnam(): socket: %s\n", sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWNAM_FROM_USER;
    fstrcpy(request.data.username, name);

    if ((nwritten = write_sock(sock, &request, sizeof(request))) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getpwnam(): write: %s\n", sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getpwnam(): read: %s\n", sys_errlist[errno]);
#endif
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getpwnam(): winbindd returned error\n");
#endif
        return NSS_STATUS_UNAVAIL;
    }

    retval = fill_pwent(result, &response, &buffer, &buflen, errnop);

#if NSS_DEBUG
    if (retval != NSS_STATUS_SUCCESS) {
        fprintf(stderr, "ntdom_getpwnam(): fill_pwent returned error\n");
    } else {
        fprintf(stderr, "ntdom_getpwnam(): ok\n");
    }
#endif

    return retval;
}

/* Return (struct passwd *) given uid */

enum nss_status
_nss_ntdom_getpwuid_r(uid_t uid,
                      struct passwd *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, nwritten;
    enum nss_status retval;

#if NSS_DEBUG
    fprintf(stderr, "ntdom_getpwuid(%d)\n", uid);
#endif

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getpwuid(): socket failed: %s\n",
                sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWNAM_FROM_UID;
    request.data.uid = uid;

    if ((nwritten = write_sock(sock, &request, sizeof(request))) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getpwuid(): write failed: %s\n",
                sys_errlist[errno]);
#endif
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) < 0) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getpwuid(): read failed: %s\n",
                sys_errlist[errno]);
#endif
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    close(sock);

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
#if NSS_DEBUG
        fprintf(stderr, "ntdom_getpwuid(): winbindd returned error\n");
#endif
        return NSS_STATUS_UNAVAIL;
    }

    retval = fill_pwent(result, &response, &buffer, &buflen, errnop);

#if NSS_DEBUG
    if (retval != WINBINDD_OK) {
        fprintf(stderr, "ntdom_getpwuid(): fill_pwent returned error\n");
    }
#endif

    return retval;
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
    int sock, nwritten;

#if NSS_DEBUG
    fprintf(stderr, "ntdom_getgrnam(%s)\n", name);
#endif

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRNAM_FROM_GROUP;
    fstrcpy(request.data.groupname, name);

    if ((nwritten = write_sock(sock, &request, sizeof(request))) < 0) {
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
        return NSS_STATUS_SUCCESS;
        return NSS_STATUS_UNAVAIL;
    }

    return fill_grent(result, &response, &buffer, &buflen, errnop);
}

enum nss_status
_nss_ntdom_getgrgid_r(gid_t gid,
                      struct group *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    int sock, nwritten;

#if NSS_DEBUG
    fprintf(stderr, "ntdom_getgrgid(%d)\n", gid);
#endif

    /* Connect to agent socket */
  
    if ((sock = connect_sock()) < 0) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRNAM_FROM_GID;
    request.data.gid = gid;

    if ((nwritten = write_sock(sock, &request, sizeof(request))) < 0) {
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

/*
Local variables:
compile-command: "make -C ~/work/nss-ntdom/samba-tng/source nsswitch"
end:
*/
