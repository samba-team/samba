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

#include "includes.h"
#include <nss.h>

/* I think I know what I'm doing here (-: */

#ifdef strcpy
#undef strcpy      
#endif

#ifdef strcat
#undef strcat
#endif

/*
 * Utility and helper functions
 */

/* Connect to winbindd socket */

static int open_root_pipe_sock(void)
{
    static int established_socket = -1;
    struct sockaddr_un sunaddr;
    static pid_t our_pid;
    struct stat st;
    fstring path;

    if (our_pid != getpid()) {
        if (established_socket != -1) close(established_socket);
        established_socket = -1;
        our_pid = getpid();
    }

    if (established_socket != -1) {
        return established_socket;
    }

    /* Check permissions on unix socket file and directory */

    if (lstat(WINBINDD_SOCKET_DIR, &st) == -1) {
        return -1;
    }

    if (!S_ISDIR(st.st_mode) || (st.st_uid != 0)) {
        return -1;
    }

    /* Create socket */

    if ((established_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return -1;
    }

    /* Connect to socket */

    strncpy(path, WINBINDD_SOCKET_DIR, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';

    strncat(path, "/", sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';

    strncat(path, WINBINDD_SOCKET_NAME, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';

    ZERO_STRUCT(sunaddr);
    sunaddr.sun_family = AF_UNIX;
    strncpy(sunaddr.sun_path, path, sizeof(sunaddr.sun_path) - 1);

    if (connect(established_socket, (struct sockaddr *)&sunaddr, 
                sizeof(sunaddr)) == -1) {
        close(established_socket);
        established_socket = -1;
        return -1;
    }

    return established_socket;
}

/* Write data to winbindd socket with timeout */

int write_sock(int sock, void *buffer, int count)
{
    int result, nwritten;

    /* Write data to socket */

    nwritten = 0;

    while(nwritten < count) {

        result = write(sock, (char *)buffer + nwritten, count - nwritten);
        
        if ((result == -1) || (result == 0)) {

            /* Write failed */
            
            return result;
        }

        nwritten += result;
    }
    
    return nwritten;
}

/* Read data from winbindd socket with timeout */

int read_sock(int sock, void *buffer, int count)
{
    int result, nread;

    /* Read data from socket */

    nread = 0;

    while(nread < count) {

        result = read(sock, (char *)buffer + nread, count - nread);
        
        if ((result == -1) || (result == 0)) {

            /* Read failed */
            
            return result;
        }
        
        nread += result;
    }

    return nread;
}

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

/* I've copied the strtok() replacement function next_token() from
   lib/util_str.c as I really don't want to have to link in any other
   objects if I can possibly avoid it. */

#ifdef strchr /* Aargh! This points at multibyte_strchr(). )-: */
#undef strchr
#endif

static char *last_ptr = NULL;

BOOL next_token(char **ptr, char *buff, char *sep, size_t bufsize)
{
    char *s;
    BOOL quoted;
    size_t len=1;
    
    if (!ptr) ptr = &last_ptr;
    if (!ptr) return(False);
    
    s = *ptr;
    
    /* default to simple separators */
    if (!sep) sep = " \t\n\r";
    
    /* find the first non sep char */
    while(*s && strchr(sep,*s)) s++;
    
    /* nothing left? */
    if (! *s) return(False);
    
    /* copy over the token */
    for (quoted = False; 
         len < bufsize && *s && (quoted || !strchr(sep,*s)); 
         s++) {

        if (*s == '\"') {
            quoted = !quoted;
        } else {
            len++;
            *buff++ = *s;
        }
    }
    
    *ptr = (*s) ? s+1 : s;  
    *buff = 0;
    last_ptr = *ptr;
  
    return(True);
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

    strcpy(result->pw_name, pw->pw_name);

    /* Password */

    if ((result->pw_passwd = 
         get_static(buffer, buflen, strlen(pw->pw_passwd) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    strcpy(result->pw_passwd, pw->pw_passwd);
        
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

    strcpy(result->pw_gecos, pw->pw_gecos);

    /* Home directory */

    if ((result->pw_dir = 
         get_static(buffer, buflen, strlen(pw->pw_dir) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    strcpy(result->pw_dir, pw->pw_dir);

    /* Logon shell */

    if ((result->pw_shell = 
         get_static(buffer, buflen, strlen(pw->pw_shell) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    strcpy(result->pw_shell, pw->pw_shell);

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
    fstring name;
    char *mem;
    int i;

    /* Group name */

    if ((result->gr_name =
         get_static(buffer, buflen, strlen(gr->gr_name) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    strcpy(result->gr_name, gr->gr_name);

    /* Password */

    if ((result->gr_passwd =
         get_static(buffer, buflen, strlen(gr->gr_passwd) + 1)) == NULL) {

        /* Out of memory */

        *errnop = ERANGE;
        return NSS_STATUS_TRYAGAIN;
    }

    strcpy(result->gr_passwd, gr->gr_passwd);

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

    mem = gr->gr_mem;

    while(next_token(&mem, name, ",", sizeof(fstring))) {
        
        /* Allocate space for member */
        
        if (((result->gr_mem)[i] = 
             get_static(buffer, buflen, strlen(name) + 1)) == NULL) {
            
            /* Out of memory */
            
            *errnop = ERANGE;
            return NSS_STATUS_TRYAGAIN;
        }        
        
        strcpy((result->gr_mem)[i], name);
        i++;
    }

    /* Terminate list */

    (result->gr_mem)[i] = NULL;
    
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
    
    if ((sock = open_root_pipe_sock()) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_SETPWENT;

    if ((result = write_sock(sock, &request, sizeof(request))) == -1) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) == -1) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

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
  
    if ((sock = open_root_pipe_sock()) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_ENDPWENT;

    if (write_sock(sock, &request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) == -1) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

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
  
    if ((sock = open_root_pipe_sock()) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWENT;

    if (write_sock(sock, &request, sizeof(request)) == -1) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) == -1) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

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
  
    if ((sock = open_root_pipe_sock()) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWNAM_FROM_UID;
    request.data.uid = uid;

    if (write_sock(sock, &request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) == -1) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

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
  
    if ((sock = open_root_pipe_sock()) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWNAM_FROM_USER;

    strncpy(request.data.username, name, sizeof(request.data.username) - 1);
    request.data.username[sizeof(request.data.username) - 1] = '\0';

    if (write_sock(sock, &request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

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
  
    if ((sock = open_root_pipe_sock()) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_SETGRENT;

    if ((result = write_sock(sock, &request, sizeof(request))) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) == -1) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

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
  
    if ((sock = open_root_pipe_sock()) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_ENDGRENT;

    if (write_sock(sock, &request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) == -1) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

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
  
    if ((sock = open_root_pipe_sock()) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRENT;

    if (write_sock(sock, &request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) == -1) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

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
  
    if ((sock = open_root_pipe_sock()) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRNAM_FROM_GROUP;

    strncpy(request.data.groupname, name, sizeof(request.data.groupname));
    request.data.groupname[sizeof(request.data.groupname) - 1] = '\0';

    if (write_sock(sock, &request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) == -1) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

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
  
    if ((sock = open_root_pipe_sock()) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRNAM_FROM_GID;
    request.data.gid = gid;

    if (write_sock(sock, &request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(sock, &response, sizeof(response)) == -1) {
        close(sock);
        return NSS_STATUS_UNAVAIL;
    }

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_UNAVAIL;
    }

    return fill_grent(result, &response, &buffer, &buflen, errnop);
}
