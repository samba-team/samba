/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Windows NT Domain nsswitch module

   Copyright (C) Tim Potter 2000
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.
   
   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.
   
   You should have received a copy of the GNU Library General Public
   License along with this library; if not, write to the
   Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA  02111-1307, USA.   
*/

#include "ntdom_config.h"
#include "winbindd_ntdom.h"

/* Global variables.  These are effectively the client state information */

static int established_socket = -1;           /* fd for winbindd socket */

/*
 * Utility and helper functions
 */

/* Close established socket */

void close_sock(void)
{
    if (established_socket != -1) {
        close(established_socket);
        established_socket = -1;
    }
}

/* Connect to winbindd socket */

static int open_root_pipe_sock(void)
{
    struct sockaddr_un sunaddr;
    static pid_t our_pid;
    struct stat st;
    pstring path;

    if (our_pid != getpid()) {
        if (established_socket != -1) {
            close(established_socket);
        }
        established_socket = -1;
        our_pid = getpid();
    }

    if (established_socket != -1) {
        return established_socket;
    }

    /* Check permissions on unix socket directory */

    if (lstat(WINBINDD_SOCKET_DIR, &st) == -1) {
        return -1;
    }

    if (!S_ISDIR(st.st_mode) || (st.st_uid != 0)) {
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

    /* If socket file doesn't exist, don't bother trying to connect with
       retry.  This is an attempt to make the system usable when the
       winbindd daemon is not running. */

    if (lstat(path, &st) == -1) {
        return -1;
    }

    /* Check permissions on unix socket file */
    
    if (!S_ISSOCK(st.st_mode) || (st.st_uid != 0)) {
        return -1;
    }

    /* Connect to socket */

    if ((established_socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return -1;
    }

    if (connect(established_socket, (struct sockaddr *)&sunaddr, 
                sizeof(sunaddr)) == -1) {
        close_sock();
        return -1;
    }
        
    return established_socket;
}

/* Write data to winbindd socket with timeout */

int write_sock(void *buffer, int count)
{
    int result, nwritten;

    /* Open connection to winbind daemon */

 restart:

    if (open_root_pipe_sock() == -1) {
        return -1;
    }

    /* Write data to socket */

    nwritten = 0;

    while(nwritten < count) {
        struct timeval tv;
        fd_set r_fds;
        int selret;

        /* Catch pipe close on other end by checking if a read() call would 
           not block by calling select(). */

        FD_ZERO(&r_fds);
        FD_SET(established_socket, &r_fds);
        ZERO_STRUCT(tv);

        if ((selret = select(established_socket + 1, &r_fds, NULL, NULL, 
                             &tv)) == -1) {
            close_sock();
            return -1;                         /* Select error */
        }

        /* Write should be OK if fd not available for reading */

        if (!FD_ISSET(established_socket, &r_fds)) {

            /* Do the write */

            result = write(established_socket, (char *)buffer + nwritten, 
                           count - nwritten);

            if ((result == -1) || (result == 0)) {

                /* Write failed */
            
                close_sock();
                return -1;
            }

            nwritten += result;

        } else {

            /* Pipe has closed on remote end */

            close_sock();
            goto restart;
        }
    }
    
    return nwritten;
}

/* Read data from winbindd socket with timeout */

int read_sock(void *buffer, int count)
{
    int result, nread;

   /* Read data from socket */

    nread = 0;

    while(nread < count) {

        result = read(established_socket, (char *)buffer + nread, 
                      count - nread);
        
        if ((result == -1) || (result == 0)) {

            /* Read failed.  I think the only useful thing we can do here 
               is just return -1 and fail since the transaction has failed
               half way through. */
            
            close_sock();
            return -1;
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
    char *domain_env;
    
    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_SETPWENT;
    request.pid = getpid();
    request.data.domain[0] = '\0';

    if ((domain_env = getenv(WINBINDD_DOMAIN_ENV))) {

        /* Copy across contents of environment variable */

        strncpy(request.data.domain, domain_env,
                sizeof(request.data.domain) - 1);
        request.data.domain[sizeof(request.data.domain) - 1] = '\0';
    }

    if (write_sock(&request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(&response, sizeof(response)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_NOTFOUND;
    }

    return NSS_STATUS_SUCCESS;
}

/* Close ntdom password database "file pointer" */

enum nss_status
_nss_ntdom_endpwent(void)
{
    struct winbindd_request request;
    struct winbindd_response response;
    char *domain_env;
    
    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_ENDPWENT;
    request.pid = getpid();
    request.data.domain[0] = '\0';

    if ((domain_env = getenv(WINBINDD_DOMAIN_ENV))) {

        /* Copy across contents of environment variable */

        strncpy(request.data.domain, domain_env,
                sizeof(request.data.domain) - 1);
        request.data.domain[sizeof(request.data.domain) - 1] = '\0';
    }

    if (write_sock(&request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(&response, sizeof(response)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_NOTFOUND;
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
    char *domain_env;

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWENT;
    request.pid = getpid();
    request.data.domain[0] = '\0';

    if ((domain_env = getenv(WINBINDD_DOMAIN_ENV))) {

        /* Copy across contents of environment variable */

        strncpy(request.data.domain, domain_env,
                sizeof(request.data.domain) - 1);
        request.data.domain[sizeof(request.data.domain) - 1] = '\0';
    }

    if (write_sock(&request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(&response, sizeof(response)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_NOTFOUND;
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

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWNAM_FROM_UID;
    request.data.uid = uid;
    request.pid = getpid();

    if (write_sock(&request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(&response, sizeof(response)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_NOTFOUND;
    }

    return fill_pwent(result, &response, &buffer, &buflen, errnop);
}

/* Return passwd struct from username */

enum nss_status
_nss_ntdom_getpwnam_r(const char *name, struct passwd *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;
    
    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETPWNAM_FROM_USER;
    request.pid = getpid();

    strncpy(request.data.username, name, sizeof(request.data.username) - 1);
    request.data.username[sizeof(request.data.username) - 1] = '\0';

    if (write_sock(&request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(&response, sizeof(response)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_NOTFOUND;
    }

    return fill_pwent(result, &response, &buffer, &buflen, errnop);
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
    char *domain_env;

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_SETGRENT;
    request.pid = getpid();
    request.data.domain[0] = '\0';

    if ((domain_env = getenv(WINBINDD_DOMAIN_ENV))) {

        /* Copy across contents of environment variable */

        strncpy(request.data.domain, domain_env,
                sizeof(request.data.domain) - 1);
        request.data.domain[sizeof(request.data.domain) - 1] = '\0';
    }

    if (write_sock(&request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(&response, sizeof(response)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_NOTFOUND;
    }

    return NSS_STATUS_SUCCESS;
}

/* Close "file pointer" for ntdom group database */

enum nss_status
_nss_ntdom_endgrent(void)
{
    struct winbindd_request request;
    struct winbindd_response response;
    char *domain_env;

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_ENDGRENT;
    request.pid = getpid();
    request.data.domain[0] = '\0';

    if ((domain_env = getenv(WINBINDD_DOMAIN_ENV))) {

        /* Copy across contents of environment variable */
        
        strncpy(request.data.domain, domain_env,
                sizeof(request.data.domain) - 1);
        request.data.domain[sizeof(request.data.domain) - 1] = '\0';
    }

    if (write_sock(&request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(&response, sizeof(response)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_NOTFOUND;
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
    char *domain_env;

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRENT;
    request.pid = getpid();
    request.data.domain[0] = '\0';

    if ((domain_env = getenv(WINBINDD_DOMAIN_ENV))) {

        /* Copy across contents of environment variable */

        strncpy(request.data.domain, domain_env, 
                sizeof(request.data.domain) - 1);
        request.data.domain[sizeof(request.data.domain) - 1] = '\0';
    }

    if (write_sock(&request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(&response, sizeof(response)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_UNAVAIL;
    }

    return fill_grent(result, &response, &buffer, &buflen, errnop);
}

/* Return group struct from group name */

enum nss_status
_nss_ntdom_getgrnam_r(const char *name,
                      struct group *result, char *buffer,
                      size_t buflen, int *errnop)
{
    struct winbindd_request request;
    struct winbindd_response response;

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRNAM_FROM_GROUP;
    request.pid = getpid();

    strncpy(request.data.groupname, name, sizeof(request.data.groupname));
    request.data.groupname[sizeof(request.data.groupname) - 1] = '\0';

    if (write_sock(&request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(&response, sizeof(response)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_NOTFOUND;
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

    /* Fill in request and send down pipe */

    request.cmd = WINBINDD_GETGRNAM_FROM_GID;
    request.data.gid = gid;
    request.pid = getpid();

    if (write_sock(&request, sizeof(request)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Wait for reply */

    if (read_sock(&response, sizeof(response)) == -1) {
        return NSS_STATUS_UNAVAIL;
    }

    /* Copy reply data from socket */

    if (response.result != WINBINDD_OK) {
        return NSS_STATUS_NOTFOUND;
    }

    return fill_grent(result, &response, &buffer, &buflen, errnop);
}
