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

/* Connect to winbindd socket */

int connect_sock(void)
{
    int sock, result;
    struct sockaddr_un sunaddr;
    fd_set writefd;
    struct timeval timeout;

    sunaddr.sun_family = AF_UNIX;
    strncpy(sunaddr.sun_path, WINBINDD_SOCKET_NAME, sizeof(sunaddr.sun_path));

    /* Create socket */

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    /* Attempt to connect.  Use select as the connect() call can block
       for a long time if the winbindd is suspended (e.g in gdb). */

    if (fcntl(sock, F_SETFL, O_NONBLOCK | fcntl(sock, F_GETFL)) < 0) {
        perror("fcntl");
        return -1;
    }

    FD_ZERO(&writefd);
    FD_SET(sock, &writefd);
    timeout.tv_sec = WINBINDD_TIMEOUT_SEC;
    timeout.tv_usec = 0;
    
    if ((result = select(sock + 1, NULL, &writefd, NULL, 
                         &timeout)) <= 0) {
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) < 0) {
        return -1;
    }

    return sock;
}

/* Create ipc socket */

int create_sock(void)
{
    struct sockaddr_un sunaddr;
    struct stat st;
    int ret, sock;

    ret = stat(WINBINDD_SOCKET_NAME, &st);
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
    strncpy(sunaddr.sun_path, WINBINDD_SOCKET_NAME, sizeof(sunaddr.sun_path));
    
    if (bind(sock, (struct sockaddr *)&sunaddr, sizeof(sunaddr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    
   if (chmod(WINBINDD_SOCKET_NAME, 0666) < 0) {
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

/* Write data to winbindd socket with timeout */

int write_sock(int sock, void *buffer, int count)
{
    int result, nwritten;
    fd_set writefd;
    struct timeval timeout;

    /* Write data to socket */

    nwritten = 0;

    FD_ZERO(&writefd);
    FD_SET(sock, &writefd);
    timeout.tv_sec = WINBINDD_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    while(nwritten < count) {

        if ((result = select(sock + 1, NULL, &writefd, NULL, 
                             &timeout)) <= 0) {

            /* Timed out or other error */

            return -1;
        }

        if ((result = write(sock, buffer, count)) < 0) {

            /* Write failed */

            return -1;
        }

        nwritten += result;
    }

    return nwritten;
}

/* Read data from winbindd socket with timeout */

int read_sock(int sock, void *buffer, int count)
{
    int result, nread;
    fd_set readfd;
    struct timeval timeout;

    /* Read data from socket */

    nread = 0;

    FD_ZERO(&readfd);
    FD_SET(sock, &readfd);
    timeout.tv_sec = WINBINDD_TIMEOUT_SEC;
    timeout.tv_usec = 0;

    while(nread < count) {

        if ((result = select(sock + 1, &readfd, NULL, NULL, &timeout)) <= 0) {

            /* Timed out or other error */

            return -1;
        }

        if ((result = read(sock, buffer, count)) <= 0) {

            /* Write failed */

            return -1;
        }

        nread += result;
    }

    return nread;
}

void remove_sock(void)
{
    unlink(WINBINDD_SOCKET_NAME);
}
