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
