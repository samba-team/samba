/* 
   Unix SMB/CIFS implementation.
   SMB client library test program for browsing with different master browsers
   Copyright (C) Derrell Lipman 2004
   
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
#include <errno.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <libsmbclient.h>

static void
auth_fn(const char * pServer,
        const char * pShare,
        char * pWorkgroup,
        int workgroup_len,
        char * pUsername,
        int username_len,
        char * pPassword,
        int password_len)
    
{
    strncpy(pUsername, "anonymous", username_len); /* doesn't matter what */
    strncpy(pPassword, "password", password_len);  /* ditto */
}


int
main(int argc, char * argv[])
{
    int                         debug = 4;
    int                         opt;
    char *                      p;
    char                        buf[1024];
    int                         dir;
    struct smbc_dirent *        dirent;
    char **                     ppUrl;
    char *                      urlList[] =
        {
            "smb://",
            "smb://?mb=.any",
            "smb://?mb=.all",
            "smb://?mb=xx",     /* this one is suupposed to fail */
            NULL
        };
    
    if (smbc_init(auth_fn, debug) != 0)
    {
        printf("Could not initialize smbc_ library\n");
        return 1;
    }
    
    for (ppUrl = urlList; *ppUrl != NULL; ppUrl++)
    {
        printf("Opening (%s)...\n", *ppUrl);
    
        if ((dir = smbc_opendir(*ppUrl)) < 0)
        {
            printf("Could not open [%s] (%d:%s)\n",
                   *ppUrl, errno, strerror(errno));
            continue;
        }
    
        while ((dirent = smbc_readdir(dir)) != NULL)
        {
            printf("%s\n", dirent->name);
        }
    
        smbc_closedir(dir);
    }
    
    exit(0);
}

