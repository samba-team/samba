#include <sys/types.h>
#include <sys/statvfs.h>
#include <stdio.h> 
#include <unistd.h>
#include <string.h> 
#include <time.h> 
#include <errno.h>
#include <libsmbclient.h> 
#include "get_auth_data_fn.h"


int main(int argc, char * argv[]) 
{ 
    int             i;
    int             fd;
    int             ret;
    int             debug = 0;
    char *          p;
    char            path[2048];
    struct stat     statbuf;
    struct statvfs  statvfsbuf;
    
    smbc_init(get_auth_data_fn, debug); 
    
    for (;;)
    {
        fprintf(stdout, "Path: ");
        *path = '\0';
        fgets(path, sizeof(path) - 1, stdin);
        if (strlen(path) == 0)
        {
            return 0;
        }

        p = path + strlen(path) - 1;
        if (*p == '\n')
        {
            *p = '\0';
        }
    
        /* Determine if it's a file or a folder */
        if (smbc_stat(path, &statbuf) < 0)
        {
            perror("smbc_stat");
            continue;
        }

        if (S_ISREG(statbuf.st_mode))
        {
            if ((fd = smbc_open(path, O_RDONLY, 0)) < 0)
            {
                perror("smbc_open");
                continue;
            }
        }
        else
        {
            if ((fd = smbc_opendir(path)) < 0)
            {
                perror("smbc_opendir");
                continue;
            }
        }

        ret = smbc_fstatvfs(fd, &statvfsbuf);

        smbc_close(fd);

        if (ret < 0)
        {
            perror("fstatvfs");
        }
        else if (statvfsbuf.f_flag == 0)
        {
            printf("No capabilities found\n");
        }
        else
        {
            printf("Capabilities: ");

            if (statvfsbuf.f_flag & SMBC_VFS_CAP_UNIXCIFS)
            {
                printf("UNIXCIFS ");
            }

            if (statvfsbuf.f_flag & SMBC_VFS_CAP_CASE_SENSITIVE)
            {
                printf("CASE_SENSITIVE ");
            }

            if (statvfsbuf.f_flag & SMBC_VFS_CAP_DFS)
            {
                printf("DFS ");
            }

            printf("\n");
        }
    }

    return 0; 
}
