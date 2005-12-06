#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <popt.h>
#include <stdlib.h>
#include <libsmbclient.h>
#include "get_auth_data_fn.h"

static void
no_auth_data_fn(const char * pServer,
                const char * pShare,
                char * pWorkgroup,
                int maxLenWorkgroup,
                char * pUsername,
                int maxLenUsername,
                char * pPassword,
                int maxLenPassword);

static void browse(char * path,
                   int scan,
                   int indent);



int
main(int argc, char * argv[])
{
    int                         debug = 0;
    int                         scan = 0;
    int                         iterations = -1;
    int                         again;
    int                         opt;
    char *                      p;
    char *                      q;
    char                        buf[1024];
    poptContext                 pc;
    struct poptOption           long_options[] =
        {
            POPT_AUTOHELP
            {
                "debug", 'd', POPT_ARG_INT, &debug,
                0, "Set debug level", "integer"
            },
            {
                "scan", 's', POPT_ARG_NONE, &scan,
                0, "Scan for servers and shares", "integer"
            },
            {
                "iterations", 'i', POPT_ARG_INT, &iterations,
                0, "Iterations", "integer"
            },
            {
                NULL
            }
        };
    
    setbuf(stdout, NULL);

    pc = poptGetContext("opendir", argc, (const char **)argv, long_options, 0);
    
    poptSetOtherOptionHelp(pc, "");
    
    while ((opt = poptGetNextOpt(pc)) != -1) {
        printf("Got option %d = %c\n", opt, opt);
        switch (opt) {
        }
    }

    if (scan)
    {
        if (smbc_init(no_auth_data_fn, debug) != 0)
        {
            printf("Could not initialize smbc_ library\n");
            return 1;
        }

        for (;
             iterations == -1 || iterations > 0;
             iterations = (iterations == -1 ? iterations : --iterations))
        {
            snprintf(buf, sizeof(buf), "smb://");
            browse(buf, scan, 0);
        }
    }
    else
    {
        if (smbc_init(get_auth_data_fn, debug) != 0)
        {
            printf("Could not initialize smbc_ library\n");
            return 1;
        }
    
        for (;
             iterations == -1 || iterations > 0;
             iterations = (iterations == -1 ? iterations : --iterations))
        {
            fputs("url: ", stdout);
            p = fgets(buf, sizeof(buf), stdin);
            if (! p)
            {
                break;
            }

            if ((p = strchr(buf, '\n')) != NULL)
            {
                *p = '\0';
            }
            
            browse(buf, scan, 0);
        }
    }

    exit(0);
}


static void
no_auth_data_fn(const char * pServer,
                const char * pShare,
                char * pWorkgroup,
                int maxLenWorkgroup,
                char * pUsername,
                int maxLenUsername,
                char * pPassword,
                int maxLenPassword)
{
    return;
}

static void browse(char * path, int scan, int indent)
{
    char *                      p;
    char                        buf[1024];
    int                         dir;
    struct stat                 stat;
    struct smbc_dirent *        dirent;

    if (! scan)
    {
        printf("Opening (%s)...\n", path);
    }
        
    if ((dir = smbc_opendir(path)) < 0)
    {
        printf("Could not open directory [%s] (%d:%s)\n",
               path, errno, strerror(errno));
        return;
    }

    while ((dirent = smbc_readdir(dir)) != NULL)
    {
        printf("%*.*s%-30s", indent, indent, "", dirent->name);

        switch(dirent->smbc_type)
        {
        case SMBC_WORKGROUP:
            printf("WORKGROUP");
            break;
            
        case SMBC_SERVER:
            printf("SERVER");
            break;
            
        case SMBC_FILE_SHARE:
            printf("FILE_SHARE");
            break;
            
        case SMBC_PRINTER_SHARE:
            printf("PRINTER_SHARE");
            break;
            
        case SMBC_COMMS_SHARE:
            printf("COMMS_SHARE");
            break;
            
        case SMBC_IPC_SHARE:
            printf("IPC_SHARE");
            break;
            
        case SMBC_DIR:
            printf("DIR");
            break;
            
        case SMBC_FILE:
            printf("FILE");

            p = path + strlen(path);
            strcat(p, "/");
            strcat(p+1, dirent->name);
            if (smbc_stat(path, &stat) < 0)
            {
                printf(" unknown size (reason %d: %s)",
                       errno, strerror(errno));
            }
            else
            {
                printf(" size %lu", (unsigned long) stat.st_size);
            }
            *p = '\0';

            break;
            
        case SMBC_LINK:
            printf("LINK");
            break;
        }

        printf("\n");

        if (scan &&
            (dirent->smbc_type == SMBC_WORKGROUP ||
             dirent->smbc_type == SMBC_SERVER))
        {
            /*
             * don't append server name to workgroup; what we want is:
             *
             *   smb://workgroup_name
             * or
             *   smb://server_name
             *
             */
            snprintf(buf, sizeof(buf), "smb://%s", dirent->name);
            browse(buf, scan, indent + 2);
        }
    }

    smbc_closedir(dir);
}
    
