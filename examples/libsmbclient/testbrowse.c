#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <popt.h>
#include <libsmbclient.h>
#include <stdlib.h>

void error_message(char * pMessage)
{
    printf("ERROR: %s\n", pMessage);
}


static void
get_auth_data_fn(const char * pServer,
                 const char * pShare,
                 char * pWorkgroup,
                 int maxLenWorkgroup,
                 char * pUsername,
                 int maxLenUsername,
                 char * pPassword,
                 int maxLenPassword)
    
{
    char temp[128];
    
    printf("Entered get_auth_data_fn\n");

    fprintf(stdout, "Need password for //%s/%s\n", pServer, pShare);
    
    fprintf(stdout, "Username: [%s] ", pUsername);
    fgets(temp, sizeof(temp), stdin);
    
    if (temp[strlen(temp) - 1] == '\n') /* A new line? */
    {
        temp[strlen(temp) - 1] = '\0';
    }
    
    if (temp[0] != '\0')
    {
        strncpy(pUsername, temp, maxLenUsername - 1);
    }
    
    strcpy(temp, getpass("Password: "));
    
    if (temp[strlen(temp) - 1] == '\n') /* A new line? */
    {
        temp[strlen(temp) - 1] = '\0';
    }
    
    if (temp[0] != '\0')
    {
        strncpy(pPassword, temp, maxLenPassword - 1);
    }

    fprintf(stdout, "Workgroup: ");
    fgets(temp, sizeof(temp), stdin);
    
    if (temp[strlen(temp) - 1] == '\n') /* A new line? */
    {
        temp[strlen(temp) - 1] = '\0';
    }
    
    if (temp[0] != '\0')
    {
        strncpy(pWorkgroup, temp, maxLenWorkgroup - 1);
    }

    putchar('\n');
}


int
main(int argc, char * argv[])
{
    int                         debug = 0;
    int                         opt;
    char *                      p;
    char *                      q;
    char                        buf[1024];
    int                         dir;
    struct stat                 stat;
    struct smbc_dirent *        dirent;
    poptContext pc;
    struct poptOption           long_options[] =
        {
            POPT_AUTOHELP
            {
                "debug", 'd', POPT_ARG_INT, &debug,
                0, "Set debug level", "integer"
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

    if (smbc_init(get_auth_data_fn, debug) != 0)
    {
        printf("Could not initialize smbc_ library\n");
        return 1;
    }
    
    for (fputs("url: ", stdout), p = fgets(buf, sizeof(buf), stdin);
         p != NULL && *p != '\n' && *p != '\0';
         fputs("url: ", stdout), p = fgets(buf, sizeof(buf), stdin))
    {
        if ((p = strchr(buf, '\n')) != NULL)
        {
            *p = '\0';
        }
        
        printf("Opening (%s)...\n", buf);
        
        if ((dir = smbc_opendir(buf)) < 0)
        {
            printf("Could not open directory [%s] (%d:%s)\n",
                   buf, errno, strerror(errno));
            continue;
        }

        while ((dirent = smbc_readdir(dir)) != NULL)
        {
            printf("%-30s", dirent->name);
            printf("%-30s", dirent->comment);

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

                q = buf + strlen(buf);
                strcat(q, "/");
                strcat(q+1, dirent->name);
                if (smbc_stat(buf, &stat) < 0)
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
        }

        smbc_closedir(dir);
    }

    exit(0);
}
