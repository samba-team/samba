#include <stdio.h> 
#include <unistd.h>
#include <string.h> 
#include <time.h> 
#include <libsmbclient.h> 

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



int main(int argc, char * argv[]) 
{ 
    char            buffer[16384]; 
    char *          pSmbPath = NULL;
    char *          pLocalPath = NULL;
    struct stat     st; 
    
    if (argc == 1)
    {
        pSmbPath = "smb://RANDOM/Public/small";
        pLocalPath = "/random/home/samba/small";
    }
    else if (argc == 2)
    {
        pSmbPath = argv[1];
        pLocalPath = NULL;
    }
    else if (argc == 3)
    {
        pSmbPath = argv[1];
        pLocalPath = argv[2];
    }
    else
    {
        printf("usage: "
               "%s [ smb://path/to/file [ /nfs/or/local/path/to/file ] ]\n",
               argv[0]);
        return 1;
    }

    smbc_init(get_auth_data_fn, 0); 
    
    int ret = smbc_stat(pSmbPath, &st); 
    
    printf("SAMBA\nret=%d,\n mtime:%lu/%s ctime:%lu/%s atime:%lu/%s\n", ret, 
           st.st_mtime, ctime(&st.st_mtime),
           st.st_ctime, ctime(&st.st_ctime),
           st.st_atime, ctime(&st.st_atime)); 
    
    if (pLocalPath != NULL)
    {
        ret = stat(pLocalPath, &st); 
        
        printf("LOCAL\nret=%d,\n mtime:%lu/%s ctime:%lu/%s atime:%lu/%s\n", ret, 
               st.st_mtime, ctime(&st.st_mtime),
               st.st_ctime, ctime(&st.st_ctime),
               st.st_atime, ctime(&st.st_atime));
    }

    return 0; 
}
